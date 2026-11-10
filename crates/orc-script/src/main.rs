//! orc SP1 host: runs the orc guest (`program/`) on a presentation plus a
//! guest input and checks it against the native `orc_core::verify_claim`.
//!
//! Two guest ELFs are embedded (see build.rs):
//! - production: trust anchors hardcoded to `api.github.com` + Mozilla roots.
//! - `--test-ca`: TEST ONLY, tlsn's public test CA + `test-server.io`, for
//!   presentations from the local e2e harness. Different vkey, NEVER deploy it.
//!
//! Subcommands (run inside the dev container, from crates/orc-script):
//!   execute --presentation <bin> --input <json> [--test-ca]
//!   vkey [--test-ca] [--elf <path>]
//!   prove --system groth16|plonk|core|compressed --presentation <bin> --input <json> [--test-ca] [--out <json>]
//!   fixture --mock [--production] [--presentation <bin>] [--input <json>] [--out <json>]
//!
//! Build with `--features profiling` for the per-phase cycle breakdown.

use std::{
    cmp::Reverse,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use orc_core::{ClaimError, GuestInput, PublicValues, VerifyParams, verify_claim};
use serde::Serialize;
use sp1_sdk::{
    Elf, ExecutionReport, HashableKey, ProvingKey, SP1ProofWithPublicValues,
    blocking::{ProveRequest, Prover, ProverClient, SP1ProofMode, SP1Stdin},
};

#[cfg(not(clippy))]
const PRODUCTION_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/elf/orc-program"));
#[cfg(not(clippy))]
const TEST_CA_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/elf/orc-program-test-ca"));
// sp1-build skips the guest build under `cargo clippy` (RUSTC_WORKSPACE_WRAPPER is
// clippy-driver), so the ELFs above do not exist there. `cfg(clippy)` is only set by
// clippy-driver, which never links a binary, so these empty stand-ins cannot ship.
#[cfg(clippy)]
const PRODUCTION_ELF: &[u8] = &[];
#[cfg(clippy)]
const TEST_CA_ELF: &[u8] = &[];

const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// Guest phases in execution order: `input`, `params` and `encode` are
/// marked by the guest itself, the rest by `orc_core::verify_claim_tracked`.
const PHASES: [&str; 7] = [
    "input",
    "params",
    orc_core::phase::DESERIALIZE,
    orc_core::phase::VERIFY,
    orc_core::phase::HTTP,
    orc_core::phase::JSON,
    "encode",
];

#[derive(Parser)]
#[command(about = "orc SP1 host: execute / vkey / prove / contract fixtures")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute the guest (no proof); compare with the native verify_claim.
    Execute(ClaimArgs),
    /// Print the program vkey (`vk.bytes32()`, the contract's `programVKey`).
    Vkey {
        /// TEST ONLY: the test-ca ELF instead of the production one.
        #[arg(long)]
        test_ca: bool,
        /// Any other guest ELF (e.g. to cross-check a vkey).
        #[arg(long, conflicts_with = "test_ca")]
        elf: Option<PathBuf>,
    },
    /// Generate and verify a real proof with the local CPU prover.
    /// Groth16/PLONK need ~14+ GB of RAM (not this machine; see M4).
    Prove(ProveArgs),
    /// Write a contract fixture `{programVKey, publicValues, proof}`.
    Fixture(FixtureArgs),
}

#[derive(Args, Clone)]
struct ClaimArgs {
    /// bincode TLSNotary presentation (`orc prove` output).
    #[arg(long)]
    presentation: PathBuf,
    /// Guest input JSON (`orc_core::GuestInput`).
    #[arg(long)]
    input: PathBuf,
    /// TEST ONLY: run the test-ca guest (tlsn test CA, test-server.io).
    #[arg(long)]
    test_ca: bool,
}

#[derive(Args)]
struct ProveArgs {
    #[command(flatten)]
    claim: ClaimArgs,
    #[arg(long, value_enum)]
    system: System,
    /// Fixture JSON path (groth16/plonk); the bincode proof goes next to it
    /// as `.bin`. Default: fixtures/proofs/orc-<variant>-<system>.json
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct FixtureArgs {
    /// Mock proof (empty proof bytes, for SP1MockVerifier). Required: real
    /// proofs come from `prove --system groth16|plonk`.
    #[arg(long, required = true)]
    mock: bool,
    /// Use the production ELF instead of the test-ca one (needs a real
    /// api.github.com 200 presentation).
    #[arg(long)]
    production: bool,
    #[arg(long, default_value_t = default_path("fixtures/test-ca/content-length.bin"))]
    presentation: String,
    #[arg(long, default_value_t = default_path("fixtures/test-ca/content-length.input.json"))]
    input: String,
    #[arg(long, default_value_t = default_path("contracts/fixtures/orc-mock.json"))]
    out: String,
}

#[derive(Clone, Copy, ValueEnum)]
enum System {
    Groth16,
    Plonk,
    Core,
    Compressed,
}

impl System {
    fn mode(self) -> SP1ProofMode {
        match self {
            Self::Groth16 => SP1ProofMode::Groth16,
            Self::Plonk => SP1ProofMode::Plonk,
            Self::Core => SP1ProofMode::Core,
            Self::Compressed => SP1ProofMode::Compressed,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Groth16 => "groth16",
            Self::Plonk => "plonk",
            Self::Core => "core",
            Self::Compressed => "compressed",
        }
    }

    /// Only these have an on-chain (`proof.bytes()`) encoding.
    fn on_chain(self) -> bool {
        matches!(self, Self::Groth16 | Self::Plonk)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Program {
    Production,
    TestCa,
}

impl Program {
    fn new(test_ca: bool) -> Self {
        if test_ca {
            Self::TestCa
        } else {
            Self::Production
        }
    }

    fn elf(self) -> Elf {
        Elf::Static(match self {
            Self::Production => PRODUCTION_ELF,
            Self::TestCa => TEST_CA_ELF,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::TestCa => "test-ca",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::Production => "PRODUCTION guest (api.github.com, Mozilla roots)",
            Self::TestCa => {
                "TEST-CA guest (tlsn test CA, test-server.io). TEST ONLY: NEVER DEPLOY THIS VKEY"
            }
        }
    }

    /// Native mirror of the guest's hardcoded trust anchors.
    fn params(self) -> Result<VerifyParams> {
        match self {
            Self::Production => Ok(VerifyParams::github()),
            Self::TestCa => {
                use tlsn_core::webpki::{CertificateDer, RootCertStore};
                use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
                let roots = RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                };
                VerifyParams::with_root_store(SERVER_DOMAIN, &roots)
                    .map_err(|e| anyhow!("test CA params: {e}"))
            }
        }
    }
}

/// A presentation + guest input, with the native verdict as the reference.
struct Claim {
    presentation: Vec<u8>,
    input: GuestInput,
    program: Program,
    native: Result<PublicValues, ClaimError>,
}

impl Claim {
    fn load(presentation: &Path, input: &Path, program: Program) -> Result<Self> {
        let presentation_bytes =
            fs::read(presentation).with_context(|| format!("read {}", presentation.display()))?;
        let input_json = fs::read(input).with_context(|| format!("read {}", input.display()))?;
        let input_value: GuestInput = serde_json::from_slice(&input_json)
            .with_context(|| format!("parse guest input {}", input.display()))?;
        let native = verify_claim(&presentation_bytes, &input_value, &program.params()?);

        println!("[claim] {}", program.describe());
        println!(
            "[claim] presentation {} ({} B) | input {}",
            presentation.display(),
            presentation_bytes.len(),
            input.display()
        );
        match &native {
            Ok(_) => println!("[native] verify_claim: ACCEPTED"),
            Err(e) => println!("[native] verify_claim: REJECTED: {e}"),
        }
        Ok(Self {
            presentation: presentation_bytes,
            input: input_value,
            program,
            native,
        })
    }

    fn from_args(args: &ClaimArgs) -> Result<Self> {
        Self::load(&args.presentation, &args.input, Program::new(args.test_ca))
    }

    /// Guest stdin, in the order program/src/main.rs reads it.
    fn stdin(&self) -> SP1Stdin {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(self.presentation.clone());
        stdin.write(&self.input);
        stdin
    }

    fn accepted(&self) -> Result<&PublicValues> {
        self.native
            .as_ref()
            .map_err(|e| anyhow!("refusing: native verify_claim rejects this claim: {e}"))
    }
}

/// `{"programVKey","publicValues","proof"}`: the hand-off format the
/// contracts (M3 forge tests, M4 Groth16 tests) read.
#[derive(Serialize)]
struct ContractFixture {
    #[serde(rename = "programVKey")]
    program_vkey: String,
    #[serde(rename = "publicValues")]
    public_values: String,
    proof: String,
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    match Cli::parse().command {
        Command::Execute(args) => execute(&args),
        Command::Vkey { test_ca, elf } => vkey(test_ca, elf),
        Command::Prove(args) => prove(&args),
        Command::Fixture(args) => fixture(&args),
    }
}

fn execute(args: &ClaimArgs) -> Result<()> {
    let claim = Claim::from_args(args)?;
    let client = ProverClient::builder().light().build();

    let (stderr_tx, stderr_rx) = tokio::sync::watch::channel(String::new());
    let started = Instant::now();
    let (public_values, report) = client
        .execute(claim.program.elf(), claim.stdin())
        .stderr(stderr_tx)
        .calculate_gas(true)
        .run()
        .map_err(|e| anyhow!("execute: {e}"))?;
    let wall = started.elapsed();
    let guest_stderr = stderr_rx.borrow().clone();

    print_report(&report, wall);
    let committed = public_values.as_slice();

    match (&claim.native, report.exit_code) {
        (Ok(native), 0) => {
            println!(
                "[guest] committed {} B: 0x{}",
                committed.len(),
                hex::encode(committed)
            );
            ensure!(
                committed == native.to_abi_bytes().as_slice(),
                "guest public values differ from the native verify_claim\n\
                 guest  0x{}\nnative 0x{}",
                hex::encode(committed),
                hex::encode(native.to_abi_bytes())
            );
            println!("{native}");
            println!(
                "[check] OK: guest ACCEPTED; public values byte-identical to native verify_claim"
            );
        }
        (Err(native_err), code) if code != 0 => {
            let expected = format!("orc claim rejected: {native_err}");
            println!("[guest] exit code {code}; stderr: {}", guest_stderr.trim());
            ensure!(
                committed.is_empty(),
                "a rejecting guest committed {} B",
                committed.len()
            );
            ensure!(
                guest_stderr.contains(&expected),
                "guest panic does not carry the native error {expected:?}"
            );
            println!("[check] OK: guest REJECTED (panic) with the native error: {native_err}");
        }
        (Ok(_), code) => {
            bail!("native accepts, but the guest exited with code {code}: {guest_stderr}")
        }
        (Err(e), _) => bail!("native rejects ({e}), but the guest exited with code 0"),
    }
    Ok(())
}

fn vkey(test_ca: bool, elf: Option<PathBuf>) -> Result<()> {
    let (label, elf) = match elf {
        Some(path) => {
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            (path.display().to_string(), Elf::from(bytes))
        }
        None => {
            let program = Program::new(test_ca);
            (program.describe().to_owned(), program.elf())
        }
    };
    // The mock prover runs the same program setup as the CPU prover without
    // loading the recursion keys (~7 GiB).
    let client = ProverClient::builder().mock().build();
    let pk = client.setup(elf).map_err(|e| anyhow!("setup: {e}"))?;
    println!("[vkey] {label}");
    println!("{}", pk.verifying_key().bytes32());
    Ok(())
}

fn prove(args: &ProveArgs) -> Result<()> {
    let claim = Claim::from_args(&args.claim)?;
    let native = claim.accepted()?;
    let out = args.out.clone().unwrap_or_else(|| {
        Path::new(REPO).join(format!(
            "fixtures/proofs/orc-{}-{}.json",
            claim.program.name(),
            args.system.name()
        ))
    });

    let started = Instant::now();
    let client = ProverClient::builder().cpu().build();
    println!("[prove] cpu prover init {:.2?}", started.elapsed());

    let started = Instant::now();
    let pk = client
        .setup(claim.program.elf())
        .map_err(|e| anyhow!("setup: {e}"))?;
    let vk = pk.verifying_key();
    println!(
        "[prove] setup {:.2?} | program vkey {}",
        started.elapsed(),
        vk.bytes32()
    );

    let started = Instant::now();
    let proof = client
        .prove(&pk, claim.stdin())
        .mode(args.system.mode())
        .run()
        .map_err(|e| anyhow!("prove {}: {e}", args.system.name()))?;
    println!(
        "[prove] {} proof in {:.2?}",
        args.system.name(),
        started.elapsed()
    );

    client
        .verify(&proof, vk, None)
        .map_err(|e| anyhow!("verify: {e}"))?;
    check_public_values(&proof, native)?;
    println!("[prove] proof verifies; public values match native");

    if let Some(dir) = out.parent() {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let bin = out.with_extension("bin");
    proof
        .save(&bin)
        .map_err(|e| anyhow!("save {}: {e}", bin.display()))?;
    println!("[prove] bincode proof -> {}", bin.display());
    if args.system.on_chain() {
        write_fixture(&out, &vk.bytes32(), &proof)?;
    } else {
        println!(
            "[prove] {} proofs have no on-chain encoding; no JSON fixture",
            args.system.name()
        );
    }
    Ok(())
}

fn fixture(args: &FixtureArgs) -> Result<()> {
    ensure!(
        args.mock,
        "only --mock fixtures are made here; use `prove --system groth16|plonk`"
    );
    let claim = Claim::load(
        Path::new(&args.presentation),
        Path::new(&args.input),
        Program::new(!args.production),
    )?;
    let native = claim.accepted()?;

    let client = ProverClient::builder().mock().build();
    let pk = client
        .setup(claim.program.elf())
        .map_err(|e| anyhow!("setup: {e}"))?;
    let vk = pk.verifying_key();
    // The mock prover executes the guest and returns an empty Groth16 proof
    // (what SP1MockVerifier expects).
    let proof = client
        .prove(&pk, claim.stdin())
        .mode(SP1ProofMode::Groth16)
        .run()
        .map_err(|e| anyhow!("mock prove: {e}"))?;
    client
        .verify(&proof, vk, None)
        .map_err(|e| anyhow!("mock verify: {e}"))?;
    check_public_values(&proof, native)?;
    ensure!(
        proof.bytes().is_empty(),
        "a mock proof must have empty proof bytes"
    );

    write_fixture(Path::new(&args.out), &vk.bytes32(), &proof)?;
    println!("{native}");
    Ok(())
}

fn check_public_values(proof: &SP1ProofWithPublicValues, native: &PublicValues) -> Result<()> {
    ensure!(
        proof.public_values.as_slice() == native.to_abi_bytes().as_slice(),
        "proof public values differ from the native verify_claim"
    );
    Ok(())
}

fn write_fixture(path: &Path, program_vkey: &str, proof: &SP1ProofWithPublicValues) -> Result<()> {
    let fixture = ContractFixture {
        program_vkey: program_vkey.to_owned(),
        public_values: format!("0x{}", hex::encode(proof.public_values.as_slice())),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let json = serde_json::to_string_pretty(&fixture)? + "\n";
    fs::write(path, &json).with_context(|| format!("write {}", path.display()))?;
    println!("[fixture] {} ->\n{json}", path.display());
    Ok(())
}

fn print_report(report: &ExecutionReport, wall: Duration) {
    println!(
        "[exec] wall {wall:.2?} | exit code {} | instructions {} | syscalls {} | gas {}",
        report.exit_code,
        report.total_instruction_count(),
        report.total_syscall_count(),
        report
            .gas()
            .map_or_else(|| "n/a".to_owned(), |g| g.to_string()),
    );

    let mut syscalls: Vec<_> = report
        .syscall_counts
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(code, n)| (format!("{code:?}"), *n))
        .collect();
    syscalls.sort_by_key(|&(_, n)| Reverse(n));
    println!("[exec] syscalls (non-zero): {syscalls:?}");

    if report.cycle_tracker.is_empty() {
        println!("[cycles] no per-phase breakdown (build with --features profiling)");
        return;
    }
    let total = report.total_instruction_count().max(1);
    let mut tracked = 0;
    for label in PHASES {
        if let Some(cycles) = report.cycle_tracker.get(label) {
            tracked += cycles;
            println!(
                "[cycles] {label:<12} {cycles:>12}  {:>5.1}%",
                *cycles as f64 * 100.0 / total as f64
            );
        } else {
            println!("[cycles] {label:<12} {:>12}  (not reached)", "-");
        }
    }
    for (label, cycles) in &report.cycle_tracker {
        if !PHASES.contains(&label.as_str()) {
            println!("[cycles] {label:<12} {cycles:>12}  (unexpected label)");
        }
    }
    println!(
        "[cycles] {:<12} {:>12}  (untracked: entrypoint, allocator, panic path)",
        "rest",
        report.total_instruction_count().saturating_sub(tracked)
    );
}

fn default_path(relative: &str) -> String {
    Path::new(REPO).join(relative).display().to_string()
}

#[cfg(test)]
mod tests {
    use orc_core::{Address, B256};

    use super::*;

    /// The guest reads `GuestInput` with `sp1_zkvm::io::read` (bincode);
    /// alloy's serde must round-trip through bincode, not only JSON.
    #[test]
    fn guest_input_round_trips_through_bincode() {
        let input = GuestInput {
            eth_address: Address::repeat_byte(0x11),
            chain_id: 84532,
            campaign_id: B256::repeat_byte(0x22),
            owner: "tlsnotary".into(),
            name: "tlsn".into(),
            threshold: 10,
        };
        let bytes = bincode::serialize(&input).expect("serialize");
        let back: GuestInput = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(back, input);
    }

    #[test]
    fn both_elfs_are_embedded_and_differ() {
        assert!(PRODUCTION_ELF.starts_with(b"\x7fELF"));
        assert!(TEST_CA_ELF.starts_with(b"\x7fELF"));
        assert_ne!(PRODUCTION_ELF, TEST_CA_ELF);
    }
}
