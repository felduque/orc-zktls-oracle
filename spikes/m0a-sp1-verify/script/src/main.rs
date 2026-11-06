//! M0a host runner. By default it EXECUTEs the guest (no proving) on M0b presentations and
//! reports committed outputs, instruction counts and syscall/precompile counts. With
//! `--prove core|compressed`, it generates a CPU proof of the `Full` mode and verifies it.
//!
//! Usage (inside the dev container):
//!   cargo run --release -- [fixture ...]                          (default: repo-noauth graphql)
//!   cargo run --release -- --prove core|compressed [fixture ...]  (default: graphql)
//! where each fixture is the `<name>` in
//! spikes/m0b-mpc-github/fixtures/presentation-<name>.bin

use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail, ensure};
use m0a_lib::{Mode, Output};
use sp1_sdk::{
    Elf, HashableKey, ProvingKey, include_elf,
    blocking::{ProveRequest, Prover, ProverClient, SP1ProofMode, SP1Stdin},
};

const ELF: Elf = include_elf!("m0a-program");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m0b-mpc-github/fixtures");
const MODES: [Mode; 3] = [Mode::Full, Mode::Split, Mode::NoIdentity];

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--prove") {
        let mode = match args.get(1).map(String::as_str) {
            Some("core") => SP1ProofMode::Core,
            Some("compressed") => SP1ProofMode::Compressed,
            other => bail!("usage: --prove core|compressed [fixture ...] (got {other:?})"),
        };
        args.drain(..2);
        if args.is_empty() {
            args = vec!["graphql".into()];
        }
        return prove(mode, &args);
    }
    if args.is_empty() {
        args = vec!["repo-noauth".into(), "graphql".into()];
    }
    execute(&args)
}

/// Executes every mode on every fixture with the light prover (it never generates proofs).
fn execute(names: &[String]) -> Result<()> {
    let client = ProverClient::builder().light().build();

    for name in names {
        let bytes = read_fixture(name)?;
        let native = native_verify(name, &bytes)?;

        for mode in MODES {
            println!("\n=== {name} ({} B) mode {mode:?} ===", bytes.len());

            let t = Instant::now();
            let (mut public_values, report) = client
                .execute(ELF, stdin(mode, &bytes))
                .run()
                .map_err(|e| anyhow!("execute {name} {mode:?}: {e}"))?;
            let wall = t.elapsed();

            let out: Output = public_values.read();
            print_output(&out);
            ensure!(report.exit_code == 0, "guest exit code {}", report.exit_code);
            check_output(&out, &native, mode)?;

            println!("[exec] wall {wall:.2?}, exit code {}", report.exit_code);
            println!(
                "[exec] total instructions: {} | total syscalls: {} | touched memory addrs: {}",
                report.total_instruction_count(),
                report.total_syscall_count(),
                report.touched_memory_addresses
            );
            let mut syscalls: Vec<_> = report
                .syscall_counts
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(code, n)| (format!("{code:?}"), *n))
                .collect();
            syscalls.sort_by(|a, b| b.1.cmp(&a.1));
            println!("[exec] syscalls (non-zero): {syscalls:?}");

            let mut tracked: Vec<_> = report.cycle_tracker.iter().collect();
            tracked.sort_by(|a, b| b.1.cmp(a.1));
            for (label, cycles) in tracked {
                println!("[cycles] {label:<12} {cycles:>14}");
            }
        }
    }
    Ok(())
}

/// CPU-proves the `Full` mode on every fixture, then verifies each proof.
fn prove(proof_mode: SP1ProofMode, names: &[String]) -> Result<()> {
    let t = Instant::now();
    let client = ProverClient::builder().cpu().build();
    println!("[prove] cpu prover init {:.2?}", t.elapsed());

    let t = Instant::now();
    let pk = client.setup(ELF).map_err(|e| anyhow!("setup: {e}"))?;
    let vk = pk.verifying_key();
    println!("[prove] setup {:.2?} | program vkey {}", t.elapsed(), vk.bytes32());

    for name in names {
        let bytes = read_fixture(name)?;
        let native = native_verify(name, &bytes)?;
        println!("\n=== {name} ({} B) mode Full, proof {proof_mode:?} ===", bytes.len());

        let t = Instant::now();
        let proof = client
            .prove(&pk, stdin(Mode::Full, &bytes))
            .mode(proof_mode)
            .run()
            .map_err(|e| anyhow!("prove {name} {proof_mode:?}: {e}"))?;
        let prove_wall = t.elapsed();

        let t = Instant::now();
        client.verify(&proof, vk, None).map_err(|e| anyhow!("verify {name}: {e}"))?;
        let verify_wall = t.elapsed();

        let out: Output = proof.public_values.clone().read();
        print_output(&out);
        check_output(&out, &native, Mode::Full)?;
        println!("[prove] {name}: prove {prove_wall:.2?} | verify OK {verify_wall:.2?}");
    }
    Ok(())
}

fn read_fixture(name: &str) -> Result<Vec<u8>> {
    let path = format!("{FIXTURES}/presentation-{name}.bin");
    std::fs::read(&path).with_context(|| format!("read {path}"))
}

/// Native baseline: the same verify code as the guest, run on the host.
fn native_verify(name: &str, bytes: &[u8]) -> Result<Output> {
    m0a_lib::verify(bytes, Mode::Full, &mut m0a_lib::NoTrack)
        .map_err(|e| anyhow!("native verify of {name}: {e}"))
}

fn stdin(mode: Mode, bytes: &[u8]) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&mode);
    stdin.write_vec(bytes.to_vec());
    stdin
}

fn check_output(out: &Output, native: &Output, mode: Mode) -> Result<()> {
    ensure!(out.mode == mode, "mode mismatch");
    ensure!(out.session_time == native.session_time, "session time != native");
    ensure!(out.recv_len == native.recv_len, "recv len != native");
    ensure!(out.notary_key == native.notary_key, "notary key != native");
    if mode != Mode::NoIdentity {
        ensure!(out.server_name == native.server_name, "server name != native");
    }
    Ok(())
}

fn print_output(out: &Output) {
    println!(
        "[commit] server_name {:?} | session_time {} | sent {} B (authed {}) | recv {} B (authed {}) | notary key alg {} = {}",
        out.server_name,
        out.session_time,
        out.sent_len,
        out.sent_authed,
        out.recv_len,
        out.recv_authed,
        out.notary_key_alg,
        hex::encode(&out.notary_key)
    );
}
