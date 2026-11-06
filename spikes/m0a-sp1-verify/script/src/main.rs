//! M0a host runner: EXECUTE the guest (no proving) on M0b presentations and
//! report committed outputs, instruction counts and syscall/precompile counts.
//!
//! Usage (inside the dev container):
//!   cargo run --release -- [fixture ...]
//! where each fixture is the `<name>` in
//! spikes/m0b-mpc-github/fixtures/presentation-<name>.bin
//! (default: repo-noauth graphql).

use std::time::Instant;

use anyhow::{Context, Result, ensure};
use m0a_lib::{Mode, Output};
use sp1_sdk::{
    Elf, include_elf,
    blocking::{Prover, ProverClient, SP1Stdin},
};

const ELF: Elf = include_elf!("m0a-program");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../m0b-mpc-github/fixtures");
const MODES: [Mode; 3] = [Mode::Full, Mode::Split, Mode::NoIdentity];

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();

    let mut names: Vec<String> = std::env::args().skip(1).collect();
    if names.is_empty() {
        names = vec!["repo-noauth".into(), "graphql".into()];
    }

    // Light prover: executes (and could verify) but never generates proofs.
    let client = ProverClient::builder().light().build();

    for name in &names {
        let path = format!("{FIXTURES}/presentation-{name}.bin");
        let bytes = std::fs::read(&path).with_context(|| format!("read {path}"))?;

        // Native baseline, same code as the guest.
        let native = m0a_lib::verify(&bytes, Mode::Full, &mut m0a_lib::NoTrack)
            .map_err(|e| anyhow::anyhow!("native verify of {name}: {e}"))?;

        for mode in MODES {
            println!("\n=== {name} ({} B) mode {mode:?} ===", bytes.len());

            let mut stdin = SP1Stdin::new();
            stdin.write(&mode);
            stdin.write_vec(bytes.clone());

            let t = Instant::now();
            let (mut public_values, report) = client
                .execute(ELF, stdin)
                .run()
                .map_err(|e| anyhow::anyhow!("execute {name} {mode:?}: {e}"))?;
            let wall = t.elapsed();

            let out: Output = public_values.read();
            print_output(&out);
            ensure!(report.exit_code == 0, "guest exit code {}", report.exit_code);
            ensure!(out.mode == mode, "mode mismatch");
            ensure!(out.session_time == native.session_time, "session time != native");
            ensure!(out.recv_len == native.recv_len, "recv len != native");
            ensure!(out.notary_key == native.notary_key, "notary key != native");
            if mode != Mode::NoIdentity {
                ensure!(out.server_name == native.server_name, "server name != native");
            }

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
