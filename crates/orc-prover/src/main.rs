//! `orc`: prove GitHub commits on-chain without revealing the token.
//!
//! The token is read from `GITHUB_TOKEN` only (never a flag) and never
//! printed or written; `--out-dir` receives just `presentation.bin` and
//! `guest-input.json`. Only fine-grained personal access tokens are accepted.
//!
//! `--campaign-id` and `--snapshot` come from the deployed `OrcClaim`:
//!   cast call <OrcClaim> "campaignId()(bytes32)"
//!   cast call <OrcClaim> "snapshot()(uint64)"

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use orc_core::{Address, B256, GuestInput, VerifyParams, time, verify_claim};
use orc_prover::{GithubToken, ProverOptions, Target, preflight, prove};

#[derive(Debug, Parser)]
#[command(
    name = "orc",
    version,
    about = "zk-TLS GitHub commit-count prover (TLSNotary)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Notarize a GitHub GraphQL query and write presentation.bin + guest-input.json.
    Prove(ProveArgs),
}

#[derive(Debug, clap::Args)]
struct ProveArgs {
    /// Repository owner.
    #[arg(long)]
    owner: String,
    /// Repository name.
    #[arg(long)]
    name: String,
    /// Minimum number of commits to prove.
    #[arg(long)]
    threshold: u64,
    /// Address allowed to claim on-chain.
    #[arg(long)]
    eth_address: Address,
    /// Target chain id (84532 = Base Sepolia).
    #[arg(long)]
    chain_id: u64,
    /// Campaign id (bytes32 hex): `cast call <OrcClaim> "campaignId()(bytes32)"`.
    /// OrcClaim derives it from the chain id, its own address and a salt.
    #[arg(long)]
    campaign_id: B256,
    /// Snapshot, unix seconds: `cast call <OrcClaim> "snapshot()(uint64)"`.
    /// Only commits authored up to it count, and the account must be older.
    #[arg(long)]
    snapshot: u64,
    /// Notary `host:port`.
    #[arg(long, default_value = "127.0.0.1:7047")]
    notary: String,
    /// Output directory.
    #[arg(long)]
    out_dir: PathBuf,
    /// Deadline per MPC phase, in seconds.
    #[arg(long, default_value_t = 120)]
    phase_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Prove(args) => run_prove(args).await,
    }
}

async fn run_prove(args: ProveArgs) -> Result<()> {
    let token = GithubToken::from_env()?;
    let input = GuestInput {
        eth_address: args.eth_address,
        chain_id: args.chain_id,
        campaign_id: args.campaign_id,
        owner: args.owner,
        name: args.name,
        threshold: args.threshold,
        snapshot: args.snapshot,
    };
    let snapshot_utc = time::format_utc(args.snapshot)
        .with_context(|| format!("--snapshot {} is past year 9999", args.snapshot))?;
    let opts = ProverOptions {
        phase_timeout: Duration::from_secs(args.phase_timeout_secs),
        ..ProverOptions::default()
    };
    let target = Target::github();
    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create {}", args.out_dir.display()))?;

    println!("[1/3] preflight: viewer id + createdAt (plain HTTPS, outside MPC)");
    let viewer = preflight::viewer(&target, &token, opts.phase_timeout).await?;
    println!(
        "      viewer.id = {}, createdAt = {}, snapshot = {snapshot_utc}",
        viewer.id, viewer.created_at
    );
    // The guest enforces this on the notarized response; failing here saves
    // an MPC session (and a GitHub API point) that could never verify.
    match time::parse_utc(&viewer.created_at) {
        Some(created) if created < args.snapshot => {}
        Some(_) => bail!(
            "this GitHub account was created at {}, not before the campaign snapshot \
             {snapshot_utc}: the claim cannot verify",
            viewer.created_at
        ),
        None => bail!("unexpected viewer.createdAt format {:?}", viewer.created_at),
    }
    let viewer_id = viewer.id;

    println!(
        "[2/3] MPC-TLS with notary {} -> {}",
        args.notary, target.connect_addr
    );
    let outcome = prove(&args.notary, &target, &token, &input, &viewer_id, &opts).await?;
    for reason in &outcome.retry_reasons {
        println!("      retried after: {reason}");
    }
    let t = outcome.timings;
    println!(
        "      attempts {}, setup {:.2?}, online {:.2?}, prove {:.2?}, attestation {:.2?}, total {:.2?}",
        outcome.attempts,
        t.setup,
        t.online,
        t.prove,
        t.attestation,
        t.total()
    );
    println!(
        "      sent {} B, recv {} B, HTTP {}, framing {}, presentation {} B",
        outcome.sent_len,
        outcome.recv_len,
        outcome.http_status,
        outcome
            .response_framing
            .map_or_else(|| "unparseable".to_owned(), |f| f.to_string()),
        outcome.presentation.len()
    );

    let presentation_path = args.out_dir.join("presentation.bin");
    let input_path = args.out_dir.join("guest-input.json");
    std::fs::write(&presentation_path, &outcome.presentation)
        .with_context(|| format!("write {}", presentation_path.display()))?;
    std::fs::write(&input_path, serde_json::to_vec_pretty(&input)?)
        .with_context(|| format!("write {}", input_path.display()))?;
    println!(
        "      wrote {} and {}",
        presentation_path.display(),
        input_path.display()
    );

    println!("[3/3] self-check: orc_core::verify_claim");
    match verify_claim(&outcome.presentation, &input, &VerifyParams::github()) {
        Ok(pv) => {
            println!("{pv}");
            println!(
                "abi.encode(PublicValues) = 0x{}",
                hex::encode(pv.to_abi_bytes())
            );
            Ok(())
        }
        Err(e) => bail!("self-check failed: {e}"),
    }
}
