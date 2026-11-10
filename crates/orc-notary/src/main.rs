//! `orc-notary`: TCP notary for the orc PoC.
//!
//! The k256 secret key comes only from `ORC_NOTARY_KEY` (64 hex chars), never
//! from a flag, so it does not show up in process listings or shell history.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use orc_notary::{
    DEFAULT_MAX_CONCURRENT_SESSIONS, DEFAULT_MAX_SESSIONS_PER_IP, DEFAULT_SESSION_TIMEOUT,
    DEFAULT_SETUP_TIMEOUT, NotaryConfig, NotaryKey, max_records, serve,
};
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(
    name = "orc-notary",
    version,
    about = "orc TLSNotary notary (MPC-TLS verifier + secp256k1 attestation signer)"
)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "ORC_NOTARY_LISTEN", default_value = "0.0.0.0:7047")]
    listen: SocketAddr,

    /// Wall-clock limit for one session (MPC + attestation), in seconds,
    /// counted from the moment the prover's protocol config is accepted.
    #[arg(long, env = "ORC_NOTARY_SESSION_TIMEOUT_SECS", default_value_t = DEFAULT_SESSION_TIMEOUT.as_secs())]
    session_timeout_secs: u64,

    /// Seconds a new connection gets to send a protocol config the notary
    /// accepts. Idle or slow connections are dropped after this and free
    /// their slot.
    #[arg(long, env = "ORC_NOTARY_SETUP_TIMEOUT_SECS", default_value_t = DEFAULT_SETUP_TIMEOUT.as_secs())]
    setup_timeout_secs: u64,

    /// Concurrent sessions (each MPC session needs ~1 GB of RAM).
    #[arg(long, env = "ORC_NOTARY_MAX_CONCURRENT_SESSIONS", default_value_t = DEFAULT_MAX_CONCURRENT_SESSIONS)]
    max_concurrent_sessions: usize,

    /// Concurrent sessions per source (IPv4 address or IPv6 /64). Behind a
    /// reverse proxy every prover shares the proxy's address: raise this to
    /// --max-concurrent-sessions there.
    #[arg(long, env = "ORC_NOTARY_MAX_SESSIONS_PER_IP", default_value_t = DEFAULT_MAX_SESSIONS_PER_IP)]
    max_sessions_per_ip: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tlsn=warn,mpz=warn".into()),
        )
        .init();

    let args = Args::parse();
    ensure!(
        args.session_timeout_secs > 0,
        "--session-timeout-secs must be > 0"
    );
    ensure!(
        args.setup_timeout_secs > 0,
        "--setup-timeout-secs must be > 0"
    );
    ensure!(
        args.max_concurrent_sessions > 0,
        "--max-concurrent-sessions must be > 0"
    );
    ensure!(
        args.max_sessions_per_ip > 0,
        "--max-sessions-per-ip must be > 0"
    );

    let key_hex = std::env::var("ORC_NOTARY_KEY")
        .context("ORC_NOTARY_KEY must hold the notary's secp256k1 secret key (64 hex chars)")?;
    let key = NotaryKey::secp256k1_from_hex(&key_hex).context("ORC_NOTARY_KEY")?;
    drop(key_hex);

    println!(
        "notary public key (k256, compressed): 0x{}",
        hex::encode(&key.verifying_key().data)
    );
    println!("notaryKeyHash: {}", key.key_hash());

    let mut config = NotaryConfig::new(key);
    config.session_timeout = Duration::from_secs(args.session_timeout_secs);
    config.setup_timeout = Duration::from_secs(args.setup_timeout_secs);
    config.max_concurrent_sessions = args.max_concurrent_sessions;
    config.max_sessions_per_ip = args.max_sessions_per_ip;

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;
    println!(
        "listening on {} (max_sent {}, max_recv {}, max records {}/{}, SHA-256, secp256k1)",
        args.listen,
        config.max_sent_data,
        config.max_recv_data,
        max_records(config.max_sent_data),
        max_records(config.max_recv_data),
    );
    println!(
        "limits: {} sessions, {} per IP, {} s setup, {} s session",
        config.max_concurrent_sessions,
        config.max_sessions_per_ip,
        args.setup_timeout_secs,
        args.session_timeout_secs,
    );

    serve(listener, Arc::new(config)).await?;
    Ok(())
}
