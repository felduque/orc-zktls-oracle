//! `orc-notary`: TCP notary for the orc PoC.
//!
//! The k256 secret key comes only from `ORC_NOTARY_KEY` (64 hex chars), never
//! from a flag, so it does not show up in process listings or shell history.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use orc_notary::{
    DEFAULT_MAX_CONCURRENT_SESSIONS, DEFAULT_MAX_RECV_DATA, DEFAULT_MAX_SENT_DATA, NotaryConfig,
    NotaryKey, serve,
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

    /// Wall-clock limit for one session, in seconds.
    #[arg(long, default_value_t = 300)]
    session_timeout_secs: u64,

    /// Concurrent sessions (each MPC session needs ~1 GB of RAM).
    #[arg(long, default_value_t = DEFAULT_MAX_CONCURRENT_SESSIONS)]
    max_concurrent_sessions: usize,
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
    config.max_concurrent_sessions = args.max_concurrent_sessions;

    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;
    println!(
        "listening on {} (max_sent {DEFAULT_MAX_SENT_DATA}, max_recv {DEFAULT_MAX_RECV_DATA}, SHA-256, secp256k1)",
        args.listen
    );

    serve(listener, Arc::new(config)).await?;
    Ok(())
}
