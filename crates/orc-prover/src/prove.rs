//! End-to-end proving with a TCP notary: timeouts, one retry, leak check.

use orc_core::{GuestInput, http::Framing};
use tokio::net::TcpStream;
use tracing::warn;

use crate::{
    Target,
    error::{ProverError, StageExt, with_timeout},
    session::{PhaseTimings, ProverOptions, notarize},
    target::GithubToken,
};

/// Result of [`prove`]. Contains no secrets.
#[derive(Debug, Clone)]
pub struct ProveOutcome {
    /// bincode `Presentation`, input to `orc_core::verify_claim` / the guest.
    pub presentation: Vec<u8>,
    /// Session attempts used (1 or 2).
    pub attempts: u32,
    /// Why earlier attempts failed (empty when the first attempt succeeded).
    pub retry_reasons: Vec<String>,
    pub timings: PhaseTimings,
    pub sent_len: usize,
    pub recv_len: usize,
    /// HTTP status of the notarized response.
    pub http_status: u16,
    /// How the notarized response was framed (`None` if it did not parse).
    pub response_framing: Option<Framing>,
}

/// Connects to the notary at `notary_addr` and runs [`notarize`], retrying
/// once (fresh notary connection, fresh TLS session) on a timeout or
/// transport failure; then builds and serializes the presentation and checks
/// it does not contain the token.
pub async fn prove(
    notary_addr: &str,
    target: &Target,
    token: &GithubToken,
    input: &GuestInput,
    viewer_node_id: &str,
    opts: &ProverOptions,
) -> Result<ProveOutcome, ProverError> {
    let max_attempts = opts.attempts.max(1);
    let mut attempt = 1;
    let mut retry_reasons = Vec::new();
    let notarized = loop {
        let result = async {
            let socket = with_timeout("connect to notary", opts.connect_timeout, async {
                TcpStream::connect(notary_addr)
                    .await
                    .stage("connect to notary")
            })
            .await?;
            // Latency matters more than throughput for the MPC round trips.
            if let Err(e) = socket.set_nodelay(true) {
                warn!(error = %e, "set_nodelay failed");
            }
            notarize(socket, target, token, input, viewer_node_id, opts).await
        }
        .await;
        match result {
            Ok(notarized) => break notarized,
            Err(e) if attempt < max_attempts && e.is_retryable() => {
                warn!(attempt, error = %e, "session failed; retrying with a fresh notary session");
                retry_reasons.push(e.to_string());
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    };

    let presentation = notarized.presentation()?;
    let bytes = bincode::serialize(&presentation).stage("encode presentation")?;
    if token.appears_in(&bytes) {
        return Err(ProverError::TokenLeak);
    }

    Ok(ProveOutcome {
        presentation: bytes,
        attempts: attempt,
        retry_reasons,
        timings: notarized.timings,
        sent_len: notarized.sent_len(),
        recv_len: notarized.received().len(),
        http_status: notarized.http_status,
        response_framing: orc_core::http::parse_response(notarized.received())
            .ok()
            .map(|r| r.framing),
    })
}
