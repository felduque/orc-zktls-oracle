//! orc notary: co-runs MPC-TLS with a prover (TLSNotary `Verifier`) and signs
//! an attestation over the prover's transcript commitments.
//!
//! The notary never sees plaintext: it learns transcript lengths, the TLS
//! session time and the server's ephemeral key, and signs SHA-256
//! commitments the prover chose. One TCP connection carries one session:
//! the tlsn session first, then the bincode attestation request (prover ->
//! notary, terminated by the prover's write shutdown) and the bincode
//! attestation (notary -> prover).
//!
//! Denial-of-service limits, in the order a connection meets them:
//! 1. [`admission`]: a global cap on concurrent sessions and a cap per source
//!    address, checked right after `accept`;
//! 2. [`NotaryConfig::setup_timeout`]: the prover must send a protocol config
//!    the notary accepts within a few seconds, or the slot is freed;
//! 3. [`check_protocol_config`]: byte budgets and record counts are bounded
//!    before any MPC resources are allocated;
//! 4. [`NotaryConfig::session_timeout`]: the MPC session and the attestation,
//!    counted from the moment the config is accepted.
//!
//! A session also ends as soon as the prover's connection does, so a prover
//! that gives up (or retries) does not keep a slot until the timeout.

pub mod admission;

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    task::{JoinError, JoinHandle},
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{Instrument, debug, info, info_span, instrument::WithSubscriber, warn};

use tlsn::{
    Session, SessionHandle,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider,
        request::Request as AttestationRequest,
        signing::{Secp256k1Signer, Secp256r1Signer, SignatureAlgId, Signer, VerifyingKey},
    },
    config::{tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig},
    connection::{CertBinding, ConnectionInfo, TranscriptLength},
    hash::HashAlgId,
    transcript::{ContentType, Record},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};

use crate::admission::Admission;

/// Largest request plaintext a prover may ask to notarize.
pub const DEFAULT_MAX_SENT_DATA: usize = 4096;
/// Largest response plaintext a prover may ask to notarize.
pub const DEFAULT_MAX_RECV_DATA: usize = 16384;
/// Wall-clock limit for one session (MPC + attestation), counted from the
/// moment the prover's protocol config is accepted.
pub const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(300);
/// Limit from `accept` to a received and accepted protocol config. An honest
/// prover sends its config right after connecting (a few hundred bytes).
pub const DEFAULT_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
/// MPC sessions take ~1 GB RAM each; extra connections are refused.
pub const DEFAULT_MAX_CONCURRENT_SESSIONS: usize = 4;
/// Concurrent sessions per source address (IPv4 address or IPv6 /64). Two
/// leave room for an honest prover's retry while its previous session ends.
pub const DEFAULT_MAX_SESSIONS_PER_IP: usize = 2;
/// Upper bound on the bincode attestation request.
pub const MAX_ATTESTATION_REQUEST_BYTES: u64 = 1 << 20;

/// Time to send a rejection and let the session driver flush it.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

// ---- prover-chosen record counts ---------------------------------------------
//
// tlsn's `MpcTlsConfig` (tlsn-core `config/tls_commit/mpc.rs`, alpha.15) lets
// the prover choose `max_sent_records` and `max_recv_records_online`, and tlsn
// itself only checks `max_recv_data_online <= max_recv_data`. The verifier
// passes both counts unchanged to mpc-tls (`tlsn/src/deps.rs`), whose
// follower allocates one AES-CTR block per record (the GCM J0 mask, in
// `mpc-tls/src/record_layer/aead/aes_gcm.rs`, `alloc`) up front, after a
// `Vec::with_capacity(records)`. So a huge count costs garbling work and RAM
// before any TLS traffic, and an absurd one aborts the whole process on a
// failed allocation.
//
// A TLS record carries at most 16 KiB of plaintext, so `n` bytes need at least
// ceil(n / 16384) records, but tiny (even empty) records are legal: the record
// size gives a floor, not a cap. tlsn's own default, used when the prover
// leaves a count unset (orc's prover does), is (`mpc-tls/src/config.rs`)
//
//     2 + default_record_count(n + 32),  default_record_count(m) = 8 + ceil((m - 4096) / 4096)
//
// i.e. 2 protocol records (Finished, alert), 8 records for the first 4 KiB and
// 4 KiB records after, over the byte budget plus 32 protocol bytes. That is 11
// sent records for 4 KiB and 14 received records for 16 KiB.
//
// The bound is set by cost instead: one record costs the notary one AES block,
// exactly what 16 bytes of the byte budget cost (one keystream block). Allowing
// at most one record per 16-byte block of the byte budget the notary already
// accepts keeps an accepted config within 2x the AES work of its byte limits:
//
//     max_records(limit) = max(2 + ceil((limit + 32) / 16), tlsn default)
//
// = 260 sent records (4 KiB) and 1028 received records (16 KiB) with the
// default limits, ~24x and ~73x tlsn's defaults: at most ~1300 extra AES
// blocks per session, the same order as the 16 KiB of online decryption the
// byte limits already allow. The `max` only matters for tiny limits, so that an
// explicit tlsn default is always accepted. An unset count becomes tlsn's
// default for the requested budget, which is at most the notary's limit, so it
// always fits.

/// Bytes tlsn adds to every MPC byte budget for TLS protocol messages.
const TLSN_PROTOCOL_BYTES: usize = 32;
/// Records tlsn adds to every record budget for TLS protocol messages.
const TLSN_PROTOCOL_RECORDS: usize = 2;
/// One AES block: the cost unit of both a record and 16 bytes of data.
const AES_BLOCK_BYTES: usize = 16;

/// Largest record count (`max_sent_records` or `max_recv_records_online`)
/// accepted for a byte budget of `limit`. See the derivation above.
pub fn max_records(limit: usize) -> usize {
    let bytes = limit.saturating_add(TLSN_PROTOCOL_BYTES);
    let per_block = TLSN_PROTOCOL_RECORDS.saturating_add(bytes.div_ceil(AES_BLOCK_BYTES));
    per_block.max(tlsn_default_records(limit))
}

/// tlsn's record count when the prover leaves it unset (mpc-tls `Config`).
fn tlsn_default_records(limit: usize) -> usize {
    let bytes = limit.saturating_add(TLSN_PROTOCOL_BYTES);
    TLSN_PROTOCOL_RECORDS + 8 + bytes.saturating_sub(4096).div_ceil(4096)
}

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Notary failure.
#[derive(Debug, thiserror::Error)]
pub enum NotaryError {
    #[error("invalid notary key: {0}")]
    Key(String),
    #[error("prover requested {what} = {requested}, above the notary limit {limit}")]
    Limit {
        what: &'static str,
        requested: usize,
        limit: usize,
    },
    #[error("unsupported protocol: {0}")]
    Protocol(String),
    #[error("attestation request exceeds {0} bytes")]
    RequestTooLarge(u64),
    #[error("{stage}: timed out after {limit:?}")]
    Timeout {
        stage: &'static str,
        limit: Duration,
    },
    #[error("{stage}: the prover closed the connection")]
    Disconnected { stage: &'static str },
    #[error("{stage}: {source}")]
    Stage {
        stage: &'static str,
        #[source]
        source: BoxError,
    },
}

trait StageExt<T> {
    fn stage(self, stage: &'static str) -> Result<T, NotaryError>;
}

impl<T, E: Into<BoxError>> StageExt<T> for Result<T, E> {
    fn stage(self, stage: &'static str) -> Result<T, NotaryError> {
        self.map_err(|e| NotaryError::Stage {
            stage,
            source: e.into(),
        })
    }
}

/// The notary's attestation signing key.
pub struct NotaryKey {
    alg: SignatureAlgId,
    secret: [u8; 32],
    verifying_key: VerifyingKey,
}

impl NotaryKey {
    /// secp256k1 key (the only algorithm `orc_core::verify_claim` accepts).
    pub fn secp256k1(secret: [u8; 32]) -> Result<Self, NotaryError> {
        let signer = Secp256k1Signer::new(&secret).map_err(|e| NotaryError::Key(e.to_string()))?;
        Ok(Self {
            alg: SignatureAlgId::SECP256K1,
            secret,
            verifying_key: signer.verifying_key(),
        })
    }

    /// NIST P-256 key. The orc verifier rejects P-256 notaries; this exists
    /// so tests can produce such a presentation.
    pub fn secp256r1(secret: [u8; 32]) -> Result<Self, NotaryError> {
        let signer = Secp256r1Signer::new(&secret).map_err(|e| NotaryError::Key(e.to_string()))?;
        Ok(Self {
            alg: SignatureAlgId::SECP256R1,
            secret,
            verifying_key: signer.verifying_key(),
        })
    }

    /// secp256k1 key from 64 hex chars (optional `0x` prefix).
    pub fn secp256k1_from_hex(hex_key: &str) -> Result<Self, NotaryError> {
        let hex_key = hex_key.trim();
        let hex_key = hex_key.strip_prefix("0x").unwrap_or(hex_key);
        let mut secret = [0u8; 32];
        hex::decode_to_slice(hex_key, &mut secret)
            .map_err(|_| NotaryError::Key("expected 32 bytes of hex".into()))?;
        Self::secp256k1(secret)
    }

    /// Signature algorithm.
    pub fn alg(&self) -> SignatureAlgId {
        self.alg
    }

    /// Public key as it appears in attestations (compressed SEC1 point).
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// `keccak256(compressed public key)`, the value `OrcClaim.sol` pins.
    pub fn key_hash(&self) -> orc_core::B256 {
        orc_core::notary_key_hash(&self.verifying_key.data)
    }

    fn install(&self, provider: &mut CryptoProvider) -> Result<(), NotaryError> {
        let result = if self.alg == SignatureAlgId::SECP256R1 {
            provider.signer.set_secp256r1(&self.secret).map(|_| ())
        } else {
            provider.signer.set_secp256k1(&self.secret).map(|_| ())
        };
        result.map_err(|e| NotaryError::Key(e.to_string()))
    }
}

impl fmt::Debug for NotaryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotaryKey")
            .field("alg", &self.alg)
            .field("public", &hex::encode(&self.verifying_key.data))
            .finish_non_exhaustive()
    }
}

/// Notary settings.
#[derive(Debug)]
pub struct NotaryConfig {
    pub key: NotaryKey,
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    /// MPC session + attestation, from the accepted protocol config on.
    pub session_timeout: Duration,
    /// From `accept` to a received and accepted protocol config.
    pub setup_timeout: Duration,
    pub max_concurrent_sessions: usize,
    /// Concurrent sessions per IPv4 address or IPv6 /64 (at least 1).
    pub max_sessions_per_ip: usize,
    /// Roots for tlsn's `VerifierConfig`. Only used if a prover reveals the
    /// server identity to the notary, which orc provers do not do (identity
    /// is proven to the SP1 guest instead).
    pub root_store: RootCertStore,
}

impl NotaryConfig {
    /// Production defaults (4096/16384 byte limits, 10 s setup, 300 s
    /// sessions, 4 sessions, 2 per IP).
    pub fn new(key: NotaryKey) -> Self {
        Self {
            key,
            max_sent_data: DEFAULT_MAX_SENT_DATA,
            max_recv_data: DEFAULT_MAX_RECV_DATA,
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            setup_timeout: DEFAULT_SETUP_TIMEOUT,
            max_concurrent_sessions: DEFAULT_MAX_CONCURRENT_SESSIONS,
            max_sessions_per_ip: DEFAULT_MAX_SESSIONS_PER_IP,
            root_store: RootCertStore::mozilla(),
        }
    }
}

/// Checks a prover's MPC-TLS config against the notary's limits: byte
/// budgets, and record counts per [`max_records`]. Unset record counts are
/// accepted (tlsn derives them from the byte budgets).
pub fn check_protocol_config(
    requested: &MpcTlsConfig,
    config: &NotaryConfig,
) -> Result<(), NotaryError> {
    let limits = [
        (
            "max_sent_data",
            Some(requested.max_sent_data()),
            config.max_sent_data,
        ),
        (
            "max_recv_data",
            Some(requested.max_recv_data()),
            config.max_recv_data,
        ),
        // tlsn already caps it at max_recv_data; kept for defense in depth.
        (
            "max_recv_data_online",
            Some(requested.max_recv_data_online()),
            config.max_recv_data,
        ),
        (
            "max_sent_records",
            requested.max_sent_records(),
            max_records(config.max_sent_data),
        ),
        (
            "max_recv_records_online",
            requested.max_recv_records_online(),
            max_records(config.max_recv_data),
        ),
    ];
    let exceeded = limits.into_iter().find_map(|(what, requested, limit)| {
        requested
            .filter(|&requested| requested > limit)
            .map(|requested| (what, requested, limit))
    });
    match exceeded {
        Some((what, requested, limit)) => Err(NotaryError::Limit {
            what,
            requested,
            limit,
        }),
        None => Ok(()),
    }
}

/// What one session notarized (lengths only; the notary sees no plaintext).
#[derive(Debug, Clone, Copy)]
pub struct SessionSummary {
    pub sent_len: usize,
    pub recv_len: usize,
    pub elapsed: Duration,
}

/// Stage name of the setup phase (connection to accepted protocol config).
const SETUP_STAGE: &str = "receive protocol config";

type DriverTask<S> = AbortOnDrop<tlsn::Result<tokio_util::compat::Compat<S>>>;

/// Runs one notarization session over `socket`: at most
/// [`NotaryConfig::setup_timeout`] to receive and accept the prover's
/// protocol config, then at most [`NotaryConfig::session_timeout`] for MPC
/// and the attestation. Ends early if the prover's connection ends before
/// it has sent its proof.
pub async fn notarize<S>(socket: S, config: &NotaryConfig) -> Result<SessionSummary, NotaryError>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let started = Instant::now();
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let mut driver_task: DriverTask<S> = AbortOnDrop::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(config.root_store.clone())
        .build()
        .stage("verifier config")?;
    let verifier = handle.new_verifier(verifier_config).stage("new verifier")?;

    // ---- 1. setup: from the first byte to a fully parsed config ----
    let commit = until_disconnect(SETUP_STAGE, &mut driver_task, async {
        verifier.commit().await.stage(SETUP_STAGE)
    });
    let commit = with_timeout(SETUP_STAGE, config.setup_timeout, commit).await?;

    let verifier = match commit {
        VerifierCommitStart::Mpc(verifier) => {
            if let Err(e) = check_protocol_config(verifier.config(), config) {
                let reason = e.to_string();
                reject_and_close(verifier.reject(Some(&reason)), &mut handle, driver_task).await;
                return Err(e);
            }
            verifier
        }
        VerifierCommitStart::Proxy(verifier) => {
            reject_and_close(
                verifier.reject(Some("the orc notary only supports MPC-TLS")),
                &mut handle,
                driver_task,
            )
            .await;
            return Err(NotaryError::Protocol("proxy mode requested".into()));
        }
    };

    // ---- 2. MPC + attestation, under the session timeout ----
    with_timeout("session", config.session_timeout, async move {
        let verifier = until_disconnect("MPC", &mut driver_task, async {
            verifier
                .accept()
                .await
                .stage("MPC setup")?
                .run()
                .await
                .stage("MPC-TLS")
        })
        .await?;

        // Not raced against the connection: an honest prover may close the
        // session as soon as it has sent its proof, while this side is still
        // verifying it.
        let (
            VerifierOutput {
                transcript_commitments,
                ..
            },
            verifier,
        ) = verifier
            .verify()
            .await
            .stage("receive prove request")?
            .accept()
            .await
            .stage("verify commitments")?;

        let tls_transcript = verifier.tls_transcript().clone();
        verifier.close().await.stage("close verifier")?;

        let sent_len = application_data_len(tls_transcript.sent());
        let recv_len = application_data_len(tls_transcript.recv());

        handle.close();
        let mut socket = driver_task
            .await
            .stage("session driver task")?
            .stage("session driver")?;

        // Attestation request: the prover half-closes its write side after it.
        let mut request_bytes = Vec::new();
        (&mut socket)
            .take(MAX_ATTESTATION_REQUEST_BYTES + 1)
            .read_to_end(&mut request_bytes)
            .await
            .stage("read attestation request")?;
        if request_bytes.len() as u64 > MAX_ATTESTATION_REQUEST_BYTES {
            return Err(NotaryError::RequestTooLarge(MAX_ATTESTATION_REQUEST_BYTES));
        }
        let request: AttestationRequest =
            bincode::deserialize(&request_bytes).stage("decode attestation request")?;

        let mut provider = CryptoProvider::default();
        config.key.install(&mut provider)?;

        let mut att_config = AttestationConfig::builder();
        att_config
            .supported_signature_algs(vec![config.key.alg()])
            .supported_hash_algs(vec![HashAlgId::SHA256]);
        let att_config = att_config.build().stage("attestation config")?;

        let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
            return Err(NotaryError::Protocol(
                "unsupported certificate binding".into(),
            ));
        };
        let transcript_length = TranscriptLength {
            sent: u32::try_from(sent_len).stage("sent length")?,
            received: u32::try_from(recv_len).stage("received length")?,
        };

        let mut builder = Attestation::builder(&att_config)
            .accept_request(request)
            .stage("accept attestation request")?;
        builder
            .connection_info(ConnectionInfo {
                time: tls_transcript.time(),
                version: tls_transcript.version(),
                transcript_length,
            })
            .server_ephemeral_key(binding.server_ephemeral_key.clone())
            .transcript_commitments(transcript_commitments);
        let attestation = builder.build(&provider).stage("sign attestation")?;

        let attestation_bytes = bincode::serialize(&attestation).stage("encode attestation")?;
        socket
            .write_all(&attestation_bytes)
            .await
            .stage("send attestation")?;
        socket.close().await.stage("close connection")?;

        Ok(SessionSummary {
            sent_len,
            recv_len,
            elapsed: started.elapsed(),
        })
    })
    .await
}

/// Accepts connections forever, one notarization session per connection
/// (see [`notarize`] for its deadlines). Connections beyond
/// `max_concurrent_sessions`, or beyond `max_sessions_per_ip` from one
/// source, are closed immediately.
pub async fn serve(listener: TcpListener, config: Arc<NotaryConfig>) -> Result<(), NotaryError> {
    let admission = Admission::new(config.max_concurrent_sessions, config.max_sessions_per_ip);
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                // Transient (e.g. EMFILE): back off instead of spinning.
                warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let permit = match admission.try_admit(peer.ip()) {
            Ok(permit) => permit,
            Err(refused) => {
                warn!(%peer, reason = %refused, "refusing connection");
                continue;
            }
        };
        if let Err(e) = socket.set_nodelay(true) {
            debug!(%peer, error = %e, "set_nodelay failed");
        }
        let config = config.clone();
        // The session's (and tlsn's) events carry the peer and go to the
        // dispatcher `serve` runs under.
        let session = async move {
            let _permit = permit;
            info!("session started");
            match notarize(socket, &config).await {
                Ok(s) => info!(
                    sent = s.sent_len,
                    recv = s.recv_len,
                    elapsed_ms = s.elapsed.as_millis() as u64,
                    "attestation signed"
                ),
                Err(e) => warn!(error = %e, "session failed"),
            }
        };
        tokio::spawn(
            session
                .instrument(info_span!("session", %peer))
                .with_current_subscriber(),
        );
    }
}

async fn with_timeout<T>(
    stage: &'static str,
    limit: Duration,
    fut: impl Future<Output = Result<T, NotaryError>>,
) -> Result<T, NotaryError> {
    tokio::time::timeout(limit, fut)
        .await
        .unwrap_or(Err(NotaryError::Timeout { stage, limit }))
}

/// Runs `fut`, failing as soon as the prover's connection ends. tlsn does
/// not always wake a pending read when the connection closes (the prover has
/// seen this in MPC phases); without this, such a session would keep its slot
/// until the deadline.
async fn until_disconnect<T, D>(
    stage: &'static str,
    driver: &mut AbortOnDrop<D>,
    fut: impl Future<Output = Result<T, NotaryError>>,
) -> Result<T, NotaryError> {
    tokio::select! {
        biased;
        result = fut => result,
        _ = driver => Err(NotaryError::Disconnected { stage }),
    }
}

/// Sends a config rejection, then closes the session and lets the driver
/// flush it before the connection drops. Aborting the driver instead can lose
/// the frame, and the prover then waits for it until its own timeout.
async fn reject_and_close<T>(
    reject: impl Future<Output = tlsn::Result<()>>,
    handle: &mut SessionHandle,
    driver_task: AbortOnDrop<T>,
) {
    match tokio::time::timeout(CLOSE_GRACE, reject).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!(error = %e, "sending the rejection failed"),
        Err(_) => debug!("sending the rejection timed out"),
    }
    handle.close();
    if tokio::time::timeout(CLOSE_GRACE, driver_task)
        .await
        .is_err()
    {
        debug!("session driver did not finish after close");
    }
}

fn application_data_len(records: &[Record]) -> usize {
    records
        .iter()
        .filter(|r| matches!(r.typ, ContentType::ApplicationData))
        .map(|r| r.ciphertext.len())
        .sum()
}

/// A spawned task that is aborted if the session future is dropped early
/// (timeout, error), so nothing keeps running in the background.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T: Send + 'static> AbortOnDrop<T> {
    /// Spawns `fut` in the current span and with the current tracing
    /// dispatcher (see `serve`).
    fn spawn(fut: impl Future<Output = T> + Send + 'static) -> Self {
        Self(tokio::spawn(
            fut.in_current_span().with_current_subscriber(),
        ))
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NotaryConfig {
        let mut config = NotaryConfig::new(NotaryKey::secp256k1([7u8; 32]).expect("key"));
        config.root_store = RootCertStore { roots: Vec::new() };
        config
    }

    fn mpc(sent: usize, recv: usize) -> tlsn::config::tls_commit::mpc::MpcTlsConfigBuilder {
        MpcTlsConfig::builder()
            .max_sent_data(sent)
            .max_recv_data(recv)
    }

    fn rejected_field(result: Result<(), NotaryError>) -> &'static str {
        match result {
            Err(NotaryError::Limit { what, .. }) => what,
            other => panic!("expected a limit error, got {other:?}"),
        }
    }

    #[test]
    fn record_bounds_with_default_limits() {
        assert_eq!(max_records(DEFAULT_MAX_SENT_DATA), 260);
        assert_eq!(max_records(DEFAULT_MAX_RECV_DATA), 1028);
        // tlsn's own unit test: default_record_count(32 KiB) == 15.
        assert_eq!(
            tlsn_default_records((1 << 15) - TLSN_PROTOCOL_BYTES),
            2 + 15
        );
        assert_eq!(tlsn_default_records(DEFAULT_MAX_SENT_DATA), 11);
        assert_eq!(tlsn_default_records(DEFAULT_MAX_RECV_DATA), 14);
    }

    #[test]
    fn record_bound_never_below_tlsn_default() {
        for limit in (0..70_000).step_by(7).chain([usize::MAX - 1, usize::MAX]) {
            assert!(max_records(limit) >= tlsn_default_records(limit), "{limit}");
        }
    }

    #[test]
    fn honest_prover_config_is_accepted() {
        // What orc-prover sends with its defaults: byte budgets only.
        let requested = mpc(DEFAULT_MAX_SENT_DATA, DEFAULT_MAX_RECV_DATA)
            .build()
            .expect("config");
        check_protocol_config(&requested, &config()).expect("honest config");

        // tlsn's defaults spelled out, and the largest accepted counts.
        let requested = mpc(DEFAULT_MAX_SENT_DATA, DEFAULT_MAX_RECV_DATA)
            .max_sent_records(max_records(DEFAULT_MAX_SENT_DATA))
            .max_recv_records_online(max_records(DEFAULT_MAX_RECV_DATA))
            .max_recv_data_online(DEFAULT_MAX_RECV_DATA)
            .defer_decryption_from_start(false)
            .build()
            .expect("config");
        check_protocol_config(&requested, &config()).expect("at the bounds");
    }

    #[test]
    fn oversized_record_counts_are_rejected() {
        let config = config();
        let sent = mpc(DEFAULT_MAX_SENT_DATA, DEFAULT_MAX_RECV_DATA)
            .max_sent_records(max_records(DEFAULT_MAX_SENT_DATA) + 1)
            .build()
            .expect("config");
        assert_eq!(
            rejected_field(check_protocol_config(&sent, &config)),
            "max_sent_records"
        );

        let recv = mpc(DEFAULT_MAX_SENT_DATA, DEFAULT_MAX_RECV_DATA)
            .max_recv_records_online(usize::MAX)
            .build()
            .expect("config");
        assert_eq!(
            rejected_field(check_protocol_config(&recv, &config)),
            "max_recv_records_online"
        );
    }

    #[test]
    fn record_bounds_follow_the_configured_byte_limits() {
        let mut config = config();
        config.max_sent_data = 1024;
        let requested = mpc(1024, DEFAULT_MAX_RECV_DATA)
            .max_sent_records(max_records(1024) + 1)
            .build()
            .expect("config");
        assert_eq!(
            rejected_field(check_protocol_config(&requested, &config)),
            "max_sent_records"
        );
    }

    #[test]
    fn oversized_byte_budgets_are_rejected() {
        let config = config();
        let sent = mpc(DEFAULT_MAX_SENT_DATA + 1, DEFAULT_MAX_RECV_DATA)
            .build()
            .expect("config");
        assert_eq!(
            rejected_field(check_protocol_config(&sent, &config)),
            "max_sent_data"
        );
        let recv = mpc(DEFAULT_MAX_SENT_DATA, DEFAULT_MAX_RECV_DATA + 1)
            .build()
            .expect("config");
        assert_eq!(
            rejected_field(check_protocol_config(&recv, &config)),
            "max_recv_data"
        );
    }
}
