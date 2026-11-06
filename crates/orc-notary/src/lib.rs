//! orc notary: co-runs MPC-TLS with a prover (TLSNotary `Verifier`) and signs
//! an attestation over the prover's transcript commitments.
//!
//! The notary never sees plaintext: it learns transcript lengths, the TLS
//! session time and the server's ephemeral key, and signs SHA-256
//! commitments the prover chose. One TCP connection carries one session:
//! the tlsn session first, then the bincode attestation request (prover ->
//! notary, terminated by the prover's write shutdown) and the bincode
//! attestation (notary -> prover).

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
    sync::Semaphore,
    task::{JoinError, JoinHandle},
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, info, warn};

use tlsn::{
    Session, SessionHandle,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider,
        request::Request as AttestationRequest,
        signing::{Secp256k1Signer, Secp256r1Signer, SignatureAlgId, Signer, VerifyingKey},
    },
    config::verifier::VerifierConfig,
    connection::{CertBinding, ConnectionInfo, TranscriptLength},
    hash::HashAlgId,
    transcript::{ContentType, Record},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};

/// Largest request plaintext a prover may ask to notarize.
pub const DEFAULT_MAX_SENT_DATA: usize = 4096;
/// Largest response plaintext a prover may ask to notarize.
pub const DEFAULT_MAX_RECV_DATA: usize = 16384;
/// Wall-clock limit for one whole session (MPC + attestation).
pub const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(300);
/// MPC sessions take ~1 GB RAM each; extra connections are refused.
pub const DEFAULT_MAX_CONCURRENT_SESSIONS: usize = 4;
/// Upper bound on the bincode attestation request.
pub const MAX_ATTESTATION_REQUEST_BYTES: u64 = 1 << 20;

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
    pub session_timeout: Duration,
    pub max_concurrent_sessions: usize,
    /// Roots for tlsn's `VerifierConfig`. Only used if a prover reveals the
    /// server identity to the notary, which orc provers do not do (identity
    /// is proven to the SP1 guest instead).
    pub root_store: RootCertStore,
}

impl NotaryConfig {
    /// Production defaults (4096/16384 byte limits, 300 s sessions).
    pub fn new(key: NotaryKey) -> Self {
        Self {
            key,
            max_sent_data: DEFAULT_MAX_SENT_DATA,
            max_recv_data: DEFAULT_MAX_RECV_DATA,
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            max_concurrent_sessions: DEFAULT_MAX_CONCURRENT_SESSIONS,
            root_store: RootCertStore::mozilla(),
        }
    }
}

/// What one session notarized (lengths only; the notary sees no plaintext).
#[derive(Debug, Clone, Copy)]
pub struct SessionSummary {
    pub sent_len: usize,
    pub recv_len: usize,
    pub elapsed: Duration,
}

/// Runs one notarization session over `socket` (no timeout; see [`serve`]).
pub async fn notarize<S>(socket: S, config: &NotaryConfig) -> Result<SessionSummary, NotaryError>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let started = Instant::now();
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = AbortOnDrop(tokio::spawn(driver));

    let verifier_config = VerifierConfig::builder()
        .root_store(config.root_store.clone())
        .build()
        .stage("verifier config")?;

    let verifier = match handle
        .new_verifier(verifier_config)
        .stage("new verifier")?
        .commit()
        .await
        .stage("receive protocol config")?
    {
        VerifierCommitStart::Mpc(verifier) => {
            let requested = verifier.config();
            let limits = [
                ("max_sent_data", requested.max_sent_data(), config.max_sent_data),
                ("max_recv_data", requested.max_recv_data(), config.max_recv_data),
            ];
            if let Some(&(what, requested, limit)) = limits.iter().find(|(_, r, l)| r > l) {
                verifier
                    .reject(Some("requested transcript limits exceed the notary's"))
                    .await
                    .stage("reject protocol config")?;
                close_session(&mut handle, driver_task).await;
                return Err(NotaryError::Limit {
                    what,
                    requested,
                    limit,
                });
            }
            verifier
                .accept()
                .await
                .stage("MPC setup")?
                .run()
                .await
                .stage("MPC-TLS")?
        }
        VerifierCommitStart::Proxy(verifier) => {
            verifier
                .reject(Some("the orc notary only supports MPC-TLS"))
                .await
                .stage("reject protocol config")?;
            close_session(&mut handle, driver_task).await;
            return Err(NotaryError::Protocol("proxy mode requested".into()));
        }
    };

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
        return Err(NotaryError::Protocol("unsupported certificate binding".into()));
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
}

/// Accepts connections forever, one notarization session per connection,
/// each bounded by `session_timeout`. Connections beyond
/// `max_concurrent_sessions` are closed immediately.
pub async fn serve(listener: TcpListener, config: Arc<NotaryConfig>) -> Result<(), NotaryError> {
    let permits = Arc::new(Semaphore::new(config.max_concurrent_sessions.max(1)));
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
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            warn!(%peer, "at capacity; refusing connection");
            continue;
        };
        if let Err(e) = socket.set_nodelay(true) {
            debug!(%peer, error = %e, "set_nodelay failed");
        }
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            info!(%peer, "session started");
            match tokio::time::timeout(config.session_timeout, notarize(socket, &config)).await {
                Ok(Ok(s)) => info!(
                    %peer,
                    sent = s.sent_len,
                    recv = s.recv_len,
                    elapsed_ms = s.elapsed.as_millis() as u64,
                    "attestation signed"
                ),
                Ok(Err(e)) => warn!(%peer, error = %e, "session failed"),
                Err(_) => warn!(%peer, timeout = ?config.session_timeout, "session timed out"),
            }
        });
    }
}

/// Closes the session and lets the driver flush pending frames (e.g. a
/// rejection) before the connection drops. Aborting the driver instead can
/// lose the frame, and the prover then waits for it until its own timeout.
async fn close_session<T>(handle: &mut SessionHandle, driver_task: AbortOnDrop<T>) {
    handle.close();
    if tokio::time::timeout(Duration::from_secs(5), driver_task)
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
