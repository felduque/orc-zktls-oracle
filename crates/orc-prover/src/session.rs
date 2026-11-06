//! One MPC-TLS session with the notary (spike m0b, productionized).
//!
//! Phases, each under [`ProverOptions::phase_timeout`]:
//! 1. setup: MPC preprocessing with the notary;
//! 2. online: TCP + MPC-TLS to the server, one HTTP request/response;
//! 3. prove: commit (SHA-256) to everything the presentation will reveal;
//! 4. attestation: send the request, receive and validate the signed attestation.

use std::{
    future::{Future, IntoFuture},
    ops::Range,
    time::{Duration, Instant},
};

use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes, header};
use hyper_util::rt::TokioIo;
use orc_core::{
    GuestInput, binding_header_value, graphql_body,
    request::{self, header as orc_header},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    task::JoinError,
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use tlsn::{
    Session,
    attestation::{
        Attestation, CryptoProvider, Secrets,
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
        signing::SignatureAlgId,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::HandshakeData,
    hash::HashAlgId,
    prover::ProverOutput,
    rangeset::set::RangeSet,
    transcript::{TranscriptCommitConfig, TranscriptCommitmentKind},
};

use crate::{
    Target,
    error::{ProverError, StageExt, with_timeout},
    target::GithubToken,
    task::AbortOnDrop,
};

/// SHA-256 everywhere: SP1 has a SHA-256 precompile, not BLAKE3.
const SHA256_KIND: TranscriptCommitmentKind = TranscriptCommitmentKind::Hash {
    alg: HashAlgId::SHA256,
};

/// Upper bound on the notary's bincode attestation.
const MAX_ATTESTATION_BYTES: u64 = 64 * 1024;

/// What the presentation reveals.
///
/// The default (everything except the `authorization` value) is the only
/// disclosure `orc_core::verify_claim` accepts. The other knobs exist so
/// tests can produce presentations the verifier must reject.
#[derive(Debug, Clone, Default)]
pub struct Disclosure {
    /// Also hide the values of these request headers (case-insensitive).
    pub also_hide_request_headers: Vec<String>,
    /// Hide these byte ranges of the response (clipped to its length).
    pub hide_received: Vec<Range<usize>>,
}

/// Prover settings.
#[derive(Debug, Clone)]
pub struct ProverOptions {
    /// MPC-TLS request budget (the notary enforces its own limit).
    pub max_sent_data: usize,
    /// MPC-TLS response budget (the notary enforces its own limit).
    pub max_recv_data: usize,
    /// Attestation signature algorithm to request (orc requires secp256k1).
    pub signature_alg: SignatureAlgId,
    /// Deadline for each session phase.
    pub phase_timeout: Duration,
    /// Deadline for opening the notary TCP connection.
    pub connect_timeout: Duration,
    /// Session attempts (spike m0b saw ~1 hang in 15 runs, so 2 by default).
    pub attempts: u32,
    pub disclosure: Disclosure,
}

impl Default for ProverOptions {
    fn default() -> Self {
        Self {
            max_sent_data: 4096,
            max_recv_data: 16384,
            signature_alg: SignatureAlgId::SECP256K1,
            phase_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(20),
            attempts: 2,
            disclosure: Disclosure::default(),
        }
    }
}

/// Wall-clock time per phase.
#[derive(Debug, Clone, Copy, Default)]
pub struct PhaseTimings {
    pub setup: Duration,
    pub online: Duration,
    pub prove: Duration,
    pub attestation: Duration,
}

impl PhaseTimings {
    pub fn total(&self) -> Duration {
        self.setup + self.online + self.prove + self.attestation
    }
}

/// A notarized session. Holds the prover's [`Secrets`] (which include the
/// raw transcript and therefore the token) in memory only; nothing here is
/// serializable on purpose.
pub struct Notarized {
    /// The notary-signed attestation (contains no plaintext).
    pub attestation: Attestation,
    secrets: Secrets,
    reveal_sent: RangeSet<usize>,
    reveal_recv: RangeSet<usize>,
    /// HTTP status hyper saw (informational).
    pub http_status: u16,
    pub timings: PhaseTimings,
}

impl Notarized {
    /// The full response bytes (never contains the token).
    pub fn received(&self) -> &[u8] {
        self.secrets.transcript().received()
    }

    /// Request length in bytes.
    pub fn sent_len(&self) -> usize {
        self.secrets.transcript().sent().len()
    }

    /// Builds the presentation: server identity proof plus the committed
    /// ranges (everything but the authorization value by default).
    pub fn presentation(&self) -> Result<Presentation, ProverError> {
        let mut proof = self.secrets.transcript_proof_builder();
        proof.commitment_kinds(&[SHA256_KIND]);
        proof
            .reveal_sent(&self.reveal_sent)
            .stage("reveal sent ranges")?;
        proof
            .reveal_recv(&self.reveal_recv)
            .stage("reveal received ranges")?;
        let proof = proof.build().stage("build transcript proof")?;

        let provider = CryptoProvider::default();
        let mut builder = self.attestation.presentation_builder(&provider);
        builder
            .identity_proof(self.secrets.identity_proof())
            .transcript_proof(proof);
        builder.build().stage("build presentation")
    }
}

/// Runs one MPC-TLS session over `notary` against `target` and returns the
/// attestation. No retry here; see [`crate::prove`].
pub async fn notarize<S>(
    notary: S,
    target: &Target,
    token: &GithubToken,
    input: &GuestInput,
    viewer_node_id: &str,
    opts: &ProverOptions,
) -> Result<Notarized, ProverError>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let limit = opts.phase_timeout;
    let mut timings = PhaseTimings::default();
    let http_request = build_request(target, token, input, viewer_node_id)?;
    let tls_config = TlsClientConfig::builder()
        .server_name(target.tlsn_server_name()?)
        .root_store(target.root_store.clone())
        .build()
        .stage("TLS client config")?;

    let session = Session::new(notary.compat());
    let (driver, mut handle) = session.split();
    let mut driver_task = AbortOnDrop::spawn(driver);

    // ---- 1. setup ----
    let started = Instant::now();
    let prover = phase("MPC setup", limit, &mut driver_task, async {
        let mpc = MpcTlsConfig::builder()
            .max_sent_data(opts.max_sent_data)
            .max_recv_data(opts.max_recv_data)
            .build()
            .stage("MPC-TLS config")?;
        handle
            .new_prover(ProverConfig::builder().build().stage("prover config")?)
            .stage("new prover")?
            .commit(mpc)
            .await
            .stage("MPC setup")
    })
    .await?;
    timings.setup = started.elapsed();

    // ---- 2. online: TLS + one HTTP exchange ----
    let started = Instant::now();
    let (mut prover, http_status) = phase("MPC-TLS request", limit, &mut driver_task, async {
        let server = TcpStream::connect(&target.connect_addr)
            .await
            .stage("connect to server")?;
        let (tls, prover_fut) = prover
            .connect(tls_config, server.compat())
            .stage("MPC-TLS connect")?;
        let prover_task = AbortOnDrop::spawn(prover_fut.into_future());

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls.compat()))
                .await
                .stage("HTTP handshake")?;
        let _connection = AbortOnDrop::spawn(connection);

        let response = sender
            .send_request(http_request)
            .await
            .stage("send request")?;
        let status = response.status().as_u16();
        // Drain the body so the whole response is in the transcript.
        response
            .into_body()
            .collect()
            .await
            .stage("read response")?;

        let prover = prover_task
            .await
            .stage("MPC-TLS task")?
            .stage("MPC-TLS")?;
        Ok((prover, status))
    })
    .await?;
    timings.online = started.elapsed();

    // ---- 3. commit + prove ----
    let started = Instant::now();
    let (sent_len, recv_len) = prover.transcript().len();
    debug!(sent_len, recv_len, http_status, "transcript");
    let reveal_sent = sent_reveal_set(prover.transcript().sent(), &opts.disclosure)?;
    let reveal_recv = recv_reveal_set(recv_len, &opts.disclosure);

    let mut commit = TranscriptCommitConfig::builder(prover.transcript());
    commit.default_kind(SHA256_KIND);
    commit.commit_sent(&reveal_sent).stage("commit sent")?;
    commit.commit_recv(&reveal_recv).stage("commit received")?;
    let commit = commit.build().stage("commit config")?;

    let mut request_config = RequestConfig::builder();
    request_config
        .signature_alg(opts.signature_alg)
        .hash_alg(HashAlgId::SHA256)
        .transcript_commit(commit);
    let request_config = request_config.build().stage("attestation request config")?;

    let mut prove_config = ProveConfig::builder(prover.transcript());
    if let Some(commit) = request_config.transcript_commit() {
        prove_config.transcript_commit(commit.clone());
    }
    let prove_config = prove_config.build().stage("prove config")?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = phase("MPC prove", limit, &mut driver_task, async {
        prover.prove(&prove_config).await.stage("MPC prove")
    })
    .await?;

    let transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    phase("close prover", limit, &mut driver_task, async {
        prover.close().await.stage("close prover")
    })
    .await?;
    timings.prove = started.elapsed();

    // ---- 4. attestation ----
    let started = Instant::now();
    let handshake = HandshakeData {
        certs: tls_transcript
            .server_cert_chain()
            .ok_or_else(|| ProverError::Invalid("TLS transcript has no certificate chain".into()))?
            .to_vec(),
        sig: tls_transcript
            .server_signature()
            .ok_or_else(|| ProverError::Invalid("TLS transcript has no server signature".into()))?
            .clone(),
        binding: tls_transcript.certificate_binding().clone(),
    };
    let mut request = AttestationRequest::builder(&request_config);
    request
        .server_name(target.tlsn_server_name()?)
        .handshake_data(handshake)
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (request, secrets) = request
        .build(&CryptoProvider::default())
        .stage("build attestation request")?;

    handle.close();
    let attestation = with_timeout("attestation", limit, async {
        let mut socket = driver_task
            .await
            .stage("session driver task")?
            .stage("session driver")?;
        let request_bytes = bincode::serialize(&request).stage("encode attestation request")?;
        socket
            .write_all(&request_bytes)
            .await
            .stage("send attestation request")?;
        // Half-close: the notary reads the request to EOF.
        socket.close().await.stage("finish attestation request")?;

        let mut attestation_bytes = Vec::new();
        (&mut socket)
            .take(MAX_ATTESTATION_BYTES + 1)
            .read_to_end(&mut attestation_bytes)
            .await
            .stage("read attestation")?;
        if attestation_bytes.len() as u64 > MAX_ATTESTATION_BYTES {
            return Err(ProverError::Invalid("attestation is too large".into()));
        }
        bincode::deserialize::<Attestation>(&attestation_bytes).stage("decode attestation")
    })
    .await?;
    request
        .validate(&attestation, &CryptoProvider::default())
        .stage("validate attestation")?;
    timings.attestation = started.elapsed();

    Ok(Notarized {
        attestation,
        secrets,
        reveal_sent,
        reveal_recv,
        http_status,
        timings,
    })
}

/// Runs one MPC phase under `limit`, failing immediately if the notary
/// connection ends first: tlsn's pending reads are not woken by a closed
/// connection, so without this a notary-side failure looks like a hang.
async fn phase<T, D, Io>(
    name: &'static str,
    limit: Duration,
    driver: &mut D,
    fut: impl Future<Output = Result<T, ProverError>>,
) -> Result<T, ProverError>
where
    D: Future<Output = Result<Result<Io, tlsn::Error>, JoinError>> + Unpin,
{
    with_timeout(name, limit, async {
        tokio::select! {
            biased;
            result = fut => result,
            ended = &mut *driver => Err(match ended {
                Ok(Ok(_)) => ProverError::Stage {
                    stage: name,
                    source: "notary closed the session".into(),
                },
                Ok(Err(e)) => ProverError::Stage { stage: name, source: e.into() },
                Err(e) => ProverError::Stage { stage: name, source: e.into() },
            }),
        }
    })
    .await
}

/// The notarized request: exactly the shape `orc_core::verify_claim` requires.
/// hyper adds `content-length` and writes header names in lowercase.
fn build_request(
    target: &Target,
    token: &GithubToken,
    input: &GuestInput,
    viewer_node_id: &str,
) -> Result<Request<Full<Bytes>>, ProverError> {
    let body = graphql_body(&input.owner, &input.name, viewer_node_id);
    let binding = binding_header_value(input.eth_address, input.chain_id, input.campaign_id);
    Request::builder()
        .method(request::METHOD)
        .uri(request::PATH)
        .header(header::HOST, &target.server_name)
        .header(header::USER_AGENT, request::USER_AGENT)
        .header(header::AUTHORIZATION, token.authorization_header()?)
        .header(header::ACCEPT_ENCODING, request::ACCEPT_ENCODING)
        .header(header::CONNECTION, request::CONNECTION)
        .header(header::CONTENT_TYPE, request::CONTENT_TYPE)
        .header(orc_header::BINDING, binding)
        .body(Full::new(Bytes::from(body)))
        .stage("build request")
}

/// `(0..sent.len())` minus the `authorization` value (and any extra headers
/// the disclosure hides).
fn sent_reveal_set(sent: &[u8], disclosure: &Disclosure) -> Result<RangeSet<usize>, ProverError> {
    let request = orc_core::http::parse_request(sent).stage("parse own request")?;
    let mut reveal: RangeSet<usize> = (0..sent.len()).into();
    let mut auth_hidden = false;
    for h in &request.headers {
        let is_auth = h.name.eq_ignore_ascii_case(orc_header::AUTHORIZATION);
        let extra = disclosure
            .also_hide_request_headers
            .iter()
            .any(|n| n.eq_ignore_ascii_case(&h.name));
        if is_auth || extra {
            reveal.difference_mut(&h.value_range);
            auth_hidden |= is_auth;
        }
    }
    if !auth_hidden {
        return Err(ProverError::Invalid(
            "request has no authorization header to hide".into(),
        ));
    }
    Ok(reveal)
}

/// `(0..recv_len)` minus the ranges the disclosure hides.
fn recv_reveal_set(recv_len: usize, disclosure: &Disclosure) -> RangeSet<usize> {
    let mut reveal: RangeSet<usize> = (0..recv_len).into();
    for range in &disclosure.hide_received {
        let clipped = range.start.min(recv_len)..range.end.min(recv_len);
        if !clipped.is_empty() {
            reveal.difference_mut(&RangeSet::from(clipped));
        }
    }
    reveal
}
