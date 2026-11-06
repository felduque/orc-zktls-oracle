//! M0b spike: TLSNotary v0.1.0-alpha.15 MPC-TLS against api.github.com.
//!
//! Port of crates/examples/attestation/{prove,present,verify}.rs at tag
//! v0.1.0-alpha.15, collapsed into one binary:
//!   prover <-> in-process notary over tokio::io::duplex, then
//!   attestation -> presentation (bincode) -> native verify.
//!
//! Usage: cargo run --release -- <repo|zen|rate_limit|graphql> [--no-auth]

use std::{env, future::IntoFuture, time::Duration, time::Instant};

use anyhow::{Context, Result, anyhow};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider, Secrets,
        presentation::{Presentation, PresentationOutput},
        request::{Request as AttestationRequest, RequestConfig},
        signing::{Secp256k1Signer, SignatureAlgId, VerifyingKey},
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::{CertBinding, ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    hash::HashAlgId,
    prover::ProverOutput,
    rangeset::set::RangeSet,
    transcript::{ContentType, TranscriptCommitConfig, TranscriptCommitmentKind},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};
use tlsn_formats::http::HttpTranscript;

const SERVER_DOMAIN: &str = "api.github.com";
const SERVER_PORT: u16 = 443;
const MAX_SENT_DATA: usize = 4096;
const MAX_RECV_DATA: usize = 16384;
const DUMMY_TOKEN: &str = "REDACTME";
const SHA256_KIND: TranscriptCommitmentKind = TranscriptCommitmentKind::Hash {
    alg: HashAlgId::SHA256,
};

struct RunSpec {
    name: String,
    method: &'static str,
    uri: &'static str,
    body: Option<&'static str>,
    with_auth: bool,
}

fn run_spec(run: &str, with_auth: bool) -> Result<RunSpec> {
    let (method, uri, body) = match run {
        "repo" => ("GET", "/repos/tlsnotary/tlsn", None),
        "zen" => ("GET", "/zen", None),
        "rate_limit" => ("GET", "/rate_limit", None),
        "graphql" => ("POST", "/graphql", Some(r#"{"query":"{viewer{login}}"}"#)),
        other => return Err(anyhow!("unknown run `{other}`")),
    };
    let name = if with_auth {
        run.to_string()
    } else {
        format!("{run}-noauth")
    };
    Ok(RunSpec {
        name,
        method,
        uri,
        body,
        with_auth,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let args: Vec<String> = env::args().skip(1).collect();
    let run = args.first().map(String::as_str).unwrap_or("repo");
    let with_auth = !args.iter().any(|a| a == "--no-auth");
    let spec = run_spec(run, with_auth)?;

    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures");
    std::fs::create_dir_all(fixtures)?;

    println!("=== M0b run `{}`: {} {} (dummy auth: {}) ===", spec.name, spec.method, spec.uri, spec.with_auth);

    let (notary_socket, prover_socket) = tokio::io::duplex(1 << 23);
    let notary_task = tokio::spawn(async move { notary(notary_socket).await });

    let t_total = Instant::now();
    let (attestation, secrets) = prover(prover_socket, &spec).await?;
    notary_task.await??;
    println!("[time] total prover+notary: {:.2?}", t_total.elapsed());

    let att_path = format!("{fixtures}/attestation-{}.bin", spec.name);
    let sec_path = format!("{fixtures}/secrets-{}.bin", spec.name);
    std::fs::write(&att_path, bincode::serialize(&attestation)?)?;
    std::fs::write(&sec_path, bincode::serialize(&secrets)?)?;

    // ---- present ----
    let t = Instant::now();
    let presentation = present(&attestation, &secrets)?;
    let pres_bytes = bincode::serialize(&presentation)?;
    let pres_path = format!("{fixtures}/presentation-{}.bin", spec.name);
    std::fs::write(&pres_path, &pres_bytes)?;
    println!(
        "[time] presentation build: {:.2?} -> {} ({} bytes)",
        t.elapsed(),
        pres_path,
        pres_bytes.len()
    );
    let leaked = pres_bytes
        .windows(DUMMY_TOKEN.len())
        .any(|w| w == DUMMY_TOKEN.as_bytes());
    println!("[redaction] `{DUMMY_TOKEN}` present in presentation bytes: {leaked}");

    // ---- verify (from disk, like verify.rs) ----
    let t = Instant::now();
    let presentation: Presentation = bincode::deserialize(&std::fs::read(&pres_path)?)?;
    verify(presentation)?;
    println!("[time] native verify: {:.2?}", t.elapsed());

    Ok(())
}

async fn prover<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    spec: &RunSpec,
) -> Result<(Attestation, Secrets)> {
    // ---- phase 1: setup (session + MPC preprocessing) ----
    let t_setup = Instant::now();
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .await?;
    println!("[time] setup (MPC preprocessing): {:.2?}", t_setup.elapsed());

    // ---- phase 2: connect + request ----
    let t_conn = Instant::now();
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, SERVER_PORT)).await?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            .root_store(RootCertStore::mozilla())
            .build()?,
        client_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let mut rb = Request::builder()
        .method(spec.method)
        .uri(spec.uri)
        .header("Host", SERVER_DOMAIN)
        .header("User-Agent", "orc-poc")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("X-Orc-Binding", "0xdeadbeef");
    if spec.with_auth {
        rb = rb.header("Authorization", format!("bearer {DUMMY_TOKEN}"));
    }
    if spec.body.is_some() {
        rb = rb.header("Content-Type", "application/json");
    }
    let body = Bytes::from_static(spec.body.unwrap_or("").as_bytes());
    let request = rb.body(Full::new(body))?;

    let response = request_sender.send_request(request).await?;
    let status = response.status();
    // Drain the body so the whole response lands in the transcript.
    let body = response.into_body().collect().await?.to_bytes();
    println!("[http] status {status}, decoded body {} bytes", body.len());

    let mut prover = prover_task.await??;
    println!("[time] connect+request (MPC-TLS online): {:.2?}", t_conn.elapsed());

    // ---- phase 3: commit + attestation ----
    let t_att = Instant::now();
    let (sent_len, recv_len) = prover.transcript().len();
    println!("[size] sent {sent_len} bytes, recv {recv_len} bytes (limits {MAX_SENT_DATA}/{MAX_RECV_DATA})");

    if env::var("M0B_DUMP").is_ok() {
        println!("---- raw sent ----\n{}", String::from_utf8_lossy(prover.transcript().sent()));
        println!("---- raw recv ----\n{}", String::from_utf8_lossy(prover.transcript().received()));
    }
    // Response framing, checked on raw bytes (spansy may refuse to parse).
    let recv = prover.transcript().received();
    let head_end = recv
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(recv.len());
    let head = String::from_utf8_lossy(&recv[..head_end]).to_ascii_lowercase();
    println!(
        "[http] response head {} B, body {} B; has content-length: {}, has transfer-encoding: {}",
        head_end,
        recv.len() - head_end,
        head.contains("\r\ncontent-length:"),
        head.contains("\r\ntransfer-encoding:")
    );
    match HttpTranscript::parse(prover.transcript()) {
        Ok(t) => {
            let resp = &t.responses[0];
            let te = resp
                .headers_with_name("transfer-encoding")
                .map(|h| String::from_utf8_lossy(&h.value.as_bytes()).into_owned())
                .collect::<Vec<_>>();
            let cl = resp
                .headers_with_name("content-length")
                .map(|h| String::from_utf8_lossy(&h.value.as_bytes()).into_owned())
                .collect::<Vec<_>>();
            println!("[http] HttpTranscript::parse OK; transfer-encoding: {te:?}, content-length: {cl:?}");
        }
        Err(e) => println!("[http] HttpTranscript::parse FAILED: {e}"),
    }

    // Commitment strategy from the plan:
    //   sent: (0..sent_len) - value(authorization)
    //   recv: 0..recv_len
    let sent_idx = sent_minus_auth(prover.transcript().sent())?;
    let recv_idx: RangeSet<usize> = (0..recv_len).into();
    println!("[redaction] committing sent {sent_idx:?}, recv {recv_idx:?}");

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    builder.default_kind(SHA256_KIND);
    builder.commit_sent(&sent_idx)?;
    builder.commit_recv(&recv_idx)?;
    let transcript_commit = builder.build()?;

    let mut builder = RequestConfig::builder();
    builder
        .signature_alg(SignatureAlgId::SECP256K1)
        .hash_alg(HashAlgId::SHA256)
        .transcript_commit(transcript_commit);
    let request_config = builder.build()?;

    let mut builder = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        builder.transcript_commit(config.clone());
    }
    let disclosure_config = builder.build()?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .context("server cert chain")?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .context("server signature")?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (request, secrets) = builder.build(&CryptoProvider::default())?;

    handle.close();
    let mut socket = driver_task.await??;

    let request_bytes = bincode::serialize(&request)?;
    socket.write_all(&request_bytes).await?;
    socket.close().await?;

    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)?;

    request.validate(&attestation, &CryptoProvider::default())?;
    println!(
        "[time] commit+attestation: {:.2?} (request {} B, attestation {} B)",
        t_att.elapsed(),
        request_bytes.len(),
        attestation_bytes.len()
    );

    Ok((attestation, secrets))
}

/// (0..sent.len()) minus the value of every `authorization` header, located
/// with the spansy request parser (the request side always parses).
fn sent_minus_auth(sent: &[u8]) -> Result<RangeSet<usize>> {
    let req = tlsn_formats::http::parse_request(sent)
        .map_err(|e| anyhow!("request parse failed: {e}"))?;
    let mut idx: RangeSet<usize> = (0..sent.len()).into();
    for h in req.headers_with_name("authorization") {
        println!(
            "[redaction] authorization value at {:?} = {:?}",
            h.value.indices(),
            String::from_utf8_lossy(&h.value.as_bytes())
        );
        idx.difference_mut(h.value.indices());
    }
    println!("[redaction] sent ranges to commit/reveal: {idx:?}");
    Ok(idx)
}

fn present(attestation: &Attestation, secrets: &Secrets) -> Result<Presentation> {
    let (_, recv_len) = secrets.transcript().len();
    let sent_idx = sent_minus_auth(secrets.transcript().sent())?;

    let mut builder = secrets.transcript_proof_builder();
    builder.commitment_kinds(&[SHA256_KIND]);
    builder.reveal_sent(&sent_idx)?;
    builder.reveal_recv(&(0..recv_len))?;
    let transcript_proof = builder.build()?;

    let provider = CryptoProvider::default();
    let mut builder = attestation.presentation_builder(&provider);
    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    Ok(builder.build()?)
}

fn verify(presentation: Presentation) -> Result<()> {
    // GitHub uses a public CA -> default provider (Mozilla roots) is enough.
    let crypto_provider = CryptoProvider::default();

    let VerifyingKey { alg, data } = presentation.verifying_key();
    println!("[verify] notary key alg {alg}, key {}", hex::encode(data));

    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation
        .verify(&crypto_provider)
        .map_err(|e| anyhow!("presentation verify failed: {e}"))?;

    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
    let server_name = server_name.context("no server name in presentation")?;
    let mut partial = transcript.context("no transcript in presentation")?;
    println!(
        "[verify] sent authed {:?}, recv authed {:?}",
        partial.sent_authed(),
        partial.received_authed()
    );
    partial.set_unauthed(b'X');

    let sent = String::from_utf8_lossy(partial.sent_unsafe());
    let recv = String::from_utf8_lossy(partial.received_unsafe());

    println!("-------------------------------------------------------------------");
    println!("Verified: data came from a session with {server_name} at {time} (unix {}).", connection_info.time);
    println!("TLS version {:?}, transcript length sent {} / recv {}", connection_info.version, connection_info.transcript_length.sent, connection_info.transcript_length.received);
    println!("Unauthenticated bytes shown as X.\n");
    println!("Data sent:\n\n{sent}\n");
    println!("Data received:\n\n{recv}\n");
    println!("-------------------------------------------------------------------");
    Ok(())
}

async fn notary<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()?;

    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(verifier) => verifier.accept().await?.run().await?,
        VerifierCommitStart::Proxy(verifier) => {
            verifier.reject(Some("expecting to use MPC-TLS")).await?;
            return Err(anyhow!("protocol configuration rejected"));
        }
    };

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    let app_len = |records: &[tlsn::transcript::Record]| {
        records
            .iter()
            .filter(|r| matches!(r.typ, ContentType::ApplicationData))
            .map(|r| r.ciphertext.len())
            .sum::<usize>()
    };
    let sent_len = app_len(tls_transcript.sent());
    let recv_len = app_len(tls_transcript.recv());

    handle.close();
    let mut socket = driver_task.await??;

    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    // Dummy secp256k1 notary key (same as upstream example).
    let signing_key = k256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into())?;
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder
        .supported_signature_algs(vec![SignatureAlgId::SECP256K1])
        .supported_hash_algs(vec![HashAlgId::SHA256]);
    let att_config = att_config_builder.build()?;

    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        return Err(anyhow!("unsupported cert binding version"));
    };
    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);

    let attestation = builder.build(&provider)?;

    socket.write_all(&bincode::serialize(&attestation)?).await?;
    socket.close().await?;
    Ok(())
}
