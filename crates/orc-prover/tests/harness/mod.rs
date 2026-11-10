//! Local, offline stand-in for api.github.com: a TLS 1.2/1.3 server with
//! tlsn's test CA (`test-server.io`, valid until 2124) that answers the
//! preflight and serves one canned GraphQL reply per scenario, with
//! selectable HTTP framing. The real orc notary runs on another local port.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use orc_core::{
    Address, B256, GuestInput, VerifyParams,
    graphql::{BranchRef, ClaimData, Commit, GraphqlResponse, History, Repository, Viewer},
};
use orc_notary::{NotaryConfig, NotaryKey};
use orc_prover::{
    Disclosure, GithubToken, ProveOutcome, ProverError, ProverOptions, Target, preflight, prove,
};
use tlsn::{
    attestation::signing::SignatureAlgId,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

pub const TOKEN: &str = "ghp_TESTtoken0123456789abcdefghijklmnopq";
pub const VIEWER_ID: &str = "U_kgDOorcTest";
pub const VIEWER_DB_ID: u64 = 583_231;
pub const REPO_DB_ID: u64 = 1_300_192;
pub const COMMITS: u64 = 42;
pub const NOTARY_SECRET: [u8; 32] = [7u8; 32];

/// Each MPC session needs a few hundred MB and several cores; cap how many
/// tests run one at the same time.
static MPC_SLOTS: Semaphore = Semaphore::const_new(2);

// ---- canned server replies --------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    ContentLength,
    Chunked,
    CloseDelimited,
    /// Close-delimited, cut in the middle of the JSON body.
    TruncatedClose,
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub status_line: &'static str,
    pub body: String,
    pub framing: Framing,
}

impl Reply {
    pub fn ok(framing: Framing) -> Self {
        Self {
            status_line: "HTTP/1.1 200 OK",
            body: claim_json(),
            framing,
        }
    }

    fn render(&self) -> Vec<u8> {
        let mut out = format!(
            "{}\r\nServer: orc-test\r\nContent-Type: application/json; charset=utf-8\r\n",
            self.status_line
        )
        .into_bytes();
        let body = self.body.as_bytes();
        match self.framing {
            Framing::ContentLength => {
                out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
                out.extend_from_slice(body);
            }
            Framing::Chunked => {
                out.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
                for chunk in body.chunks(64) {
                    out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    out.extend_from_slice(chunk);
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"0\r\n\r\n");
            }
            Framing::CloseDelimited => {
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(body);
            }
            Framing::TruncatedClose => {
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(&body[..body.len() / 2]);
            }
        }
        out
    }
}

/// The GraphQL `data` GitHub would return for the orc query.
pub fn claim_data() -> ClaimData {
    ClaimData {
        viewer: Viewer {
            login: "octo-test".into(),
            database_id: VIEWER_DB_ID,
            id: VIEWER_ID.into(),
        },
        repository: Repository {
            database_id: REPO_DB_ID,
            default_branch_ref: BranchRef {
                name: "main".into(),
                target: Commit {
                    oid: "4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e4f1c2d3e".into(),
                    history: History {
                        total_count: COMMITS,
                    },
                },
            },
        },
    }
}

pub fn claim_json() -> String {
    serde_json::to_string(&GraphqlResponse { data: claim_data() }).expect("serialize")
}

// ---- TLS server -------------------------------------------------------------

pub struct TestServer {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_server(reply: Reply) -> TestServer {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                SERVER_CERT_DER.to_vec(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(SERVER_KEY_DER.to_vec().into()),
        )
        .expect("server cert");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let addr = listener.local_addr().expect("server addr");

    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let reply = reply.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_one(tcp, acceptor, reply).await {
                    eprintln!("test server connection error: {e}");
                }
            });
        }
    });
    TestServer { addr, task }
}

async fn serve_one(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    reply: Reply,
) -> std::io::Result<()> {
    let mut tls = acceptor.accept(tcp).await?;
    let body = read_request_body(&mut tls).await?;
    let response = if body == preflight::PREFLIGHT_BODY.as_bytes() {
        Reply {
            status_line: "HTTP/1.1 200 OK",
            body: format!(r#"{{"data":{{"viewer":{{"id":"{VIEWER_ID}"}}}}}}"#),
            framing: Framing::ContentLength,
        }
        .render()
    } else {
        reply.render()
    };
    tls.write_all(&response).await?;
    tls.flush().await?;
    // close_notify + FIN: ends close-delimited bodies.
    let _ = tls.shutdown().await;
    Ok(())
}

async fn read_request_body<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let content_length = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let body_start = head_end + 4;
            if buf.len() >= body_start + content_length {
                return Ok(buf[body_start..body_start + content_length].to_vec());
            }
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

pub fn test_roots() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}

pub fn verify_params() -> VerifyParams {
    VerifyParams::with_root_store(SERVER_DOMAIN, &test_roots()).expect("verify params")
}

// ---- notary -----------------------------------------------------------------

pub struct TestNotary {
    pub addr: SocketAddr,
    pub key_hash: B256,
    task: JoinHandle<()>,
}

impl Drop for TestNotary {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_notary(key: NotaryKey) -> TestNotary {
    let key_hash = key.key_hash();
    let mut config = NotaryConfig::new(key);
    config.root_store = test_roots();
    config.session_timeout = Duration::from_secs(120);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind notary");
    let addr = listener.local_addr().expect("notary addr");
    let task = tokio::spawn(async move {
        if let Err(e) = orc_notary::serve(listener, Arc::new(config)).await {
            eprintln!("notary stopped: {e}");
        }
    });
    TestNotary {
        addr,
        key_hash,
        task,
    }
}

// ---- scenarios ----------------------------------------------------------------

pub fn input() -> GuestInput {
    GuestInput {
        eth_address: Address::repeat_byte(0x11),
        chain_id: 84532,
        campaign_id: B256::repeat_byte(0x22),
        owner: "tlsnotary".into(),
        name: "tlsn".into(),
        threshold: 10,
    }
}

/// How a scenario deviates from the honest flow.
#[derive(Default)]
pub struct Scenario {
    /// Send this `$a` instead of the preflight's viewer id.
    pub viewer_override: Option<String>,
    pub disclosure: Disclosure,
    /// Notary signs with P-256 instead of secp256k1.
    pub p256_notary: bool,
    /// Ask the notary for this MPC response budget.
    pub max_recv_data: Option<usize>,
    pub attempts: Option<u32>,
    /// Prover deadline per session phase (default 20 s).
    pub phase_timeout: Option<Duration>,
}

pub struct Run {
    pub outcome: ProveOutcome,
    pub input: GuestInput,
    pub notary_key_hash: B256,
}

/// Runs preflight + MPC-TLS + attestation + presentation against a local
/// server serving `reply`, with a fresh local notary.
pub async fn run(reply: Reply, scenario: Scenario) -> Result<Run, ProverError> {
    run_timed(reply, scenario).await.0
}

/// [`run`], plus how long the scenario took once it held an MPC slot: time
/// spent queueing behind other tests' sessions is not counted.
pub async fn run_timed(reply: Reply, scenario: Scenario) -> (Result<Run, ProverError>, Duration) {
    let _slot = MPC_SLOTS.acquire().await.expect("semaphore");
    let started = Instant::now();
    let result = run_session(reply, scenario).await;
    (result, started.elapsed())
}

async fn run_session(reply: Reply, scenario: Scenario) -> Result<Run, ProverError> {
    let server = spawn_server(reply).await;
    let key = if scenario.p256_notary {
        NotaryKey::secp256r1(NOTARY_SECRET).expect("p256 key")
    } else {
        NotaryKey::secp256k1(NOTARY_SECRET).expect("k256 key")
    };
    let notary = spawn_notary(key).await;

    let target = Target {
        server_name: SERVER_DOMAIN.to_owned(),
        connect_addr: server.addr.to_string(),
        root_store: test_roots(),
    };
    let token = GithubToken::new(TOKEN).expect("token");
    let mut opts = ProverOptions {
        // Local phases take ~1 s; a hang (see spike m0b) is cut at 20 s and retried.
        phase_timeout: scenario.phase_timeout.unwrap_or(Duration::from_secs(20)),
        disclosure: scenario.disclosure,
        ..ProverOptions::default()
    };
    if scenario.p256_notary {
        opts.signature_alg = SignatureAlgId::SECP256R1;
    }
    if let Some(max_recv) = scenario.max_recv_data {
        opts.max_recv_data = max_recv;
    }
    if let Some(attempts) = scenario.attempts {
        opts.attempts = attempts;
    }

    let viewer = preflight::viewer_node_id(&target, &token, Duration::from_secs(30)).await?;
    assert_eq!(
        viewer, VIEWER_ID,
        "preflight must return the server's viewer id"
    );
    let viewer = scenario.viewer_override.unwrap_or(viewer);

    let input = input();
    let outcome = prove(
        &notary.addr.to_string(),
        &target,
        &token,
        &input,
        &viewer,
        &opts,
    )
    .await?;
    for reason in &outcome.retry_reasons {
        eprintln!("note: MPC session retried after: {reason}");
    }
    Ok(Run {
        outcome,
        input,
        notary_key_hash: notary.key_hash,
    })
}

/// Index of the first occurrence of `needle`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
