//! Local, offline stand-in for api.github.com: a TLS 1.2/1.3 server with
//! tlsn's test CA (`test-server.io`, valid until 2124) that answers the
//! preflight and serves one canned GraphQL reply per scenario, with
//! selectable HTTP framing. The real orc notary runs on another local port.
//!
//! Each scenario holds one of [`MPC_SLOTS`], runs up to
//! [`Scenario::attempts`] fresh notary sessions, retrying only a phase
//! timeout (tlsn's MPC setup stall, see `logs`), and prints the prover's and
//! the notary's log tails for every attempt that failed.

mod logs;

use std::{
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use orc_core::{
    Address, B256, GuestInput, VerifyParams, campaign_id,
    graphql::{BranchRef, ClaimData, Commit, GraphqlResponse, History, Repository, Viewer},
    keccak256,
    request::{FINE_GRAINED_PAT_PREFIX, FINE_GRAINED_PAT_SECRET_LEN},
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
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use tracing::{Dispatch, instrument::WithSubscriber};

use self::logs::SessionLogs;

pub const VIEWER_ID: &str = "U_kgDOorcTest";
pub const VIEWER_CREATED_AT: &str = "2015-06-01T12:34:56Z";
/// 2026-01-01T00:00:00Z: before any fixture's session time, after the account.
pub const SNAPSHOT: u64 = 1_767_225_600;
pub const VIEWER_DB_ID: u64 = 583_231;
pub const REPO_DB_ID: u64 = 1_300_192;
pub const COMMITS: u64 = 42;
pub const NOTARY_SECRET: [u8; 32] = [7u8; 32];

/// Concurrent MPC sessions across the test binary (default 2). Each needs a
/// few hundred MB and several cores. CI sets 1.
pub const MPC_SLOTS_ENV: &str = "ORC_TEST_MPC_SLOTS";
/// Overrides [`DEFAULT_ATTEMPTS`] (CI raises it, see ci.yml).
pub const ATTEMPTS_ENV: &str = "ORC_TEST_ATTEMPTS";
/// Overrides [`DEFAULT_PHASE_TIMEOUT`], in seconds (CI lowers it).
pub const PHASE_TIMEOUT_ENV: &str = "ORC_TEST_PHASE_TIMEOUT_SECS";

/// A positive integer from the environment, if set.
fn env_count(name: &str) -> Option<u32> {
    let value = std::env::var(name).ok()?;
    let count = value.trim().parse::<u32>().ok().filter(|&n| n > 0);
    Some(count.unwrap_or_else(|| panic!("{name}={value:?}: expected a positive integer")))
}

/// Caps how many tests run an MPC session at the same time.
static MPC_SLOTS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(env_count(MPC_SLOTS_ENV).unwrap_or(2) as usize));

/// A fake fine-grained PAT (`github_pat_` + 22 + `_` + 59 characters, the
/// real shape). Built at run time so the repository holds no token-shaped
/// literal; varied characters so a leak check cannot match by accident.
pub fn token() -> String {
    const ALNUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let secret: String = (0..FINE_GRAINED_PAT_SECRET_LEN)
        .map(|i| {
            if i == 22 {
                '_'
            } else {
                char::from(ALNUM[(i * 7 + 3) % ALNUM.len()])
            }
        })
        .collect();
    format!("{FINE_GRAINED_PAT_PREFIX}{secret}")
}

/// The part of [`token`] the presentation must never contain.
pub fn token_secret() -> String {
    token()[FINE_GRAINED_PAT_PREFIX.len()..].to_owned()
}

/// Fixture convention for `campaignId` (see the README, "Fixtures"): what an
/// `OrcClaim` deployed at this placeholder address on chain 84532 with
/// `campaignSalt = keccak256("orc-poc-github-v1")` derives. The forge fixture
/// test deploys `OrcClaim` exactly there, so harness fixtures claim on it.
pub const FIXTURE_ORC_ADDRESS: &str = "0x000000000000000000000000000000000000C1A1";
pub const FIXTURE_CAMPAIGN_SALT_PREIMAGE: &[u8] = b"orc-poc-github-v1";

pub fn fixture_campaign_id(chain_id: u64) -> B256 {
    let orc: Address = FIXTURE_ORC_ADDRESS.parse().expect("fixture address");
    campaign_id(chain_id, orc, keccak256(FIXTURE_CAMPAIGN_SALT_PREIMAGE))
}

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

    /// A 200 whose `viewer.createdAt` is `created_at`.
    pub fn ok_created_at(framing: Framing, created_at: &str) -> Self {
        let mut data = claim_data();
        data.viewer.created_at = created_at.to_owned();
        Self {
            status_line: "HTTP/1.1 200 OK",
            body: serde_json::to_string(&GraphqlResponse { data }).expect("serialize"),
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
            created_at: VIEWER_CREATED_AT.into(),
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
            body: format!(
                r#"{{"data":{{"viewer":{{"id":"{VIEWER_ID}","createdAt":"{VIEWER_CREATED_AT}"}}}}}}"#
            ),
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

/// A notary with production limits (10 s setup deadline, 2 sessions per
/// source address: every harness connection comes from 127.0.0.1) and a
/// 120 s session timeout, logging to `logs`.
pub async fn spawn_notary(key: NotaryKey, logs: Dispatch) -> TestNotary {
    let key_hash = key.key_hash();
    let mut config = NotaryConfig::new(key);
    config.root_store = test_roots();
    config.session_timeout = Duration::from_secs(120);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind notary");
    let addr = listener.local_addr().expect("notary addr");
    let task = tokio::spawn(
        async move {
            if let Err(e) = orc_notary::serve(listener, Arc::new(config)).await {
                eprintln!("notary stopped: {e}");
            }
        }
        .with_subscriber(logs),
    );
    TestNotary {
        addr,
        key_hash,
        task,
    }
}

// ---- simulated hang ---------------------------------------------------------

/// A TCP relay in front of the notary. It forwards both ways, except on its
/// first `stall` connections: there it forwards the prover's bytes but
/// swallows every byte the notary sends, so the prover waits in MPC setup
/// for a reply that never comes, with idle CPU, like tlsn's real stall. Once
/// the prover gives up and closes, the relay closes the notary side too.
pub struct StallProxy {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for StallProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_stall_proxy(notary: SocketAddr, stall: u32) -> StallProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");
    let task = tokio::spawn(async move {
        // Owned here, so aborting the proxy aborts every relay.
        let mut relays = JoinSet::new();
        let mut accepted = 0u32;
        loop {
            let Ok((prover, _)) = listener.accept().await else {
                continue;
            };
            while relays.try_join_next().is_some() {}
            relays.spawn(relay(prover, notary, accepted < stall));
            accepted = accepted.saturating_add(1);
        }
    });
    StallProxy { addr, task }
}

async fn relay(mut prover: TcpStream, notary: SocketAddr, stall: bool) {
    let Ok(mut notary) = TcpStream::connect(notary).await else {
        return;
    };
    let _ = prover.set_nodelay(true);
    let _ = notary.set_nodelay(true);
    if !stall {
        let _ = tokio::io::copy_bidirectional(&mut prover, &mut notary).await;
        return;
    }
    let (mut from_prover, _to_prover) = prover.split();
    let (mut from_notary, mut to_notary) = notary.split();
    let swallow = async {
        let _ = tokio::io::copy(&mut from_notary, &mut tokio::io::sink()).await;
        // Even if the notary hangs up, the prover must not hear about it.
        std::future::pending::<()>().await
    };
    tokio::select! {
        _ = tokio::io::copy(&mut from_prover, &mut to_notary) => {}
        () = swallow => {}
    }
}

// ---- scenarios ----------------------------------------------------------------

pub fn input() -> GuestInput {
    GuestInput {
        eth_address: Address::repeat_byte(0x11),
        chain_id: 84532,
        campaign_id: fixture_campaign_id(84532),
        owner: "tlsnotary".into(),
        name: "tlsn".into(),
        threshold: 10,
        snapshot: SNAPSHOT,
    }
}

/// Default session attempts ([`ATTEMPTS_ENV`]). Only a phase timeout is
/// retried: tlsn's MPC setup stall (README, "Known issues") hit both of 2
/// attempts in CI run 42850036536.
pub const DEFAULT_ATTEMPTS: u32 = 3;
/// Default deadline per MPC phase ([`PHASE_TIMEOUT_ENV`]; production: 120 s).
/// A healthy phase takes at most ~1.4 s even on 4 CPUs; a stalled session
/// sits idle and never recovers, so waiting longer only delays the retry.
pub const DEFAULT_PHASE_TIMEOUT: Duration = Duration::from_secs(45);
/// Session attempts of a scenario that does not set them: [`ATTEMPTS_ENV`]
/// or [`DEFAULT_ATTEMPTS`].
pub fn default_attempts() -> u32 {
    env_count(ATTEMPTS_ENV).unwrap_or(DEFAULT_ATTEMPTS)
}

/// Wait after a timed-out attempt before reporting it (the notary ends a
/// session ~1 ms after the prover's connection closes).
const NOTARY_GRACE: Duration = Duration::from_millis(500);

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
    /// Session attempts (default [`ATTEMPTS_ENV`] or [`DEFAULT_ATTEMPTS`]).
    pub attempts: Option<u32>,
    /// Prover deadline per session phase (default [`PHASE_TIMEOUT_ENV`] or
    /// [`DEFAULT_PHASE_TIMEOUT`]).
    pub phase_timeout: Option<Duration>,
    /// Simulated hang: the notary's first `stall_sessions` sessions never
    /// answer the prover (see [`StallProxy`]).
    pub stall_sessions: u32,
    /// Attempts fail on purpose: keep their diagnostics off the real stderr
    /// and out of `ORC_TEST_LOG_DIR` (they are still in [`Report::failures`]).
    pub expect_failures: bool,
}

pub struct Run {
    pub outcome: ProveOutcome,
    pub input: GuestInput,
    pub notary_key_hash: B256,
    /// Session attempts used (fresh notary session each).
    pub attempts: u32,
}

/// Runs preflight + MPC-TLS + attestation + presentation against a local
/// server serving `reply`, with a fresh local notary.
pub async fn run(reply: Reply, scenario: Scenario) -> Result<Run, ProverError> {
    run_report(reply, scenario).await.result
}

pub struct Report {
    pub result: Result<Run, ProverError>,
    /// How long the scenario took once it held an MPC slot: time spent
    /// queueing behind other tests' sessions is not counted.
    pub elapsed: Duration,
    /// Diagnostics (log tails) of each failed attempt, oldest first.
    pub failures: Vec<String>,
}

/// [`run`], with timing and the diagnostics of failed attempts.
pub async fn run_report(reply: Reply, scenario: Scenario) -> Report {
    // libtest names each test's thread after the test; `#[tokio::test]`
    // polls the test body (and so this) on it.
    let test = std::thread::current()
        .name()
        .filter(|name| *name != "main")
        .unwrap_or("e2e")
        .to_owned();
    let _slot = MPC_SLOTS.acquire().await.expect("semaphore");
    let started = Instant::now();
    let mut failures = Vec::new();
    let result = run_session(&test, reply, scenario, &mut failures).await;
    Report {
        result,
        elapsed: started.elapsed(),
        failures,
    }
}

async fn run_session(
    test: &str,
    reply: Reply,
    scenario: Scenario,
    failures: &mut Vec<String>,
) -> Result<Run, ProverError> {
    let mut logs = SessionLogs::new(test);
    let server = spawn_server(reply).await;
    let key = if scenario.p256_notary {
        NotaryKey::secp256r1(NOTARY_SECRET).expect("p256 key")
    } else {
        NotaryKey::secp256k1(NOTARY_SECRET).expect("k256 key")
    };
    let notary = spawn_notary(key, logs.notary_dispatch()).await;
    let proxy = match scenario.stall_sessions {
        0 => None,
        stall => Some(spawn_stall_proxy(notary.addr, stall).await),
    };
    let notary_addr = proxy.as_ref().map_or(notary.addr, |p| p.addr).to_string();

    let target = Target {
        server_name: SERVER_DOMAIN.to_owned(),
        connect_addr: server.addr.to_string(),
        root_store: test_roots(),
    };
    let token = GithubToken::new(token()).expect("token");
    let phase_timeout = env_count(PHASE_TIMEOUT_ENV).map(|secs| Duration::from_secs(secs.into()));
    let mut opts = ProverOptions {
        phase_timeout: scenario
            .phase_timeout
            .or(phase_timeout)
            .unwrap_or(DEFAULT_PHASE_TIMEOUT),
        // The attempts are run below, so each can be diagnosed.
        attempts: 1,
        disclosure: scenario.disclosure,
        ..ProverOptions::default()
    };
    if scenario.p256_notary {
        opts.signature_alg = SignatureAlgId::SECP256R1;
    }
    if let Some(max_recv) = scenario.max_recv_data {
        opts.max_recv_data = max_recv;
    }

    let viewer = preflight::viewer_node_id(&target, &token, Duration::from_secs(30)).await?;
    assert_eq!(
        viewer, VIEWER_ID,
        "preflight must return the server's viewer id"
    );
    let viewer = scenario.viewer_override.unwrap_or(viewer);

    let input = input();
    let attempts = scenario.attempts.unwrap_or_else(default_attempts).max(1);
    let prover_logs = logs.prover_dispatch();
    let mut attempt = 1;
    loop {
        logs.attempt_started(attempt, attempts);
        // A fresh notary connection and tlsn session. A timed-out attempt
        // leaves nothing running: its session driver and MPC tasks are
        // aborted when `prove` returns, and the notary ends its side when the
        // connection closes.
        let result = prove(&notary_addr, &target, &token, &input, &viewer, &opts)
            .with_subscriber(prover_logs.clone())
            .await;
        match result {
            Ok(outcome) => {
                return Ok(Run {
                    outcome,
                    input,
                    notary_key_hash: notary.key_hash,
                    attempts: attempt,
                });
            }
            Err(e) => {
                let failed_at = Instant::now();
                let timed_out = matches!(e, ProverError::Timeout { .. });
                if timed_out {
                    // Let the notary notice the closed connection and log
                    // how its side of the stalled session ended.
                    tokio::time::sleep(NOTARY_GRACE).await;
                }
                // Only the known stall is retried; anything else is a real
                // failure (or the outcome the test expects).
                let retry = timed_out && attempt < attempts;
                let report =
                    logs.report(attempt, attempts, &e, retry, timed_out.then_some(failed_at));
                if !scenario.expect_failures {
                    logs.publish(attempt, &report);
                }
                failures.push(report);
                if !retry {
                    return Err(e);
                }
                attempt += 1;
            }
        }
    }
}

/// Index of the first occurrence of `needle`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
