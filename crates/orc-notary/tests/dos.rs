//! Denial-of-service limits of the notary's admission path, without running
//! MPC: idle and slow connections lose their slot at the setup deadline, one
//! source cannot take more than its share of slots, and absurd record counts
//! are rejected before anything is allocated.
//!
//! Probes speak the real tlsn protocol up to the config check and always
//! propose a config the notary must reject, so nothing here starts MPC.
//! Deadlines are short and configurable; no test asserts on absolute times
//! (the `GUARD` timeouts only turn a hang into a failure).

use std::{
    error::Error as _,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use orc_notary::{
    DEFAULT_MAX_RECV_DATA, DEFAULT_MAX_SENT_DATA, NotaryConfig, NotaryError, NotaryKey,
    max_records, notarize, serve,
};
use tlsn::{
    Session,
    config::{prover::ProverConfig, tls_commit::mpc::MpcTlsConfig},
    webpki::RootCertStore,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinHandle,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// Upper bound for anything that should happen "promptly"; only hit on a bug.
const GUARD: Duration = Duration::from_secs(5);
const SOURCE_A: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const SOURCE_B: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

fn notary_config(setup: Duration, sessions: usize, per_ip: usize) -> NotaryConfig {
    let mut config = NotaryConfig::new(NotaryKey::secp256k1([7u8; 32]).expect("key"));
    config.root_store = RootCertStore { roots: Vec::new() };
    config.setup_timeout = setup;
    // Long, so only the setup deadline (or a disconnect) can free a slot here.
    config.session_timeout = Duration::from_secs(120);
    config.max_concurrent_sessions = sessions;
    config.max_sessions_per_ip = per_ip;
    config
}

struct Notary {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Notary {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_notary(config: NotaryConfig) -> Notary {
    let listener = TcpListener::bind((SOURCE_A, 0)).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        serve(listener, Arc::new(config)).await.expect("serve");
    });
    Notary { addr, task }
}

async fn connect_from(source: IpAddr, addr: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::new(source, 0))?;
    socket.connect(addr).await
}

/// A config with byte budgets the notary accepts and a record count it must
/// reject (one above the bound for the default 4 KiB request budget).
fn oversized_records() -> MpcTlsConfig {
    MpcTlsConfig::builder()
        .max_sent_data(DEFAULT_MAX_SENT_DATA)
        .max_recv_data(DEFAULT_MAX_RECV_DATA)
        .max_sent_records(max_records(DEFAULT_MAX_SENT_DATA) + 1)
        .build()
        .expect("config")
}

/// Proposes `mpc` as a tlsn prover and returns the notary's rejection reason.
/// `Err` if the connection ended without a verdict (e.g. it was refused).
/// Never returns for an accepted config (the prover would start MPC), so
/// callers only send configs the notary must reject.
async fn propose<S>(io: S, mpc: MpcTlsConfig) -> Result<String, String>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let session = Session::new(io.compat());
    let (driver, mut handle) = session.split();
    let mut driver = tokio::spawn(driver);
    let prover = handle
        .new_prover(ProverConfig::builder().build().expect("prover config"))
        .expect("new prover");
    // tlsn may not wake a pending read when the connection closes: race it.
    let verdict = tokio::select! {
        biased;
        result = prover.commit(mpc) => match result {
            Ok(_) => panic!("the notary accepted a config it must reject"),
            Err(e) if e.is_user() => Ok(error_chain(&e)),
            Err(e) => Err(error_chain(&e)),
        },
        _ = &mut driver => Err("connection closed without a verdict".to_string()),
    };
    driver.abort();
    verdict
}

/// Retries [`propose`] from `source` until the notary admits the connection
/// (slots are released asynchronously after the notary closes a socket).
async fn propose_until_admitted(source: IpAddr, addr: SocketAddr, mpc: MpcTlsConfig) -> String {
    tokio::time::timeout(GUARD, async {
        loop {
            let stream = connect_from(source, addr).await.expect("connect");
            match propose(stream, mpc.clone()).await {
                Ok(reason) => return reason,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .expect("the notary never admitted the prover")
}

fn error_chain(e: &tlsn::Error) -> String {
    let mut chain = e.to_string();
    let mut source = e.source();
    while let Some(e) = source {
        chain = format!("{chain}: {e}");
        source = e.source();
    }
    chain
}

/// Whether the notary closes `stream` within [`GUARD`] (bytes it sends
/// first, e.g. mux keep-alives, are skipped).
async fn closed_by_notary(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 256];
    tokio::time::timeout(GUARD, async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await
    .is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_connection_times_out_in_setup() {
    let config = notary_config(Duration::from_millis(200), 4, 2);
    // Keep the peer end open and silent.
    let (notary_io, _idle_prover) = duplex(4096);
    let result = tokio::time::timeout(GUARD, notarize(notary_io, &config))
        .await
        .expect("the setup deadline must end the session");
    assert!(
        matches!(
            result,
            Err(NotaryError::Timeout {
                stage: "receive protocol config",
                ..
            })
        ),
        "{result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_config_times_out_in_setup() {
    // A real prover whose bytes reach the notary one every 20 ms: the config
    // starts arriving at once but cannot be complete before the deadline.
    let config = notary_config(Duration::from_millis(300), 4, 2);
    let (notary_io, relay_notary) = duplex(4096);
    let (prover_io, relay_prover) = duplex(4096);
    let forwarded = Arc::new(AtomicUsize::new(0));

    let (mut from_prover, mut to_prover) = tokio::io::split(relay_prover);
    let (mut from_notary, mut to_notary) = tokio::io::split(relay_notary);
    let counter = forwarded.clone();
    let trickle = tokio::spawn(async move {
        let mut byte = [0u8; 1];
        while let Ok(1) = from_prover.read(&mut byte).await {
            if to_notary.write_all(&byte).await.is_err() {
                break;
            }
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    let back = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut from_notary, &mut to_prover).await;
    });
    let prover = tokio::spawn(propose(prover_io, oversized_records()));

    let result = tokio::time::timeout(GUARD, notarize(notary_io, &config))
        .await
        .expect("the setup deadline must end the session");
    let arrived = forwarded.load(Ordering::SeqCst);
    prover.abort();
    trickle.abort();
    back.abort();

    // A Limit error here would mean the config was parsed after the deadline.
    assert!(
        matches!(
            result,
            Err(NotaryError::Timeout {
                stage: "receive protocol config",
                ..
            })
        ),
        "{result:?}"
    );
    assert!(arrived > 0, "no config bytes reached the notary");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_connections_free_their_slots_at_the_setup_deadline() {
    // Two idle connections take both slots. The session timeout is 120 s, so
    // only the setup deadline can free them within GUARD.
    let notary = spawn_notary(notary_config(Duration::from_millis(300), 2, 2)).await;
    let mut idle = [
        TcpStream::connect(notary.addr).await.expect("connect"),
        TcpStream::connect(notary.addr).await.expect("connect"),
    ];
    for stream in &mut idle {
        assert!(closed_by_notary(stream).await, "idle connection kept open");
    }

    // A prover connecting afterwards is admitted and gets a verdict.
    let reason = propose_until_admitted(SOURCE_A, notary.addr, oversized_records()).await;
    assert!(reason.contains("max_sent_records"), "{reason}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_ip_cap_refuses_the_extra_connection() {
    // Long setup deadline: an admitted connection stays open for the whole
    // test, so a prompt close can only be a refusal.
    let notary = spawn_notary(notary_config(Duration::from_secs(60), 4, 2)).await;
    let first = connect_from(SOURCE_A, notary.addr).await.expect("connect");
    let _second = connect_from(SOURCE_A, notary.addr).await.expect("connect");
    let mut third = connect_from(SOURCE_A, notary.addr).await.expect("connect");
    assert!(
        closed_by_notary(&mut third).await,
        "3rd concurrent connection from one IP was admitted"
    );

    // Another source still gets served (2 of 4 global slots are taken).
    match connect_from(SOURCE_B, notary.addr).await {
        Ok(stream) => {
            let reason = tokio::time::timeout(GUARD, propose(stream, oversized_records()))
                .await
                .expect("verdict")
                .expect("other source refused");
            assert!(reason.contains("max_sent_records"), "{reason}");
        }
        // 127.0.0.2 is loopback on Linux, not on every OS.
        Err(e) => eprintln!("skipping the second-source check: {e}"),
    }

    // Closing a connection frees its slot without waiting for the deadline.
    drop(first);
    let reason = propose_until_admitted(SOURCE_A, notary.addr, oversized_records()).await;
    assert!(reason.contains("max_sent_records"), "{reason}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_record_counts_are_rejected_before_mpc() {
    // Sequential probes from one IP; the per-IP cap is not under test here.
    let notary = spawn_notary(notary_config(Duration::from_secs(10), 4, 4)).await;
    let budget = || {
        MpcTlsConfig::builder()
            .max_sent_data(DEFAULT_MAX_SENT_DATA)
            .max_recv_data(DEFAULT_MAX_RECV_DATA)
    };
    let cases = [
        ("max_sent_records", oversized_records()),
        (
            "max_recv_records_online",
            budget()
                .max_recv_records_online(max_records(DEFAULT_MAX_RECV_DATA) + 1)
                .build()
                .expect("config"),
        ),
        (
            "max_sent_records",
            budget().max_sent_records(100_000).build().expect("config"),
        ),
    ];
    for (field, mpc) in cases {
        let stream = TcpStream::connect(notary.addr).await.expect("connect");
        let reason = tokio::time::timeout(GUARD, propose(stream, mpc))
            .await
            .expect("the rejection must arrive promptly")
            .expect("connection closed without a verdict");
        assert!(reason.contains("rejected"), "{reason}");
        assert!(reason.contains(field), "{reason}");
    }
}
