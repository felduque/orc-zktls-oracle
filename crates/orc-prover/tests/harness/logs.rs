//! Per-session tracing capture, printed only when an MPC phase times out.
//!
//! tlsn alpha.15 sometimes stalls in MPC setup with idle CPU (README, "Known
//! issues"). To show WHERE it stalled, every harness session records the
//! prover's and the notary's tracing output (orc, tlsn, mpc-tls and its
//! components, mpz, and the tlsn-mux multiplexer, which logs through the
//! `log` crate) into bounded in-memory buffers. Nothing is printed unless an
//! attempt fails; then [`SessionLogs::report`] has the tail of each and, for
//! a timeout, the spans that sat idle until the timeout closed them: where
//! each side was waiting.
//!
//! Attribution: the prover's futures run under one scoped dispatcher and the
//! notary's under another (orc's spawned tasks inherit theirs). tlsn runs
//! MPC sub-protocols on its own executor threads (`mpz-executor-worker`),
//! which inherit no dispatcher: their events go to one process-wide buffer
//! ("other threads"), shared by every session running at that moment. With
//! `ORC_TEST_MPC_SLOTS=1` (as in CI) that is exactly one prover and one notary.

use std::{
    collections::VecDeque,
    fmt::Write as _,
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, Mutex, Once, OnceLock, PoisonError},
    time::{Duration, Instant},
};

use tracing::Dispatch;
use tracing_subscriber::{
    EnvFilter,
    fmt::{MakeWriter, format::FmtSpan},
};

/// Tracing directives (`EnvFilter` syntax) replacing [`DEFAULT_FILTER`].
pub const LOG_FILTER_ENV: &str = "ORC_TEST_LOG";
/// If set, the full logs of every failed attempt are also written to files
/// in this directory (CI uploads it as an artifact).
pub const LOG_DIR_ENV: &str = "ORC_TEST_LOG_DIR";
/// orc, tlsn (also matches tlsn_core, tlsn_deap and tlsn_mux), mpc-tls and
/// its components, mpz (every mpz_* crate), serio. Directive targets match by
/// prefix. tlsn-mux's frame codec traces every read/write state change; its
/// connection layer already traces each frame sent and received.
const DEFAULT_FILTER: &str = "orc_prover=trace,orc_notary=trace,tlsn=trace,tlsn_mux::frame=debug,\
                              mpc_tls=trace,hmac_sha256=trace,key_exchange=trace,mpz=trace,\
                              serio=trace";
/// Lines kept per buffer (oldest dropped first).
const CAPACITY: usize = 50_000;
/// Lines of each log printed for a failed attempt.
pub const TAIL: usize = 200;
/// Lines logged in the last second before a timeout is reported are the
/// reaction to it (spans closing, the session being torn down), not the
/// stall: a stalled session logs nothing for the whole phase timeout.
const TIMEOUT_REACTION: Duration = Duration::from_secs(1);

/// A bounded, shared buffer of formatted log lines.
#[derive(Clone, Default)]
pub struct LogBuffer(Arc<Mutex<Lines>>);

#[derive(Default)]
struct Lines {
    lines: VecDeque<(Instant, String)>,
    /// Lines dropped to stay within [`CAPACITY`].
    dropped: usize,
}

impl LogBuffer {
    fn lock(&self) -> std::sync::MutexGuard<'_, Lines> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, line: String) {
        let mut inner = self.lock();
        if inner.lines.len() == CAPACITY {
            inner.lines.pop_front();
            inner.dropped += 1;
        }
        inner.lines.push_back((Instant::now(), line));
    }

    /// Lines recorded in `from..=to` (unbounded where `None`), oldest first,
    /// plus how many lines the buffer ever dropped.
    fn range(&self, from: Option<Instant>, to: Option<Instant>) -> (Vec<String>, usize) {
        let inner = self.lock();
        let lines = inner
            .lines
            .iter()
            .filter(|(at, _)| from.is_none_or(|from| *at >= from))
            .filter(|(at, _)| to.is_none_or(|to| *at <= to))
            .map(|(_, line)| line.clone())
            .collect();
        (lines, inner.dropped)
    }
}

impl Write for LogBuffer {
    /// `tracing_subscriber::fmt` writes each formatted event in one call.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for line in String::from_utf8_lossy(buf).lines() {
            if !line.is_empty() {
                self.push(line.to_owned());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LogBuffer;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A tracing dispatcher that formats everything [`filter`] enables into `buffer`.
fn dispatch(buffer: LogBuffer) -> Dispatch {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(buffer)
        .with_ansi(false)
        // Ids, not names: fmt pads names to the longest seen, and libtest
        // names threads after (long) test names.
        .with_thread_ids(true)
        // Span creation and close, so a stall shows which span never closed.
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .finish();
    Dispatch::new(subscriber)
}

fn filter() -> EnvFilter {
    match std::env::var(LOG_FILTER_ENV) {
        Ok(directives) => EnvFilter::try_new(&directives)
            .unwrap_or_else(|e| panic!("{LOG_FILTER_ENV}={directives:?}: {e}")),
        Err(_) => EnvFilter::new(DEFAULT_FILTER),
    }
}

/// Events from threads that run under no session's dispatcher.
fn other_threads() -> &'static LogBuffer {
    static OTHER: OnceLock<LogBuffer> = OnceLock::new();
    OTHER.get_or_init(LogBuffer::default)
}

/// Once per process: `log` records (tlsn-mux) become tracing events, and
/// events outside any session go to [`other_threads`].
fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Fails only if another logger is installed; then mux lines are missing.
        let _ = tracing_log::LogTracer::builder()
            .with_max_level(tracing_log::log::LevelFilter::Trace)
            .init();
        let _ = tracing::dispatcher::set_global_default(dispatch(other_threads().clone()));
    });
}

/// The prover's and the notary's logs for one harness session (all attempts).
pub struct SessionLogs {
    test: String,
    prover: LogBuffer,
    notary: LogBuffer,
    attempt_started: Instant,
}

impl SessionLogs {
    pub fn new(test: &str) -> Self {
        init();
        Self {
            test: test.to_owned(),
            prover: LogBuffer::default(),
            notary: LogBuffer::default(),
            attempt_started: Instant::now(),
        }
    }

    /// Dispatcher for the prover side (`prove()` and its spawned tasks).
    pub fn prover_dispatch(&self) -> Dispatch {
        dispatch(self.prover.clone())
    }

    /// Dispatcher for the notary side (`serve()` and its session tasks).
    pub fn notary_dispatch(&self) -> Dispatch {
        dispatch(self.notary.clone())
    }

    /// Marks the start of an attempt in both logs.
    pub fn attempt_started(&mut self, attempt: u32, attempts: u32) {
        self.attempt_started = Instant::now();
        let mark = format!(
            "======== {}: attempt {attempt}/{attempts} ========",
            self.test
        );
        self.prover.push(mark.clone());
        self.notary.push(mark);
    }

    /// The log tails for a failed attempt. For a phase timeout that fired
    /// at `timed_out_at`, the tails end before the reaction to it, followed by
    /// the spans that idled until the timeout closed them.
    pub fn report(
        &self,
        attempt: u32,
        attempts: u32,
        error: &dyn std::fmt::Display,
        retry: bool,
        timed_out_at: Option<Instant>,
    ) -> String {
        let now = Instant::now();
        let cut = timed_out_at.map_or(now, |at| at.checked_sub(TIMEOUT_REACTION).unwrap_or(at));
        let next = if retry {
            "retrying with a fresh notary session"
        } else if attempt == attempts {
            "no attempts left"
        } else {
            "not retried: only a phase timeout is"
        };
        let mut out = format!(
            "\n==== orc e2e diagnostics: {}: attempt {attempt}/{attempts} failed: {error} \
             ({next}) ====\n",
            self.test
        );
        let sections = [
            (
                "prover (orc prove, tlsn Prover, mux driver)",
                &self.prover,
                None,
            ),
            (
                "notary (orc-notary serve, tlsn Verifier, mux driver)",
                &self.notary,
                None,
            ),
            (
                "other threads since this attempt began (tlsn's MPC executor workers of \
                 every session running at the time; the mux connection id in each side's \
                 `new connection: <id>` line tells them apart)",
                other_threads(),
                Some(self.attempt_started),
            ),
        ];
        let mut idled = Vec::new();
        for (name, buffer, since) in sections {
            let (lines, dropped) = buffer.range(since, Some(cut));
            let shown = lines.len().min(TAIL);
            let _ = writeln!(
                out,
                "---- {name}: last {shown} of {} lines{}{} ----",
                lines.len(),
                if timed_out_at.is_some() {
                    " before the timeout"
                } else {
                    ""
                },
                if dropped > 0 { " (oldest dropped)" } else { "" }
            );
            for line in &lines[lines.len() - shown..] {
                out.push_str(line);
                out.push('\n');
            }
            let (later, _) = buffer.range(Some(cut), Some(now));
            if timed_out_at.is_some() && !later.is_empty() {
                let _ = writeln!(
                    out,
                    "(+{} lines after: the timeout and teardown)",
                    later.len()
                );
                let side = name.split_whitespace().next().unwrap_or(name);
                idled.extend(
                    later
                        .iter()
                        .filter(|line| idled_a_second(line))
                        .map(|line| format!("{side} | {line}")),
                );
            }
        }
        if timed_out_at.is_some() {
            let _ = writeln!(
                out,
                "---- spans that sat idle (>= 1 s) until the timeout closed them: where each \
                 side was waiting ----"
            );
            for line in &idled {
                out.push_str(line);
                out.push('\n');
            }
        }
        let _ = writeln!(
            out,
            "==== end of orc e2e diagnostics: {}: attempt {attempt}/{attempts} ====",
            self.test
        );
        out
    }

    /// Prints `report` on the real stderr and, with [`LOG_DIR_ENV`] set,
    /// writes the attempt's full logs to files.
    ///
    /// `std::io::stderr()` is not captured by the test harness (only the
    /// `eprint!` family is), so the report shows in CI even when a retry
    /// then passes the test.
    pub fn publish(&self, attempt: u32, report: &str) {
        let _ = io::stderr().lock().write_all(report.as_bytes());
        let Ok(dir) = std::env::var(LOG_DIR_ENV) else {
            return;
        };
        let dir = PathBuf::from(dir);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            let _ = writeln!(io::stderr(), "{LOG_DIR_ENV}: {}: {e}", dir.display());
            return;
        }
        let name: String = self
            .test
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let files = [
            ("prover", &self.prover, None),
            ("notary", &self.notary, None),
            ("other-threads", other_threads(), Some(self.attempt_started)),
        ];
        for (side, buffer, since) in files {
            let path = dir.join(format!("{name}.attempt{attempt}.{side}.log"));
            let (lines, _) = buffer.range(since, None);
            if let Err(e) = std::fs::write(&path, lines.join("\n") + "\n") {
                let _ = writeln!(io::stderr(), "{}: {e}", path.display());
            }
        }
    }
}

/// Whether `line` is a span close (`FmtSpan::CLOSE`) after at least a second
/// of idle time: `time.idle=45.0s`, not `577ms`, `7.00µs` or `0.00ns`.
fn idled_a_second(line: &str) -> bool {
    line.rsplit_once(" time.idle=")
        .and_then(|(_, idle)| idle.trim().strip_suffix('s'))
        .and_then(|secs| secs.parse::<f64>().ok())
        .is_some_and(|secs| secs >= 1.0)
}
