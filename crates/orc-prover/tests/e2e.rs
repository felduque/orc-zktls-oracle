//! End-to-end: real orc prover + real orc notary (MPC-TLS, attestation,
//! presentation) against a local TLS server, then `orc_core::verify_claim`.
//! Offline: no GitHub token, no network.
//!
//! The honest content-length run is shared by the tests that only change
//! the verifier's inputs; every other scenario runs its own MPC session.

mod harness;

use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use harness::{
    COMMITS, Framing, REPO_DB_ID, Reply, Run, SNAPSHOT, Scenario, VIEWER_DB_ID, VIEWER_ID, find,
    token, token_secret, verify_params,
};
use orc_core::{
    Address, B256, ClaimError, GuestInput, PublicValues, VerifyParams, http, nullifier,
    request::AUTH_VISIBLE_PREFIX, verify_claim,
};
use orc_prover::{Disclosure, ProverError};
use tokio::sync::OnceCell;

static HONEST: OnceCell<Run> = OnceCell::const_new();

async fn honest() -> &'static Run {
    HONEST
        .get_or_init(|| async {
            harness::run(Reply::ok(Framing::ContentLength), Scenario::default())
                .await
                .expect("honest content-length session")
        })
        .await
}

async fn run(reply: Reply, scenario: Scenario) -> Run {
    harness::run(reply, scenario).await.expect("MPC session")
}

fn verify(run: &Run, input: &GuestInput) -> Result<PublicValues, ClaimError> {
    verify_claim(&run.outcome.presentation, input, &verify_params())
}

fn assert_honest_public_values(run: &Run, pv: &PublicValues) {
    assert_eq!(pv.ethAddress, run.input.eth_address);
    assert_eq!(pv.chainId, run.input.chain_id);
    assert_eq!(pv.campaignId, run.input.campaign_id);
    assert_eq!(pv.repoDatabaseId, REPO_DB_ID);
    assert_eq!(pv.threshold, run.input.threshold);
    assert_eq!(pv.snapshot, SNAPSHOT);
    assert_eq!(pv.notaryKeyHash, run.notary_key_hash);
    assert_eq!(pv.nullifier, nullifier(VIEWER_DB_ID, run.input.campaign_id));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    assert!(
        pv.sessionTime.abs_diff(now) < 600,
        "sessionTime {}",
        pv.sessionTime
    );
}

macro_rules! assert_err {
    ($result:expr, $pattern:pat) => {
        match $result {
            Err(e) => assert!(matches!(e, $pattern), "unexpected error: {e}"),
            Ok(pv) => panic!("expected an error, got public values:\n{pv}"),
        }
    };
}

// ---- positive ---------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_content_length_response_verifies() {
    let run = honest().await;
    assert_eq!(run.outcome.http_status, 200);
    assert_eq!(
        run.outcome.response_framing,
        Some(http::Framing::ContentLength)
    );
    let pv = verify(run, &run.input).expect("claim verifies");
    assert_honest_public_values(run, &pv);
    assert_eq!(pv.to_abi_bytes().len(), 288);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn presentation_does_not_contain_the_token() {
    let run = honest().await;
    let p = &run.outcome.presentation;
    assert!(find(p, token().as_bytes()).is_none());
    let secret = token_secret();
    assert!(find(p, secret.as_bytes()).is_none());
    // Not even a 12-byte window of the secret part.
    for window in secret.as_bytes().windows(12) {
        assert!(find(p, window).is_none());
    }
    // The fine-grained prefix is revealed on purpose (the verifier checks it).
    assert!(find(p, AUTH_VISIBLE_PREFIX.as_bytes()).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_response_verifies() {
    let run = run(Reply::ok(Framing::Chunked), Scenario::default()).await;
    assert_eq!(run.outcome.response_framing, Some(http::Framing::Chunked));
    let pv = verify(&run, &run.input).expect("claim verifies");
    assert_honest_public_values(&run, &pv);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_delimited_response_verifies() {
    let run = run(Reply::ok(Framing::CloseDelimited), Scenario::default()).await;
    assert_eq!(
        run.outcome.response_framing,
        Some(http::Framing::CloseDelimited)
    );
    let pv = verify(&run, &run.input).expect("claim verifies");
    assert_honest_public_values(&run, &pv);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn threshold_equal_to_count_verifies() {
    let run = honest().await;
    let input = GuestInput {
        threshold: COMMITS,
        ..run.input.clone()
    };
    let pv = verify(run, &input).expect("count == threshold verifies");
    assert_eq!(pv.threshold, COMMITS);
}

// ---- verifier-input tampering (shared honest presentation) ------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn count_below_threshold_fails() {
    let run = honest().await;
    let input = GuestInput {
        threshold: COMMITS + 1,
        ..run.input.clone()
    };
    assert_err!(
        verify(run, &input),
        ClaimError::BelowThreshold { count: COMMITS, .. }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_binding_fails() {
    let run = honest().await;
    let wrong_address = GuestInput {
        eth_address: Address::repeat_byte(0x33),
        ..run.input.clone()
    };
    assert_err!(verify(run, &wrong_address), ClaimError::BindingMismatch);
    let wrong_chain = GuestInput {
        chain_id: 1,
        ..run.input.clone()
    };
    assert_err!(verify(run, &wrong_chain), ClaimError::BindingMismatch);
    let wrong_campaign = GuestInput {
        campaign_id: B256::repeat_byte(0x44),
        ..run.input.clone()
    };
    assert_err!(verify(run, &wrong_campaign), ClaimError::BindingMismatch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_repo_in_input_fails_body_check() {
    let run = honest().await;
    let other_repo = GuestInput {
        name: "other-repo".into(),
        ..run.input.clone()
    };
    assert_err!(verify(run, &other_repo), ClaimError::BodyMismatch);
    let other_owner = GuestInput {
        owner: "someone-else".into(),
        ..run.input.clone()
    };
    assert_err!(verify(run, &other_owner), ClaimError::BodyMismatch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_presentation_bytes_fail() {
    let run = honest().await;
    let mut bytes = run.outcome.presentation.clone();
    // Flip one revealed byte of the authenticated viewer id.
    let at = find(&bytes, VIEWER_ID.as_bytes()).expect("viewer id is revealed");
    bytes[at + 2] ^= 0x01;
    assert_err!(
        verify_claim(&bytes, &run.input, &verify_params()),
        ClaimError::Presentation(_)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_server_name_fails() {
    let run = honest().await;
    let params =
        VerifyParams::with_root_store("api.github.com", &harness::test_roots()).expect("params");
    assert_err!(
        verify_claim(&run.outcome.presentation, &run.input, &params),
        ClaimError::ServerName { .. }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_roots_reject_the_test_ca() {
    let run = honest().await;
    assert_err!(
        verify_claim(
            &run.outcome.presentation,
            &run.input,
            &VerifyParams::github()
        ),
        ClaimError::Presentation(_)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_snapshot_in_input_fails_body_check() {
    let run = honest().await;
    for snapshot in [SNAPSHOT - 1, SNAPSHOT + 1] {
        let input = GuestInput {
            snapshot,
            ..run.input.clone()
        };
        assert_err!(verify(run, &input), ClaimError::BodyMismatch);
    }
}

// ---- dishonest provers / bad responses (one MPC session each) ---------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_viewer_id_in_variables_fails() {
    let scenario = Scenario {
        viewer_override: Some("U_kgDOsomeoneElse".into()),
        ..Scenario::default()
    };
    let run = run(Reply::ok(Framing::ContentLength), scenario).await;
    assert_err!(verify(&run, &run.input), ClaimError::BodyMismatch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extra_hidden_sent_range_fails() {
    let scenario = Scenario {
        disclosure: Disclosure {
            also_hide_request_headers: vec!["user-agent".into()],
            ..Disclosure::default()
        },
        ..Scenario::default()
    };
    let run = run(Reply::ok(Framing::ContentLength), scenario).await;
    assert_err!(verify(&run, &run.input), ClaimError::SentRedaction);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whole_authorization_value_hidden_fails() {
    // What orc revealed before it required fine-grained tokens: nothing of the
    // value, so the verifier cannot tell what kind of token GitHub received.
    let scenario = Scenario {
        disclosure: Disclosure {
            also_hide_request_headers: vec!["authorization".into()],
            ..Disclosure::default()
        },
        ..Scenario::default()
    };
    let run = run(Reply::ok(Framing::ContentLength), scenario).await;
    assert!(find(&run.outcome.presentation, AUTH_VISIBLE_PREFIX.as_bytes()).is_none());
    assert_err!(verify(&run, &run.input), ClaimError::AuthPrefix);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_created_at_the_snapshot_fails() {
    let created_at = orc_core::time::format_utc(SNAPSHOT).expect("snapshot");
    let reply = Reply::ok_created_at(Framing::ContentLength, &created_at);
    let run = run(reply, Scenario::default()).await;
    assert_err!(
        verify(&run, &run.input),
        ClaimError::AccountTooNew {
            created_at: SNAPSHOT,
            snapshot: SNAPSHOT
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hidden_received_range_fails() {
    // `hide_received` is a list of byte ranges: ONE range (bytes 0..8) is exactly
    // what this test means, not the numbers 0..8 nor a Vec of length 8.
    #[allow(clippy::single_range_in_vec_init)]
    let scenario = Scenario {
        disclosure: Disclosure {
            hide_received: vec![0..8],
            ..Disclosure::default()
        },
        ..Scenario::default()
    };
    let run = run(Reply::ok(Framing::ContentLength), scenario).await;
    assert_err!(verify(&run, &run.input), ClaimError::HiddenReceived(8));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p256_notary_key_fails() {
    let scenario = Scenario {
        p256_notary: true,
        ..Scenario::default()
    };
    let run = run(Reply::ok(Framing::ContentLength), scenario).await;
    assert_err!(verify(&run, &run.input), ClaimError::NotaryKeyAlg(_));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graphql_errors_key_fails() {
    let mut reply = Reply::ok(Framing::ContentLength);
    reply.body = reply.body.replacen(
        "{\"data\"",
        "{\"errors\":[{\"message\":\"partial failure\"}],\"data\"",
        1,
    );
    let run = run(reply, Scenario::default()).await;
    assert_err!(verify(&run, &run.input), ClaimError::ResponseJson(_));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_200_status_fails() {
    let reply = Reply {
        status_line: "HTTP/1.1 401 Unauthorized",
        body:
            r#"{"message":"Bad credentials","documentation_url":"https://docs.github.com/graphql"}"#
                .into(),
        framing: Framing::ContentLength,
    };
    let run = run(reply, Scenario::default()).await;
    assert_eq!(run.outcome.http_status, 401);
    assert_err!(verify(&run, &run.input), ClaimError::Status(401));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_close_delimited_response_fails() {
    let run = run(Reply::ok(Framing::TruncatedClose), Scenario::default()).await;
    assert_eq!(
        run.outcome.response_framing,
        Some(http::Framing::CloseDelimited)
    );
    assert_err!(verify(&run, &run.input), ClaimError::ResponseJson(_));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notary_rejects_oversized_transcript_budget() {
    // Long, so a slow shared runner is never mistaken for a hang; shorter than
    // the harness notary's 120 s session timeout, so a lost rejection trips
    // the prover's own timeout rather than the notary's.
    let phase_timeout = Duration::from_secs(90);
    let scenario = Scenario {
        max_recv_data: Some(2 * orc_notary::DEFAULT_MAX_RECV_DATA),
        attempts: Some(1),
        phase_timeout: Some(phase_timeout),
        expect_failures: true,
        ..Scenario::default()
    };
    let report = harness::run_report(Reply::ok(Framing::ContentLength), scenario).await;
    let elapsed = report.elapsed;
    let Err(err) = report.result else {
        panic!("the notary must refuse a 32 KiB response budget");
    };
    // The rejection reaches the prover; it does not wait for a phase timeout.
    let timed_out = matches!(err, ProverError::Timeout { .. });
    let chain = format!("{:?}", anyhow::Error::from(err));
    assert!(!timed_out && !chain.contains("timed out after"), "{chain}");
    assert!(chain.contains("rejected"), "{chain}");
    // Secondary: far from the deadline (queueing for an MPC slot excluded).
    assert!(
        elapsed < phase_timeout / 2,
        "took {elapsed:?} of a {phase_timeout:?} phase timeout"
    );
}

// ---- simulated MPC setup hang (the harness's diagnostics and retries) ---------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulated_setup_hang_is_diagnosed_and_retried() {
    // Two sessions stall, so the session that succeeds also shows that the
    // notary freed the slots of the abandoned ones: it admits 2 per source
    // address, and every harness connection comes from 127.0.0.1. Later
    // sessions can still hit tlsn's real stall (often, on 4 CPUs), so they
    // get the usual retries on top.
    let stalls = 2;
    let attempts = stalls + harness::default_attempts();
    let scenario = Scenario {
        stall_sessions: stalls,
        attempts: Some(attempts),
        phase_timeout: Some(Duration::from_secs(8)),
        expect_failures: true,
        ..Scenario::default()
    };
    let report = harness::run_report(Reply::ok(Framing::ContentLength), scenario).await;
    // Shown with `--nocapture` or if the test fails.
    for diagnostics in &report.failures {
        eprintln!("{diagnostics}");
    }
    let run = report
        .result
        .expect("a session after the stalled ones succeeds");
    assert!(run.attempts > stalls, "{} attempts", run.attempts);
    assert_eq!(report.failures.len(), run.attempts as usize - 1);
    for (i, diagnostics) in report.failures.iter().take(stalls as usize).enumerate() {
        assert_stall_diagnostics(diagnostics, i + 1, attempts as usize);
    }
    let pv = verify(&run, &run.input).expect("claim verifies");
    assert_honest_public_values(&run, &pv);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulated_setup_hang_fails_after_the_last_attempt() {
    let scenario = Scenario {
        stall_sessions: u32::MAX,
        attempts: Some(2),
        phase_timeout: Some(Duration::from_secs(2)),
        expect_failures: true,
        ..Scenario::default()
    };
    let report = harness::run_report(Reply::ok(Framing::ContentLength), scenario).await;
    for diagnostics in &report.failures {
        eprintln!("{diagnostics}");
    }
    let Err(err) = report.result else {
        panic!("every session stalls");
    };
    assert!(
        matches!(
            err,
            ProverError::Timeout {
                phase: "MPC setup",
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(report.failures.len(), 2);
    for (i, diagnostics) in report.failures.iter().enumerate() {
        assert_stall_diagnostics(diagnostics, i + 1, 2);
    }
}

/// The diagnostics of a stalled attempt name it and show where each side
/// waits: the prover in tlsn's `commit` (MPC setup), the notary in `accept`
/// (MPC preprocessing) of a session it admitted, both until the timeout.
fn assert_stall_diagnostics(diagnostics: &str, attempt: usize, attempts: usize) {
    let header = format!("attempt {attempt}/{attempts} failed: MPC setup timed out after");
    assert!(diagnostics.contains(&header), "{diagnostics}");
    let prover = section(diagnostics, "---- prover");
    assert!(prover.contains("prover:commit"), "{diagnostics}");
    let notary = section(diagnostics, "---- notary");
    assert!(
        notary.contains("orc_notary: session started"),
        "{diagnostics}"
    );
    assert!(notary.contains("verifier:accept"), "{diagnostics}");
    section(diagnostics, "---- other threads");
    let idle = section(diagnostics, "---- spans that sat idle");
    for span in [
        "prover:commit: tlsn::prover: close",
        "verifier:accept: tlsn::verifier: close",
    ] {
        assert!(idle.contains(span), "{span}:\n{diagnostics}");
    }
}

/// The lines of one section of a diagnostics report.
fn section<'a>(diagnostics: &'a str, header: &str) -> &'a str {
    let start = diagnostics
        .find(header)
        .unwrap_or_else(|| panic!("no {header:?} section:\n{diagnostics}"));
    let rest = &diagnostics[start + header.len()..];
    &rest[..rest.find("\n----").unwrap_or(rest.len())]
}

// ---- fixtures for the SP1 guest (M2) ------------------------------------------

/// Writes harness presentations and guest inputs to `fixtures/test-ca/` for
/// the test-ca SP1 guest (`orc-script execute --test-ca`):
///
/// - `content-length`, `chunked`, `close-delimited`: `<name>.bin` +
///   `<name>.input.json`, each verified natively before it is written.
/// - `neg-wrong-binding`, `neg-below-threshold`: `<name>.input.json` only;
///   pair them with `content-length.bin`. Each is checked to fail natively
///   with the expected error.
/// - `neg-auth-hidden` (the whole authorization value hidden: M1) and
///   `neg-account-too-new` (`viewer.createdAt` == snapshot: H1):
///   `<name>.bin` + `<name>.input.json`, each checked to fail natively.
///
/// Ignored because it rewrites checked-in files (and `sessionTime` changes):
/// `cargo test -p orc-prover --test e2e -- --ignored dump_test_ca_fixtures`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "rewrites fixtures/test-ca/; run explicitly"]
async fn dump_test_ca_fixtures() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/test-ca");
    std::fs::create_dir_all(&dir).expect("create fixtures/test-ca");
    let write_input = |name: &str, input: &GuestInput| {
        let json = serde_json::to_string_pretty(input).expect("input json") + "\n";
        std::fs::write(dir.join(format!("{name}.input.json")), json).expect("write input");
    };
    let write_presentation = |name: &str, run: &Run| {
        assert!(find(&run.outcome.presentation, token_secret().as_bytes()).is_none());
        std::fs::write(dir.join(format!("{name}.bin")), &run.outcome.presentation)
            .expect("write presentation");
        write_input(name, &run.input);
    };
    let write_run = |name: &str, run: &Run| {
        let pv = verify(run, &run.input).expect("positive fixture verifies natively");
        assert_honest_public_values(run, &pv);
        write_presentation(name, run);
    };

    let content_length = honest().await;
    write_run("content-length", content_length);
    let chunked = run(Reply::ok(Framing::Chunked), Scenario::default()).await;
    assert_eq!(
        chunked.outcome.response_framing,
        Some(http::Framing::Chunked)
    );
    write_run("chunked", &chunked);
    let close = run(Reply::ok(Framing::CloseDelimited), Scenario::default()).await;
    assert_eq!(
        close.outcome.response_framing,
        Some(http::Framing::CloseDelimited)
    );
    write_run("close-delimited", &close);

    let wrong_binding = GuestInput {
        eth_address: Address::repeat_byte(0x33),
        ..content_length.input.clone()
    };
    assert_err!(
        verify(content_length, &wrong_binding),
        ClaimError::BindingMismatch
    );
    write_input("neg-wrong-binding", &wrong_binding);

    let below_threshold = GuestInput {
        threshold: COMMITS + 1,
        ..content_length.input.clone()
    };
    assert_err!(
        verify(content_length, &below_threshold),
        ClaimError::BelowThreshold { count: COMMITS, .. }
    );
    write_input("neg-below-threshold", &below_threshold);

    let auth_hidden = run(
        Reply::ok(Framing::ContentLength),
        Scenario {
            disclosure: Disclosure {
                also_hide_request_headers: vec!["authorization".into()],
                ..Disclosure::default()
            },
            ..Scenario::default()
        },
    )
    .await;
    assert_err!(
        verify(&auth_hidden, &auth_hidden.input),
        ClaimError::AuthPrefix
    );
    write_presentation("neg-auth-hidden", &auth_hidden);

    let created_at = orc_core::time::format_utc(SNAPSHOT).expect("snapshot");
    let too_new = run(
        Reply::ok_created_at(Framing::ContentLength, &created_at),
        Scenario::default(),
    )
    .await;
    assert_err!(
        verify(&too_new, &too_new.input),
        ClaimError::AccountTooNew { .. }
    );
    write_presentation("neg-account-too-new", &too_new);
}
