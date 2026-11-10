//! [`verify_claim`]: every check the SP1 guest performs, in order.
//!
//! 0. The snapshot is representable as `YYYY-MM-DDTHH:MM:SSZ`.
//! 1. Decode the bincode `Presentation` (size-limited, no trailing bytes).
//! 2. Notary key is k256, 33-byte compressed; `notaryKeyHash = keccak256(key)`.
//! 3. Full `Presentation::verify` (notary signature, Merkle openings, server
//!    certificate chain + TLS signature, transcript hash openings); signature
//!    alg is secp256k1, commitment root is SHA-256, server name matches.
//! 4. Redaction: all received bytes are revealed. The (single) `authorization`
//!    value starts with the revealed `bearer github_pat_`, and the only hidden
//!    sent bytes are exactly the 82 token bytes after it: GitHub received a
//!    fine-grained PAT, and the hidden range is too short to carry a smuggled
//!    alternative query (see [`check_transcript`]).
//! 5. Exactly one request and one response.
//! 6. Request: `POST /graphql HTTP/1.1`, exactly the orc header set with the
//!    expected values, `x-orc-binding` derived from the input.
//! 7. Response: status 200, body parses strictly as the expected GraphQL data.
//! 8. Request body is byte-identical to
//!    `graphql_body(owner, name, viewer.id, snapshot)`, so the commit count is
//!    the authenticated viewer's, counted up to the snapshot.
//! 9. `viewer.createdAt` (strict `YYYY-MM-DDTHH:MM:SSZ`) is before the snapshot.
//! 10. `totalCount >= threshold`.
//!
//! [`verify_claim_tracked`] reports these steps as phases to a [`Tracker`]
//! (the SP1 guest turns them into cycle-tracker markers); [`verify_claim`]
//! is the same function with a no-op tracker.

use alloy_primitives::B256;
use bincode::Options;
use tlsn_attestation::{
    CryptoProvider,
    presentation::{Presentation, PresentationOutput},
    signing::{KeyAlgId, SignatureAlgId},
};
use tlsn_core::{
    hash::HashAlgId,
    transcript::PartialTranscript,
    webpki::{RootCertStore, ServerCertVerifier},
};

use crate::{
    abi::{PublicValues, binding_header_value, notary_key_hash, nullifier},
    error::ClaimError,
    graphql::{self, ClaimData, graphql_body},
    http::{self, HttpRequest, HttpResponse},
    input::GuestInput,
    request::{self, AUTH_VISIBLE_PREFIX, FINE_GRAINED_PAT_SECRET_LEN, header},
    time,
};

/// Production server name.
pub const GITHUB_API_HOST: &str = "api.github.com";

/// Upper bound on a serialized presentation (a 16 KiB transcript plus the
/// certificate chain is ~30 KiB).
pub const MAX_PRESENTATION_BYTES: u64 = 256 * 1024;

/// What the verifier trusts: the server name and the root certificates
/// (inside `provider`).
#[derive(Debug)]
pub struct VerifyParams {
    /// Required authenticated server name (and `Host` header value).
    pub expected_server: String,
    /// Crypto provider; its certificate verifier holds the trusted roots.
    pub provider: CryptoProvider,
}

impl VerifyParams {
    /// Production parameters: `api.github.com` with the Mozilla root store.
    pub fn github() -> Self {
        Self {
            expected_server: GITHUB_API_HOST.to_owned(),
            provider: CryptoProvider::default(),
        }
    }

    /// Parameters for another server name and root store (local test CA).
    pub fn with_root_store(
        expected_server: impl Into<String>,
        roots: &RootCertStore,
    ) -> Result<Self, ClaimError> {
        let cert = ServerCertVerifier::new(roots).map_err(|e| ClaimError::Params(e.to_string()))?;
        Ok(Self {
            expected_server: expected_server.into(),
            provider: CryptoProvider {
                cert,
                ..CryptoProvider::default()
            },
        })
    }
}

/// Phase labels reported by [`verify_claim_tracked`], in order.
pub mod phase {
    /// Step 1: bounded bincode decode of the presentation.
    pub const DESERIALIZE: &str = "deserialize";
    /// Steps 2-3: notary key checks and the full `Presentation::verify`
    /// (attestation signature, server certificate chain, transcript openings).
    pub const VERIFY: &str = "verify";
    /// Steps 4-6: redaction rule, HTTP request/response parsing, request shape.
    pub const HTTP: &str = "http";
    /// Steps 7-10: strict GraphQL JSON parse, body/account-age/threshold
    /// checks, nullifier.
    pub const JSON: &str = "json";
}

/// Receives phase boundaries from [`verify_claim_tracked`]. Every `start`
/// is matched by an `end` with the same label unless the phase fails.
pub trait Tracker {
    fn start(&mut self, label: &'static str);
    fn end(&mut self, label: &'static str);
}

/// A [`Tracker`] that does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoTracker;

impl Tracker for NoTracker {
    fn start(&mut self, _label: &'static str) {}
    fn end(&mut self, _label: &'static str) {}
}

/// Verifies a bincode-encoded TLSNotary presentation against the claim in
/// `input` and returns the values to commit on-chain.
///
/// The notary key itself is not pinned here: it is committed as
/// `notaryKeyHash` and checked by the contract.
pub fn verify_claim(
    presentation: &[u8],
    input: &GuestInput,
    params: &VerifyParams,
) -> Result<PublicValues, ClaimError> {
    verify_claim_tracked(presentation, input, params, &mut NoTracker)
}

/// [`verify_claim`], reporting the [`phase`]s to `tracker`.
pub fn verify_claim_tracked(
    presentation: &[u8],
    input: &GuestInput,
    params: &VerifyParams,
    tracker: &mut impl Tracker,
) -> Result<PublicValues, ClaimError> {
    // The snapshot as the request's `until` variable (cheap, so first).
    let until =
        time::format_utc(input.snapshot).ok_or(ClaimError::SnapshotOutOfRange(input.snapshot))?;

    let session = verify_session(presentation, params, tracker)?;

    tracker.start(phase::HTTP);
    let exchange = check_transcript(session.transcript)?;
    check_request(&exchange.request, input, params)?;
    tracker.end(phase::HTTP);

    tracker.start(phase::JSON);
    let data = check_response(&exchange.response)?;

    // The query variable `$a` must be the authenticated viewer, otherwise the
    // count could be someone else's commits; `$u` must be the snapshot.
    let expected_body = graphql_body(&input.owner, &input.name, &data.viewer.id, &until);
    if exchange.request.body != expected_body.as_bytes() {
        return Err(ClaimError::BodyMismatch);
    }

    check_account_age(&data.viewer.created_at, input.snapshot)?;

    let count = data
        .repository
        .default_branch_ref
        .target
        .history
        .total_count;
    if count < input.threshold {
        return Err(ClaimError::BelowThreshold {
            count,
            threshold: input.threshold,
        });
    }

    let public_values = PublicValues {
        ethAddress: input.eth_address,
        chainId: input.chain_id,
        campaignId: input.campaign_id,
        repoDatabaseId: data.repository.database_id,
        threshold: input.threshold,
        snapshot: input.snapshot,
        notaryKeyHash: session.notary_key_hash,
        sessionTime: session.session_time,
        nullifier: nullifier(data.viewer.database_id, input.campaign_id),
    };
    tracker.end(phase::JSON);
    Ok(public_values)
}

/// Output of steps 1-3.
struct VerifiedSession {
    notary_key_hash: B256,
    session_time: u64,
    transcript: PartialTranscript,
}

/// The parsed HTTP exchange (steps 4-5).
#[derive(Debug)]
struct Exchange {
    request: HttpRequest,
    response: HttpResponse,
}

fn decode_presentation(bytes: &[u8]) -> Result<Presentation, ClaimError> {
    if bytes.len() as u64 > MAX_PRESENTATION_BYTES {
        return Err(ClaimError::Decode(format!(
            "{} bytes exceeds the {MAX_PRESENTATION_BYTES}-byte limit",
            bytes.len()
        )));
    }
    // Same wire format as `bincode::serialize` (fixint, little endian), but
    // bounded and without trailing bytes.
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_PRESENTATION_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| ClaimError::Decode(e.to_string()))
}

fn verify_session(
    bytes: &[u8],
    params: &VerifyParams,
    tracker: &mut impl Tracker,
) -> Result<VerifiedSession, ClaimError> {
    tracker.start(phase::DESERIALIZE);
    let presentation = decode_presentation(bytes)?;
    tracker.end(phase::DESERIALIZE);

    tracker.start(phase::VERIFY);

    let key = presentation.verifying_key();
    if key.alg != KeyAlgId::K256 {
        return Err(ClaimError::NotaryKeyAlg(key.alg.to_string()));
    }
    if key.data.len() != 33 || !matches!(key.data.first(), Some(0x02 | 0x03)) {
        return Err(ClaimError::NotaryKeyEncoding);
    }
    let notary_key_hash = notary_key_hash(&key.data);

    let PresentationOutput {
        attestation,
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation.verify(&params.provider)?;

    if attestation.signature.alg != SignatureAlgId::SECP256K1 {
        return Err(ClaimError::SignatureAlg(format!(
            "{:?}",
            attestation.signature.alg
        )));
    }
    if attestation.header.root.alg != HashAlgId::SHA256 {
        return Err(ClaimError::HashAlg(format!(
            "{:?}",
            attestation.header.root.alg
        )));
    }

    let server_name = server_name
        .ok_or(ClaimError::MissingServerName)?
        .to_string();
    if !server_name.eq_ignore_ascii_case(&params.expected_server) {
        return Err(ClaimError::ServerName {
            expected: params.expected_server.clone(),
            actual: server_name,
        });
    }

    let session = VerifiedSession {
        notary_key_hash,
        session_time: connection_info.time,
        transcript: transcript.ok_or(ClaimError::MissingTranscript)?,
    };
    tracker.end(phase::VERIFY);
    Ok(session)
}

/// Steps 4-5: the redaction rule (M1), then one request and one response.
///
/// The `authorization` value must be the revealed `bearer github_pat_`
/// followed by exactly [`FINE_GRAINED_PAT_SECRET_LEN`] hidden bytes, and
/// those must be the only hidden sent bytes. Why this shape:
///
/// - The revealed prefix is authenticated transcript data, so GitHub received
///   a fine-grained PAT. Someone holding a different credential for the same
///   account (an OAuth app or GitHub App token, a classic PAT) cannot claim.
/// - The verifier cannot see hidden bytes, so a dishonest prover could hide
///   header or body bytes in that range (e.g. `\r\n\r\n` and a different
///   GraphQL query). 82 bytes is far less than any query whose response
///   matches the strict [`graphql::GraphqlResponse`] shape (~170 bytes of
///   field names alone), so that is infeasible.
fn check_transcript(mut transcript: PartialTranscript) -> Result<Exchange, ClaimError> {
    let hidden_recv = transcript.received_unauthed();
    if !hidden_recv.is_empty() {
        return Err(ClaimError::HiddenReceived(hidden_recv.len()));
    }
    let hidden_sent = transcript.sent_unauthed();

    // Hidden bytes become 'X' so the request still parses; the parse result
    // locates the authorization value. 'X' never occurs in the visible prefix,
    // so a hidden byte can never pass for a revealed one.
    transcript.set_unauthed(b'X');
    let sent = transcript.sent_unsafe();
    let request = http::parse_request(sent)?;

    let value = {
        let mut auth = request.headers_named(header::AUTHORIZATION);
        match (auth.next(), auth.next()) {
            (Some(h), None) => h.value_range.clone(),
            _ => {
                return Err(ClaimError::Request(
                    "exactly one authorization header is required".into(),
                ));
            }
        }
    };
    let value = match value.iter().collect::<Vec<_>>().as_slice() {
        [range] => range.clone(),
        _ => return Err(ClaimError::SentRedaction),
    };

    // `bearer github_pat_`, revealed.
    let token_start = value.start + AUTH_VISIBLE_PREFIX.len();
    if token_start > value.end || sent[value.start..token_start] != *AUTH_VISIBLE_PREFIX.as_bytes()
    {
        return Err(ClaimError::AuthPrefix);
    }
    // Exactly the rest of the value is hidden, and nothing else.
    let token = token_start..value.end;
    if hidden_sent != token {
        return Err(ClaimError::SentRedaction);
    }
    if token.len() != FINE_GRAINED_PAT_SECRET_LEN {
        return Err(ClaimError::AuthTokenLength {
            len: token.len(),
            expected: FINE_GRAINED_PAT_SECRET_LEN,
        });
    }

    let response = http::parse_response(transcript.received_unsafe())?;
    Ok(Exchange { request, response })
}

fn check_request(
    req: &HttpRequest,
    input: &GuestInput,
    params: &VerifyParams,
) -> Result<(), ClaimError> {
    if req.request_line != request::REQUEST_LINE {
        return Err(ClaimError::Request(format!(
            "request line {:?}, expected {:?}",
            req.request_line,
            request::REQUEST_LINE
        )));
    }

    let binding = binding_header_value(input.eth_address, input.chain_id, input.campaign_id);
    let content_length = req.body.len().to_string();
    let mut seen = [false; header::ALL.len()];

    for h in &req.headers {
        let name = h.name.to_ascii_lowercase();
        let idx = header::ALL
            .iter()
            .position(|n| *n == name)
            .ok_or_else(|| ClaimError::Request(format!("unexpected header {name:?}")))?;
        if std::mem::replace(&mut seen[idx], true) {
            return Err(ClaimError::Request(format!("duplicate header {name:?}")));
        }

        let expected: &[u8] = match name.as_str() {
            header::HOST => params.expected_server.as_bytes(),
            header::USER_AGENT => request::USER_AGENT.as_bytes(),
            header::ACCEPT_ENCODING => request::ACCEPT_ENCODING.as_bytes(),
            header::CONNECTION => request::CONNECTION.as_bytes(),
            header::CONTENT_TYPE => request::CONTENT_TYPE.as_bytes(),
            header::CONTENT_LENGTH => content_length.as_bytes(),
            header::BINDING => {
                if h.value != binding.as_bytes() {
                    return Err(ClaimError::BindingMismatch);
                }
                continue;
            }
            // authorization: its shape was checked in check_transcript.
            _ => continue,
        };
        if h.value != expected {
            return Err(ClaimError::Request(format!(
                "header {name:?} has an unexpected value"
            )));
        }
    }

    if let Some((missing, _)) = header::ALL.iter().zip(seen).find(|(_, s)| !s) {
        return Err(ClaimError::Request(format!("missing header {missing:?}")));
    }
    Ok(())
}

/// Step 9: the account existed before the snapshot (H1). Commits are
/// attributed to an account by email, so an email moved to a fresh account
/// would otherwise let the same commits be claimed again under a new nullifier.
fn check_account_age(created_at: &str, snapshot: u64) -> Result<(), ClaimError> {
    let created =
        time::parse_utc(created_at).ok_or_else(|| ClaimError::CreatedAt(created_at.to_owned()))?;
    if created >= snapshot {
        return Err(ClaimError::AccountTooNew {
            created_at: created,
            snapshot,
        });
    }
    Ok(())
}

fn check_response(response: &HttpResponse) -> Result<ClaimData, ClaimError> {
    if response.status != 200 {
        return Err(ClaimError::Status(response.status));
    }
    graphql::parse_response(&response.body)
        .map(|r| r.data)
        .map_err(|e| ClaimError::ResponseJson(e.to_string()))
}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use alloy_primitives::{Address, B256, hex};
    use rangeset::set::RangeSet;
    use tlsn_core::transcript::Transcript;

    use super::*;
    use crate::{abi::keccak256, http::Framing, request::FINE_GRAINED_PAT_PREFIX};

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name)
    }

    fn any_input() -> GuestInput {
        GuestInput {
            eth_address: Address::ZERO,
            chain_id: 84532,
            campaign_id: B256::ZERO,
            owner: "tlsnotary".into(),
            name: "tlsn".into(),
            threshold: 0,
            snapshot: 1_767_225_600,
        }
    }

    /// Real api.github.com presentation from spike M0b: `POST /graphql` with a
    /// dummy token, answered by a close-delimited 401. Exercises the
    /// production root store, the full verify on real certificates and the
    /// close-delimited fallback parser. The spike hid the WHOLE `bearer <dummy>`
    /// value (the pre-M1 disclosure), so the redaction rule rejects it.
    #[test]
    fn real_github_401_close_delimited_fixture() {
        let bytes = std::fs::read(fixture("m0b-github-graphql-401.bin")).expect("fixture");
        let params = VerifyParams::github();

        let session = verify_session(&bytes, &params, &mut NoTracker).expect("verify session");
        // M0b notary dummy key [1u8; 32].
        let key = hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")
            .expect("hex");
        assert_eq!(session.notary_key_hash, keccak256(&key));

        assert!(session.transcript.received_unauthed().is_empty());
        let response =
            http::parse_response(session.transcript.received_unsafe()).expect("401 response");
        assert_eq!(response.status, 401);
        assert_eq!(response.framing, Framing::CloseDelimited);
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).expect("401 body is JSON");
        assert_eq!(body["message"], "Bad credentials");

        assert!(matches!(
            check_transcript(session.transcript),
            Err(ClaimError::AuthPrefix)
        ));
        let err = verify_claim(&bytes, &any_input(), &params).expect_err("must fail");
        assert!(matches!(err, ClaimError::AuthPrefix), "{err}");
    }

    /// Phases are reported in order; a failing phase is started but not ended.
    #[test]
    fn tracker_sees_phases_in_order() {
        struct Record(Vec<String>);
        impl Tracker for Record {
            fn start(&mut self, label: &'static str) {
                self.0.push(format!("+{label}"));
            }
            fn end(&mut self, label: &'static str) {
                self.0.push(format!("-{label}"));
            }
        }

        let bytes = std::fs::read(fixture("m0b-github-graphql-401.bin")).expect("fixture");
        let mut record = Record(Vec::new());
        let err = verify_claim_tracked(&bytes, &any_input(), &VerifyParams::github(), &mut record)
            .expect_err("must fail");
        assert!(matches!(err, ClaimError::AuthPrefix), "{err}");
        assert_eq!(
            record.0,
            [
                "+deserialize",
                "-deserialize",
                "+verify",
                "-verify",
                "+http"
            ]
        );
    }

    #[test]
    fn real_github_fixture_fails_for_another_server_name() {
        let bytes = std::fs::read(fixture("m0b-github-graphql-401.bin")).expect("fixture");
        let params = VerifyParams {
            expected_server: "example.com".into(),
            ..VerifyParams::github()
        };
        let err = verify_claim(&bytes, &any_input(), &params).expect_err("must fail");
        assert!(matches!(err, ClaimError::ServerName { .. }), "{err}");
    }

    #[test]
    fn real_github_fixture_fails_with_an_untrusted_root_store() {
        let bytes = std::fs::read(fixture("m0b-github-graphql-401.bin")).expect("fixture");
        let params = VerifyParams::with_root_store(GITHUB_API_HOST, &RootCertStore::empty())
            .expect("params");
        let err = verify_claim(&bytes, &any_input(), &params).expect_err("must fail");
        assert!(matches!(err, ClaimError::Presentation(_)), "{err}");
    }

    #[test]
    fn trailing_and_garbage_bytes_are_rejected() {
        let mut bytes = std::fs::read(fixture("m0b-github-graphql-401.bin")).expect("fixture");
        bytes.push(0);
        let err = verify_claim(&bytes, &any_input(), &VerifyParams::github()).expect_err("fail");
        assert!(matches!(err, ClaimError::Decode(_)), "{err}");

        let err = verify_claim(b"not a presentation", &any_input(), &VerifyParams::github())
            .expect_err("fail");
        assert!(matches!(err, ClaimError::Decode(_)), "{err}");
    }

    #[test]
    fn snapshot_past_year_9999_is_rejected_before_decoding() {
        let input = GuestInput {
            snapshot: time::MAX_UNIX_SECONDS + 1,
            ..any_input()
        };
        let err =
            verify_claim(b"not a presentation", &input, &VerifyParams::github()).expect_err("fail");
        assert!(matches!(err, ClaimError::SnapshotOutOfRange(_)), "{err}");
    }

    /// Real authenticated 200 from `orc prove`, if one has been recorded
    /// (`fixtures/github-graphql-200.bin` + `.input.json`). Needs a PAT to
    /// produce, so it is skipped when absent.
    #[test]
    fn real_github_200_fixture_if_present() {
        let path = fixture("github-graphql-200.bin");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: {} not recorded", path.display());
            return;
        };
        let input: GuestInput = serde_json::from_slice(
            &std::fs::read(fixture("github-graphql-200.input.json")).expect("guest input"),
        )
        .expect("guest input json");
        let pv = verify_claim(&bytes, &input, &VerifyParams::github()).expect("claim verifies");
        assert_eq!(pv.ethAddress, input.eth_address);
        assert_eq!(pv.threshold, input.threshold);
        assert_eq!(pv.snapshot, input.snapshot);
        assert!(pv.sessionTime > pv.snapshot);

        // The snapshot is bound by the request body: any other one fails.
        let shifted = GuestInput {
            snapshot: input.snapshot - 1,
            ..input.clone()
        };
        let err = verify_claim(&bytes, &shifted, &VerifyParams::github()).expect_err("fail");
        assert!(matches!(err, ClaimError::BodyMismatch), "{err}");
    }

    #[test]
    fn guest_input_json_is_strict() {
        let json = r#"{"eth_address":"0x00000000000000000000000000000000deadbeef","chain_id":84532,"campaign_id":"0x1111111111111111111111111111111111111111111111111111111111111111","owner":"o","name":"n","threshold":3,"snapshot":1767225600}"#;
        let input: GuestInput = serde_json::from_str(json).expect("parse");
        assert_eq!(input.chain_id, 84532);
        assert_eq!(input.snapshot, 1_767_225_600);
        let extra = json.replacen("{", "{\"x\":1,", 1);
        assert!(serde_json::from_str::<GuestInput>(&extra).is_err());
        let missing = json.replacen(",\"snapshot\":1767225600", "", 1);
        assert!(serde_json::from_str::<GuestInput>(&missing).is_err());
    }

    // ---- H1: account age -------------------------------------------------------

    #[test]
    fn account_must_predate_the_snapshot() {
        let snapshot = 1_767_225_600; // 2026-01-01T00:00:00Z
        assert!(check_account_age("2015-06-01T12:34:56Z", snapshot).is_ok());
        assert!(check_account_age("2025-12-31T23:59:59Z", snapshot).is_ok());
        assert!(matches!(
            check_account_age("2026-01-01T00:00:00Z", snapshot),
            Err(ClaimError::AccountTooNew {
                created_at: 1_767_225_600,
                snapshot: 1_767_225_600
            })
        ));
        assert!(matches!(
            check_account_age("2026-03-01T00:00:00Z", snapshot),
            Err(ClaimError::AccountTooNew { .. })
        ));
        for bad in [
            "2015-06-01T12:34:56.000Z",
            "2015-06-01T12:34:56+00:00",
            "",
            "x",
        ] {
            assert!(
                matches!(
                    check_account_age(bad, snapshot),
                    Err(ClaimError::CreatedAt(_))
                ),
                "{bad:?}"
            );
        }
    }

    // ---- M1: fine-grained PATs only (synthetic transcripts) ------------------
    //
    // `check_transcript` sees exactly what the presentation proves: a partial
    // transcript with the hidden ranges unknown. These build one directly, so
    // every disclosure a dishonest prover could choose can be tried offline.
    // Tokens are assembled at run time: no token-shaped literal in the repo.

    const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";

    /// A token with the shape of a fine-grained PAT and `secret_len` bytes
    /// after `github_pat_` (a real one has 82: 22, `_`, 59).
    fn fine_grained(secret_len: usize) -> String {
        let secret: String = (0..secret_len)
            .map(|i| {
                if i == 22 {
                    '_'
                } else {
                    (b'a' + (i % 26) as u8) as char
                }
            })
            .collect();
        format!("{FINE_GRAINED_PAT_PREFIX}{secret}")
    }

    /// `<prefix>` + 36 characters: the shape of classic (`ghp_`), OAuth
    /// (`gho_`), user-to-server (`ghu_`) and installation (`ghs_`) tokens.
    fn short_token(prefix: &str) -> String {
        format!("{prefix}{}", "Z".repeat(36))
    }

    /// The orc-shaped request with `value` as the authorization value, and the
    /// value's transcript range.
    fn request(value: &str) -> (Vec<u8>, Range<usize>) {
        let head = "POST /graphql HTTP/1.1\r\nhost: api.github.com\r\nauthorization: ";
        let sent = format!("{head}{value}\r\ncontent-length: 2\r\n\r\n{{}}");
        (sent.into_bytes(), head.len()..head.len() + value.len())
    }

    /// Runs `check_transcript` on the request for `value`, with the ranges
    /// `hide(value_range)` hidden and everything else (both directions) revealed.
    fn check(
        value: &str,
        hide: impl FnOnce(Range<usize>) -> RangeSet<usize>,
    ) -> Result<Exchange, ClaimError> {
        let (sent, value_range) = request(value);
        let mut reveal = RangeSet::from(0..sent.len());
        // Range by range: `difference_mut` with an OWNED `RangeSet` argument
        // did not terminate with rangeset 0.4.0 (observed: tests spinning at
        // 100% CPU). `Range` and `&RangeSet` arguments are fine.
        for range in hide(value_range).iter() {
            reveal.difference_mut(range);
        }
        let partial = Transcript::new(sent, RESPONSE.to_vec())
            .to_partial(reveal, RangeSet::from(0..RESPONSE.len()));
        check_transcript(partial)
    }

    /// The honest disclosure: everything after `bearer github_pat_` hidden.
    fn token_part(value: Range<usize>) -> RangeSet<usize> {
        RangeSet::from(value.start + AUTH_VISIBLE_PREFIX.len()..value.end)
    }

    /// The pre-M1 disclosure: the whole value hidden, scheme included.
    fn whole_value(value: Range<usize>) -> RangeSet<usize> {
        RangeSet::from(value)
    }

    fn bearer(token: &str) -> String {
        format!("bearer {token}")
    }

    #[test]
    fn fine_grained_token_with_honest_disclosure_passes() {
        let token = fine_grained(FINE_GRAINED_PAT_SECRET_LEN);
        assert_eq!(token.len(), 93);
        let exchange = check(&bearer(&token), token_part).expect("honest shape passes");
        assert_eq!(exchange.request.request_line, request::REQUEST_LINE);
        assert_eq!(exchange.response.status, 200);
    }

    #[test]
    fn classic_oauth_and_app_tokens_are_rejected() {
        for prefix in ["ghp_", "gho_", "ghu_", "ghs_"] {
            let value = bearer(&short_token(prefix));
            // Revealing the same 18 bytes an honest prover does shows the prefix.
            assert!(
                matches!(check(&value, token_part), Err(ClaimError::AuthPrefix)),
                "{prefix} with the honest disclosure"
            );
            // Hiding the whole value (what orc did before M1) shows nothing.
            assert!(
                matches!(check(&value, whole_value), Err(ClaimError::AuthPrefix)),
                "{prefix} fully hidden"
            );
        }
    }

    #[test]
    fn fine_grained_token_fully_hidden_is_rejected() {
        let value = bearer(&fine_grained(FINE_GRAINED_PAT_SECRET_LEN));
        assert!(matches!(
            check(&value, whole_value),
            Err(ClaimError::AuthPrefix)
        ));
    }

    #[test]
    fn altered_visible_prefix_is_rejected() {
        let token = fine_grained(FINE_GRAINED_PAT_SECRET_LEN);
        for value in [
            format!("Bearer {token}"),
            format!("BEARER {token}"),
            format!("token {token}"),
            format!("bearer  {token}"),
            format!("bearer x{}", &token[1..]),
            format!(
                "bearer github_pat-{}",
                &token[FINE_GRAINED_PAT_PREFIX.len()..]
            ),
        ] {
            assert!(
                matches!(check(&value, token_part), Err(ClaimError::AuthPrefix)),
                "{}",
                &value[..20]
            );
        }
        // Hiding any byte of the prefix (here the trailing `_`) is the same as
        // not revealing it.
        let value = bearer(&token);
        assert!(matches!(
            check(&value, |r| RangeSet::from(
                r.start + AUTH_VISIBLE_PREFIX.len() - 1..r.end
            )),
            Err(ClaimError::AuthPrefix)
        ));
        // A value shorter than the prefix.
        assert!(matches!(
            check("bearer github", whole_value),
            Err(ClaimError::AuthPrefix)
        ));
    }

    #[test]
    fn wrong_hidden_length_is_rejected() {
        for len in [1, 40, 81, 83, 93, 120] {
            let value = bearer(&fine_grained(len));
            match check(&value, token_part) {
                Err(ClaimError::AuthTokenLength { len: got, expected }) => {
                    assert_eq!((got, expected), (len, FINE_GRAINED_PAT_SECRET_LEN));
                }
                other => panic!("secret length {len}: {other:?}"),
            }
        }
        // Nothing hidden at all: `bearer github_pat_` with an empty token.
        assert!(matches!(
            check(&bearer(FINE_GRAINED_PAT_PREFIX), |_| RangeSet::default()),
            Err(ClaimError::SentRedaction)
        ));
    }

    #[test]
    fn any_other_hidden_sent_byte_is_rejected() {
        let value = bearer(&fine_grained(FINE_GRAINED_PAT_SECRET_LEN));
        let token_start = |r: &Range<usize>| r.start + AUTH_VISIBLE_PREFIX.len();
        // The first token byte revealed.
        assert!(matches!(
            check(&value, |r| RangeSet::from(token_start(&r) + 1..r.end)),
            Err(ClaimError::SentRedaction)
        ));
        // The last token byte revealed.
        assert!(matches!(
            check(&value, |r| RangeSet::from(token_start(&r)..r.end - 1)),
            Err(ClaimError::SentRedaction)
        ));
        // The token plus a byte of the request line (`P`).
        assert!(matches!(
            check(&value, |r| RangeSet::from([0..1, token_start(&r)..r.end])),
            Err(ClaimError::Http(_) | ClaimError::SentRedaction)
        ));
        // The token plus the host value.
        assert!(matches!(
            check(&value, |r| RangeSet::from([30..44, token_start(&r)..r.end])),
            Err(ClaimError::SentRedaction)
        ));
        // The token plus the CRLF after it: rejected, however it parses.
        assert!(check(&value, |r| RangeSet::from(token_start(&r)..r.end + 2)).is_err());
    }

    #[test]
    fn duplicate_authorization_header_is_rejected() {
        let token = fine_grained(FINE_GRAINED_PAT_SECRET_LEN);
        let head = "POST /graphql HTTP/1.1\r\nauthorization: bearer x\r\nauthorization: ";
        let sent = format!("{head}{}\r\ncontent-length: 2\r\n\r\n{{}}", bearer(&token));
        let start = head.len() + AUTH_VISIBLE_PREFIX.len();
        let mut reveal = RangeSet::from(0..sent.len());
        reveal.difference_mut(start..start + FINE_GRAINED_PAT_SECRET_LEN);
        let partial = Transcript::new(sent.into_bytes(), RESPONSE.to_vec())
            .to_partial(reveal, RangeSet::from(0..RESPONSE.len()));
        assert!(matches!(
            check_transcript(partial),
            Err(ClaimError::Request(_))
        ));
    }
}
