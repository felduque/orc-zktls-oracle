//! [`verify_claim`]: every check the SP1 guest performs, in order.
//!
//! 1. Decode the bincode `Presentation` (size-limited, no trailing bytes).
//! 2. Notary key is k256, 33-byte compressed; `notaryKeyHash = keccak256(key)`.
//! 3. Full `Presentation::verify` (notary signature, Merkle openings, server
//!    certificate chain + TLS signature, transcript hash openings); signature
//!    alg is secp256k1, commitment root is SHA-256, server name matches.
//! 4. Redaction: all received bytes are revealed; the only hidden sent bytes
//!    are exactly the (single) `authorization` header value, and it is short
//!    enough that it cannot carry a smuggled alternative query (see
//!    [`DEFAULT_MAX_AUTH_VALUE_LEN`]).
//! 5. Exactly one request and one response.
//! 6. Request: `POST /graphql HTTP/1.1`, exactly the orc header set with the
//!    expected values, `x-orc-binding` derived from the input.
//! 7. Response: status 200, body parses strictly as the expected GraphQL data.
//! 8. Request body is byte-identical to `graphql_body(owner, name, viewer.id)`,
//!    so the commit count is the authenticated viewer's.
//! 9. `totalCount >= threshold`.
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
    request::{self, header},
};

/// Production server name.
pub const GITHUB_API_HOST: &str = "api.github.com";

/// Upper bound on a serialized presentation (a 16 KiB transcript plus the
/// certificate chain is ~30 KiB).
pub const MAX_PRESENTATION_BYTES: u64 = 256 * 1024;

/// Upper bound on the hidden `authorization` value (`bearer <token>`).
///
/// The verifier cannot see hidden bytes, so a malicious prover could hide
/// header or body bytes inside that range (e.g. `\r\n\r\n` and a different
/// GraphQL query). Bounding the range keeps that infeasible: after `bearer `
/// and a real token (40 chars classic, 93 fine-grained) at most ~80 bytes
/// remain, far less than any query whose response matches the strict
/// [`graphql::GraphqlResponse`] shape (~160 bytes of field names alone).
/// 128 accepts both token formats.
pub const DEFAULT_MAX_AUTH_VALUE_LEN: usize = 128;

/// What the verifier trusts: the server name, the root certificates (inside
/// `provider`) and the hidden-range bound.
#[derive(Debug)]
pub struct VerifyParams {
    /// Required authenticated server name (and `Host` header value).
    pub expected_server: String,
    /// Crypto provider; its certificate verifier holds the trusted roots.
    pub provider: CryptoProvider,
    /// See [`DEFAULT_MAX_AUTH_VALUE_LEN`].
    pub max_auth_value_len: usize,
}

impl VerifyParams {
    /// Production parameters: `api.github.com` with the Mozilla root store.
    pub fn github() -> Self {
        Self {
            expected_server: GITHUB_API_HOST.to_owned(),
            provider: CryptoProvider::default(),
            max_auth_value_len: DEFAULT_MAX_AUTH_VALUE_LEN,
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
            max_auth_value_len: DEFAULT_MAX_AUTH_VALUE_LEN,
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
    /// Steps 7-9: strict GraphQL JSON parse, body/threshold checks, nullifier.
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
    let session = verify_session(presentation, params, tracker)?;

    tracker.start(phase::HTTP);
    let exchange = check_transcript(session.transcript, params)?;
    check_request(&exchange.request, input, params)?;
    tracker.end(phase::HTTP);

    tracker.start(phase::JSON);
    let data = check_response(&exchange.response)?;

    // The query variable `$a` must be the authenticated viewer, otherwise the
    // count could be someone else's commits.
    let expected_body = graphql_body(&input.owner, &input.name, &data.viewer.id);
    if exchange.request.body != expected_body.as_bytes() {
        return Err(ClaimError::BodyMismatch);
    }

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

fn check_transcript(
    mut transcript: PartialTranscript,
    params: &VerifyParams,
) -> Result<Exchange, ClaimError> {
    let hidden_recv = transcript.received_unauthed();
    if !hidden_recv.is_empty() {
        return Err(ClaimError::HiddenReceived(hidden_recv.len()));
    }
    let hidden_sent = transcript.sent_unauthed();

    // Hidden bytes become 'X' so the request still parses; the parse result
    // locates the authorization value, which must be exactly what is hidden.
    transcript.set_unauthed(b'X');
    let request = http::parse_request(transcript.sent_unsafe())?;

    let auth_value = {
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
    if auth_value.is_empty() || hidden_sent != auth_value {
        return Err(ClaimError::SentRedaction);
    }
    if auth_value.len() > params.max_auth_value_len {
        return Err(ClaimError::AuthValueTooLong {
            len: auth_value.len(),
            max: params.max_auth_value_len,
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
            // authorization: hidden; its range was checked in check_transcript.
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
    use alloy_primitives::{Address, B256, hex};

    use super::*;
    use crate::{abi::keccak256, http::Framing};

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
        }
    }

    /// Real api.github.com presentation from spike M0b: `POST /graphql` with a
    /// dummy redacted token, answered by a close-delimited 401. Exercises the
    /// production root store, the full verify on real certificates, the
    /// redaction rule and the close-delimited fallback parser.
    #[test]
    fn real_github_401_close_delimited_fixture() {
        let bytes = std::fs::read(fixture("m0b-github-graphql-401.bin")).expect("fixture");
        let params = VerifyParams::github();

        let session = verify_session(&bytes, &params, &mut NoTracker).expect("verify session");
        // M0b notary dummy key [1u8; 32].
        let key = hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")
            .expect("hex");
        assert_eq!(session.notary_key_hash, keccak256(&key));

        let exchange = check_transcript(session.transcript, &params).expect("transcript");
        assert_eq!(exchange.request.request_line, request::REQUEST_LINE);
        assert_eq!(exchange.response.status, 401);
        assert_eq!(exchange.response.framing, Framing::CloseDelimited);
        let body: serde_json::Value =
            serde_json::from_slice(&exchange.response.body).expect("401 body is JSON");
        assert_eq!(body["message"], "Bad credentials");

        // The spike sent `x-orc-binding: 0xdeadbeef`, so the claim fails there.
        let err = verify_claim(&bytes, &any_input(), &params).expect_err("must fail");
        assert!(matches!(err, ClaimError::BindingMismatch), "{err}");
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
        assert!(matches!(err, ClaimError::BindingMismatch), "{err}");
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
    }

    #[test]
    fn guest_input_json_is_strict() {
        let json = r#"{"eth_address":"0x00000000000000000000000000000000deadbeef","chain_id":84532,"campaign_id":"0x1111111111111111111111111111111111111111111111111111111111111111","owner":"o","name":"n","threshold":3}"#;
        let input: GuestInput = serde_json::from_str(json).expect("parse");
        assert_eq!(input.chain_id, 84532);
        let extra = json.replacen("{", "{\"x\":1,", 1);
        assert!(serde_json::from_str::<GuestInput>(&extra).is_err());
    }
}
