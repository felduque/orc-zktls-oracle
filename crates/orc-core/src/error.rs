use tlsn_attestation::presentation::PresentationError;

use crate::http::HttpError;

/// Why a claim was rejected. Every check in [`crate::verify_claim`] has its
/// own variant so tests (and users) can tell exactly which rule failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimError {
    #[error("invalid verifier parameters: {0}")]
    Params(String),

    #[error("snapshot {0} is past 9999-12-31T23:59:59Z")]
    SnapshotOutOfRange(u64),

    #[error("presentation is not a valid bincode Presentation: {0}")]
    Decode(String),

    #[error("notary key algorithm must be k256, got {0}")]
    NotaryKeyAlg(String),

    #[error("notary key must be a 33-byte compressed SEC1 point")]
    NotaryKeyEncoding,

    #[error("attestation must be signed with secp256k1, got {0}")]
    SignatureAlg(String),

    #[error("attestation must use SHA-256, got {0}")]
    HashAlg(String),

    #[error("presentation verification failed: {0}")]
    Presentation(#[from] PresentationError),

    #[error("presentation has no server identity proof")]
    MissingServerName,

    #[error("server name is {actual}, expected {expected}")]
    ServerName { expected: String, actual: String },

    #[error("presentation has no transcript proof")]
    MissingTranscript,

    #[error("received data must be fully revealed, but {0} bytes are hidden")]
    HiddenReceived(usize),

    #[error(
        "the visible start of the authorization value must be exactly `bearer github_pat_` (fine-grained personal access tokens only)"
    )]
    AuthPrefix,

    #[error(
        "the only hidden sent bytes must be exactly the token after `bearer github_pat_` in the authorization value"
    )]
    SentRedaction,

    #[error(
        "the hidden token is {len} bytes, a fine-grained PAT has exactly {expected} after its prefix"
    )]
    AuthTokenLength { len: usize, expected: usize },

    #[error(transparent)]
    Http(#[from] HttpError),

    #[error("request does not match the orc request shape: {0}")]
    Request(String),

    #[error("x-orc-binding does not match the guest input")]
    BindingMismatch,

    #[error(
        "request body is not the canonical GraphQL body for this input and the authenticated viewer"
    )]
    BodyMismatch,

    #[error("HTTP status {0}, expected 200")]
    Status(u16),

    #[error("response body is not the expected GraphQL data: {0}")]
    ResponseJson(String),

    #[error("viewer.createdAt {0:?} is not a YYYY-MM-DDTHH:MM:SSZ timestamp")]
    CreatedAt(String),

    #[error("the account was created at {created_at}, not before the snapshot {snapshot}")]
    AccountTooNew { created_at: u64, snapshot: u64 },

    #[error("commit count {count} is below the threshold {threshold}")]
    BelowThreshold { count: u64, threshold: u64 },
}
