use tlsn_attestation::presentation::PresentationError;

use crate::http::HttpError;

/// Why a claim was rejected. Every check in [`crate::verify_claim`] has its
/// own variant so tests (and users) can tell exactly which rule failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimError {
    #[error("invalid verifier parameters: {0}")]
    Params(String),

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

    #[error("the only hidden sent bytes must be exactly the authorization header value")]
    SentRedaction,

    #[error("hidden authorization value is {len} bytes, at most {max} are allowed")]
    AuthValueTooLong { len: usize, max: usize },

    #[error(transparent)]
    Http(#[from] HttpError),

    #[error("request does not match the orc request shape: {0}")]
    Request(String),

    #[error("x-orc-binding does not match the guest input")]
    BindingMismatch,

    #[error("request body is not the canonical GraphQL body for this input and the authenticated viewer")]
    BodyMismatch,

    #[error("HTTP status {0}, expected 200")]
    Status(u16),

    #[error("response body is not the expected GraphQL data: {0}")]
    ResponseJson(String),

    #[error("commit count {count} is below the threshold {threshold}")]
    BelowThreshold { count: u64, threshold: u64 },
}
