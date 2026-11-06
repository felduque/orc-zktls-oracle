//! The exact HTTP request the prover sends inside MPC-TLS.
//!
//! Shared by the prover (which builds it) and [`crate::verify`] (which
//! requires it byte for byte), so the two can never drift apart.

/// Request line. HTTP/1.1, no absolute-form target.
pub const REQUEST_LINE: &str = "POST /graphql HTTP/1.1\r\n";
/// HTTP method.
pub const METHOD: &str = "POST";
/// GraphQL endpoint path.
pub const PATH: &str = "/graphql";
/// GitHub answers 403 without a User-Agent.
pub const USER_AGENT: &str = "orc-poc";
/// Uncompressed body, so the response is parseable inside the guest.
pub const ACCEPT_ENCODING: &str = "identity";
/// One request per connection; also makes close-delimited bodies well defined.
pub const CONNECTION: &str = "close";
/// Request body content type.
pub const CONTENT_TYPE: &str = "application/json";

/// Header names, lowercase (hyper writes them lowercase on the wire; the
/// verifier matches case-insensitively).
pub mod header {
    pub const HOST: &str = "host";
    pub const USER_AGENT: &str = "user-agent";
    pub const AUTHORIZATION: &str = "authorization";
    pub const ACCEPT_ENCODING: &str = "accept-encoding";
    pub const CONNECTION: &str = "connection";
    pub const CONTENT_TYPE: &str = "content-type";
    pub const CONTENT_LENGTH: &str = "content-length";
    pub const BINDING: &str = "x-orc-binding";

    /// The complete set of request headers. The verifier rejects any other
    /// header and any duplicate, so a prover cannot smuggle in headers that
    /// change what the server returns (e.g. alternate media types).
    pub const ALL: [&str; 8] = [
        HOST,
        USER_AGENT,
        AUTHORIZATION,
        ACCEPT_ENCODING,
        CONNECTION,
        CONTENT_TYPE,
        CONTENT_LENGTH,
        BINDING,
    ];
}

/// Prefix of the `Authorization` value (`bearer <token>`).
pub const AUTH_SCHEME_PREFIX: &str = "bearer ";
