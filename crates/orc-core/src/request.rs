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

/// Prefix of a GitHub fine-grained personal access token. orc accepts no
/// other token type (classic `ghp_`, OAuth `gho_`, user-to-server `ghu_`,
/// installation `ghs_`, ...): see [`AUTH_VISIBLE_PREFIX`].
pub const FINE_GRAINED_PAT_PREFIX: &str = "github_pat_";

/// Length of the secret part of a fine-grained PAT, after
/// [`FINE_GRAINED_PAT_PREFIX`]: 22 characters, `_`, 59 characters (93 in all).
pub const FINE_GRAINED_PAT_SECRET_LEN: usize = 82;

/// The revealed start of the `Authorization` value:
/// [`AUTH_SCHEME_PREFIX`] + [`FINE_GRAINED_PAT_PREFIX`].
///
/// The prover reveals it and hides exactly the [`FINE_GRAINED_PAT_SECRET_LEN`]
/// bytes after it. Because the revealed bytes are authenticated transcript
/// data, the verifier knows GitHub received a fine-grained PAT, so a holder of
/// some other credential for the account (an OAuth or GitHub App token) cannot
/// claim as that user. The fixed hidden length also caps what a dishonest
/// prover could hide there (see `crate::verify`).
pub const AUTH_VISIBLE_PREFIX: &str = "bearer github_pat_";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_prefix_is_scheme_plus_token_prefix() {
        assert_eq!(
            AUTH_VISIBLE_PREFIX,
            format!("{AUTH_SCHEME_PREFIX}{FINE_GRAINED_PAT_PREFIX}")
        );
        // Hidden bytes are replaced by `X` before parsing (crate::verify), so a
        // hidden byte can never pass for a revealed prefix byte.
        assert!(!AUTH_VISIBLE_PREFIX.contains('X'));
    }
}
