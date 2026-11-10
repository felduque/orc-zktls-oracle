use std::{fmt, sync::Arc};

use hyper::header::HeaderValue;
use orc_core::{
    GITHUB_API_HOST,
    request::{AUTH_SCHEME_PREFIX, FINE_GRAINED_PAT_PREFIX, FINE_GRAINED_PAT_SECRET_LEN},
};
use tlsn::{connection::ServerName, webpki::RootCertStore};

use crate::error::{ProverError, StageExt};

/// Where the prover connects and what it trusts. Production is
/// [`Target::github`]; tests point it at a local TLS server with a test CA.
#[derive(Debug, Clone)]
pub struct Target {
    /// TLS server name (SNI, certificate check, `Host` header).
    pub server_name: String,
    /// `host:port` to open the TCP connection to.
    pub connect_addr: String,
    /// Trusted roots for the TLS certificate check.
    pub root_store: RootCertStore,
}

impl Target {
    /// `api.github.com:443` with the Mozilla root store.
    pub fn github() -> Self {
        Self {
            server_name: GITHUB_API_HOST.to_owned(),
            connect_addr: format!("{GITHUB_API_HOST}:443"),
            root_store: RootCertStore::mozilla(),
        }
    }

    pub(crate) fn tlsn_server_name(&self) -> Result<ServerName, ProverError> {
        let name = self
            .server_name
            .as_str()
            .try_into()
            .map_err(|_| ProverError::Invalid(format!("server name {:?}", self.server_name)))?;
        Ok(ServerName::Dns(name))
    }

    /// rustls client config for the preflight request (outside MPC).
    pub(crate) fn rustls_client_config(&self) -> Result<rustls::ClientConfig, ProverError> {
        let mut roots = rustls::RootCertStore::empty();
        let (added, _ignored) = roots.add_parsable_certificates(
            self.root_store
                .roots
                .iter()
                .map(|c| rustls::pki_types::CertificateDer::from(c.0.as_slice())),
        );
        if added == 0 {
            return Err(ProverError::Invalid("no usable root certificates".into()));
        }
        Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .stage("TLS protocol versions")?
        .with_root_certificates(roots)
        .with_no_client_auth())
    }
}

/// A GitHub fine-grained personal access token. `Debug` never prints it; it
/// is only ever written into the `Authorization` header and compared against
/// outputs to detect leaks.
///
/// Only fine-grained PATs are accepted (`github_pat_` + 82 characters): the
/// verifier requires the revealed `bearer github_pat_` prefix and exactly 82
/// hidden bytes, so any other token type (classic `ghp_`, OAuth `gho_`, GitHub
/// App `ghu_`/`ghs_`) would only fail later, after a full MPC session.
pub struct GithubToken(String);

impl GithubToken {
    /// Environment variable the CLI reads.
    pub const ENV: &'static str = "GITHUB_TOKEN";

    /// Validates `token` (surrounding whitespace is trimmed): it must be a
    /// fine-grained PAT, `github_pat_` followed by exactly 82 of `[A-Za-z0-9_]`.
    pub fn new(token: impl Into<String>) -> Result<Self, ProverError> {
        let token = token.into();
        let token = token.trim().to_owned();
        if token.is_empty() {
            return Err(ProverError::Invalid("GitHub token is empty".into()));
        }
        let Some(secret) = token.strip_prefix(FINE_GRAINED_PAT_PREFIX) else {
            // Name the kind of token from its public prefix, never more.
            let kind = match token.get(..4) {
                Some("ghp_") => "a classic personal access token (ghp_)",
                Some("gho_") => "an OAuth app token (gho_)",
                Some("ghu_") => "a GitHub App user-to-server token (ghu_)",
                Some("ghs_") => "a GitHub App installation token (ghs_)",
                Some("ghr_") => "a GitHub App refresh token (ghr_)",
                _ => "not a GitHub fine-grained token",
            };
            return Err(ProverError::Invalid(format!(
                "GITHUB_TOKEN is {kind}; orc accepts only fine-grained personal access tokens \
                 ({FINE_GRAINED_PAT_PREFIX}...): GitHub -> Settings -> Developer settings -> \
                 Fine-grained tokens"
            )));
        };
        if secret.len() != FINE_GRAINED_PAT_SECRET_LEN
            || !secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(ProverError::Invalid(format!(
                "GITHUB_TOKEN starts with {FINE_GRAINED_PAT_PREFIX} but is not a fine-grained \
                 personal access token: expected exactly {FINE_GRAINED_PAT_SECRET_LEN} characters \
                 of [A-Za-z0-9_] after the prefix, got {} bytes",
                secret.len()
            )));
        }
        Ok(Self(token))
    }

    /// Reads [`Self::ENV`].
    pub fn from_env() -> Result<Self, ProverError> {
        let token = std::env::var(Self::ENV)
            .map_err(|_| ProverError::Invalid(format!("{} is not set", Self::ENV)))?;
        Self::new(token)
    }

    /// `bearer <token>`, marked sensitive so hyper never logs it.
    pub(crate) fn authorization_header(&self) -> Result<HeaderValue, ProverError> {
        let mut value = HeaderValue::from_str(&format!("{AUTH_SCHEME_PREFIX}{}", self.0))
            .map_err(|_| ProverError::Invalid("token is not a valid header value".into()))?;
        value.set_sensitive(true);
        Ok(value)
    }

    /// The secret part of the token (everything after `github_pat_`), the
    /// bytes the presentation must hide.
    fn secret(&self) -> &[u8] {
        &self.0.as_bytes()[FINE_GRAINED_PAT_PREFIX.len()..]
    }

    /// True if `haystack` contains the token's secret part (the public
    /// `github_pat_` prefix is revealed by design).
    pub fn appears_in(&self, haystack: &[u8]) -> bool {
        let secret = self.secret();
        haystack.windows(secret.len()).any(|w| w == secret)
    }
}

impl fmt::Debug for GithubToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GithubToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built at run time: no token-shaped literal in the repository.
    fn fine_grained(secret_len: usize) -> String {
        let secret: String = (0..secret_len)
            .map(|i| {
                if i == 22 {
                    '_'
                } else {
                    (b'A' + (i % 26) as u8) as char
                }
            })
            .collect();
        format!("{FINE_GRAINED_PAT_PREFIX}{secret}")
    }

    fn invalid_message(token: String) -> String {
        match GithubToken::new(token) {
            Err(ProverError::Invalid(msg)) => msg,
            Err(e) => panic!("unexpected error {e}"),
            Ok(_) => panic!("token accepted"),
        }
    }

    #[test]
    fn accepts_a_fine_grained_pat() {
        let token = GithubToken::new(format!("  {}\n", fine_grained(82))).expect("valid");
        assert_eq!(token.0.len(), 93);
        assert_eq!(
            token.authorization_header().expect("header").as_bytes(),
            format!("bearer {}", fine_grained(82)).as_bytes()
        );
        assert_eq!(format!("{token:?}"), "GithubToken(<redacted>)");
    }

    #[test]
    fn rejects_other_token_types_early() {
        for (prefix, kind) in [
            ("ghp_", "classic"),
            ("gho_", "OAuth"),
            ("ghu_", "user-to-server"),
            ("ghs_", "installation"),
            ("ghr_", "refresh"),
            ("abcd", "not a GitHub fine-grained token"),
        ] {
            let msg = invalid_message(format!("{prefix}{}", "Q".repeat(36)));
            assert!(msg.contains(kind), "{prefix}: {msg}");
            assert!(msg.contains("fine-grained"), "{prefix}: {msg}");
            // The error never echoes the token.
            assert!(!msg.contains("QQQQ"), "{msg}");
        }
        assert!(invalid_message(String::new()).contains("empty"));
    }

    #[test]
    fn rejects_malformed_fine_grained_tokens() {
        for len in [0, 81, 83, 120] {
            let msg = invalid_message(fine_grained(len));
            assert!(msg.contains(&format!("got {len} bytes")), "{msg}");
        }
        let mut bad = fine_grained(82);
        bad.replace_range(40..41, "-");
        assert!(invalid_message(bad).contains("[A-Za-z0-9_]"));
    }

    #[test]
    fn leak_check_looks_for_the_secret_part() {
        let token = GithubToken::new(fine_grained(82)).expect("valid");
        let secret = &fine_grained(82)[FINE_GRAINED_PAT_PREFIX.len()..];
        assert!(!token.appears_in(b"authorization: bearer github_pat_\r\n"));
        assert!(token.appears_in(format!("xx{secret}yy").as_bytes()));
    }
}
