use std::{fmt, sync::Arc};

use hyper::header::HeaderValue;
use orc_core::{DEFAULT_MAX_AUTH_VALUE_LEN, GITHUB_API_HOST, request::AUTH_SCHEME_PREFIX};
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

/// A GitHub token. `Debug` never prints it; it is only ever written into
/// the `Authorization` header and compared against outputs to detect leaks.
pub struct GithubToken(String);

impl GithubToken {
    /// Environment variable the CLI reads.
    pub const ENV: &'static str = "GITHUB_TOKEN";

    /// Validates `token` (visible ASCII, short enough for the verifier's
    /// hidden-range bound).
    pub fn new(token: impl Into<String>) -> Result<Self, ProverError> {
        let token = token.into();
        let token = token.trim().to_owned();
        if token.is_empty() {
            return Err(ProverError::Invalid("GitHub token is empty".into()));
        }
        if !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ProverError::Invalid(
                "GitHub token must be visible ASCII".into(),
            ));
        }
        let auth_len = AUTH_SCHEME_PREFIX.len() + token.len();
        if auth_len > DEFAULT_MAX_AUTH_VALUE_LEN {
            return Err(ProverError::Invalid(format!(
                "authorization value would be {auth_len} bytes; the verifier accepts at most {DEFAULT_MAX_AUTH_VALUE_LEN}"
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

    /// True if `haystack` contains the token bytes.
    pub fn appears_in(&self, haystack: &[u8]) -> bool {
        haystack
            .windows(self.0.len())
            .any(|w| w == self.0.as_bytes())
    }
}

impl fmt::Debug for GithubToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GithubToken(<redacted>)")
    }
}
