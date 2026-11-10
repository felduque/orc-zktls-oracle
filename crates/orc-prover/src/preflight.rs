//! Preflight: learn the token owner's GraphQL node id and creation time with
//! an ordinary HTTPS request (no MPC), so the notarized query can name the id
//! in `$a`, and an account newer than the snapshot is refused before an MPC
//! session is spent on it.
//!
//! Nothing here is trusted by the verifier: if the id is wrong, the
//! notarized response's `viewer.id` will not match the request body and
//! `orc_core::verify_claim` fails; the account age is checked again on the
//! notarized `viewer.createdAt`.

use std::{sync::Arc, time::Duration};

use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes, header};
use hyper_util::rt::TokioIo;
use orc_core::request;
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::{
    Target,
    error::{ProverError, StageExt, with_timeout},
    target::GithubToken,
    task::AbortOnDrop,
};

/// `{viewer{id createdAt}}`.
pub const PREFLIGHT_BODY: &str = r#"{"query":"{viewer{id createdAt}}"}"#;

/// The token owner, as the preflight saw it (unauthenticated by the notary).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightViewer {
    /// GraphQL node id (`$a` in the notarized query).
    pub id: String,
    /// Account creation time, `YYYY-MM-DDTHH:MM:SSZ`.
    pub created_at: String,
}

/// Returns `data.viewer` (`id`, `createdAt`) for the token owner.
pub async fn viewer(
    target: &Target,
    token: &GithubToken,
    timeout: Duration,
) -> Result<PreflightViewer, ProverError> {
    with_timeout("preflight", timeout, fetch_viewer(target, token)).await
}

/// Returns `data.viewer.id` for the token owner.
pub async fn viewer_node_id(
    target: &Target,
    token: &GithubToken,
    timeout: Duration,
) -> Result<String, ProverError> {
    viewer(target, token, timeout).await.map(|v| v.id)
}

async fn fetch_viewer(
    target: &Target,
    token: &GithubToken,
) -> Result<PreflightViewer, ProverError> {
    let connector = TlsConnector::from(Arc::new(target.rustls_client_config()?));
    let server_name = rustls::pki_types::ServerName::try_from(target.server_name.clone())
        .map_err(|_| ProverError::Invalid(format!("server name {:?}", target.server_name)))?;

    let tcp = TcpStream::connect(&target.connect_addr)
        .await
        .stage("preflight: connect")?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .stage("preflight: TLS handshake")?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .stage("preflight: HTTP handshake")?;
    let _connection = AbortOnDrop::spawn(connection);

    let req = Request::builder()
        .method(request::METHOD)
        .uri(request::PATH)
        .header(header::HOST, &target.server_name)
        .header(header::USER_AGENT, request::USER_AGENT)
        .header(header::AUTHORIZATION, token.authorization_header()?)
        .header(header::ACCEPT_ENCODING, request::ACCEPT_ENCODING)
        .header(header::CONNECTION, request::CONNECTION)
        .header(header::CONTENT_TYPE, request::CONTENT_TYPE)
        .body(Full::new(Bytes::from_static(PREFLIGHT_BODY.as_bytes())))
        .stage("preflight: build request")?;

    let response = sender
        .send_request(req)
        .await
        .stage("preflight: send request")?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .stage("preflight: read response")?
        .to_bytes();

    if !status.is_success() {
        return Err(ProverError::Preflight(format!(
            "HTTP {status}: {}",
            snippet(&body)
        )));
    }
    parse_viewer(&body)
}

#[derive(Deserialize)]
struct PreflightResponse {
    data: Option<PreflightData>,
    errors: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct PreflightData {
    viewer: PreflightViewer,
}

fn parse_viewer(body: &[u8]) -> Result<PreflightViewer, ProverError> {
    let parsed: PreflightResponse = serde_json::from_slice(body)
        .map_err(|e| ProverError::Preflight(format!("invalid JSON ({e}): {}", snippet(body))))?;
    if let Some(errors) = parsed.errors {
        return Err(ProverError::Preflight(format!("GraphQL errors: {errors}")));
    }
    parsed
        .data
        .map(|d| d.viewer)
        .ok_or_else(|| ProverError::Preflight("response has no data.viewer".into()))
}

fn snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    text.chars().take(300).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_viewer() {
        let viewer = parse_viewer(
            br#"{"data":{"viewer":{"id":"U_kgDOabc","createdAt":"2015-06-01T12:34:56Z"}}}"#,
        )
        .expect("viewer");
        assert_eq!(viewer.id, "U_kgDOabc");
        assert_eq!(viewer.created_at, "2015-06-01T12:34:56Z");
    }

    #[test]
    fn graphql_errors_fail() {
        let body = br#"{"data":null,"errors":[{"message":"nope"}]}"#;
        assert!(matches!(parse_viewer(body), Err(ProverError::Preflight(_))));
        let no_created_at = br#"{"data":{"viewer":{"id":"U_kgDOabc"}}}"#;
        assert!(matches!(
            parse_viewer(no_created_at),
            Err(ProverError::Preflight(_))
        ));
    }
}
