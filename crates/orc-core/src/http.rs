//! Strict HTTP/1.1 parsing of a notarized transcript.
//!
//! The primary parser is `tlsn-formats` (spansy), the same one
//! `HttpTranscript::parse` uses. Each direction must hold exactly one
//! message spanning the whole transcript; trailing bytes are an error.
//!
//! Responses have a fallback. spansy rejects responses with neither
//! `Content-Length` nor `Transfer-Encoding`, and GitHub sends such
//! close-delimited responses (seen on its 401). Because the request carries
//! `Connection: close`, a body without length framing runs to the end of the
//! transcript (RFC 9112 §6.3). Truncation is not detectable at this layer;
//! callers must parse the body strictly (JSON objects cannot be truncated
//! into valid JSON). The fallback also accepts an exact `Content-Length`
//! body, so a spansy limitation unrelated to framing (its JSON grammar) does
//! not reject a well-formed response. Chunked bodies are only accepted
//! through spansy.

use rangeset::set::RangeSet;
use tlsn_formats::http::{Requests, Responses};

/// How the response body length was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// `Content-Length`.
    ContentLength,
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// No length framing: the body runs to the end of the transcript.
    CloseDelimited,
    /// No body (1xx, 204, 304).
    NoBody,
}

impl core::fmt::Display for Framing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Framing::ContentLength => "content-length",
            Framing::Chunked => "chunked",
            Framing::CloseDelimited => "close-delimited",
            Framing::NoBody => "no-body",
        })
    }
}

/// One header as it appears on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    /// Name as sent (compare case-insensitively).
    pub name: String,
    /// Raw value bytes, without surrounding whitespace.
    pub value: Vec<u8>,
    /// Transcript indices of the value.
    pub value_range: RangeSet<usize>,
}

/// A parsed request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Request line including the trailing CRLF.
    pub request_line: String,
    pub method: String,
    pub target: String,
    pub headers: Vec<HttpHeader>,
    /// Body bytes (de-chunked if chunked).
    pub body: Vec<u8>,
}

/// A parsed response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<HttpHeader>,
    /// Body bytes (de-chunked if chunked).
    pub body: Vec<u8>,
    pub framing: Framing,
}

impl HttpRequest {
    /// Headers with `name`, case-insensitively.
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a HttpHeader> {
        headers_named(&self.headers, name)
    }
}

impl HttpResponse {
    /// Headers with `name`, case-insensitively.
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a HttpHeader> {
        headers_named(&self.headers, name)
    }
}

fn headers_named<'a>(
    headers: &'a [HttpHeader],
    name: &'a str,
) -> impl Iterator<Item = &'a HttpHeader> {
    headers
        .iter()
        .filter(move |h| h.name.eq_ignore_ascii_case(name))
}

/// HTTP parsing failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    #[error("malformed request: {0}")]
    Request(String),
    #[error("sent transcript must contain exactly one request and nothing else")]
    RequestCount,
    #[error("malformed response: {0}")]
    Response(String),
    #[error("received transcript must contain exactly one response and nothing else")]
    ResponseCount,
}

const MAX_HEADERS: usize = 128;

/// Parses the sent transcript as exactly one HTTP request.
pub fn parse_request(sent: &[u8]) -> Result<HttpRequest, HttpError> {
    // spansy `expect`s CRLF line endings that httparse does not enforce, so
    // reject bare CR/LF in the head up front (sent bytes are prover-controlled).
    let head_end = find(sent, b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| HttpError::Request("incomplete request head".into()))?;
    if !strict_crlf(&sent[..head_end]) {
        return Err(HttpError::Request("bare CR or LF in request head".into()));
    }

    let request = match Requests::new_from_slice(sent).next() {
        Some(Ok(request)) => request,
        Some(Err(e)) => return Err(HttpError::Request(e.to_string())),
        None => return Err(HttpError::RequestCount),
    };
    if request.indices().end() != Some(sent.len()) {
        return Err(HttpError::RequestCount);
    }

    Ok(HttpRequest {
        request_line: request.request.as_str().into_owned(),
        method: request.request.method.as_str().into_owned(),
        target: request.request.target.as_str().into_owned(),
        headers: request
            .headers
            .iter()
            .map(|h| HttpHeader {
                name: h.name.as_str().into_owned(),
                value: h.value.as_bytes().into_owned(),
                value_range: h.value.indices().clone(),
            })
            .collect(),
        body: request
            .body
            .as_ref()
            .map(|b| b.content_data().into_owned())
            .unwrap_or_default(),
    })
}

/// Parses the received transcript as exactly one HTTP response
/// (spansy first, then the length-framing fallback described in the module docs).
pub fn parse_response(recv: &[u8]) -> Result<HttpResponse, HttpError> {
    match Responses::new_from_slice(recv).next() {
        Some(Ok(response)) => {
            if response.indices().end() != Some(recv.len()) {
                return Err(HttpError::ResponseCount);
            }
            let status = response
                .status
                .code
                .as_str()
                .parse::<u16>()
                .map_err(|e| HttpError::Response(format!("status code: {e}")))?;
            let headers: Vec<HttpHeader> = response
                .headers
                .iter()
                .map(|h| HttpHeader {
                    name: h.name.as_str().into_owned(),
                    value: h.value.as_bytes().into_owned(),
                    value_range: h.value.indices().clone(),
                })
                .collect();
            let framing = match &response.body {
                Some(body) if body.chunks.is_some() => Framing::Chunked,
                Some(_) => Framing::ContentLength,
                None if headers_named(&headers, "content-length").next().is_some() => {
                    Framing::ContentLength
                }
                None => Framing::NoBody,
            };
            let body = response
                .body
                .as_ref()
                .map(|b| b.content_data().into_owned())
                .unwrap_or_default();
            Ok(HttpResponse {
                status,
                headers,
                body,
                framing,
            })
        }
        Some(Err(spansy_err)) => parse_response_fallback(recv, &spansy_err.to_string()),
        None => Err(HttpError::ResponseCount),
    }
}

/// Minimal response parser for bodies spansy refuses (see module docs).
fn parse_response_fallback(recv: &[u8], spansy_err: &str) -> Result<HttpResponse, HttpError> {
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut raw_headers);
    let head_len = match parsed.parse(recv) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return Err(HttpError::Response("incomplete response head".into()));
        }
        Err(e) => return Err(HttpError::Response(e.to_string())),
    };
    if !strict_crlf(&recv[..head_len]) {
        return Err(HttpError::Response("bare CR or LF in response head".into()));
    }
    let status = parsed
        .code
        .ok_or_else(|| HttpError::Response("missing status code".into()))?;

    let base = recv.as_ptr() as usize;
    let headers = parsed
        .headers
        .iter()
        .map(|h| {
            // httparse values borrow from `recv`; recover their offsets.
            let start = (h.value.as_ptr() as usize)
                .checked_sub(base)
                .filter(|start| start + h.value.len() <= head_len)
                .ok_or_else(|| HttpError::Response("header value outside the head".into()))?;
            Ok(HttpHeader {
                name: h.name.to_owned(),
                value: h.value.to_vec(),
                value_range: RangeSet::from(start..start + h.value.len()),
            })
        })
        .collect::<Result<Vec<_>, HttpError>>()?;

    if headers_named(&headers, "transfer-encoding").next().is_some() {
        // Chunked (or other codings) must go through spansy.
        return Err(HttpError::Response(spansy_err.to_owned()));
    }

    let content_length = {
        let mut lengths = headers_named(&headers, "content-length");
        match (lengths.next(), lengths.next()) {
            (None, _) => None,
            (Some(h), None) => Some(h.value.clone()),
            (Some(_), Some(_)) => {
                return Err(HttpError::Response("duplicate content-length".into()));
            }
        }
    };
    let (body, framing) = match content_length {
        None => (recv[head_len..].to_vec(), Framing::CloseDelimited),
        Some(value) => {
            let len: usize = core::str::from_utf8(&value)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| HttpError::Response("invalid content-length".into()))?;
            if head_len.checked_add(len) != Some(recv.len()) {
                // Truncated body, or trailing bytes after it.
                return Err(HttpError::Response(spansy_err.to_owned()));
            }
            (recv[head_len..].to_vec(), Framing::ContentLength)
        }
    };

    Ok(HttpResponse {
        status,
        headers,
        body,
        framing,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Every CR is followed by LF and every LF is preceded by CR.
fn strict_crlf(head: &[u8]) -> bool {
    head.iter().enumerate().all(|(i, &b)| match b {
        b'\r' => head.get(i + 1) == Some(&b'\n'),
        b'\n' => i > 0 && head[i - 1] == b'\r',
        _ => true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{"ok":true}"#;

    fn cl_response() -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n{BODY}",
            BODY.len()
        )
        .into_bytes()
    }

    #[test]
    fn content_length_response() {
        let r = parse_response(&cl_response()).expect("parse");
        assert_eq!(r.status, 200);
        assert_eq!(r.framing, Framing::ContentLength);
        assert_eq!(r.body, BODY.as_bytes());
    }

    #[test]
    fn chunked_response_is_dechunked() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"ok\"\r\n6\r\n:true}\r\n0\r\n\r\n";
        let r = parse_response(raw).expect("parse");
        assert_eq!(r.framing, Framing::Chunked);
        assert_eq!(r.body, BODY.as_bytes());
    }

    #[test]
    fn close_delimited_response_uses_fallback() {
        let raw = format!("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{BODY}");
        let r = parse_response(raw.as_bytes()).expect("parse");
        assert_eq!(r.status, 401);
        assert_eq!(r.framing, Framing::CloseDelimited);
        assert_eq!(r.body, BODY.as_bytes());
    }

    #[test]
    fn truncated_content_length_is_rejected() {
        let raw = cl_response();
        assert!(parse_response(&raw[..raw.len() - 3]).is_err());
    }

    #[test]
    fn trailing_bytes_after_response_are_rejected() {
        let mut raw = cl_response();
        raw.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(parse_response(&raw).err(), Some(HttpError::ResponseCount));
    }

    #[test]
    fn unsupported_transfer_encoding_is_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxx";
        assert!(parse_response(raw).is_err());
    }

    #[test]
    fn header_value_ranges_point_into_the_transcript() {
        let raw = format!("HTTP/1.1 401 Unauthorized\r\nX-A: hello\r\n\r\n{BODY}");
        let r = parse_response(raw.as_bytes()).expect("parse");
        let h = r.headers_named("x-a").next().expect("header");
        let range = h.value_range.iter().next().expect("range").clone();
        assert_eq!(&raw.as_bytes()[range], b"hello");
    }

    #[test]
    fn request_with_body() {
        let raw = format!(
            "POST /graphql HTTP/1.1\r\nhost: h\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{BODY}",
            BODY.len()
        );
        let r = parse_request(raw.as_bytes()).expect("parse");
        assert_eq!(r.request_line, "POST /graphql HTTP/1.1\r\n");
        assert_eq!(r.method, "POST");
        assert_eq!(r.target, "/graphql");
        assert_eq!(r.body, BODY.as_bytes());
        assert_eq!(r.headers.len(), 3);
    }

    #[test]
    fn second_request_is_rejected() {
        let raw = b"GET / HTTP/1.1\r\nhost: h\r\n\r\nGET / HTTP/1.1\r\nhost: h\r\n\r\n";
        assert_eq!(parse_request(raw).err(), Some(HttpError::RequestCount));
    }

    #[test]
    fn bare_lf_in_request_head_is_rejected() {
        let raw = b"GET / HTTP/1.1\r\nhost: h\nx: y\r\n\r\n";
        assert!(matches!(parse_request(raw), Err(HttpError::Request(_))));
    }
}
