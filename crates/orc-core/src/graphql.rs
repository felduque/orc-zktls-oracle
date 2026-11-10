//! The canonical GraphQL request body and the strict response schema.

use serde::{Deserialize, Serialize};

/// The one query orc proves. `$a` is the viewer's node id, so the commit
/// count is for the token owner; [`crate::verify`] checks `$a` equals the
/// `viewer.id` the server returned. `$u` is the snapshot (`until`, a
/// `GitTimestamp`): only commits authored up to it count, and
/// `viewer.createdAt` lets the verifier require an account older than it.
pub const GRAPHQL_QUERY: &str = "query($o:String!,$n:String!,$a:ID!,$u:GitTimestamp!){viewer{login databaseId id createdAt} repository(owner:$o,name:$n){databaseId defaultBranchRef{name target{... on Commit{oid history(author:{id:$a},until:$u,first:1){totalCount}}}}}}";

/// The canonical, byte-exact JSON request body:
/// `{"query":"<GRAPHQL_QUERY>","variables":{"o":<owner>,"n":<name>,"a":<viewer_node_id>,"u":<until>}}`.
///
/// `until` is the snapshot as `YYYY-MM-DDTHH:MM:SSZ`
/// ([`crate::time::format_utc`]). No whitespace; values are JSON string
/// literals escaped exactly like `serde_json` does. The verifier recomputes
/// this from the guest input and the authenticated `viewer.id` and compares
/// bytes, so any other body (different variables, extra fields, different
/// query) is rejected.
pub fn graphql_body(owner: &str, name: &str, viewer_node_id: &str, until: &str) -> String {
    let mut body = String::with_capacity(GRAPHQL_QUERY.len() + 96);
    body.push_str(r#"{"query":"#);
    push_json_string(&mut body, GRAPHQL_QUERY);
    body.push_str(r#","variables":{"o":"#);
    push_json_string(&mut body, owner);
    body.push_str(r#","n":"#);
    push_json_string(&mut body, name);
    body.push_str(r#","a":"#);
    push_json_string(&mut body, viewer_node_id);
    body.push_str(r#","u":"#);
    push_json_string(&mut body, until);
    body.push_str("}}");
    body
}

/// Appends `s` as a JSON string literal (RFC 8259), matching `serde_json`'s
/// escaping: short escapes for `" \ \b \f \n \r \t`, `\u00xx` (lowercase hex)
/// for other control characters, everything else verbatim.
fn push_json_string(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let b = c as u32 as usize;
                out.push_str("\\u00");
                out.push(char::from(HEX[b >> 4]));
                out.push(char::from(HEX[b & 0xf]));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---- strict response schema -------------------------------------------------
//
// Every level denies unknown fields, so a top-level `errors` key (partial
// results), `extensions`, or any shape other than exactly what
// GRAPHQL_QUERY selects fails to parse. Nullable GraphQL fields are not
// `Option`: a missing repository or an empty repo (no default branch) fails.

/// `{"data": ...}` and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlResponse {
    pub data: ClaimData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimData {
    pub viewer: Viewer,
    pub repository: Repository,
}

/// The token owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Viewer {
    pub login: String,
    pub database_id: u64,
    /// GraphQL node id; must equal the `$a` variable in the request body.
    pub id: String,
    /// Account creation time, `YYYY-MM-DDTHH:MM:SSZ` (a GraphQL `DateTime`);
    /// must be before the snapshot.
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Repository {
    pub database_id: u64,
    pub default_branch_ref: BranchRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchRef {
    pub name: String,
    pub target: Commit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub oid: String,
    pub history: History,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct History {
    /// Commits on the default branch authored by the viewer.
    pub total_count: u64,
}

/// Strictly parses a GraphQL response body. Trailing non-whitespace,
/// truncation, unknown keys and duplicate keys are all errors.
pub fn parse_response(body: &[u8]) -> Result<GraphqlResponse, serde_json::Error> {
    serde_json::from_slice(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{"data":{"viewer":{"login":"octo","databaseId":583231,"id":"U_kgDOAAA","createdAt":"2015-06-01T12:34:56Z"},"repository":{"databaseId":1300192,"defaultBranchRef":{"name":"main","target":{"oid":"abc","history":{"totalCount":42}}}}}}"#;

    #[test]
    fn body_matches_plan_template_byte_for_byte() {
        let body = graphql_body("tlsnotary", "tlsn", "U_kgDOAAA", "2026-01-01T00:00:00Z");
        let expected = concat!(
            r#"{"query":"query($o:String!,$n:String!,$a:ID!,$u:GitTimestamp!){viewer{login databaseId id createdAt} repository(owner:$o,name:$n){databaseId defaultBranchRef{name target{... on Commit{oid history(author:{id:$a},until:$u,first:1){totalCount}}}}}}","#,
            r#""variables":{"o":"tlsnotary","n":"tlsn","a":"U_kgDOAAA","u":"2026-01-01T00:00:00Z"}}"#
        );
        assert_eq!(body, expected);
    }

    #[test]
    fn body_is_valid_json_with_the_expected_variables() {
        let body = graphql_body("o", "n", "a", "u");
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(v["query"], GRAPHQL_QUERY);
        assert_eq!(v["variables"]["o"], "o");
        assert_eq!(v["variables"]["n"], "n");
        assert_eq!(v["variables"]["a"], "a");
        assert_eq!(v["variables"]["u"], "u");
        assert_eq!(v["variables"].as_object().map(|o| o.len()), Some(4));
    }

    #[test]
    fn escaping_matches_serde_json() {
        for s in [
            "plain",
            "q\"uote",
            "back\\slash",
            "nl\n cr\r tab\t",
            "\u{1}\u{1f}\u{7f}",
            "ünï",
        ] {
            let mut ours = String::new();
            push_json_string(&mut ours, s);
            assert_eq!(
                ours,
                serde_json::to_string(s).expect("serialize"),
                "input {s:?}"
            );
        }
    }

    #[test]
    fn valid_response_parses() {
        let r = parse_response(VALID.as_bytes()).expect("parse");
        assert_eq!(r.data.viewer.id, "U_kgDOAAA");
        assert_eq!(
            r.data
                .repository
                .default_branch_ref
                .target
                .history
                .total_count,
            42
        );
    }

    #[test]
    fn errors_key_is_rejected() {
        let with_errors =
            VALID.replacen("{\"data\"", "{\"errors\":[{\"message\":\"x\"}],\"data\"", 1);
        assert!(parse_response(with_errors.as_bytes()).is_err());
    }

    #[test]
    fn unknown_nested_field_is_rejected() {
        let extra = VALID.replacen("\"login\"", "\"name\":\"x\",\"login\"", 1);
        assert!(parse_response(extra.as_bytes()).is_err());
    }

    #[test]
    fn null_repository_is_rejected() {
        let null_repo = r#"{"data":{"viewer":{"login":"o","databaseId":1,"id":"U","createdAt":"2015-06-01T12:34:56Z"},"repository":null}}"#;
        assert!(parse_response(null_repo.as_bytes()).is_err());
    }

    #[test]
    fn missing_or_null_created_at_is_rejected() {
        let missing = VALID.replacen(",\"createdAt\":\"2015-06-01T12:34:56Z\"", "", 1);
        assert_ne!(missing, VALID);
        assert!(parse_response(missing.as_bytes()).is_err());
        let null = VALID.replacen("\"2015-06-01T12:34:56Z\"", "null", 1);
        assert!(parse_response(null.as_bytes()).is_err());
    }

    #[test]
    fn truncation_is_rejected_at_every_cut() {
        for cut in 0..VALID.len() {
            assert!(
                parse_response(&VALID.as_bytes()[..cut]).is_err(),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let dup = VALID.replacen(
            "\"login\":\"octo\"",
            "\"login\":\"octo\",\"login\":\"evil\"",
            1,
        );
        assert!(parse_response(dup.as_bytes()).is_err());
    }
}
