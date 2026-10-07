//! The per-access elevated-read log's Rust half (elevation plan EL-8,
//! migration 127): what a serving process hands the recorder, how it finds
//! the ids an elevated response named, and the one call that records.
//!
//! # Who records, and on what connection
//!
//! The API's response layer and the MCP tool-call wrapper record every
//! request served to an ELEVATED viewer, BEFORE the response leaves, through
//! `ScopedPool::record_elevated_access` (one transaction stamped with that
//! viewer). If recording fails, the response is withheld: the caller maps the
//! error to a server error and drops the body. Only a pool built by
//! `ScopedPool::connect_recording_elevated_access` declares the recorder
//! (`crate::ACCESS_RECORDER_GUC`), and a connection that does not declare it
//! is never elevated, so a process that does not record never serves an
//! elevated read.
//!
//! # The database decides; the process collects
//!
//! [`candidate_ids_in`] collects every id-shaped string a response carries;
//! the definer decides which of them name a private row the viewer could not
//! read unelevated, and whose group owns it. [`rows_in`] counts the rows the
//! response carried. [`id_fields_in`] keeps a request body's id-shaped fields
//! (never its content) for the row's `args`.

use crate::errors::DbError;
use std::collections::BTreeMap;
use uuid::Uuid;

/// One elevated request, as the serving process describes it to the recorder.
#[derive(Debug, Clone, PartialEq)]
pub struct ElevatedAccess {
    /// The route (`GET /api/v1/claims/:id`) or tool (`mcp:get_claim`).
    pub surface: String,
    /// The request's ids and filters (path, query, id-shaped body fields),
    /// never content. A JSON object; 127 bounds its size.
    pub args: serde_json::Value,
    /// How many rows the response carried ([`rows_in`]).
    pub row_count: i32,
    /// Every id the response named ([`candidate_ids_in`]).
    pub candidate_ids: Vec<Uuid>,
}

/// The most ids [`id_fields_in`] keeps from one request body.
pub const MAX_ARG_IDS: usize = 256;

/// The longest surface the log accepts (127's CHECK).
pub const MAX_SURFACE_LEN: usize = 512;

/// Record one elevated request through migration 127's recorder,
/// `epigraph_record_elevated_access`, on `conn`, which the caller has stamped
/// with an ELEVATED viewer. The definer refuses (`ELV07`) a connection that is
/// not elevated; it takes the session, person, assignment and reason from the
/// session row and decides the owner groups itself. Returns the row's id.
///
/// # Errors
/// `DbError::QueryFailed` when the recorder refuses or the statement fails.
pub(crate) async fn record(
    conn: &mut sqlx::PgConnection,
    access: &ElevatedAccess,
) -> Result<Uuid, DbError> {
    let id: Uuid =
        sqlx::query_scalar("SELECT public.epigraph_record_elevated_access($1, $2, $3, $4)")
            .bind(&access.surface)
            .bind(&access.args)
            .bind(access.row_count)
            .bind(&access.candidate_ids)
            .fetch_one(&mut *conn)
            .await?;
    Ok(id)
}

const UUID_LEN: usize = 36;

/// Whether `b[i..i + 36]` is a hyphenated UUID (8-4-4-4-12 hex digits).
fn uuid_at(b: &[u8], i: usize) -> bool {
    if i + UUID_LEN > b.len() {
        return false;
    }
    b[i..i + UUID_LEN].iter().enumerate().all(|(k, c)| {
        if matches!(k, 8 | 13 | 18 | 23) {
            *c == b'-'
        } else {
            c.is_ascii_hexdigit()
        }
    })
}

/// Every distinct hyphenated UUID in `body`, in order of first appearance.
///
/// A byte scan, not a JSON walk: it reads ids anywhere (a JSON string, an
/// MCP tool's text content, an escaped JSON document inside a string, a
/// plain-text error), with no word boundary required. Over-collecting is
/// harmless (the recorder ignores an id that names no row); missing an id
/// would hide a subject, so the scan errs wide.
#[must_use]
pub fn candidate_ids_in(body: &[u8]) -> Vec<Uuid> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut i = 0;
    while i + UUID_LEN <= body.len() {
        if uuid_at(body, i) {
            // The window is ASCII by construction.
            let text = std::str::from_utf8(&body[i..i + UUID_LEN]).unwrap_or_default();
            if let Ok(id) = Uuid::parse_str(text) {
                if seen.insert(id) {
                    out.push(id);
                }
            }
            i += UUID_LEN;
        } else {
            i += 1;
        }
    }
    out
}

fn is_uuid_str(s: &str) -> bool {
    s.len() == UUID_LEN && uuid_at(s.as_bytes(), 0)
}

/// How many rows a JSON response carried: the number of objects, at any
/// depth, that have an `id` field holding a UUID. A by-id read is 1, a list
/// of N rows is N (plus any nested row object), an aggregate is 0. Saturates
/// at `i32::MAX`.
#[must_use]
pub fn rows_in(body: &serde_json::Value) -> i32 {
    fn walk(v: &serde_json::Value, n: &mut u64) {
        match v {
            serde_json::Value::Object(m) => {
                if m.get("id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(is_uuid_str)
                {
                    *n += 1;
                }
                for child in m.values() {
                    walk(child, n);
                }
            }
            serde_json::Value::Array(a) => {
                for child in a {
                    walk(child, n);
                }
            }
            _ => {}
        }
    }
    let mut n = 0_u64;
    walk(body, &mut n);
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// The id-shaped fields of a request body, by field name: every field (at any
/// depth) whose value is a UUID string or an array holding UUID strings, and
/// nothing else, so no content reaches the log. At most [`MAX_ARG_IDS`] ids
/// in all.
#[must_use]
pub fn id_fields_in(body: &serde_json::Value) -> serde_json::Value {
    fn walk(v: &serde_json::Value, out: &mut BTreeMap<String, Vec<String>>, kept: &mut usize) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, child) in m {
                    let mut push = |s: &str| {
                        if *kept < MAX_ARG_IDS && is_uuid_str(s) {
                            out.entry(k.clone()).or_default().push(s.to_string());
                            *kept += 1;
                        }
                    };
                    match child {
                        serde_json::Value::String(s) => push(s),
                        serde_json::Value::Array(a) => {
                            for e in a {
                                if let serde_json::Value::String(s) = e {
                                    push(s);
                                }
                            }
                        }
                        _ => {}
                    }
                    walk(child, out, kept);
                }
            }
            serde_json::Value::Array(a) => {
                for child in a {
                    walk(child, out, kept);
                }
            }
            _ => {}
        }
    }
    let mut out = BTreeMap::new();
    let mut kept = 0;
    walk(body, &mut out, &mut kept);
    serde_json::json!(out)
}

/// `s` cut to at most `max` bytes on a character boundary.
#[must_use]
pub fn bounded(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const B: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

    #[test]
    fn candidate_ids_are_found_anywhere_and_once() {
        // A JSON body whose text field carries an escaped JSON document, as an
        // MCP tool result's text content does.
        let body =
            format!(r#"{{"id":"{A}","x":["{B}","{A}"],"text":"see {B} and {{\"id\":\"{A}\"}}"}}"#);
        let ids = candidate_ids_in(body.as_bytes());
        assert_eq!(
            ids,
            vec![Uuid::parse_str(A).unwrap(), Uuid::parse_str(B).unwrap()],
            "both ids, once each, in order of first appearance"
        );
        // No word boundary is required: an id glued to other text is still
        // collected (erring wide).
        assert_eq!(
            candidate_ids_in(format!("ref:{A}0").as_bytes()),
            vec![Uuid::parse_str(A).unwrap()]
        );
        assert!(candidate_ids_in(b"no ids here").is_empty());
        assert!(
            candidate_ids_in(&A.as_bytes()[..35]).is_empty(),
            "a cut id is not one"
        );
        assert_eq!(
            candidate_ids_in(A.to_uppercase().as_bytes()),
            vec![Uuid::parse_str(A).unwrap()],
            "upper case hex"
        );
    }

    #[test]
    fn rows_are_objects_with_a_uuid_id() {
        let one = serde_json::json!({"id": A, "content": "c", "agent_id": B});
        assert_eq!(rows_in(&one), 1);
        let list = serde_json::json!({"claims": [{"id": A}, {"id": B}, {"id": A}], "total": 3});
        assert_eq!(rows_in(&list), 3);
        let agg = serde_json::json!({"count": 12, "by_type": {"a": 1}});
        assert_eq!(rows_in(&agg), 0);
        assert_eq!(rows_in(&serde_json::json!({"id": "not-a-uuid"})), 0);
        assert_eq!(rows_in(&serde_json::json!({"id": 7})), 0);
    }

    #[test]
    fn id_fields_keep_ids_and_drop_content() {
        let body = serde_json::json!({
            "claim_id": A,
            "content": "secret prose",
            "ids": [A, B, "x"],
            "nested": {"target": B, "note": "more prose"},
            "limit": 5,
        });
        let kept = id_fields_in(&body);
        assert_eq!(
            kept,
            serde_json::json!({"claim_id": [A], "ids": [A, B], "target": [B]})
        );
        assert!(!kept.to_string().contains("prose"));
    }

    #[test]
    fn id_fields_are_capped() {
        let many: Vec<String> = (0..(MAX_ARG_IDS + 10))
            .map(|_| Uuid::new_v4().to_string())
            .collect();
        let kept = id_fields_in(&serde_json::json!({ "ids": many }));
        assert_eq!(kept["ids"].as_array().map(Vec::len), Some(MAX_ARG_IDS));
    }

    #[test]
    fn bounded_cuts_on_a_char_boundary() {
        assert_eq!(bounded("abc", 5), "abc");
        assert_eq!(bounded("abcdef", 3), "abc");
        assert_eq!(bounded("aé", 2), "a");
    }
}
