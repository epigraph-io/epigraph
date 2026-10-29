//! The advertised input schema of MCP `query_claims_by_label` (backlog
//! 6f072833, ruling R-9). LLM callers learn the keyset contract only from the
//! tool's JSON schema, so it must name the `after` parameter and say that the
//! response then carries `next_cursor` to pass back.
//!
//! Kept apart from `query_claims_by_label_cursor.rs` so it builds against a
//! params struct without the field and fails on the assertion there.

use epigraph_mcp::types::QueryClaimsByLabelParams;

#[test]
fn advertised_schema_documents_the_after_cursor_and_next_cursor() {
    let schema = serde_json::to_value(schemars::schema_for!(QueryClaimsByLabelParams))
        .expect("schema serializes");
    let after = &schema["properties"]["after"];
    assert!(
        after.is_object(),
        "the tool schema must advertise an `after` parameter: {}",
        schema["properties"]
    );
    let description = after["description"].as_str().unwrap_or_default();
    assert!(
        description.contains("next_cursor"),
        "`after` must tell the caller to pass back next_cursor: {description:?}"
    );
    assert!(
        description.contains("{claims"),
        "`after` must say the response becomes the {{claims, next_cursor}} envelope: {description:?}"
    );
    assert!(
        !schema["required"]
            .as_array()
            .is_some_and(|r| r.iter().any(|v| v == "after")),
        "`after` must stay optional so legacy callers are unaffected: {schema}"
    );
}
