//! End-to-end tests for the `patch_edge` / `delete_edge` MCP tools.
//!
//! Drives `do_patch_edge` / `do_delete_edge` directly against a `sqlx::test`
//! pool, so the same repo layer the production rmcp dispatcher uses is
//! exercised. The assertions that matter are the ones a "call returned Ok"
//! smoke test would miss:
//!
//! * `properties` really SHALLOW-merges (non-overlapping keys survive) —
//!   mirrors `routes/edges.rs`'s "PATCH /edges/:id shallow-merges properties"
//!   case, which is the behaviour the JSONB `||` operator gives and which a
//!   naive `SET properties = $2` would silently break;
//! * a non-object `properties` is REJECTED BEFORE reaching Postgres, which
//!   would otherwise turn the column into an array with no error;
//! * `valid_to` only moves when asked, and a properties-only patch leaves the
//!   lifecycle window open (the repo's `COALESCE($2, valid_to)` contract);
//! * a delete removes exactly the targeted row and leaves its siblings alone.

mod common;

use common::{build_test_server, seed_claim};
use epigraph_mcp::tools::edge_mutation::{do_delete_edge, do_patch_edge};
use epigraph_mcp::types::{DeleteEdgeParams, PatchEdgeParams};
use sqlx::PgPool;
use uuid::Uuid;

fn response_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .expect("at least one content block")
        .as_text()
        .expect("text content")
        .text
        .clone();
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("response JSON: {e}; raw={text}"))
}

/// Insert an edge row directly (no MCP tool creates edges with pre-set
/// properties AND returns the row, and these tests are about mutation, not
/// creation).
async fn seed_edge(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    relationship: &str,
    properties: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'claim', $2, 'claim', $3, $4) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .bind(properties)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

async fn read_edge(
    pool: &PgPool,
    edge_id: Uuid,
) -> Option<(serde_json::Value, Option<chrono::DateTime<chrono::Utc>>)> {
    sqlx::query_as::<_, (serde_json::Value, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT properties, valid_to FROM edges WHERE id = $1",
    )
    .bind(edge_id)
    .fetch_optional(pool)
    .await
    .expect("read edge")
}

/// Count durable `events` rows of `event_type` carrying this `edge_id` in
/// their payload. Both tools emit through `EventRepository::publish_or_log`,
/// whose failures are swallowed by design (`let _ = …`) — so a silently broken
/// event path is invisible unless the row itself is asserted.
async fn edge_event_count(pool: &PgPool, event_type: &str, edge_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM events WHERE event_type = $1 AND payload->>'edge_id' = $2",
    )
    .bind(event_type)
    .bind(edge_id.to_string())
    .fetch_one(pool)
    .await
    .expect("count events")
}

// ── patch: shallow merge + retirement ───────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn patch_shallow_merges_properties_and_retires(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let source = seed_claim(&pool, "source claim", 0.5).await;
    let target = seed_claim(&pool, "target claim", 0.5).await;
    let edge_id = seed_edge(
        &pool,
        source,
        target,
        "contradicts",
        serde_json::json!({"keep": "me", "overwrite": "old"}),
    )
    .await;

    // ── properties-only patch: merges, and must NOT close the window ──
    let merged = do_patch_edge(
        &server,
        PatchEdgeParams {
            edge_id: edge_id.to_string(),
            valid_to: None,
            properties: Some(serde_json::json!({"overwrite": "new", "added": 1})),
        },
    )
    .await
    .expect("properties-only patch succeeds");
    let merged_json = response_json(&merged);

    let (props, valid_to) = read_edge(&pool, edge_id).await.expect("edge still present");
    assert_eq!(
        props,
        serde_json::json!({"keep": "me", "overwrite": "new", "added": 1}),
        "patch must SHALLOW-merge: untouched keys preserved, overlapping keys overwritten, \
         new keys added"
    );
    assert!(
        valid_to.is_none(),
        "a properties-only patch must leave the lifecycle window open"
    );
    assert_eq!(
        merged_json["retired"], false,
        "retired must be false when the patch did not set valid_to"
    );
    assert_eq!(
        merged_json["properties"], props,
        "the response must echo the post-merge properties actually stored"
    );
    assert_eq!(merged_json["relationship"], "contradicts");
    assert_eq!(merged_json["source_id"], source.to_string());
    assert_eq!(merged_json["target_id"], target.to_string());

    // `edge.updated` fires on every patch; `edge.retired` is reserved for the
    // patch that closes the lifecycle window and must NOT fire here.
    assert_eq!(
        edge_event_count(&pool, "edge.updated", edge_id).await,
        1,
        "a properties patch must emit exactly one edge.updated"
    );
    assert_eq!(
        edge_event_count(&pool, "edge.retired", edge_id).await,
        0,
        "edge.retired must NOT fire for a patch that left valid_to untouched"
    );

    // ── retire with the "now" literal ──
    let retired = do_patch_edge(
        &server,
        PatchEdgeParams {
            edge_id: edge_id.to_string(),
            valid_to: Some("now".to_string()),
            properties: None,
        },
    )
    .await
    .expect("retirement patch succeeds");
    let retired_json = response_json(&retired);

    let (props_after, valid_to_after) = read_edge(&pool, edge_id).await.expect("edge survives");
    assert!(
        valid_to_after.is_some(),
        "valid_to=\"now\" must close the lifecycle window"
    );
    assert_eq!(
        retired_json["retired"], true,
        "retired must be true when the patch set valid_to"
    );
    assert_eq!(
        props_after,
        serde_json::json!({"keep": "me", "overwrite": "new", "added": 1}),
        "a valid_to-only patch must not disturb properties"
    );
    // Retiring is non-destructive by definition — the row is the audit trail.
    assert!(
        read_edge(&pool, edge_id).await.is_some(),
        "patch must never delete the row"
    );

    assert_eq!(
        edge_event_count(&pool, "edge.retired", edge_id).await,
        1,
        "closing the lifecycle window must emit edge.retired"
    );
    assert_eq!(
        edge_event_count(&pool, "edge.updated", edge_id).await,
        2,
        "edge.updated fires on every patch, so two patches means two rows"
    );
}

// ── patch: guards ───────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn patch_rejects_non_object_properties_without_corrupting_the_column(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let source = seed_claim(&pool, "source claim", 0.5).await;
    let target = seed_claim(&pool, "target claim", 0.5).await;
    let edge_id = seed_edge(
        &pool,
        source,
        target,
        "supports",
        serde_json::json!({"a": 1}),
    )
    .await;

    // Postgres would evaluate '{"a":1}'::jsonb || '5'::jsonb to [{"a":1}, 5]
    // — object silently becomes array. The guard must fire first.
    for bad in [
        serde_json::json!(5),
        serde_json::json!("str"),
        serde_json::json!([1, 2]),
        serde_json::json!(null),
    ] {
        let err = do_patch_edge(
            &server,
            PatchEdgeParams {
                edge_id: edge_id.to_string(),
                valid_to: None,
                properties: Some(bad.clone()),
            },
        )
        .await
        .unwrap_err_or_panic(&format!("non-object properties {bad} must be rejected"));
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    let (props, _) = read_edge(&pool, edge_id).await.expect("edge present");
    assert_eq!(
        props,
        serde_json::json!({"a": 1}),
        "a rejected patch must leave the JSONB column untouched (still an object)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn patch_rejects_empty_body_and_unknown_edge(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let empty = do_patch_edge(
        &server,
        PatchEdgeParams {
            edge_id: Uuid::new_v4().to_string(),
            valid_to: None,
            properties: None,
        },
    )
    .await
    .expect_err("empty patch body must be rejected");
    assert_eq!(empty.code, rmcp::model::ErrorCode::INVALID_PARAMS);

    // Unknown edge must be a caller-actionable INVALID_PARAMS naming the id,
    // not an opaque INTERNAL_ERROR an autonomous agent cannot recover from.
    let missing_id = Uuid::new_v4();
    let missing = do_patch_edge(
        &server,
        PatchEdgeParams {
            edge_id: missing_id.to_string(),
            valid_to: Some("now".to_string()),
            properties: None,
        },
    )
    .await
    .expect_err("patching a nonexistent edge must fail");
    assert_eq!(missing.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(
        missing.message.contains(&missing_id.to_string()),
        "not-found message must name the edge id, got: {}",
        missing.message
    );
}

// ── delete ──────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn delete_removes_only_the_targeted_edge(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let source = seed_claim(&pool, "source claim", 0.5).await;
    let target = seed_claim(&pool, "target claim", 0.5).await;
    let doomed = seed_edge(&pool, source, target, "contradicts", serde_json::json!({})).await;
    // Same endpoints, different relationship — must survive.
    let sibling = seed_edge(&pool, source, target, "supports", serde_json::json!({})).await;

    let result = do_delete_edge(
        &server,
        DeleteEdgeParams {
            edge_id: doomed.to_string(),
        },
    )
    .await
    .expect("delete succeeds");
    let json = response_json(&result);
    assert_eq!(json["deleted"], true);
    assert_eq!(json["edge_id"], doomed.to_string());

    // The row must SURVIVE and be out of force. Under the previous hard delete this
    // asserted `is_none()`; edge removal is now a retraction, so destroying the row
    // would destroy its provenance along with it.
    let (_props, closed_at) = read_edge(&pool, doomed)
        .await
        .expect("the targeted edge row must survive retraction");
    assert!(
        closed_at.is_some(),
        "the targeted edge must be out of force (valid_to set)"
    );
    assert!(
        read_edge(&pool, sibling).await.is_some(),
        "an edge sharing both endpoints must NOT be collaterally deleted"
    );
    assert_eq!(
        edge_event_count(&pool, "edge.deleted", doomed).await,
        1,
        "delete must emit exactly one edge.deleted for the targeted edge"
    );
    assert_eq!(
        edge_event_count(&pool, "edge.deleted", sibling).await,
        0,
        "no edge.deleted may be emitted for the surviving sibling"
    );

    // Re-deleting is an error naming the id, not a silent deleted=false —
    // otherwise a retry cannot distinguish "already done" from "wrong id".
    let repeat = do_delete_edge(
        &server,
        DeleteEdgeParams {
            edge_id: doomed.to_string(),
        },
    )
    .await
    .expect_err("deleting a nonexistent edge must fail");
    assert_eq!(repeat.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert!(repeat.message.contains(&doomed.to_string()));
}

/// Small helper so the loop above reads cleanly.
trait UnwrapErrOrPanic<T, E> {
    fn unwrap_err_or_panic(self, msg: &str) -> E;
}

impl<T, E> UnwrapErrOrPanic<T, E> for Result<T, E> {
    fn unwrap_err_or_panic(self, msg: &str) -> E {
        match self {
            Ok(_) => panic!("{msg}"),
            Err(e) => e,
        }
    }
}
