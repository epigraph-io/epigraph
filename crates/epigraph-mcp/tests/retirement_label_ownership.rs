//! The `resolved`-label ownership gate on `update_labels` / `patch_claim`
//! (issue #374).
//!
//! `resolve_backlog_item`, `supersede_claim` and `mark_duplicate` all run
//! `require_owner_or_admin`; `update_labels` and `patch_claim` ran nothing,
//! while reaching the same observable end state — a claim carrying `resolved`
//! disappears from `query_claims_by_label(labels=["backlog"],
//! exclude_labels=["resolved"])` whether or not the caller owned it, and
//! without the resolution claim the gated verb exists to create.
//!
//! What these tests pin:
//!
//! * with an `AuthContext` (HTTP), adding OR removing `resolved` on a claim the
//!   principal neither owns nor has `claims:admin` for is refused, and nothing
//!   is written;
//! * `claims:admin` still passes;
//! * every OTHER label is still ungated for a foreign principal — the gate is
//!   scoped to the one label with retirement semantics, because cross-agent
//!   taxonomy maintenance is legitimate and high-volume;
//! * with `auth = None` (stdio) the mutation is still permitted. That carve-out
//!   is deliberate and load-bearing: epiclaw's agent-runner exports
//!   `EPIGRAPH_AGENT_MODEL`/`EPIGRAPH_AGENT_SYSTEM_PROMPT_HASH`, so the fleet
//!   runs with `signer_identity_declared = true` and CANNOT reach
//!   `resolve_backlog_item` for a cross-agent claim; gating stdio would leave
//!   those agents no way to retire a backlog item at all.

use epigraph_auth::{AuthContext, ClientType};
use epigraph_mcp::types::{PatchClaimParams, UpdateLabelsParams};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::{build_test_server, seed_claim_with_labels};

fn write_auth(principal: Uuid) -> AuthContext {
    AuthContext {
        client_id: principal,
        agent_id: None,
        owner_id: Some(principal),
        client_type: ClientType::Service,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
    }
}

fn admin_write_auth() -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: None,
        owner_id: None,
        client_type: ClientType::Service,
        scopes: vec!["claims:admin".to_string()],
        jti: Uuid::new_v4(),
    }
}

async fn labels_of(pool: &PgPool, claim_id: Uuid) -> Vec<String> {
    let (labels,): (Vec<String>,) =
        sqlx::query_as("SELECT COALESCE(labels, ARRAY[]::text[]) FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .expect("read labels");
    labels
}

/// The bypass the reporter actually exercised: an HTTP `claims:write` token
/// retiring a claim owned by someone else.
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_adding_resolved_to_a_foreign_claim_is_refused(pool: PgPool) {
    let claim = seed_claim_with_labels(&pool, "someone else's backlog item", &["backlog"]).await;
    let server = build_test_server(pool.clone());

    let err = epigraph_mcp::tools::claims::update_labels(
        &server,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec!["resolved".into()],
            remove: vec![],
        },
        Some(&write_auth(Uuid::new_v4())),
    )
    .await
    .expect_err("a non-owner without claims:admin must not be able to retire a claim");

    let msg = err.message.to_string();
    assert!(
        msg.contains("claims:admin") || msg.contains("ownership"),
        "denial must cite the required permission, got: {msg:?}"
    );

    let labels = labels_of(&pool, claim).await;
    assert!(
        !labels.contains(&"resolved".to_string()),
        "refused call must not have written the label: {labels:?}"
    );
}

/// Removing `resolved` un-retires a claim, which is the same authority as
/// retiring it — so the gate covers both directions.
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_removing_resolved_from_a_foreign_claim_is_refused(pool: PgPool) {
    let claim = seed_claim_with_labels(
        &pool,
        "someone else's retired item",
        &["backlog", "resolved"],
    )
    .await;
    let server = build_test_server(pool.clone());

    epigraph_mcp::tools::claims::update_labels(
        &server,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec![],
            remove: vec!["resolved".into()],
        },
        Some(&write_auth(Uuid::new_v4())),
    )
    .await
    .expect_err("un-retiring a foreign claim must be refused too");

    let labels = labels_of(&pool, claim).await;
    assert!(
        labels.contains(&"resolved".to_string()),
        "refused call must not have removed the label: {labels:?}"
    );
}

/// `patch_claim` accepts `add_labels` too, so an ungated twin would just move
/// the bypass one tool over. Also asserts the non-label halves of the patch did
/// not land — a gate that refuses after writing `properties` is not a gate.
#[sqlx::test(migrations = "../../migrations")]
async fn patch_claim_adding_resolved_to_a_foreign_claim_is_refused(pool: PgPool) {
    let claim = seed_claim_with_labels(&pool, "patch_claim bypass subject", &["backlog"]).await;
    let server = build_test_server(pool.clone());

    epigraph_mcp::tools::claims::patch_claim(
        &server,
        PatchClaimParams {
            claim_id: claim.to_string(),
            trace_id: None,
            properties: Some(serde_json::json!({"retired_by": "not-the-owner"})),
            add_labels: vec!["resolved".into()],
            remove_labels: vec![],
        },
        Some(&write_auth(Uuid::new_v4())),
    )
    .await
    .expect_err("patch_claim must enforce the same gate as update_labels");

    let labels = labels_of(&pool, claim).await;
    assert!(
        !labels.contains(&"resolved".to_string()),
        "refused patch must not have written the label: {labels:?}"
    );

    let (props,): (serde_json::Value,) =
        sqlx::query_as("SELECT COALESCE(properties, '{}'::jsonb) FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read properties");
    assert!(
        props.get("retired_by").is_none(),
        "the gate must run BEFORE the patch transaction; got {props}"
    );
}

/// `claims:admin` is the sanctioned cross-agent route and must still work.
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_admin_scope_may_retire_a_foreign_claim(pool: PgPool) {
    let claim = seed_claim_with_labels(&pool, "admin-retired item", &["backlog"]).await;
    let server = build_test_server(pool.clone());

    epigraph_mcp::tools::claims::update_labels(
        &server,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec!["resolved".into()],
            remove: vec![],
        },
        Some(&admin_write_auth()),
    )
    .await
    .expect("claims:admin must still be able to retire a foreign claim");

    let labels = labels_of(&pool, claim).await;
    assert!(labels.contains(&"resolved".to_string()), "{labels:?}");
}

/// Scope control. This is the behaviour a blanket `require_owner_or_admin`
/// would have broken, and it is exactly the 161-claim relabel the reporter
/// describes as legitimate. Passes before and after the change by design.
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_leaves_non_retirement_labels_ungated_for_a_foreign_principal(pool: PgPool) {
    let claim =
        seed_claim_with_labels(&pool, "cross-agent taxonomy maintenance", &["backlog"]).await;
    let server = build_test_server(pool.clone());

    epigraph_mcp::tools::claims::update_labels(
        &server,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec!["telemetry".into()],
            remove: vec!["backlog".into()],
        },
        Some(&write_auth(Uuid::new_v4())),
    )
    .await
    .expect("free-form label maintenance must remain ungated");

    let labels = labels_of(&pool, claim).await;
    assert!(labels.contains(&"telemetry".to_string()), "{labels:?}");
    assert!(!labels.contains(&"backlog".to_string()), "{labels:?}");
}

/// The stdio carve-out, pinned so it cannot be closed by accident. `auth =
/// None` is the transport epiclaw's scheduled agents run on, and their
/// documented retirement procedure is exactly this call. Closing it without
/// first making `resolve_backlog_item` reachable for them would break the
/// fleet, not an abuse.
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_still_permits_resolved_on_the_unauthenticated_stdio_path(pool: PgPool) {
    let claim = seed_claim_with_labels(&pool, "epiclaw-retired item", &["backlog"]).await;
    let server = build_test_server(pool.clone());

    epigraph_mcp::tools::claims::update_labels(
        &server,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec!["resolved".into()],
            remove: vec![],
        },
        None,
    )
    .await
    .expect("stdio retirement must keep working until the sanctioned path is reachable");

    let labels = labels_of(&pool, claim).await;
    assert!(labels.contains(&"resolved".to_string()), "{labels:?}");
}
