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

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::types::{PatchClaimParams, UpdateLabelsParams};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::{build_scoped_test_server, seed_claim_with_labels};

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
    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_caller, caller_auth, caller_viewer) = common::seed_caller(&pool, &["claims:write"]).await;

    let err = epigraph_mcp::tools::claims::update_labels(
        &server,
        &caller_viewer,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec!["resolved".into()],
            remove: vec![],
        },
        Some(&caller_auth),
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
    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_caller, caller_auth, caller_viewer) = common::seed_caller(&pool, &["claims:write"]).await;

    epigraph_mcp::tools::claims::update_labels(
        &server,
        &caller_viewer,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec![],
            remove: vec!["resolved".into()],
        },
        Some(&caller_auth),
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
    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_caller, caller_auth, caller_viewer) = common::seed_caller(&pool, &["claims:write"]).await;

    epigraph_mcp::tools::claims::patch_claim(
        &server,
        &caller_viewer,
        PatchClaimParams {
            claim_id: claim.to_string(),
            trace_id: None,
            properties: Some(serde_json::json!({"retired_by": "not-the-owner"})),
            add_labels: vec!["resolved".into()],
            remove_labels: vec![],
        },
        Some(&caller_auth),
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

/// `claims:admin` satisfies issue #374's retirement AUTHZ gate on a foreign
/// claim — the gate must admit the sanctioned cross-agent route.
///
/// # What this arm does and does NOT measure, and why the name changed
///
/// It was called `update_labels_admin_scope_may_retire_a_foreign_claim`, which
/// reads as a claim about the WRITE landing. That half is **vacuous here**:
/// `#[sqlx::test]` connects as `epigraph` — superuser, `BYPASSRLS`, owner of
/// every protected table — so `claims_tenancy`'s `WITH CHECK` filters nothing on
/// this pool and the `UPDATE claims` succeeds whatever the policies say. It would
/// pass identically on a tree where the write is refused, which is precisely the
/// vacuity three reviewers of PR #494 raised.
///
/// What it legitimately pins is the AUTHZ half, which is the subject of #374 and
/// is real on any role: `gate_retirement_label` must let a `claims:admin` caller
/// through where it refuses a `claims:write` one, and the `expect` below fails if
/// the gate ever starts refusing admin. The label read-back is kept because it
/// distinguishes "the gate let the call through" from "the call returned Ok and
/// did nothing".
///
/// The TENANCY half — whether the write actually lands once the orphan
/// `claims_privacy` policy is gone — is measured on the non-bypassing
/// `epigraph_app` role by
/// `epigraph-db/tests/tool_write_tables_require_a_stamp.rs::
/// relabelling_a_foreign_groups_claim_is_refused_on_a_stamped_app_session`, and
/// the answer there is that it is REFUSED. That is a registered residual of the
/// tenancy model, not of this gate; see that file's header for the operational
/// consequence (epiclaw's scheduled agents retire cross-agent backlog items
/// through exactly this call).
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_admin_scope_passes_the_retirement_authz_gate(pool: PgPool) {
    let claim = seed_claim_with_labels(&pool, "admin-retired item", &["backlog"]).await;
    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (admin_auth, admin_viewer) = common::server_admin(&server).await;

    epigraph_mcp::tools::claims::update_labels(
        &server,
        &admin_viewer,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec!["resolved".into()],
            remove: vec![],
        },
        Some(&admin_auth),
    )
    .await
    .expect(
        "the #374 retirement gate must ADMIT a claims:admin caller on a foreign claim. This \
         assertion is about the gate only — the write half is vacuous on this BYPASSRLS harness \
         connection; see this arm's doc.",
    );

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
    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_caller, caller_auth, caller_viewer) = common::seed_caller(&pool, &["claims:write"]).await;

    epigraph_mcp::tools::claims::update_labels(
        &server,
        &caller_viewer,
        UpdateLabelsParams {
            claim_id: claim.to_string(),
            add: vec!["telemetry".into()],
            remove: vec!["backlog".into()],
        },
        Some(&caller_auth),
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
    let viewer = fixture::public_viewer(&pool).await;
    // Scoped: these tools now write on author-stamped transactions, and a
    // server with no `ScopedPool` refuses them by name rather than writing on
    // the unstamped pool, where the tier-A `WITH CHECK` refuses the `claims`
    // UPDATE with 42501.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    epigraph_mcp::tools::claims::update_labels(
        &server,
        &viewer,
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

/// Batch H-a review (atomicity-authz): on the authenticated transport the WHOLE
/// patch, not just the retirement label, needs claims:admin or ownership, as
/// `PATCH /api/v1/claims/:id` does. The write runs under the SERVER agent's
/// stamp, so without this a caller that could merely read a claim could rewrite
/// its properties with the server's write authority. A patch that touches no
/// label at all is the discriminating case: the retirement gate never fires on
/// it.
#[sqlx::test(migrations = "../../migrations")]
async fn patch_claim_without_labels_on_a_foreign_claim_is_refused_over_http(pool: PgPool) {
    let claim = seed_claim_with_labels(&pool, "patch_claim property subject", &["topic"]).await;
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (admin_auth, admin_viewer) = common::server_admin(&server).await;
    let (_caller, caller_auth, caller_viewer) = common::seed_caller(&pool, &["claims:write"]).await;
    let patch = |value: &str| PatchClaimParams {
        claim_id: claim.to_string(),
        trace_id: None,
        properties: Some(serde_json::json!({ "patched_by": value })),
        add_labels: vec![],
        remove_labels: vec![],
    };

    epigraph_mcp::tools::claims::patch_claim(
        &server,
        &caller_viewer,
        patch("a-reader-not-the-owner"),
        Some(&caller_auth),
    )
    .await
    .expect_err("an authenticated non-owner without claims:admin must not patch the claim");
    assert!(
        properties_of(&pool, claim)
            .await
            .get("patched_by")
            .is_none(),
        "the refused patch must not have written"
    );

    // Calibration: claims:admin passes the same gate, so the refusal above is
    // the ownership check and not a fixture accident.
    epigraph_mcp::tools::claims::patch_claim(
        &server,
        &admin_viewer,
        patch("admin"),
        Some(&admin_auth),
    )
    .await
    .expect("claims:admin may patch another agent's claim");
    assert_eq!(
        properties_of(&pool, claim).await.get("patched_by"),
        Some(&serde_json::json!("admin"))
    );

    // And stdio (no AuthContext) is unchanged: the #374 stdio half stays open.
    epigraph_mcp::tools::claims::patch_claim(&server, &viewer, patch("stdio"), None)
        .await
        .expect("the unauthenticated stdio path is not gated here");
}

async fn properties_of(pool: &PgPool, claim_id: Uuid) -> serde_json::Value {
    let (props,): (serde_json::Value,) =
        sqlx::query_as("SELECT COALESCE(properties, '{}'::jsonb) FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .expect("read properties");
    props
}
