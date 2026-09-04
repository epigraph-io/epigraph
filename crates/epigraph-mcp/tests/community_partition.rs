//! First-ever integration coverage of the `community` partition arm (PR-05).
//!
//! # Why this file did not exist before
//!
//! `ownership.partition_type` admits three values, and until this file the test
//! suite exercised two. EVERY existing fixture inserts `'private'` —
//! `crates/epigraph-api/tests/common/mod.rs::seed_private_ownership`,
//! `read_path_redaction.rs:248`, `query_claims_redaction.rs:41`,
//! `query_claims_by_label.rs:164`, `get_claim.rs:91` — and no test in the
//! workspace has ever written `partition_type = 'community'`. The entire
//! `"community"` arm of `epigraph_db::access_control::check_content_access`,
//! including its two-hop `community_members ⋈ perspectives` membership join and
//! its owner-only fallback, was unexecuted by any test.
//!
//! That matters more in PR-05 than it would have before, because PR-05 rewrites
//! that arm: migration 068 moves the gating community out of
//! `ownership.encryption_key_id` (a `text` column whose NAME meant something
//! else entirely, holding a stringified UUID) into a typed
//! `ownership.community_id` with an FK to `communities`. A rewrite of an
//! untested branch is a rewrite with no safety net; this is the net.
//!
//! # What is asserted
//!
//! The whole matrix the arm has: member, non-member, anonymous, the
//! `community_id IS NULL` fallback, the owner-who-is-not-a-member case, and the
//! batch (`access_map`) path. Case 5 in particular pins behaviour NO test has
//! ever asserted — that on the community arm, ownership alone does NOT grant
//! access once a community resolves — so PR-14, which deletes this module, has
//! to change it deliberately rather than silently. Cases 7–10 cover the write
//! side and the two ways the decision can be wrong for reasons that are not
//! about membership at all: a gate left on a partition that does not use it,
//! and a query that FAILS rather than returning a row.
//!
//! The HTTP half of the same arm lives in
//! `crates/epigraph-api/tests/read_path_authz_test.rs`
//! (`get_claim_community_member_sees_content_and_outsider_does_not`), which
//! goes through the production middleware stack; this file exercises the MCP
//! tools directly.
//!
//! Modelled on `read_path_redaction.rs`: same `build_test_server` harness, same
//! `#[sqlx::test(migrations = "../../migrations")]`, same `parse_claim` helper,
//! and each case runs against its own fresh database so a redaction assertion
//! proves REDACTION and not a missing row.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_mcp::tools::claims::{get_claim, query_claims};
use epigraph_mcp::types::{GetClaimParams, QueryClaimsParams};
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

// The `REDACTED` constant this file used to carry is GONE, and its absence is
// the headline result of PR-12 on this surface. Every assertion here that once
// read `content == "[REDACTED]"` is now an absence assertion, because migration
// 071 transcribes `ownership` into the tenancy columns and the Viewer predicate
// drops the row before any handler can blank it. Redaction is not merely
// unused on the community arm — it is unreachable.
//
// That is exactly what plan PR-14 ("delete redaction; a non-visible row is
// absent, not blanked") is scheduled to formalise, and what
// `docs/tenancy/progress.json`'s Q6 means by recording `check_content_access`
// retention as `gated_on: "PR-12 transcription completing"`. PR-12 does not
// delete `check_content_access`; it makes its remaining branches unreachable.

// ── 1. The discriminating positive: the two-hop membership path ─────────────
//
// `access_control.rs` does NOT ask "is this agent in the community". It asks
// whether the agent OWNS A PERSPECTIVE that is a member — `community_members ⋈
// perspectives ON p.owner_agent_id = $2`. Migration 068 collapses exactly this
// two-hop path into agent-level `group_memberships` rows. If the join is ever
// simplified to a one-hop lookup, this case is what fails.
#[sqlx::test(migrations = "../../migrations")]
async fn community_member_via_perspective_sees_content(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let member = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    join_community(&pool, community, member).await;

    let claim_id = seed_claim(&pool, owner).await;
    let expected = format!("test claim {}", claim_id.as_uuid());
    seed_community_ownership(&pool, claim_id, owner, Some(community)).await;

    let server = build_test_server(pool.clone());
    let body = get_claim_as(&server, &pool, claim_id, Some(member)).await;
    assert_eq!(
        body["content"].as_str().unwrap(),
        expected,
        "an agent owning a perspective that is a member of the gating community \
         must see the full content — after PR-12 that means its projected \
         group_memberships row puts the community group in its Viewer"
    );
}

// ── 2. A non-member is redacted ────────────────────────────────────────────
//
// The community EXISTS and resolves; the requester simply is not in it. Paired
// with case 1 against the same fixture shape, this is what proves the
// membership join is load-bearing rather than always-true.
#[sqlx::test(migrations = "../../migrations")]
async fn community_non_member_is_redacted(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let member = seed_agent(&pool).await;
    let outsider = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    join_community(&pool, community, member).await;
    // The outsider owns a perspective too — just not one in this community. A
    // join that forgot its `cm.community_id = $1` predicate would pass case 1
    // and fail here.
    seed_perspective(&pool, Some(outsider)).await;

    let claim_id = seed_claim(&pool, owner).await;
    seed_community_ownership(&pool, claim_id, owner, Some(community)).await;

    let server = build_test_server(pool.clone());
    // PR-12 TIGHTENING: absent, not blanked. The claim is now genuinely
    // ('group', <community group>) and the outsider is in no such group.
    assert_claim_absent_for(&server, &pool, claim_id, Some(outsider)).await;
}

// ── 3. Anonymous is redacted before any lookup ─────────────────────────────
//
// `let Some(agent_id) = requester_agent_id else { return Redacted }` — the
// guard that fires before the membership query runs. D3 ("no anonymous read
// authority") applies to the community arm too, and nothing had asserted it
// here.
#[sqlx::test(migrations = "../../migrations")]
async fn community_anonymous_requester_is_redacted(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    // Make the owner a member, so the ONLY reason to redact is anonymity.
    join_community(&pool, community, owner).await;

    let claim_id = seed_claim(&pool, owner).await;
    seed_community_ownership(&pool, claim_id, owner, Some(community)).await;

    let server = build_test_server(pool.clone());
    // PR-12 TIGHTENING: absent, not blanked.
    assert_claim_absent_for(&server, &pool, claim_id, None).await;
}

// ── 4. `community_id IS NULL` → owner-only fallback ────────────────────────
//
// This arm was previously reachable ONLY via an `encryption_key_id` that failed
// `Uuid::parse_str`. Migration 068 removes the string parse entirely, so the
// arm is now reached by a genuine `NULL` in the typed column — which is also
// the state a legacy row lands in when its old `encryption_key_id` did not
// resolve to a live community (it goes to `ownership_key_id_quarantine` and
// `community_id` stays NULL).
//
// The fallback grants the OWNER full access. That is preserved verbatim from
// the pre-068 behaviour, deliberately: PR-05 is a de-overloading change, and
// tightening this to fail-closed at the same time would make a regression here
// indistinguishable from an intended change. PR-14, which replaces this module
// with the Viewer predicate, owns that decision.
#[sqlx::test(migrations = "../../migrations")]
async fn community_row_with_null_community_id_falls_back_to_owner_only(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let stranger = seed_agent(&pool).await;

    let claim_id = seed_claim(&pool, owner).await;
    let expected = format!("test claim {}", claim_id.as_uuid());
    seed_community_ownership(&pool, claim_id, owner, None).await;

    let server = build_test_server(pool.clone());

    let owner_body = get_claim_as(&server, &pool, claim_id, Some(owner)).await;
    assert_eq!(
        owner_body["content"].as_str().unwrap(),
        expected,
        "with no gating community recorded, the owner keeps access — migration 071 \
         falls the unresolvable-community case back to the owner's personal group"
    );

    // PR-12 TIGHTENING: absent, not blanked.
    assert_claim_absent_for(&server, &pool, claim_id, Some(stranger)).await;
}

// ── 5. The owner who is not a member IS redacted ───────────────────────────
//
// Pins the current, deliberate semantics: once `community_id` resolves, the
// community arm consults membership and NOTHING else. Ownership does not
// short-circuit it, so an agent can be locked out of a node they own by leaving
// the community.
//
// No test has ever asserted this. It is surprising enough that a future reader
// could plausibly "fix" it by adding an `agent_id == owner_id` short-circuit —
// which would silently widen access for every community node whose owner is not
// a member. Asserted explicitly so that change has to be argued.
#[sqlx::test(migrations = "../../migrations")]
async fn community_owner_who_is_not_a_member_is_redacted(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let member = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    join_community(&pool, community, member).await;
    // The owner is NOT joined.

    let claim_id = seed_claim(&pool, owner).await;
    let expected = format!("test claim {}", claim_id.as_uuid());
    seed_community_ownership(&pool, claim_id, owner, Some(community)).await;

    let server = build_test_server(pool.clone());

    // PR-12 TIGHTENING: absent, not blanked — and the underlying decision is
    // UNCHANGED. Migration 071 deliberately does NOT project the declaring owner
    // into the community's group, precisely so this property survives; see the
    // comment at that arm, which cites this test by name.
    assert_claim_absent_for(&server, &pool, claim_id, Some(owner)).await;

    // And the member does, so the fixture is not simply broken.
    let member_body = get_claim_as(&server, &pool, claim_id, Some(member)).await;
    assert_eq!(member_body["content"].as_str().unwrap(), expected);
}

// ── 6. The batch / per-id `access_map` path ────────────────────────────────
//
// `query_claims` goes through `batch_check_content_access`, a DIFFERENT code
// path from singular `get_claim`, whose distinctive failure mode is a
// mispairing — the decision landing on the wrong claim's content. That cannot
// occur with one claim, so this seeds three with three different dispositions
// and asserts each gets its own.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_check_mixed_community_and_public(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let member = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    let other_community = seed_community(&pool).await;
    join_community(&pool, community, member).await;

    // (a) public — no ownership row at all. Truth 0.80.
    let public_id = seed_claim_with_truth(&pool, owner, 0.80).await;
    let public_content = format!("test claim {}", public_id.as_uuid());

    // (b) community the requester IS in. Truth 0.50.
    let visible_id = seed_claim_with_truth(&pool, owner, 0.50).await;
    let visible_content = format!("test claim {}", visible_id.as_uuid());
    seed_community_ownership(&pool, visible_id, owner, Some(community)).await;

    // (c) community the requester is NOT in. Truth 0.20.
    let hidden_id = seed_claim_with_truth(&pool, owner, 0.20).await;
    seed_community_ownership(&pool, hidden_id, owner, Some(other_community)).await;

    let server = build_test_server(pool.clone());
    let viewer = viewer_for(&pool, Some(member)).await;
    let result = query_claims(
        &server,
        &viewer,
        QueryClaimsParams {
            min_truth: Some(0.0),
            max_truth: Some(1.0),
            limit: Some(50),
        },
        Some(member),
    )
    .await
    .expect("query_claims");
    let claims = parse_claims(&result);

    assert_eq!(
        find_claim(&claims, public_id)["content"].as_str().unwrap(),
        public_content,
        "a public claim must not be collateral damage of a community decision"
    );
    assert_eq!(
        find_claim(&claims, visible_id)["content"].as_str().unwrap(),
        visible_content,
        "the member's own community claim must survive the batch path"
    );
    // PR-12 TIGHTENING: the third claim is now ('group', <other community>),
    // which the member is not in, so the Viewer predicate drops it from the
    // result set rather than the handler blanking its content.
    //
    // The discriminating property the original assertion was protecting is
    // PRESERVED and is still asserted above: `visible_id` and `hidden_id` differ
    // only in WHICH community gates them, so a per-id mispairing would still
    // swap them — and would now show up as `visible_id` going missing while
    // `hidden_id` appears.
    assert!(
        claims
            .iter()
            .all(|c| c["id"].as_str() != Some(hidden_id.as_uuid().to_string().as_str())),
        "a claim gated by a DIFFERENT community must be ABSENT for this member, \
         not returned blanked; got {claims:?}"
    );
}

// ── 7. The write path agrees with the read path ────────────────────────────
//
// `OwnershipRepository::assign_with_community` used to stringify the community
// UUID into `encryption_key_id` (`repos/ownership.rs:101`, deleted in PR-05).
// It now writes the typed column and binds `encryption_key_id` to NULL on BOTH
// the insert and the conflict arm. This asserts the column the writer fills is
// the column the reader reads — the exact seam the de-overloading could get
// wrong while every other test stayed green, because the fixtures above write
// the row by hand.
#[sqlx::test(migrations = "../../migrations")]
async fn assign_with_community_writes_the_column_access_control_reads(pool: PgPool) {
    use epigraph_db::OwnershipRepository;

    let owner = seed_agent(&pool).await;
    let member = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    join_community(&pool, community, member).await;

    let claim_id = seed_claim(&pool, owner).await;
    let expected = format!("test claim {}", claim_id.as_uuid());

    let row = OwnershipRepository::assign_with_community(
        &pool,
        claim_id.as_uuid(),
        "claim",
        "community",
        owner,
        Some(community),
    )
    .await
    .expect("assign_with_community");

    assert_eq!(row.community_id, Some(community));
    assert!(
        row.encryption_key_id.is_none(),
        "the writer must leave encryption_key_id NULL; a stale value there while \
         community_id went NULL would populate ownership_key_id_quarantine and \
         block migration 084's pre-flight"
    );

    // Nothing ends up in the quarantine as a result of a normal write.
    let quarantined: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM ownership_key_id_quarantine")
            .fetch_one(&pool)
            .await
            .expect("quarantine count");
    assert_eq!(quarantined, 0);

    let server = build_test_server(pool.clone());
    let body = get_claim_as(&server, &pool, claim_id, Some(member)).await;
    assert_eq!(
        body["content"].as_str().unwrap(),
        expected,
        "a row written by the repository must be readable by the access-control \
         reader — same column, both sides"
    );
}

// ── 8. Demotion out of the community partition clears the gate ─────────────
//
// `update_partition` nulls `community_id` whenever the new partition is not
// `community`, so a later re-promotion cannot silently reuse a community the
// caller never named. Without that, demote-to-private then promote-to-community
// would resurrect the old gate.
#[sqlx::test(migrations = "../../migrations")]
async fn demoting_out_of_community_clears_the_gate(pool: PgPool) {
    use epigraph_db::OwnershipRepository;

    let owner = seed_agent(&pool).await;
    let member = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    join_community(&pool, community, member).await;

    let claim_id = seed_claim(&pool, owner).await;
    OwnershipRepository::assign_with_community(
        &pool,
        claim_id.as_uuid(),
        "claim",
        "community",
        owner,
        Some(community),
    )
    .await
    .expect("assign");

    // A LEGACY VALUE IN THE DEPRECATED COLUMN, PUT THERE BY HAND.
    //
    // Without this the test is vacuous with respect to `encryption_key_id`:
    // `assign_with_community` binds it to NULL on both arms, so the field under
    // test would always be NULL going in and an `update_partition` that failed
    // to clear it would still pass. Migration 068 drains and clears every row
    // it can, but nothing stops a row acquiring a value afterwards, and 084's
    // pre-flight is what has to come up empty. UUID-shaped so it satisfies
    // `ownership_key_id_is_uuid`.
    sqlx::query("UPDATE ownership SET encryption_key_id = $2::text WHERE node_id = $1")
        .bind(claim_id.as_uuid())
        .bind(community)
        .execute(&pool)
        .await
        .expect("plant a legacy encryption_key_id");

    let demoted = OwnershipRepository::update_partition(&pool, claim_id.as_uuid(), "private")
        .await
        .expect("update_partition")
        .expect("row");
    assert_eq!(demoted.partition_type, "private");
    assert_eq!(
        demoted.community_id, None,
        "leaving the community partition must clear community_id, or a later \
         re-promotion inherits a gate nobody asked for"
    );
    assert!(
        demoted.encryption_key_id.is_none(),
        "the DEPRECATED string must be cleared in the same statement. Leaving it while \
         community_id goes NULL is precisely the ownership_key_id_quarantine predicate: \
         the row becomes indistinguishable from a value that never resolved, and blocks \
         migration 084's pre-flight."
    );

    let quarantined: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM ownership_key_id_quarantine")
            .fetch_one(&pool)
            .await
            .expect("quarantine count");
    assert_eq!(
        quarantined, 0,
        "demoting a node must not add a row to the 084 pre-flight's quarantine"
    );

    // The member (who is not the owner) now sees nothing: the row is private.
    let server = build_test_server(pool.clone());
    // PR-12 TIGHTENING: absent, not blanked. The demoted row is now
    // ('group', <owner's personal group>), which the member is not in.
    assert_claim_absent_for(&server, &pool, claim_id, Some(member)).await;
}

// ── 9. A gate may only exist on the partition that uses it ─────────────────
//
// `update_partition` nulls `community_id` on demotion and argues (in its own
// comment) that a stray gate would be "silently reused by a later
// re-promotion". `assign_with_community` used to accept exactly that pair, so
// the invariant one writer enforced the other could pre-load — and the MCP
// `assign_ownership` tool passes `community_id` straight through from the
// caller. Refused in the repository (a 400, with a reason) and again by the
// database's `ownership_community_needs_community_partition` CHECK.
#[sqlx::test(migrations = "../../migrations")]
async fn a_community_id_on_a_private_partition_is_refused(pool: PgPool) {
    use epigraph_db::OwnershipRepository;

    let owner = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    let claim_id = seed_claim(&pool, owner).await;

    let err = OwnershipRepository::assign_with_community(
        &pool,
        claim_id.as_uuid(),
        "claim",
        "private",
        owner,
        Some(community),
    )
    .await
    .expect_err("a gate on a private row must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("community_id may only be set on partition_type 'community'"),
        "the refusal must explain itself, not surface as a bare constraint name: {msg}"
    );

    // Nothing was written, so a later promotion cannot inherit anything.
    let rows: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM ownership WHERE node_id = $1")
        .bind(claim_id.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("ownership count");
    assert_eq!(rows, 0);
}

// ── 10. A FAILED ownership lookup redacts; it does not publish ─────────────
//
// `check_content_access` used to end its lookup with `.unwrap_or(None)`, and
// `None` is the sentinel for "no ownership row -> public". Every transient
// database failure — pool exhaustion, a statement timeout, a reset connection,
// or a binary rolled ahead of migration 068 so `ownership.community_id` does
// not exist yet — therefore returned FULL CONTENT for a private or
// community-gated claim. `EPIGRAPH_MIGRATE_ON_BOOT` is default-off, so the
// schema-skew case is operator-reachable rather than theoretical, and the MCP
// server has no startup probe that would catch it.
//
// A closed pool is the cheapest way to make the query return `Err` and not
// `Ok(None)`, which is exactly the distinction under test.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_ownership_lookup_redacts(pool: PgPool) {
    use epigraph_db::access_control::{check_content_access, ContentAccess};

    let owner = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    let claim_id = seed_claim(&pool, owner).await;
    seed_community_ownership(&pool, claim_id, owner, Some(community)).await;

    // Control: while the pool works, the owner-less stranger is Redacted and
    // the row is genuinely present — so the assertion below is about the ERROR
    // path and not about a missing fixture.
    let control = check_content_access(&pool, claim_id.as_uuid(), Some(owner)).await;
    assert_eq!(control, ContentAccess::Redacted);

    pool.close().await;
    let broken = check_content_access(&pool, claim_id.as_uuid(), Some(owner)).await;
    assert_eq!(
        broken,
        ContentAccess::Redacted,
        "a query error must FAIL CLOSED. `Err` is not `Ok(None)`, and only `Ok(None)` \
         means 'no ownership row, therefore public'."
    );
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Seed an `ownership` row on the `community` partition.
///
/// Writes `community_id`, NEVER `encryption_key_id` — that is the entire point
/// of PR-05, and a fixture that wrote the old column would keep passing while
/// the production writer had moved.
async fn seed_community_ownership(
    pool: &PgPool,
    node_id: ClaimId,
    owner_id: Uuid,
    community_id: Option<Uuid>,
) {
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, community_id) \
         VALUES ($1, 'claim', 'community', $2, $3)",
    )
    .bind(node_id.as_uuid())
    .bind(owner_id)
    .bind(community_id)
    .execute(pool)
    .await
    .expect("seed community ownership");
}

/// `communities.name` is `UNIQUE varchar(200)`, so randomise it.
async fn seed_community(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO communities (name) VALUES ($1) RETURNING id")
        .bind(format!("community-{}", Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("seed community")
}

/// `perspectives.owner_agent_id` is NULLABLE with an FK to `agents(id)`.
async fn seed_perspective(pool: &PgPool, owner_agent_id: Option<Uuid>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("perspective-{}", Uuid::new_v4()))
    .bind(owner_agent_id)
    .fetch_one(pool)
    .await
    .expect("seed perspective")
}

/// Put `agent` in `community` the only way the access-control join recognises:
/// via a perspective the agent owns.
async fn join_community(pool: &PgPool, community: Uuid, agent: Uuid) {
    let perspective = seed_perspective(pool, Some(agent)).await;
    sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
        .bind(community)
        .bind(perspective)
        .execute(pool)
        .await
        .expect("join community");
}

/// Resolve the Viewer for `requester`, or the public viewer when anonymous.
///
/// # Why this replaced a shared `fixture::public_viewer`
///
/// Every test in this file used to build ONE `public_viewer` (empty group set)
/// and then pass the acting principal separately as the `requester` wire
/// parameter, because before PR-12 the community gate lived entirely in
/// `check_content_access`'s two-hop join and the Viewer predicate matched every
/// row (all content was `visibility='public'`).
///
/// Migration 071 transcribes `ownership` into the tenancy columns, so the
/// Viewer is now the FIRST filter and a viewer with no groups can no longer see
/// a community-gated claim at all — regardless of who the `requester` says it
/// is. Keeping the empty viewer would have made every test here assert against
/// a principal that cannot exist in production: `Viewer::resolve` is called on
/// the authenticated agent, so viewer and requester are the same principal on
/// every real request.
///
/// Resolving from `requester` restores that correspondence, and the tests now
/// exercise the real composition — Viewer filter, THEN redaction.
async fn viewer_for(pool: &PgPool, requester: Option<Uuid>) -> epigraph_db::visibility::Viewer {
    match requester {
        Some(agent) => epigraph_db::visibility::Viewer::resolve(pool, agent)
            .await
            .expect("resolve viewer"),
        None => fixture::public_viewer(pool).await,
    }
}

async fn get_claim_as(
    server: &epigraph_mcp::EpiGraphMcpFull,
    pool: &PgPool,
    claim_id: ClaimId,
    requester: Option<Uuid>,
) -> Value {
    let viewer = viewer_for(pool, requester).await;
    let result = get_claim(
        server,
        &viewer,
        GetClaimParams {
            claim_id: claim_id.as_uuid().to_string(),
            frame_id: None,
            perspective_id: None,
        },
        requester,
    )
    .await
    .expect("get_claim");
    parse_claim(&result)
}

/// Assert `requester` cannot see `claim_id` AT ALL.
///
/// After PR-12 a non-visible row is ABSENT, not blanked: the Viewer predicate
/// excludes it and `get_claim` reports "not found". That is strictly less
/// disclosure than the old `[REDACTED]` body, which told a stranger the claim
/// existed, and it is the end state plan PR-14 formalises.
async fn assert_claim_absent_for(
    server: &epigraph_mcp::EpiGraphMcpFull,
    pool: &PgPool,
    claim_id: ClaimId,
    requester: Option<Uuid>,
) {
    let viewer = viewer_for(pool, requester).await;
    let result = get_claim(
        server,
        &viewer,
        GetClaimParams {
            claim_id: claim_id.as_uuid().to_string(),
            frame_id: None,
            perspective_id: None,
        },
        requester,
    )
    .await;
    match result {
        Err(e) => assert!(
            e.to_string().contains("not found"),
            "expected a not-found for a claim outside the viewer's scope, got: {e}"
        ),
        Ok(ok) => panic!(
            "expected the claim to be ABSENT for this requester, but get_claim \
             returned a body: {:?}",
            parse_claim(&ok)
        ),
    }
}

fn parse_claim(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    serde_json::from_str(&text).expect("response is JSON")
}

fn parse_claims(result: &CallToolResult) -> Vec<Value> {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block");
    let parsed: Value = serde_json::from_str(&text).expect("response is JSON");
    parsed.as_array().expect("response is JSON array").clone()
}

fn find_claim(claims: &[Value], id: ClaimId) -> &Value {
    let id_str = id.as_uuid().to_string();
    claims
        .iter()
        .find(|c| c["id"].as_str() == Some(id_str.as_str()))
        .unwrap_or_else(|| panic!("claim {id_str} not in response: {claims:?}"))
}

/// `agents.public_key` is `UNIQUE` and length-checked (32 bytes); derive it from
/// a fresh uuid so several agents in one test cannot collide.
async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid) -> ClaimId {
    seed_claim_with_truth(pool, agent_id, 0.5).await
}

async fn seed_claim_with_truth(pool: &PgPool, agent_id: Uuid, truth: f64) -> ClaimId {
    let id = Uuid::new_v4();
    // 16-byte UUID padded to a 32-byte content_hash. `repeat(0).take(16)` keeps
    // this MSRV-safe (avoids `iter::repeat_n`).
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat(0).take(16))
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             labels, is_current) \
         VALUES ($1, $2, $3, $4, $5, ARRAY[]::text[], true)",
    )
    .bind(id)
    .bind(format!("test claim {}", id))
    .bind(hash)
    .bind(truth)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    ClaimId::from_uuid(id)
}
