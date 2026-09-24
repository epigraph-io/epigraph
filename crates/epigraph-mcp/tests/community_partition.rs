//! First-ever integration coverage of the `community` partition arm (PR-05).
//!
//! # Why this file did not exist before
//!
//! `ownership.partition_type` admitted three values, and until this file the
//! test suite exercised two: every fixture in the workspace wrote `'private'`,
//! and no test had ever written `partition_type = 'community'`. The entire
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
//! # Where the gate lives NOW (PR-22)
//!
//! `ownership` is retired by migration 084. The community gate is a projected
//! `groups` / `group_memberships` pair and the claim's own tenancy columns, and
//! the fixtures below write exactly what migration 071's shim used to write on
//! their behalf. The MATRIX is unchanged, which is the point: the arm was
//! specified by these cases and it still passes them.
//!
//! # What is asserted
//!
//! The whole matrix the arm has: member, non-member, anonymous, the
//! `community_id IS NULL` fallback, the owner-who-is-not-a-member case, and the
//! batch (`access_map`) path. Case 5 in particular pins behaviour NO test has
//! ever asserted — that on the community arm, ownership alone does NOT grant
//! access once a community resolves — so PR-14, which deletes this module, has
//! to change it deliberately rather than silently. Case 10 covers the way the
//! decision can be wrong for a reason that is not about membership at all: a
//! query that FAILS rather than returning a row. Cases 7–9 covered the
//! `OwnershipRepository` write side and are deleted with it; see the note where
//! they used to be.
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
// read `content == "[REDACTED]"` is now an absence assertion, because the claim
// carries group tenancy in its own columns and the Viewer predicate drops the
// row before any handler can blank it. Redaction is not merely unused on the
// community arm — it is unreachable.
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
async fn community_non_member_cannot_see_the_claim(pool: PgPool) {
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
async fn community_anonymous_requester_cannot_see_the_claim(pool: PgPool) {
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
// `Uuid::parse_str`. Migration 068 removed the string parse, so the arm is
// reached by a genuine absent community — which is also the state a legacy row
// landed in when its old `encryption_key_id` did not resolve. The fixture
// spells that as `None`.
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
async fn community_owner_who_is_not_a_member_cannot_see_the_claim(pool: PgPool) {
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

    // (a) public — never gated at all. Truth 0.80.
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
            // Both populations: the fixture seeds only current rows, and
            // pinning `None` keeps this test about VISIBILITY rather than
            // about `a85ee585`'s current-only default.
            is_current: None,
        },
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

// ── 7, 8, 9. The `OwnershipRepository` cases, DELETED in PR-22 ─────────────
//
// Three cases lived here and all three had `epigraph_db::OwnershipRepository` as
// their subject:
//
//   7. `assign_with_community_writes_the_column_access_control_reads` — that the
//      typed `community_id` column the writer fills is the one the reader reads,
//      the seam PR-05's de-overloading of `encryption_key_id` could get wrong;
//   8. `demoting_out_of_community_clears_the_gate` — that `update_partition`
//      nulls both `community_id` and the deprecated string, so a later
//      re-promotion cannot inherit a gate nobody named;
//   9. `a_community_id_on_a_private_partition_is_refused` — that a gate may only
//      exist on the partition that uses it.
//
// PR-22 deletes `repos/ownership.rs` and migration 084 drops the table, so all
// three assert properties of code and columns that no longer exist. They are
// removed rather than re-pointed: there is nothing to re-point them AT. The
// community gate itself is still covered — cases 1 through 6 and 10 exercise it
// end to end through the tenancy columns, which is where it now lives.
//
// What 8's `encryption_key_id` half was ultimately protecting — that migration
// 084's quarantine pre-flight comes up empty — is now asserted directly against
// the migration in
// `epigraph-db/tests/retire_ownership_preflight.rs::pre_flight_1_refuses_an_untriaged_quarantine_row`
// and its passing control.

// ── 10. A FAILED lookup REFUSES; it does not publish (D1) ─────────────────
//
// PR-14 RETARGETED, NOT DELETED. The original case pinned the D1 archetype in
// `check_content_access`, which ended its ownership lookup with
// `.unwrap_or(None)` — and `None` was the sentinel for "no ownership row =>
// public". Every transient database failure (pool exhaustion, statement
// timeout, reset connection, or a binary rolled ahead of its migration)
// therefore returned FULL CONTENT for a private claim. That function is gone,
// so the original assertion has no subject.
//
// The property is NOT gone, and this is where it now lives. Visibility is
// decided by a `Viewer` predicate inside the repo statement, and a repo read
// returns `Result<_, DbError>`. There is no value in that type which means
// "public": a failure is an `Err` the caller must handle, not a sentinel that
// silently widens. This case proves that empirically on the same cheap
// failure injection the original used — a closed pool — because "we changed the
// shape so the bug is impossible" is exactly the kind of claim that deserves a
// test rather than a comment.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_read_refuses_rather_than_publishing(pool: PgPool) {
    let owner = seed_agent(&pool).await;
    let community = seed_community(&pool).await;
    let claim_id = seed_claim(&pool, owner).await;
    seed_community_ownership(&pool, claim_id, owner, Some(community)).await;

    let stranger = Uuid::new_v4();
    let stranger_viewer = epigraph_db::visibility::Viewer::resolve(&pool, stranger)
        .await
        .expect("resolve stranger viewer");

    // Control: while the pool works the read SUCCEEDS and returns nothing for
    // the stranger. Both halves matter — this is what distinguishes the error
    // path below from a fixture that was simply never visible.
    let control = epigraph_db::ClaimRepository::get_by_id(&pool, &stranger_viewer, claim_id)
        .await
        .expect("a working pool must not error");
    assert!(
        control.is_none(),
        "control: a community claim the stranger is not a member of must be absent"
    );

    // And the owner CAN read it, so the fixture is genuinely present rather
    // than absent for everybody (Class P — a mechanism that returns nothing to
    // anybody would pass the assertion above).
    let owner_viewer = epigraph_db::visibility::Viewer::resolve(&pool, owner)
        .await
        .expect("resolve owner viewer");
    assert!(
        epigraph_db::ClaimRepository::get_by_id(&pool, &owner_viewer, claim_id)
            .await
            .expect("a working pool must not error")
            .is_some(),
        "control: the owner must be able to read the claim, or the absence \
         above proves nothing about tenancy"
    );

    pool.close().await;
    let broken = epigraph_db::ClaimRepository::get_by_id(&pool, &owner_viewer, claim_id).await;
    assert!(
        broken.is_err(),
        "a query error must surface as `Err`, never as a value the caller can \
         mistake for an answer. The deleted `check_content_access` laundered \
         exactly this `Err` into `Ok(None)` and then read `None` as 'public'."
    );
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Gate claim `node_id` on `community_id`'s projected group, falling back to the
/// owner's personal group when no community resolves.
///
/// **This wrote a `partition_type = 'community'` row into `ownership` until
/// PR-22** and let migration 071's `ownership_transcribe` trigger project the
/// community onto a group and stamp the claim. Migration 084 retires the table,
/// so the fixture writes the tenancy columns the trigger used to write. The
/// three arms are 071's, and each is a reviewed decision, not a convenience:
///
/// * a community whose projected group has a live member stamps
///   `('group', community_id)` — migration 068's projection is ID-preserving, so
///   a community's group id IS its community id;
/// * a community with no projectable member falls back to the owner's personal
///   group rather than stamping a group nobody is in, which would make the claim
///   unreadable by everyone including its owner;
/// * a NULL or dangling `community_id` is a LEGACY SHAPE, not an error path, and
///   falls back the same way — fail-closed, still `'group'`, still not public.
///
/// **The owner is deliberately NOT added to the community group.** On the
/// community arm, ownership alone does not grant access once a community
/// resolves; membership is the whole test, and case 4 below asserts it.
async fn seed_community_ownership(
    pool: &PgPool,
    node_id: ClaimId,
    owner_id: Uuid,
    community_id: Option<Uuid>,
) {
    let resolved: Option<Uuid> = match community_id {
        None => None,
        Some(c) => sqlx::query_scalar(
            "SELECT g.id FROM groups g \
              WHERE g.id = $1 AND g.kind = 'community' \
                AND EXISTS (SELECT 1 FROM group_memberships m \
                             WHERE m.group_id = g.id AND m.revoked_at IS NULL)",
        )
        .bind(c)
        .fetch_optional(pool)
        .await
        .expect("resolve the projected community group"),
    };

    match resolved {
        Some(g) => common::stamp_group_private(pool, node_id.as_uuid(), g).await,
        None => {
            common::seed_private_tenancy(pool, node_id.as_uuid(), owner_id).await;
        }
    }
}

/// `communities.name` is `UNIQUE varchar(200)`, so randomise it.
///
/// It also PROJECTS the community onto its ID-preserving group, which migration
/// 071's shim used to replay on the fixture's behalf. Not optional:
/// `Viewer::resolve` reads `group_memberships`, so a community with no projected
/// group produces a claim nobody can read. Shapes copied from migration 068 and
/// `CommunityRepository::create`, including `public_key = ''::bytea` — migration
/// 060's `groups_public_key_shape` requires `octet_length = 0` for every
/// `kind <> 'team'`.
async fn seed_community(pool: &PgPool) -> Uuid {
    let id: Uuid = sqlx::query_scalar("INSERT INTO communities (name) VALUES ($1) RETURNING id")
        .bind(format!("community-{}", Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("seed community");

    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_at) \
         SELECT c.id, c.name, 'did:epigraph:community:' || c.id::text, ''::bytea, \
                'community', c.created_at \
           FROM communities c WHERE c.id = $1 \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("project the community onto a group");

    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, wrapped_key, status) \
         VALUES ($1, 0, NULL, 'active') ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("project the community's epoch 0");

    id
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

    // PROJECT the membership. `community_members` is the community's own
    // registry; `group_memberships` is what `Viewer::resolve` reads, and
    // migration 071's shim used to replay this projection whenever it stamped a
    // community row. `role = 'reader'` for 068's stated reason: membership
    // attests read interest and says nothing about write authority.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         SELECT g.id, p.owner_agent_id, ''::bytea, 0, 'reader' \
           FROM perspectives p \
           JOIN groups g ON g.id = $1 AND g.kind = 'community' \
          WHERE p.id = $2 AND p.owner_agent_id IS NOT NULL \
         ON CONFLICT (group_id, agent_id, epoch) DO UPDATE SET revoked_at = NULL",
    )
    .bind(community)
    .bind(perspective)
    .execute(pool)
    .await
    .expect("project the community membership");
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
/// The fixtures now write those tenancy columns directly, so the
/// Viewer is the FIRST filter and a viewer with no groups cannot see
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
