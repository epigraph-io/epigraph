//! `share_claims_with_team` and `publicize_claims` by SELECTION, with a dry
//! run (backlog 02d9e9a1), on the APPLICATION ROLE.
//!
//! A selection names a root claim and the closure to walk from it (edge types,
//! direction, depth). The walk runs on the caller's own stamped connection and
//! asks the act's definer how it would classify every claim reached; a claim
//! the definer would move joins the plan, any other is a BOUNDARY: listed with
//! its reason, left untouched, and not walked through. The act then runs on the
//! plan exactly as on an explicit id list (all or nothing, one audit row).
//!
//! Every server is built from ONE `ScopedPool` downgraded to `epigraph_app`,
//! and every "who can read it" question is asked on a connection of that pool
//! stamped as the reader. Seeding runs on the superuser pool.
//!
//! What is pinned:
//! * a dry run lists the claims that would move and every boundary with its
//!   reason, and changes nothing (tenancy, audit rows);
//! * the act moves exactly the plan: boundary claims, claims beyond a
//!   boundary, claims over an edge type or in a direction not followed and
//!   superseded claims stay where they were;
//! * a teammate reads what moved, a non-member reads nothing it did not read
//!   before, and the one audit row names every moved id;
//! * publicize stops at a claim the caller does not administer;
//! * a root the caller cannot read answers exactly as a missing one, dry run
//!   or not; a root the act refuses is refused with the act's own reason;
//! * a selection over the 500-claim cap is refused whole;
//! * a malformed selection is refused before anything runs.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::visibility::{publicize_claims, share_claims_with_team};
use epigraph_mcp::types::{PublicizeClaimsParams, SelectionParams, ShareClaimsWithTeamParams};
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

struct AppRole {
    server: EpiGraphMcpFull,
    scoped: ScopedPool,
}

async fn app_role(pool: &PgPool) -> AppRole {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, scoped.clone());
    server.server_agent_id().await.expect("server agent");
    AppRole { server, scoped }
}

fn token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

/// A keyed TEAM group, with no members.
async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// A current claim by `agent`, owned by `group` with `visibility`.
async fn claim(pool: &PgPool, agent: Uuid, group: Uuid, visibility: &str, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.7, $4, true, $5, $6)",
    )
    .bind(id)
    .bind(content)
    .bind(blake3::hash(content.as_bytes()).as_bytes().as_slice())
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', $4)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
    id
}

/// `(visibility, owner_group_id)` as stored.
async fn tenancy(pool: &PgPool, id: Uuid) -> (String, Uuid) {
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("tenancy")
}

/// Can `agent` read `claim` on an app-role connection stamped as `agent`?
async fn reads(pool: &PgPool, s: &AppRole, agent: Uuid, claim: Uuid) -> bool {
    let v = viewer(pool, agent).await;
    let mut conn = s.scoped.acquire_as(&v).await.expect("stamped connection");
    ClaimRepository::get_by_id(&mut *conn, &v, ClaimId::from_uuid(claim))
        .await
        .expect("read")
        .is_some()
}

/// `(agent_id, details)` of every audit row of `event_type`.
async fn audits(pool: &PgPool, event_type: &str) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as("SELECT agent_id, details FROM security_events WHERE event_type = $1")
        .bind(event_type)
        .fetch_all(pool)
        .await
        .expect("audit rows")
}

fn selection(root: Uuid) -> SelectionParams {
    SelectionParams {
        root: root.to_string(),
        ..SelectionParams::default()
    }
}

async fn share(
    pool: &PgPool,
    s: &AppRole,
    agent: Uuid,
    sel: SelectionParams,
    group: Uuid,
    dry_run: bool,
) -> Result<serde_json::Value, epigraph_mcp::errors::McpError> {
    share_claims_with_team(
        &s.server,
        &viewer(pool, agent).await,
        ShareClaimsWithTeamParams {
            selection: Some(sel),
            dry_run: Some(dry_run),
            group_id: group.to_string(),
            reason: "share the worked-out argument".to_string(),
            ..ShareClaimsWithTeamParams::default()
        },
        Some(&token(agent)),
    )
    .await
    .map(|r| first_text(&r))
}

async fn publicize(
    pool: &PgPool,
    s: &AppRole,
    agent: Uuid,
    sel: SelectionParams,
    dry_run: bool,
) -> Result<serde_json::Value, epigraph_mcp::errors::McpError> {
    publicize_claims(
        &s.server,
        &viewer(pool, agent).await,
        PublicizeClaimsParams {
            selection: Some(sel),
            dry_run: Some(dry_run),
            reason: "publish the worked-out argument".to_string(),
            ..PublicizeClaimsParams::default()
        },
        Some(&token(agent)),
    )
    .await
    .map(|r| first_text(&r))
}

fn ids(list: &serde_json::Value) -> BTreeSet<Uuid> {
    list.as_array()
        .unwrap_or_else(|| panic!("not a list: {list}"))
        .iter()
        .map(|c| c["claim_id"].as_str().expect("claim_id").parse().unwrap())
        .collect()
}

fn set(of: &[Uuid]) -> BTreeSet<Uuid> {
    of.iter().copied().collect()
}

/// The boundary entry for `claim` in a plan.
fn boundary_of(plan: &serde_json::Value, claim: Uuid) -> serde_json::Value {
    plan["boundaries"]
        .as_array()
        .expect("boundaries")
        .iter()
        .find(|b| b["claim_id"] == claim.to_string())
        .cloned()
        .unwrap_or_else(|| panic!("{claim} is not a boundary: {plan}"))
}

/// The audit row's `claim_ids`, as a set.
fn audited_ids(details: &serde_json::Value) -> BTreeSet<Uuid> {
    details["claim_ids"]
        .as_array()
        .expect("claim_ids")
        .iter()
        .map(|i| i.as_str().unwrap().parse().unwrap())
        .collect()
}

/// Alice shares a root and its decomposes_to / supports closure with her
/// team. The graph, all hers and private unless said otherwise:
///
/// ```text
///   R --decomposes_to--> A --supports--> B
///   A --decomposes_to--> P (carol's, PUBLIC)  --decomposes_to--> Q
///   R --decomposes_to--> O (superseded)
///   R --elaborates-->    X (edge type not followed)
///   E --supports-->      R (incoming, not followed)
/// ```
///
/// The dry run plans R, A and B; P is a boundary (`refused_not_private`) and
/// O one (`not_current`); Q, X and E are not reached. Nothing changes. The act
/// then moves exactly R, A and B: a teammate reads them, carol (a non-member)
/// reads none of the private claims, and the one audit row names R, A and B.
///
/// Verified to fail with the walk going on through a boundary (Q is planned
/// and moved), with `dry_run` committing, and with the edge-type filter
/// dropped (X is moved).
#[sqlx::test(migrations = "../../migrations")]
async fn a_share_selection_moves_the_closure_and_stops_at_boundaries(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "sel-alice").await;
    let (bob, _) = fixture::seed_agent_with_group(&pool, "sel-bob").await;
    let (carol, carols) = fixture::seed_agent_with_group(&pool, "sel-carol").await;
    add_member(&pool, t, alice, "writer").await;
    add_member(&pool, t, bob, "reader").await;

    let r = claim(&pool, alice, home, "group", "root thesis").await;
    let a = claim(&pool, alice, home, "group", "first sub-claim").await;
    let b = claim(&pool, alice, home, "group", "support for the sub-claim").await;
    let p = claim(&pool, carol, carols, "public", "carol's public step").await;
    let q = claim(&pool, alice, home, "group", "beyond the public step").await;
    let o = claim(&pool, alice, home, "group", "an old sub-claim").await;
    let x = claim(&pool, alice, home, "group", "an elaboration").await;
    let e = claim(&pool, alice, home, "group", "evidence for the root").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(o)
        .execute(&pool)
        .await
        .expect("supersede o");
    edge(&pool, r, a, "decomposes_to").await;
    edge(&pool, a, b, "supports").await;
    edge(&pool, a, p, "decomposes_to").await;
    edge(&pool, p, q, "decomposes_to").await;
    edge(&pool, r, o, "decomposes_to").await;
    edge(&pool, r, x, "elaborates").await;
    edge(&pool, e, r, "supports").await;
    let private = [r, a, b, q, o, x, e];

    // The dry run.
    let body = share(&pool, &s, alice, selection(r), t, true)
        .await
        .expect("dry run");
    assert_eq!(body["dry_run"], true, "{body}");
    assert_eq!(body["results"], serde_json::json!([]), "{body}");
    let plan = &body["plan"];
    assert_eq!(ids(&plan["claims"]), set(&[r, a, b]), "{plan}");
    assert_eq!(ids(&plan["boundaries"]), set(&[p, o]), "{plan}");
    let at_p = boundary_of(plan, p);
    assert_eq!(at_p["reason"], "refused_not_private", "{plan}");
    assert_eq!(at_p["reached_from"], a.to_string(), "{plan}");
    assert_eq!(at_p["relationship"], "decomposes_to", "{plan}");
    assert!(at_p["detail"].as_str().is_some(), "{plan}");
    assert_eq!(boundary_of(plan, o)["reason"], "not_current", "{plan}");
    assert_eq!(plan["capped"], false, "{plan}");
    for c in private {
        assert_eq!(tenancy(&pool, c).await, ("group".to_string(), home));
    }
    assert!(audits(&pool, "claim.shared_with_team").await.is_empty());
    assert!(!reads(&pool, &s, bob, r).await, "the dry run moved nothing");

    // The act.
    let body = share(&pool, &s, alice, selection(r), t, false)
        .await
        .expect("shared");
    assert_eq!(body["dry_run"], false, "{body}");
    assert_eq!(ids(&body["results"]), set(&[r, a, b]), "{body}");
    assert!(body["results"]
        .as_array()
        .unwrap()
        .iter()
        .all(|o| o["outcome"] == "shared"));
    for c in [r, a, b] {
        assert_eq!(tenancy(&pool, c).await, ("group".to_string(), t), "{c}");
        assert!(reads(&pool, &s, bob, c).await, "the teammate reads {c}");
    }
    for c in [q, o, x, e] {
        assert_eq!(
            tenancy(&pool, c).await,
            ("group".to_string(), home),
            "{c} was not in the plan and stays private"
        );
        assert!(!reads(&pool, &s, bob, c).await, "{c}");
    }
    assert_eq!(
        tenancy(&pool, p).await,
        ("public".to_string(), carols),
        "the boundary is untouched"
    );
    for c in private {
        assert!(!reads(&pool, &s, carol, c).await, "a non-member reads {c}");
    }
    let rows = audits(&pool, "claim.shared_with_team").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, Some(alice));
    assert_eq!(audited_ids(&rows[0].1), set(&[r, a, b]), "{rows:?}");
}

/// Direction and depth: `incoming` from R reaches E (E supports R) and not A;
/// `max_depth: 1` stops at A. A dry run with explicit ids plans them too.
#[sqlx::test(migrations = "../../migrations")]
async fn direction_and_depth_bound_the_walk(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "sel-alice").await;
    add_member(&pool, t, alice, "writer").await;
    let r = claim(&pool, alice, home, "group", "root").await;
    let a = claim(&pool, alice, home, "group", "child").await;
    let b = claim(&pool, alice, home, "group", "grandchild").await;
    let e = claim(&pool, alice, home, "group", "supporter").await;
    edge(&pool, r, a, "decomposes_to").await;
    edge(&pool, a, b, "decomposes_to").await;
    edge(&pool, e, r, "SUPPORTS").await;

    let body = share(
        &pool,
        &s,
        alice,
        SelectionParams {
            direction: Some("incoming".to_string()),
            ..selection(r)
        },
        t,
        true,
    )
    .await
    .expect("incoming");
    assert_eq!(
        ids(&body["plan"]["claims"]),
        set(&[r, e]),
        "an upper-case SUPPORTS row is followed too: {body}"
    );

    let body = share(
        &pool,
        &s,
        alice,
        SelectionParams {
            max_depth: Some(1),
            ..selection(r)
        },
        t,
        true,
    )
    .await
    .expect("depth 1");
    assert_eq!(ids(&body["plan"]["claims"]), set(&[r, a]), "{body}");

    let body = share_claims_with_team(
        &s.server,
        &viewer(&pool, alice).await,
        ShareClaimsWithTeamParams {
            claim_ids: vec![a.to_string(), b.to_string()],
            dry_run: Some(true),
            group_id: t.to_string(),
            reason: "plan".to_string(),
            ..ShareClaimsWithTeamParams::default()
        },
        Some(&token(alice)),
    )
    .await
    .map(|r| first_text(&r))
    .expect("ids dry run");
    assert_eq!(ids(&body["plan"]["claims"]), set(&[a, b]), "{body}");
    for c in [r, a, b, e] {
        assert_eq!(tenancy(&pool, c).await, ("group".to_string(), home));
    }
    assert!(audits(&pool, "claim.shared_with_team").await.is_empty());
}

/// Eve administers team T and only writes team U. Publicizing from R walks R
/// and A (T's) and stops at S (U's: `refused_not_admin`), so S and the T claim
/// beyond it stay group-only: a stranger reads R and A afterwards and neither
/// S nor W. The audit row names R and A.
#[sqlx::test(migrations = "../../migrations")]
async fn a_publicize_selection_stops_at_a_claim_the_caller_does_not_administer(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "admin-team").await;
    let u = team(&pool, "writer-team").await;
    let (eve, _) = fixture::seed_agent_with_group(&pool, "sel-eve").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "sel-stranger").await;
    add_member(&pool, t, eve, "admin").await;
    add_member(&pool, u, eve, "writer").await;
    let r = claim(&pool, eve, t, "group", "team root").await;
    let a = claim(&pool, eve, t, "group", "team step").await;
    let st = claim(&pool, eve, u, "group", "the other team's step").await;
    let w = claim(&pool, eve, t, "group", "beyond the other team").await;
    edge(&pool, r, a, "decomposes_to").await;
    edge(&pool, a, st, "supports").await;
    edge(&pool, st, w, "decomposes_to").await;

    let body = publicize(&pool, &s, eve, selection(r), true)
        .await
        .expect("dry run");
    assert_eq!(ids(&body["plan"]["claims"]), set(&[r, a]), "{body}");
    assert_eq!(ids(&body["plan"]["boundaries"]), set(&[st]), "{body}");
    assert_eq!(
        boundary_of(&body["plan"], st)["reason"],
        "refused_not_admin",
        "{body}"
    );
    assert!(audits(&pool, "claim.publicized").await.is_empty());
    assert!(!reads(&pool, &s, carol, r).await);

    let body = publicize(&pool, &s, eve, selection(r), false)
        .await
        .expect("published");
    assert_eq!(ids(&body["results"]), set(&[r, a]), "{body}");
    for c in [r, a] {
        assert_eq!(tenancy(&pool, c).await, ("public".to_string(), t));
        assert!(reads(&pool, &s, carol, c).await, "now anyone reads {c}");
    }
    assert_eq!(tenancy(&pool, st).await, ("group".to_string(), u));
    assert_eq!(tenancy(&pool, w).await, ("group".to_string(), t));
    for c in [st, w] {
        assert!(!reads(&pool, &s, carol, c).await, "a stranger reads {c}");
    }
    let rows = audits(&pool, "claim.publicized").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, Some(eve));
    assert_eq!(audited_ids(&rows[0].1), set(&[r, a]), "{rows:?}");
}

/// A root the caller cannot read answers exactly as a missing one, dry run or
/// not, and reveals no plan. A root the act refuses (a public claim, for a
/// share) is a boundary in the dry run and refused with the act's own reason.
///
/// Verified to fail with the root's `not_found` returned as a plan boundary.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_root_answers_as_missing_and_a_refused_root_is_refused(pool: PgPool) {
    let s = app_role(&pool).await;
    let ct = team(&pool, "carols-team").await;
    let at = team(&pool, "alices-team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "sel-alice").await;
    let (carol, _) = fixture::seed_agent_with_group(&pool, "sel-carol").await;
    add_member(&pool, ct, carol, "writer").await;
    add_member(&pool, at, alice, "writer").await;
    let r = claim(&pool, alice, home, "group", "alice's private root").await;
    let a = claim(&pool, alice, home, "group", "alice's private child").await;
    edge(&pool, r, a, "decomposes_to").await;
    let random = Uuid::new_v4();

    for dry_run in [true, false] {
        let err = share(&pool, &s, carol, selection(r), ct, dry_run)
            .await
            .expect_err("unreadable root");
        let err_random = share(&pool, &s, carol, selection(random), ct, dry_run)
            .await
            .expect_err("missing root");
        assert_eq!(err.code, err_random.code, "{err:?}");
        assert_eq!(
            err.message.replace(&r.to_string(), "<id>"),
            err_random.message.replace(&random.to_string(), "<id>"),
            "an unreadable root answers like a missing one"
        );
        assert!(!err.message.contains(&a.to_string()), "{err:?}");
        let err = publicize(&pool, &s, carol, selection(r), dry_run)
            .await
            .expect_err("unreadable root, publicize");
        let err_random = publicize(&pool, &s, carol, selection(random), dry_run)
            .await
            .expect_err("missing root, publicize");
        assert_eq!(
            err.message.replace(&r.to_string(), "<id>"),
            err_random.message.replace(&random.to_string(), "<id>"),
        );
    }

    // Alice's own public claim is not hers to SHARE: a boundary at the root.
    let p = claim(&pool, alice, home, "public", "alice's public root").await;
    edge(&pool, p, a, "decomposes_to").await;
    let body = share(&pool, &s, alice, selection(p), at, true)
        .await
        .expect("dry run");
    assert_eq!(body["plan"]["claims"], serde_json::json!([]), "{body}");
    assert_eq!(
        boundary_of(&body["plan"], p)["reason"],
        "refused_not_private",
        "{body}"
    );
    let err = share(&pool, &s, alice, selection(p), at, false)
        .await
        .expect_err("the root is refused");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_REQUEST, "{err:?}");
    assert!(err.message.contains("not private"), "{err:?}");
    assert_eq!(tenancy(&pool, a).await, ("group".to_string(), home));
    assert!(audits(&pool, "claim.shared_with_team").await.is_empty());
}

/// A selection reaching more than 500 claims to move is refused whole; its
/// dry run says `capped`. Nothing moves.
#[sqlx::test(migrations = "../../migrations")]
async fn a_selection_over_the_cap_is_refused_whole(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "sel-alice").await;
    add_member(&pool, t, alice, "writer").await;
    let r = claim(&pool, alice, home, "group", "a very wide root").await;
    sqlx::query(
        "WITH k AS ( \
           INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                               is_current, visibility, owner_group_id) \
           SELECT gen_random_uuid(), 'part ' || g, sha256(convert_to('part ' || g, 'UTF8')), \
                  0.7, $1, true, 'group', $2 \
             FROM generate_series(1, 501) AS g \
           RETURNING id) \
         INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         SELECT $3, 'claim', k.id, 'claim', 'decomposes_to' FROM k",
    )
    .bind(alice)
    .bind(home)
    .bind(r)
    .execute(&pool)
    .await
    .expect("seed 501 parts");

    let body = share(&pool, &s, alice, selection(r), t, true)
        .await
        .expect("dry run");
    assert_eq!(body["plan"]["capped"], true, "capped");
    let err = share(&pool, &s, alice, selection(r), t, false)
        .await
        .expect_err("over the cap");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(err.message.contains("more than 500"), "{err:?}");
    let moved: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE owner_group_id = $1")
        .bind(t)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(moved, 0);
    assert!(audits(&pool, "claim.shared_with_team").await.is_empty());
}

/// A malformed request is refused before anything runs.
#[sqlx::test(migrations = "../../migrations")]
async fn a_malformed_selection_is_refused(pool: PgPool) {
    let s = app_role(&pool).await;
    let t = team(&pool, "team").await;
    let (alice, home) = fixture::seed_agent_with_group(&pool, "sel-alice").await;
    add_member(&pool, t, alice, "writer").await;
    let r = claim(&pool, alice, home, "group", "root").await;
    let bad = [
        (
            SelectionParams {
                edge_types: Some(vec!["supersedes".to_string()]),
                ..selection(r)
            },
            "edge_types",
        ),
        (
            SelectionParams {
                edge_types: Some(vec![]),
                ..selection(r)
            },
            "edge_types",
        ),
        (
            SelectionParams {
                direction: Some("sideways".to_string()),
                ..selection(r)
            },
            "direction",
        ),
        (
            SelectionParams {
                max_depth: Some(11),
                ..selection(r)
            },
            "max_depth",
        ),
        (
            SelectionParams {
                root: "not-a-uuid".to_string(),
                ..SelectionParams::default()
            },
            "root",
        ),
    ];
    for (sel, field) in bad {
        let err = share(&pool, &s, alice, sel, t, false)
            .await
            .expect_err(field);
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
        assert!(err.message.contains(field), "{field}: {err:?}");
    }
    let err = share_claims_with_team(
        &s.server,
        &viewer(&pool, alice).await,
        ShareClaimsWithTeamParams {
            claim_ids: vec![r.to_string()],
            selection: Some(selection(r)),
            group_id: t.to_string(),
            reason: "both".to_string(),
            ..ShareClaimsWithTeamParams::default()
        },
        Some(&token(alice)),
    )
    .await
    .expect_err("ids and a selection");
    assert!(err.message.contains("not both"), "{err:?}");
    assert_eq!(tenancy(&pool, r).await, ("group".to_string(), home));
}
