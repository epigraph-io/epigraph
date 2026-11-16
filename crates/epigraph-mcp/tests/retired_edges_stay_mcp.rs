//! Supersede SPEC §11 phase 1, K1 and K2, through the MCP tools: the edges
//! `supersede_claim`, `mark_duplicate` and `consolidate_claims` leave on the
//! claim they retire.
//!
//! K1 (ruling R-133, which generalises R-113(2)): an agent's `AUTHORED` /
//! `asserts` edge, and a supersession act edge, stay on the retired claim.
//! K2: a retracted edge stays on the retired claim.
//!
//! The server's pools are the application role (`epigraph_app`); with the
//! cascade inline, its maintenance pool is a NOSUPERUSER
//! `epigraph_maintenance` login, which the deferred replay also uses (SPEC
//! §12). Seeding runs on the superuser harness. The DB-level twin, including
//! the per-function upper-case `SUPERSEDES` cases, is
//! `crates/epigraph-db/tests/retired_edges_stay.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::consolidate::consolidate_claims;
use epigraph_mcp::tools::supersede::{mark_duplicate, supersede_claim};
use epigraph_mcp::types::{ConsolidateClaimsParams, MarkDuplicateParams, SupersedeClaimParams};
use sqlx::PgPool;
use uuid::Uuid;

/// `(source_id, target_id, still in force)` of one edge.
type Ends = (Uuid, Uuid, bool);

/// The application-role `ScopedPool`; with `inline`, its maintenance pool is a
/// NOSUPERUSER `epigraph_maintenance` login, so the cascade runs in the call.
async fn app_role_server(pool: &PgPool, inline: bool) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "epigraph_app holds BYPASSRLS: vacuous");
    let url = fixture::database_url_for(pool).await;
    let mut scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    if inline {
        scoped = scoped
            .with_maintenance_pool(fixture::downgraded_pool(pool, "epigraph_maintenance").await);
    }
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

fn human(agent: Uuid) -> AuthContext {
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

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("{content} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// An edge written on the harness, with `properties` (`{}` when `None`).
async fn edge(
    pool: &PgPool,
    (source, source_type): (Uuid, &str),
    (target, target_type): (Uuid, &str),
    relationship: &str,
    properties: Option<serde_json::Value>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .bind(properties.unwrap_or_else(|| serde_json::json!({})))
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {relationship} edge: {e}"))
}

async fn ends(pool: &PgPool, ids: &[Uuid]) -> Vec<Ends> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(
            sqlx::query_as(
                "SELECT source_id, target_id, valid_to IS NULL FROM edges WHERE id = $1",
            )
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("edge"),
        );
    }
    out
}

fn uuid_field(body: &serde_json::Value, field: &str) -> Uuid {
    body[field]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{field} in {body}"))
}

/// `author` supersedes `old` through `supersede_claim`; returns the successor
/// and asserts the cascade status.
async fn supersede_via_mcp(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    author: Uuid,
    old: Uuid,
    status: &str,
) -> Uuid {
    let r = supersede_claim(
        server,
        &viewer(pool, author).await,
        SupersedeClaimParams {
            claim_id: old.to_string(),
            content: format!("a correction of {old}"),
            truth_value: 0.6,
            reason: "retired-edges mcp".to_string(),
        },
        Some(&human(author)),
    )
    .await
    .expect("the author's supersede");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], status, "{body}");
    uuid_field(&body, "new_claim_id")
}

/// The act edge a supersession wrote onto `successor` for `actor`.
async fn act_edge_of(pool: &PgPool, actor: Uuid, successor: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = 'AUTHORED' AND properties ? $3",
    )
    .bind(actor)
    .bind(successor)
    .bind(epigraph_db::SUPERSEDE_ACT_PROPERTY)
    .fetch_one(pool)
    .await
    .expect("the act edge on the successor")
}

/// The `properties` a supersession act edge carries.
fn act_marker() -> serde_json::Value {
    serde_json::json!({
        "tool": "supersede_claim",
        "was_created": true,
        epigraph_db::SUPERSEDE_ACT_PROPERTY: "supersede_claim",
    })
}

/// The deferred-cascade replay, on a NOSUPERUSER maintenance login.
async fn replay_now(pool: &PgPool) -> epigraph_engine::admin_cascade::ReplayReport {
    let url = fixture::database_url_for(pool).await;
    let maintenance = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("ScopedPool")
            .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, admin_viewer) = session.split();
    epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        "k2-mcp",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

/// Retract edge `id` (set `valid_to`) on the harness, and check it took.
async fn retract(pool: &PgPool, id: Uuid) {
    let retracted: bool = sqlx::query_scalar(
        "UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1 \
         RETURNING valid_to IS NOT NULL",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("retract the edge");
    assert!(retracted, "fixture: edge {id} is retracted");
}

// ── K1: agent authorship and act edges ──────────────────────────────────────

/// Another agent's `AUTHORED` and a third agent's `asserts` into `x`, and a
/// third claim's `supports` (the control every act moves).
struct Authorship {
    authored: Uuid,
    asserts: Uuid,
    control: Uuid,
}

async fn seed_authorship(pool: &PgPool, author: Uuid, group: Uuid, x: Uuid) -> Authorship {
    let (w1, _) = fixture::seed_agent_with_group(pool, "k1-mcp-authored-by").await;
    let (w2, _) = fixture::seed_agent_with_group(pool, "k1-mcp-asserted-by").await;
    let y = claim_of(pool, author, group, "k1 mcp third claim").await;
    Authorship {
        authored: edge(pool, (w1, "agent"), (x, "claim"), "AUTHORED", None).await,
        asserts: edge(pool, (w2, "agent"), (x, "claim"), "asserts", None).await,
        control: edge(pool, (y, "claim"), (x, "claim"), "supports", None).await,
    }
}

/// `supersede_claim` twice, cascade inline: the second act retires a
/// successor that carries the first act's REAL act edge. R-133 (SPEC SF-23).
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_leaves_agent_authorship_and_act_edges_on_the_retired_claim(pool: PgPool) {
    let server = app_role_server(&pool, true).await;
    let (author, group) = fixture::seed_agent_with_group(&pool, "k1-mcp-supersede").await;
    let first = claim_of(&pool, author, group, "k1 mcp first version").await;
    let x = supersede_via_mcp(&server, &pool, author, first, "applied").await;
    let act_edge = act_edge_of(&pool, author, x).await;
    let a = seed_authorship(&pool, author, group, x).await;
    let kept = [a.authored, a.asserts, act_edge];
    let before = ends(&pool, &kept).await;

    let n = supersede_via_mcp(&server, &pool, author, x, "applied").await;

    assert_eq!(
        ends(&pool, &[a.control]).await[0].1,
        n,
        "the control supports edge followed the successor: the cascade ran"
    );
    assert_eq!(
        ends(&pool, &kept).await,
        before,
        "agent AUTHORED, agent asserts and the act edge stay on the retired claim"
    );
}

/// `mark_duplicate`, cascade inline. A supersession successor cannot be
/// marked (its `supersedes` is set), so the act edge on the duplicate is
/// harness-written in the act's shape. R-133 (SPEC SF-23).
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_leaves_agent_authorship_and_act_edges_on_the_duplicate(pool: PgPool) {
    let server = app_role_server(&pool, true).await;
    let (author, group) = fixture::seed_agent_with_group(&pool, "k1-mcp-dedup").await;
    let dup = claim_of(&pool, author, group, "k1 mcp duplicate").await;
    let canonical = claim_of(&pool, author, group, "k1 mcp canonical").await;
    let a = seed_authorship(&pool, author, group, dup).await;
    let act_edge = edge(
        &pool,
        (author, "agent"),
        (dup, "claim"),
        "AUTHORED",
        Some(act_marker()),
    )
    .await;
    let kept = [a.authored, a.asserts, act_edge];
    let before = ends(&pool, &kept).await;

    let r = mark_duplicate(
        &server,
        &viewer(&pool, author).await,
        MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
        Some(&human(author)),
    )
    .await
    .expect("the author's dedup");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "applied", "{body}");

    let control = ends(&pool, &[a.control]).await[0];
    assert_eq!(
        (control.1, control.2),
        (canonical, true),
        "the control supports edge followed the canonical: the repair ran"
    );
    assert_eq!(
        ends(&pool, &kept).await,
        before,
        "agent AUTHORED, agent asserts and the act edge stay on the duplicate"
    );
}

/// `consolidate_claims`, cascade inline (there is no consolidate HTTP route).
/// R-133 (SPEC SF-23).
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_claims_leaves_agent_authorship_and_act_edges_on_the_sources(pool: PgPool) {
    let server = app_role_server(&pool, true).await;
    let (author, group) = fixture::seed_agent_with_group(&pool, "k1-mcp-merge").await;
    let s1 = claim_of(&pool, author, group, "k1 mcp source one").await;
    let s2 = claim_of(&pool, author, group, "k1 mcp source two").await;
    let a1 = seed_authorship(&pool, author, group, s1).await;
    let a2 = seed_authorship(&pool, author, group, s2).await;
    let act1 = edge(
        &pool,
        (author, "agent"),
        (s1, "claim"),
        "AUTHORED",
        Some(act_marker()),
    )
    .await;
    let kept = [a1.authored, a1.asserts, act1, a2.authored, a2.asserts];
    let before = ends(&pool, &kept).await;

    let r = consolidate_claims(
        &server,
        &viewer(&pool, author).await,
        ConsolidateClaimsParams {
            source_claim_ids: vec![s1.to_string(), s2.to_string()],
            merged_content: "k1 mcp sources, merged".to_string(),
            mode: "merge".to_string(),
            reason: "retired-edges mcp".to_string(),
            confidence: Some(0.6),
            survivor_claim_id: None,
        },
        Some(&human(author)),
    )
    .await
    .expect("the author's merge");
    let body = first_text(&r);
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    let merged = uuid_field(&body, "merged_claim_id");

    assert_eq!(
        ends(&pool, &[a1.control, a2.control])
            .await
            .iter()
            .map(|e| e.1)
            .collect::<Vec<_>>(),
        vec![merged, merged],
        "both control supports edges followed the merge: the cascade ran"
    );
    assert_eq!(
        ends(&pool, &kept).await,
        before,
        "agent AUTHORED, agent asserts and the act edge stay on their sources"
    );
}

// ── K2: retracted edges ─────────────────────────────────────────────────────

/// A retracted incoming and a retracted outgoing edge on the predecessor, and
/// their live twins (the controls, which move).
struct Retracted {
    x: Uuid,
    y: Uuid,
    z: Uuid,
    incoming: Uuid,
    outgoing: Uuid,
    live_in: Uuid,
    live_out: Uuid,
}

async fn seed_retracted(pool: &PgPool, author: Uuid, group: Uuid) -> Retracted {
    let x = claim_of(pool, author, group, "k2 mcp predecessor").await;
    let y = claim_of(pool, author, group, "k2 mcp supporter").await;
    let z = claim_of(pool, author, group, "k2 mcp supported claim").await;
    let incoming = edge(pool, (y, "claim"), (x, "claim"), "supports", None).await;
    let outgoing = edge(pool, (x, "claim"), (z, "claim"), "supports", None).await;
    retract(pool, incoming).await;
    retract(pool, outgoing).await;
    Retracted {
        x,
        y,
        z,
        incoming,
        outgoing,
        live_in: edge(pool, (y, "claim"), (x, "claim"), "corroborates", None).await,
        live_out: edge(pool, (x, "claim"), (z, "claim"), "corroborates", None).await,
    }
}

async fn assert_retracted_stayed(pool: &PgPool, r: &Retracted, before: &[Ends], n: Uuid) {
    assert_eq!(
        ends(pool, &[r.live_in, r.live_out]).await,
        vec![(r.y, n, true), (n, r.z, true)],
        "the live controls followed the successor: the cascade ran"
    );
    assert_eq!(
        ends(pool, &[r.incoming, r.outgoing]).await,
        before,
        "the retracted incoming and outgoing edges stay on the predecessor"
    );
}

/// The supersede, cascade inline.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_inline_leaves_retracted_edges_on_the_predecessor(pool: PgPool) {
    let server = app_role_server(&pool, true).await;
    let (author, group) = fixture::seed_agent_with_group(&pool, "k2-mcp-inline").await;
    let r = seed_retracted(&pool, author, group).await;
    let before = ends(&pool, &[r.incoming, r.outgoing]).await;

    let n = supersede_via_mcp(&server, &pool, author, r.x, "applied").await;

    assert_retracted_stayed(&pool, &r, &before, n).await;
}

/// The supersede with no maintenance connection: deferred, then replayed on
/// the maintenance login.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_deferred_replay_leaves_retracted_edges_on_the_predecessor(pool: PgPool) {
    let server = app_role_server(&pool, false).await;
    let (author, group) = fixture::seed_agent_with_group(&pool, "k2-mcp-deferred").await;
    let r = seed_retracted(&pool, author, group).await;
    let before = ends(&pool, &[r.incoming, r.outgoing]).await;

    let n = supersede_via_mcp(&server, &pool, author, r.x, "deferred").await;
    let report = replay_now(&pool).await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");

    assert_retracted_stayed(&pool, &r, &before, n).await;
}
