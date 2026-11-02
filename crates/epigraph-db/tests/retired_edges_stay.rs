//! Supersede SPEC §11 phase 1, K1 and K2: the edges every replacement act
//! leaves on the claim it retires, in each of the three edge-migration
//! functions (`claim.rs::migrate_superseded_edges`,
//! `::repair_marked_duplicate`, `::migrate_consolidated_edges`).
//!
//! K1 (ruling R-133, which generalises R-113(2); SPEC §5.1 authorship row):
//! an AGENT's `AUTHORED` / `asserts` edge records that THAT agent stated THAT
//! content, and a supersession act edge (`AUTHORED` carrying the reserved
//! `supersede_act` marker, R-23) records who wrote THAT claim. Re-pointed onto
//! a successor, a canonical or a merge, each would credit an agent with
//! content it never saw and strip the retired claim of its record. Before
//! R-133 the supersede cascade kept them only inside a step lineage (U047
//! sub-decision A), and the dedup and merge cascades moved them always.
//!
//! K2 (SPEC §5.1 retracted and lineage rows): a retracted edge is history,
//! and a lineage edge (`supersedes`, newer to older) is never re-pointed. The
//! supersede cascade moved retracted edges, and all three functions excluded
//! only the byte-exact lower-case `supersedes`, so a legacy upper-case
//! `SUPERSEDES` edge on the retired claim was re-pointed (or, in the dedup
//! repair, retracted as a colliding copy).
//!
//! Every act runs on the APPLICATION ROLE stamped as the claims' author; every
//! edge half runs on the `epigraph_maintenance` role (the connection the
//! inline cascade and the deferred replay use), twice, as a replay of an
//! already-applied cascade would. Seeding is on the superuser harness.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, ConsolidateMode, SupersedeActor, SupersedeTool};
use sqlx::PgPool;
use uuid::Uuid;

/// `(source_id, target_id, still in force)` of one edge.
type Ends = (Uuid, Uuid, bool);

/// A public claim authored by `agent`, owned by `group`.
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

/// The ends of every edge in `ids`, in that order, so one assertion shows
/// every edge that moved.
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

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("claim")
}

/// Run `f` on an `epigraph_app` connection stamped as `principal`, with
/// `group` readable and writable, then unstamp.
async fn as_app_stamped<F, Fut, T>(pool: &PgPool, principal: Uuid, group: Uuid, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false)",
        )
        .bind(principal.to_string())
        .bind(group.to_string())
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

/// The supersede act on the application role, stamped as `author` (who is
/// also the actor, so the act edge names `author`), committed.
async fn supersede_act(pool: &PgPool, author: Uuid, group: Uuid, old: Uuid) -> Uuid {
    as_app_stamped(pool, author, group, |mut conn| async move {
        let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
        let (new_id, _) = ClaimRepository::supersede_act_conn(
            &mut tx,
            ClaimId::from_uuid(old),
            &format!("a restatement of {old}"),
            TruthValue::clamped(0.6),
            "restated",
            SupersedeActor::new(author, SupersedeTool::SupersedeClaim),
        )
        .await
        .expect("the author's supersede act on the application role");
        tx.commit().await.expect("commit");
        (conn, new_id)
    })
    .await
}

async fn dedup_act(pool: &PgPool, author: Uuid, group: Uuid, dup: Uuid, canonical: Uuid) {
    as_app_stamped(pool, author, group, |mut conn| async move {
        let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
        ClaimRepository::mark_duplicate_act_conn(
            &mut tx,
            ClaimId::from_uuid(dup),
            ClaimId::from_uuid(canonical),
        )
        .await
        .expect("the author's dedup act on the application role");
        tx.commit().await.expect("commit");
        (conn, ())
    })
    .await
}

async fn consolidate_act(pool: &PgPool, author: Uuid, group: Uuid, sources: Vec<Uuid>) -> Uuid {
    as_app_stamped(pool, author, group, |mut conn| async move {
        let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
        let merged = ClaimRepository::consolidate_act_conn(
            &mut tx,
            &sources,
            "the sources, merged",
            0.6,
            ConsolidateMode::Merge,
            "merge",
            author,
        )
        .await
        .expect("the author's merge act on the application role")
        .merged_id;
        tx.commit().await.expect("commit");
        (conn, merged)
    })
    .await
}

/// The Supersede cascade's edge half, on the maintenance role.
async fn replay_supersede(pool: &PgPool, old: Uuid, new: Uuid) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        ClaimRepository::migrate_superseded_edges_conn(&mut conn, old, new)
            .await
            .expect("supersede edge migration on the maintenance role");
        (conn, ())
    })
    .await;
}

async fn replay_dedup(pool: &PgPool, dup: Uuid, canonical: Uuid) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        ClaimRepository::repair_marked_duplicate_conn(
            &mut conn,
            ClaimId::from_uuid(dup),
            ClaimId::from_uuid(canonical),
        )
        .await
        .expect("dedup repair on the maintenance role");
        (conn, ())
    })
    .await;
}

async fn replay_consolidate(pool: &PgPool, merged: Uuid, sources: Vec<Uuid>) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        ClaimRepository::migrate_consolidated_edges_conn(&mut conn, merged, &sources)
            .await
            .expect("consolidation edge migration on the maintenance role");
        (conn, ())
    })
    .await;
}

/// The `properties` a supersession act edge carries
/// (`ClaimRepository::supersede_act_conn`).
fn act_marker() -> serde_json::Value {
    serde_json::json!({
        "tool": "supersede_claim",
        "was_created": true,
        epigraph_db::SUPERSEDE_ACT_PROPERTY: "supersede_claim",
    })
}

// ── K1: agent authorship and act edges ──────────────────────────────────────

/// Incoming authorship on one retired claim `x`: another agent's `AUTHORED`,
/// a third agent's `asserts`, and a claim-sourced edge carrying the reserved
/// act marker (SPEC §5.2 rule 2 is keyed on the marker, not on the source;
/// no shipped writer can write the marker since the reserved-property
/// refusals, so this one is harness-written). `control` is a third claim's
/// `supports`, which every replacement act moves: it proves the migration ran.
struct Authorship {
    authored: Uuid,
    asserts: Uuid,
    marked: Uuid,
    control: Uuid,
}

async fn seed_authorship(pool: &PgPool, author: Uuid, group: Uuid, x: Uuid) -> Authorship {
    let (w1, _) = fixture::seed_agent_with_group(pool, "k1-authored-by").await;
    let (w2, _) = fixture::seed_agent_with_group(pool, "k1-asserted-by").await;
    let y = claim_of(pool, author, group, "k1 a third claim").await;
    let z = claim_of(pool, author, group, "k1 a marked source").await;
    Authorship {
        authored: edge(pool, (w1, "agent"), (x, "claim"), "AUTHORED", None).await,
        asserts: edge(pool, (w2, "agent"), (x, "claim"), "asserts", None).await,
        marked: edge(
            pool,
            (z, "claim"),
            (x, "claim"),
            "supports",
            Some(act_marker()),
        )
        .await,
        control: edge(pool, (y, "claim"), (x, "claim"), "supports", None).await,
    }
}

/// The supersede cascade outside a step lineage (`supersede_claim` writes no
/// `step_lineage_id`). The retired claim is itself a supersession successor,
/// so it carries a REAL act edge (written by the first act); a second
/// supersession retires it. R-133 (SPEC SF-23, K1).
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_leaves_agent_authorship_and_act_edges_on_the_retired_claim(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "k1-supersede").await;
    let first = claim_of(&pool, author, group, "k1 the first version").await;
    let x = supersede_act(&pool, author, group, first).await;
    replay_supersede(&pool, first, x).await;
    let act_edge: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = 'AUTHORED' AND properties ? $3",
    )
    .bind(author)
    .bind(x)
    .bind(epigraph_db::SUPERSEDE_ACT_PROPERTY)
    .fetch_one(&pool)
    .await
    .expect("the first act's act edge on its successor");
    let a = seed_authorship(&pool, author, group, x).await;
    let before = ends(&pool, &[a.authored, a.asserts, a.marked, act_edge]).await;

    let n = supersede_act(&pool, author, group, x).await;
    replay_supersede(&pool, x, n).await;
    replay_supersede(&pool, x, n).await;

    assert!(!is_current(&pool, x).await, "the act retired x");
    assert_eq!(
        ends(&pool, &[a.control]).await[0].1,
        n,
        "the control supports edge followed the successor: the migration ran"
    );
    assert_eq!(
        ends(&pool, &[a.authored, a.asserts, a.marked, act_edge]).await,
        before,
        "agent AUTHORED, agent asserts, the marked edge and the act edge stay on x"
    );
}

/// The dedup repair. A supersession successor cannot be marked a duplicate
/// (`mark_duplicate_act` refuses a row whose `supersedes` is set), so the act
/// edge on the duplicate is harness-written in the act's own shape; it stands
/// for an act edge on a row that reaches the dedup another way. R-133 (SPEC
/// SF-23, K1).
#[sqlx::test(migrations = "../../migrations")]
async fn dedup_repair_leaves_agent_authorship_and_act_edges_on_the_duplicate(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "k1-dedup").await;
    let dup = claim_of(&pool, author, group, "k1 the duplicate").await;
    let canonical = claim_of(&pool, author, group, "k1 the canonical").await;
    let a = seed_authorship(&pool, author, group, dup).await;
    let act_edge = edge(
        &pool,
        (author, "agent"),
        (dup, "claim"),
        "AUTHORED",
        Some(act_marker()),
    )
    .await;
    let before = ends(&pool, &[a.authored, a.asserts, a.marked, act_edge]).await;

    dedup_act(&pool, author, group, dup, canonical).await;
    replay_dedup(&pool, dup, canonical).await;
    replay_dedup(&pool, dup, canonical).await;

    assert!(
        !is_current(&pool, dup).await,
        "the act retired the duplicate"
    );
    let control = ends(&pool, &[a.control]).await[0];
    assert_eq!(
        (control.1, control.2),
        (canonical, true),
        "the control supports edge followed the canonical: the repair ran"
    );
    assert_eq!(
        ends(&pool, &[a.authored, a.asserts, a.marked, act_edge]).await,
        before,
        "agent AUTHORED, agent asserts, the marked edge and the act edge stay on the duplicate"
    );
}

/// The merge cascade. Each source carries its own authorship set; nothing of
/// either moves onto the merged claim. A merge source cannot be a supersession
/// successor either (`consolidate_act_conn` refuses `supersedes` set), so the
/// act edges are harness-written. R-133 (SPEC SF-23, K1).
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_leaves_agent_authorship_and_act_edges_on_the_sources(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "k1-merge").await;
    let s1 = claim_of(&pool, author, group, "k1 source one").await;
    let s2 = claim_of(&pool, author, group, "k1 source two").await;
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
    let act2 = edge(
        &pool,
        (author, "agent"),
        (s2, "claim"),
        "AUTHORED",
        Some(act_marker()),
    )
    .await;
    let kept = [
        a1.authored,
        a1.asserts,
        a1.marked,
        act1,
        a2.authored,
        a2.asserts,
        a2.marked,
        act2,
    ];
    let before = ends(&pool, &kept).await;

    let merged = consolidate_act(&pool, author, group, vec![s1, s2]).await;
    replay_consolidate(&pool, merged, vec![s1, s2]).await;
    replay_consolidate(&pool, merged, vec![s1, s2]).await;

    assert!(!is_current(&pool, s1).await && !is_current(&pool, s2).await);
    assert_eq!(
        ends(&pool, &[a1.control, a2.control])
            .await
            .iter()
            .map(|e| e.1)
            .collect::<Vec<_>>(),
        vec![merged, merged],
        "both control supports edges followed the merge: the migration ran"
    );
    assert_eq!(
        ends(&pool, &kept).await,
        before,
        "agent AUTHORED, agent asserts, the marked edges and the act edges stay on their sources"
    );
}
