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
//! The document ingest's record of a claim (`paper -ingested_claim->`) is
//! about the row that ingest created or found: moved by any of the three, it
//! loses its ingest-written marker, so the claim it then points at reads no
//! ingest of that paper (the last test).
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

async fn relationship_of(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT relationship FROM edges WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("edge")
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

/// A legacy upper-case lineage edge, checked byte-exact after the write (a
/// write path that folded it would make the test pass for the wrong reason).
async fn upper_lineage(pool: &PgPool, newer: Uuid, older: Uuid) -> Uuid {
    let id = edge(pool, (newer, "claim"), (older, "claim"), "SUPERSEDES", None).await;
    assert_eq!(
        relationship_of(pool, id).await,
        "SUPERSEDES",
        "fixture: the legacy spelling is stored byte-exact"
    );
    id
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
    act_marker_of(epigraph_db::SupersedeTool::SupersedeClaim.as_str())
}

/// [`act_marker`] for the act written by `tool` (a [`SupersedeTool`] value:
/// `supersede_claim` or the custodial supersede's).
///
/// [`SupersedeTool`]: epigraph_db::SupersedeTool
fn act_marker_of(tool: &str) -> serde_json::Value {
    serde_json::json!({
        "tool": tool,
        "was_created": true,
        epigraph_db::SUPERSEDE_ACT_PROPERTY: tool,
    })
}

/// `(target, in force)` of each edge in `ids`: what a moved edge must show.
async fn targets(pool: &PgPool, ids: &[Uuid]) -> Vec<(Uuid, bool)> {
    ends(pool, ids)
        .await
        .into_iter()
        .map(|(_, t, live)| (t, live))
        .collect()
}

// ── K1: agent authorship and act edges ──────────────────────────────────────

/// Incoming authorship on one retired claim `x`: another agent's `AUTHORED`,
/// a third agent's `asserts`, and a claim-sourced edge carrying the reserved
/// act marker with tool value `act_tool` (SPEC §5.2 rule 2 is keyed on the
/// marker, not on the source; it is harness-written here: the generic edge
/// writers that run the reserved-property refusal reject the marker, though
/// MCP `link_epistemic` / `link_hierarchical` do not run it yet).
///
/// Then the boundary, edges every replacement act still moves: `control` is
/// a third claim's `supports` (it proves the migration ran), and
/// `claim_asserts` / `claim_authored` are CLAIM-sourced `asserts` and
/// `AUTHORED` without the marker. R-133 keeps only AGENT-sourced authorship
/// (SPEC §5.1), so these two follow the act like any other edge; they pin the
/// `source_type = 'agent'` conjunct of each function's exclusion.
struct Authorship {
    authored: Uuid,
    asserts: Uuid,
    marked: Uuid,
    control: Uuid,
    claim_asserts: Uuid,
    claim_authored: Uuid,
}

impl Authorship {
    /// The edges the act must move, in a fixed order.
    fn moved(&self) -> [Uuid; 3] {
        [self.control, self.claim_asserts, self.claim_authored]
    }
}

async fn seed_authorship(
    pool: &PgPool,
    author: Uuid,
    group: Uuid,
    x: Uuid,
    act_tool: &str,
) -> Authorship {
    let (w1, _) = fixture::seed_agent_with_group(pool, "k1-authored-by").await;
    let (w2, _) = fixture::seed_agent_with_group(pool, "k1-asserted-by").await;
    let y = claim_of(pool, author, group, "k1 a third claim").await;
    let z = claim_of(pool, author, group, "k1 a marked source").await;
    let ca = claim_of(pool, author, group, "k1 an asserting claim").await;
    let cw = claim_of(pool, author, group, "k1 an authoring claim").await;
    Authorship {
        authored: edge(pool, (w1, "agent"), (x, "claim"), "AUTHORED", None).await,
        asserts: edge(pool, (w2, "agent"), (x, "claim"), "asserts", None).await,
        marked: edge(
            pool,
            (z, "claim"),
            (x, "claim"),
            "supports",
            Some(act_marker_of(act_tool)),
        )
        .await,
        control: edge(pool, (y, "claim"), (x, "claim"), "supports", None).await,
        claim_asserts: edge(pool, (ca, "claim"), (x, "claim"), "asserts", None).await,
        claim_authored: edge(pool, (cw, "claim"), (x, "claim"), "AUTHORED", None).await,
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
    let a = seed_authorship(
        &pool,
        author,
        group,
        x,
        epigraph_db::SupersedeTool::SupersedeClaim.as_str(),
    )
    .await;
    let before = ends(&pool, &[a.authored, a.asserts, a.marked, act_edge]).await;

    let n = supersede_act(&pool, author, group, x).await;
    replay_supersede(&pool, x, n).await;
    replay_supersede(&pool, x, n).await;

    assert!(!is_current(&pool, x).await, "the act retired x");
    assert_eq!(
        targets(&pool, &a.moved()).await,
        vec![(n, true); 3],
        "the control supports, the claim-sourced asserts and the claim-sourced \
         AUTHORED followed the successor: the migration ran, and only AGENT \
         authorship stays"
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
    // The custodial supersede's tool value, so both SUPERSEDE_ACT_TOOLS
    // entries are pinned across the K1 tests.
    let a = seed_authorship(
        &pool,
        author,
        group,
        dup,
        epigraph_db::SupersedeTool::CustodialSupersede.as_str(),
    )
    .await;
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
    assert_eq!(
        targets(&pool, &a.moved()).await,
        vec![(canonical, true); 3],
        "the control supports, the claim-sourced asserts and the claim-sourced \
         AUTHORED followed the canonical: the repair ran, and only AGENT \
         authorship stays"
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
    let a1 = seed_authorship(
        &pool,
        author,
        group,
        s1,
        epigraph_db::SupersedeTool::SupersedeClaim.as_str(),
    )
    .await;
    let a2 = seed_authorship(
        &pool,
        author,
        group,
        s2,
        epigraph_db::SupersedeTool::CustodialSupersede.as_str(),
    )
    .await;
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
    let moved: Vec<Uuid> = a1.moved().into_iter().chain(a2.moved()).collect();
    assert_eq!(
        targets(&pool, &moved).await,
        vec![(merged, true); 6],
        "both sources' control supports, claim-sourced asserts and claim-sourced \
         AUTHORED followed the merge: the migration ran, and only AGENT \
         authorship stays"
    );
    assert_eq!(
        ends(&pool, &kept).await,
        before,
        "agent AUTHORED, agent asserts, the marked edges and the act edges stay on their sources"
    );
}

// ── K2: retracted edges and lineage edges of either spelling ────────────────

/// The supersede cascade: a retracted incoming and a retracted outgoing edge
/// are history about the predecessor and stay on it; their live twins (the
/// controls) move.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_leaves_retracted_edges_on_the_predecessor(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "k2-retracted").await;
    let x = claim_of(&pool, author, group, "k2 the predecessor").await;
    let y = claim_of(&pool, author, group, "k2 a supporter").await;
    let z = claim_of(&pool, author, group, "k2 a supported claim").await;
    let incoming = edge(&pool, (y, "claim"), (x, "claim"), "supports", None).await;
    let outgoing = edge(&pool, (x, "claim"), (z, "claim"), "supports", None).await;
    retract(&pool, incoming).await;
    retract(&pool, outgoing).await;
    let live_in = edge(&pool, (y, "claim"), (x, "claim"), "corroborates", None).await;
    let live_out = edge(&pool, (x, "claim"), (z, "claim"), "corroborates", None).await;
    let before = ends(&pool, &[incoming, outgoing]).await;

    let n = supersede_act(&pool, author, group, x).await;
    replay_supersede(&pool, x, n).await;
    replay_supersede(&pool, x, n).await;

    assert_eq!(
        ends(&pool, &[live_in, live_out]).await,
        vec![(y, n, true), (n, z, true)],
        "the live controls followed the successor: the migration ran"
    );
    assert_eq!(
        ends(&pool, &[incoming, outgoing]).await,
        before,
        "the retracted incoming and outgoing edges stay on the predecessor"
    );
}

/// The supersede cascade: a legacy upper-case `SUPERSEDES` edge in either
/// direction on the predecessor is lineage and is never re-pointed.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_leaves_upper_case_lineage_edges_on_the_predecessor(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "k2-upper-supersede").await;
    let x = claim_of(&pool, author, group, "k2 the predecessor").await;
    let newer = claim_of(&pool, author, group, "k2 a legacy newer claim").await;
    let older = claim_of(&pool, author, group, "k2 a legacy older claim").await;
    let incoming = upper_lineage(&pool, newer, x).await;
    let outgoing = upper_lineage(&pool, x, older).await;
    let control = edge(&pool, (newer, "claim"), (x, "claim"), "supports", None).await;
    let before = ends(&pool, &[incoming, outgoing]).await;

    let n = supersede_act(&pool, author, group, x).await;
    replay_supersede(&pool, x, n).await;
    replay_supersede(&pool, x, n).await;

    assert_eq!(
        ends(&pool, &[control]).await[0].1,
        n,
        "the control followed the successor: the migration ran"
    );
    assert_eq!(
        ends(&pool, &[incoming, outgoing]).await,
        before,
        "both upper-case lineage edges stay on the predecessor"
    );
}

/// The dedup repair: upper-case `SUPERSEDES` edges on the duplicate are
/// neither re-pointed (the two re-points) nor retracted as a colliding copy of
/// a triple the canonical already holds (the two collision guards).
#[sqlx::test(migrations = "../../migrations")]
async fn dedup_repair_leaves_upper_case_lineage_edges_on_the_duplicate(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "k2-upper-dedup").await;
    let dup = claim_of(&pool, author, group, "k2 the duplicate").await;
    let canonical = claim_of(&pool, author, group, "k2 the canonical").await;
    let newer = claim_of(&pool, author, group, "k2 a legacy newer claim").await;
    let older = claim_of(&pool, author, group, "k2 a legacy older claim").await;
    let shared_newer = claim_of(&pool, author, group, "k2 a newer claim of both").await;
    let shared_older = claim_of(&pool, author, group, "k2 an older claim of both").await;
    let incoming = upper_lineage(&pool, newer, dup).await;
    let outgoing = upper_lineage(&pool, dup, older).await;
    // The canonical holds the same triples, so the collision guards see these.
    let colliding_in = upper_lineage(&pool, shared_newer, dup).await;
    upper_lineage(&pool, shared_newer, canonical).await;
    let colliding_out = upper_lineage(&pool, dup, shared_older).await;
    upper_lineage(&pool, canonical, shared_older).await;
    let control = edge(&pool, (newer, "claim"), (dup, "claim"), "supports", None).await;
    let kept = [incoming, outgoing, colliding_in, colliding_out];
    let before = ends(&pool, &kept).await;

    dedup_act(&pool, author, group, dup, canonical).await;
    replay_dedup(&pool, dup, canonical).await;
    replay_dedup(&pool, dup, canonical).await;

    let c = ends(&pool, &[control]).await[0];
    assert_eq!(
        (c.1, c.2),
        (canonical, true),
        "the control followed the canonical: the repair ran"
    );
    assert_eq!(
        ends(&pool, &kept).await,
        before,
        "every upper-case lineage edge stays, in force, on the duplicate"
    );
}

/// The merge cascade: upper-case `SUPERSEDES` edges on a source are not
/// candidates (neither moved nor retracted).
#[sqlx::test(migrations = "../../migrations")]
async fn consolidate_leaves_upper_case_lineage_edges_on_the_sources(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "k2-upper-merge").await;
    let s1 = claim_of(&pool, author, group, "k2 source one").await;
    let s2 = claim_of(&pool, author, group, "k2 source two").await;
    let newer = claim_of(&pool, author, group, "k2 a legacy newer claim").await;
    let older = claim_of(&pool, author, group, "k2 a legacy older claim").await;
    let incoming = upper_lineage(&pool, newer, s1).await;
    let outgoing = upper_lineage(&pool, s2, older).await;
    let control = edge(&pool, (newer, "claim"), (s1, "claim"), "supports", None).await;
    let before = ends(&pool, &[incoming, outgoing]).await;

    let merged = consolidate_act(&pool, author, group, vec![s1, s2]).await;
    replay_consolidate(&pool, merged, vec![s1, s2]).await;
    replay_consolidate(&pool, merged, vec![s1, s2]).await;

    assert_eq!(
        ends(&pool, &[control]).await[0].1,
        merged,
        "the control followed the merge: the migration ran"
    );
    assert_eq!(
        ends(&pool, &[incoming, outgoing]).await,
        before,
        "both upper-case lineage edges stay on their sources"
    );
}

// ── The document ingest's record of a claim stays with that claim ──────────

/// `claim` created by `filer`'s ingest of a fresh paper, as the walk records
/// it: the paper's ingest-written assertion and the creation record. Returns
/// the paper and the record's edge id.
async fn ingest_created(pool: &PgPool, filer: Uuid, claim: Uuid) -> (Uuid, Uuid) {
    let paper: Uuid =
        sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, $1) RETURNING id")
            .bind(format!("10.9999/moved-record-{}", Uuid::new_v4()))
            .fetch_one(pool)
            .await
            .expect("paper");
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        filer,
        paper,
        "paper",
        claim,
        "claim",
        "asserts",
        None,
    )
    .await
    .expect("the paper's assertion");
    assert!(epigraph_db::ClaimIngestRepository::record_signed_conn(
        &mut conn,
        None,
        paper,
        claim,
        filer,
        true,
        "ingest_document",
        "test-pipeline",
    )
    .await
    .expect("the creation record"));
    let record: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND relationship = 'ingested_claim'",
    )
    .bind(paper)
    .fetch_one(&mut *conn)
    .await
    .expect("record id");
    (paper, record)
}

/// The papers `viewer` reads as having ingested `claim`, and the creator's.
async fn ingests_of(pool: &PgPool, filer: Uuid, claim: Uuid) -> (Vec<Uuid>, Option<Uuid>) {
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, filer)
        .await
        .expect("viewer");
    let mut conn = pool.acquire().await.expect("conn");
    let got = epigraph_db::ClaimIngestRepository::for_claim(&mut conn, &viewer, claim)
        .await
        .expect("for_claim");
    (
        got.records.iter().map(|r| r.paper_id).collect(),
        got.creator.map(|c| c.paper_id),
    )
}

async fn filer_of(pool: &PgPool, claim: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("filer")
}

/// A creation record says which document ingest created THAT row. The three
/// replacement cascades re-point incoming claim edges onto the successor, the
/// canonical or the merge, the record and its paper's assertion included;
/// moved, both lose the ingest-written marker (migration 198), so the claim
/// they now point at reads no ingest of that paper, and never as created by
/// it, although its filer is the same ingester (which, without the marker
/// requirement, would make it read as that paper's literature). CALIBRATION:
/// before the act the retired claim reads the paper as its creator. This
/// test: the supersede cascade.
#[sqlx::test(migrations = "../../migrations")]
async fn a_superseded_claims_ingest_record_names_no_ingest_on_its_successor(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "moved-record").await;
    let old = claim_of(&pool, author, group, "ingest-created, superseded").await;
    let (p, record) = ingest_created(&pool, author, old).await;
    assert_eq!(ingests_of(&pool, author, old).await, (vec![p], Some(p)), "CALIBRATION");
    let new = supersede_act(&pool, author, group, old).await;
    replay_supersede(&pool, old, new).await;
    replay_supersede(&pool, old, new).await;
    assert_eq!(filer_of(&pool, new).await, author, "CALIBRATION: the same filer");
    assert_eq!(
        ingests_of(&pool, author, new).await,
        (vec![], None),
        "the successor is no ingest's creation (record now on {:?})",
        ends(&pool, &[record]).await
    );
}

/// As above, for the dedup cascade: an ingest-created duplicate of a claim
/// its filer filed directly.
#[sqlx::test(migrations = "../../migrations")]
async fn a_duplicates_ingest_record_names_no_ingest_on_its_canonical(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "moved-record").await;
    let dup = claim_of(&pool, author, group, "ingest-created duplicate").await;
    let canonical = claim_of(&pool, author, group, "filed directly").await;
    let (p, record) = ingest_created(&pool, author, dup).await;
    assert_eq!(ingests_of(&pool, author, dup).await, (vec![p], Some(p)), "CALIBRATION");
    dedup_act(&pool, author, group, dup, canonical).await;
    replay_dedup(&pool, dup, canonical).await;
    replay_dedup(&pool, dup, canonical).await;
    assert_eq!(
        ingests_of(&pool, author, canonical).await,
        (vec![], None),
        "the canonical stays the filer's own (record now on {:?})",
        ends(&pool, &[record]).await
    );
}

/// As above, for the merge cascade.
#[sqlx::test(migrations = "../../migrations")]
async fn a_merge_sources_ingest_record_names_no_ingest_on_the_merge(pool: PgPool) {
    let (author, group) = fixture::seed_agent_with_group(&pool, "moved-record").await;
    let a = claim_of(&pool, author, group, "ingest-created merge source").await;
    let b = claim_of(&pool, author, group, "another merge source").await;
    let (p, record) = ingest_created(&pool, author, a).await;
    assert_eq!(ingests_of(&pool, author, a).await, (vec![p], Some(p)), "CALIBRATION");
    let merged = consolidate_act(&pool, author, group, vec![a, b]).await;
    replay_consolidate(&pool, merged, vec![a, b]).await;
    replay_consolidate(&pool, merged, vec![a, b]).await;
    assert_eq!(filer_of(&pool, merged).await, author, "CALIBRATION: the same filer");
    assert_eq!(
        ingests_of(&pool, author, merged).await,
        (vec![], None),
        "the merge is no ingest's creation (record now on {:?})",
        ends(&pool, &[record]).await
    );
}
