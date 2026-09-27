//! Migration 115: DELETE is owner-scoped on every tier-A table.
//!
//! 077's FOR ALL policies used the READ predicate as DELETE's USING, so the
//! rows a session could remove were the rows it could read. 115 adds one
//! RESTRICTIVE, FOR DELETE policy per table (owner in the writable set; for
//! `edges` also the co-owner, and the source's writer for an edge nobody owns),
//! and moves the three cascades that remove other writers' edge-keyed BBAs
//! behind an audited definer.
//!
//! Migration 117 then made those cascades an ADMINISTRATIVE act: the definer
//! keeps only its owner arm (a non-privileged call over another writer's row
//! is refused, CD02), and the dedup repair, the supersede edge migration and
//! the match-candidate retirement cascade run on the maintenance connection,
//! which each of them now requires. The cascade arms below assert exactly that
//! split: refused for every non-privileged session, landing on
//! `epigraph_maintenance`.
//!
//! # Why every arm runs as `epigraph_app`
//!
//! `#[sqlx::test]` connects as the superuser `epigraph`, for whom every policy
//! is bypassed, so "the delete removed nothing" and "the delete removed the
//! row" are indistinguishable on the harness connection. Every arm below that
//! asserts a refusal or an admission switches to the non-bypassing
//! `epigraph_app` (`SET SESSION AUTHORIZATION`, so `session_user` is the app
//! role) and stamps the session GUCs exactly as `ScopedPool::begin_as` does.
//!
//! # The application code paths that DELETE a tier-A row (grep, at this commit)
//!
//! `claims` (`ClaimRepository::delete`), `evidence` (`evidence.rs::delete`,
//! `visibility.rs`'s `{WRITABLE:e}` deletes -- already owner-scoped),
//! `mass_functions` (the three cascades below, and `delete_for_claim`, which
//! has no caller), `edges` (`workflow_steps.rs`'s `step_follows` rewire, and the
//! node-delete trigger), `claim_cluster_membership` (the bridge-cluster GC).
//! No application path deletes a registry row (`frames`, `contexts`,
//! `perspectives`, `communities`).
//!
//! # What is accepted rather than gated
//!
//! FK `ON DELETE CASCADE` is a referential action and consults no policy. Five
//! (parent, child) pairs reach a tier-A child from a parent the application may
//! delete without an owner rule (`harvester_sources`, `experiment_entities`
//! twice, `graph_clusters`, `graph_neighborhoods`; the last is reached from
//! `claim_themes`' rebuild and the cluster-run deletes). All are
//! materializations. `every_unscoped_fk_cascade_into_tier_a_is_listed` is the
//! exact register. Node tables outside tier A keep 001's invoker edge cascade,
//! and `no_application_path_deletes_a_non_tier_a_edge_node` registers every
//! application DELETE of one.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{FrameRepository, MassFunctionRepository, MatchCandidateRepo};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

async fn assert_app_role_does_not_bypass(pool: &PgPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so every arm in this file is vacuous"
    );
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Stamp `conn` for `agent` exactly as `ScopedPool::begin_as` would.
async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
    assert!(
        !writable.is_empty(),
        "a writer with no writable group makes every arm vacuous"
    );
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(groups)
    .bind(writable)
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp session gucs");
}

/// The unstamped steady state of an app session.
async fn unstamp(conn: &mut PgConnection) {
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', '', false), \
                set_config('epigraph.writable_group_ids', '', false), \
                set_config('epigraph.principal_id', '', false)",
    )
    .execute(&mut *conn)
    .await
    .expect("clear session gucs");
}

async fn seed_frame(pool: &PgPool, name: &str) -> Uuid {
    FrameRepository::create(
        pool,
        name,
        Some("owner-scoped delete fixture"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("seed frame")
    .id
}

/// A public claim owned by `group` (not the world): what the write path gives a
/// claim its own author submits.
async fn seed_public_claim_owned_by(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("owner-scoped delete fixture claim {tag}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a public claim owned by a group");
    id
}

/// An edge id is also the perspective its BBAs are keyed by
/// (`ensure_edge_perspective`); `mass_functions.perspective_id` is an FK.
async fn seed_perspective(pool: &PgPool, id: Uuid) {
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("edge {id}"))
        .execute(pool)
        .await
        .expect("seed edge perspective");
}

async fn insert_evidence(conn: &mut PgConnection, claim: Uuid, tag: &str) -> Uuid {
    let hash: Vec<u8> = blake3::hash(format!("{claim}:{tag}").as_bytes())
        .as_bytes()
        .to_vec();
    sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, raw_content) \
         VALUES ($1, 'observation', $2, $3) RETURNING id",
    )
    .bind(claim)
    .bind(&hash)
    .bind(format!("owner-scoped evidence {tag}"))
    .fetch_one(&mut *conn)
    .await
    .expect("attach evidence")
}

async fn insert_trace(conn: &mut PgConnection, claim: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, explanation) \
         VALUES ($1, 'deductive', 'owner-scoped trace') RETURNING id",
    )
    .bind(claim)
    .fetch_one(&mut *conn)
    .await
    .expect("attach trace")
}

async fn store_bba(
    conn: &mut PgConnection,
    claim: Uuid,
    frame: Uuid,
    source_agent: Uuid,
    perspective: Option<Uuid>,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        claim,
        frame,
        Some(source_agent),
        perspective,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("test"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("store bba")
}

async fn delete_by_id(conn: &mut PgConnection, table: &str, id: Uuid) -> u64 {
    sqlx::query(&format!("DELETE FROM {table} WHERE id = $1"))
        .bind(id)
        .execute(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("DELETE FROM {table}: {e}"))
        .rows_affected()
}

async fn exists(pool: &PgPool, table: &str, id: Uuid) -> bool {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM {table} WHERE id = $1)"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read {table}: {e}"))
}

async fn writer_owned(pool: &PgPool, table: &str, id: Uuid) -> (Uuid, bool) {
    sqlx::query_as(&format!(
        "SELECT owner_group_id, writer_owned FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read {table} {id}: {e}"))
}

/// `(agent_id, cause, deleted, arms)` of every cascade audit row, oldest first.
async fn cascade_audit(pool: &PgPool) -> Vec<(Option<Uuid>, String, i64, serde_json::Value)> {
    sqlx::query_as(
        "SELECT agent_id, details->>'cause', (details->>'deleted')::bigint, details->'arms' \
           FROM security_events WHERE event_type = 'derived.cascade_bba_delete' \
          ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .expect("read cascade audit")
}

// ===========================================================================
// 1. The refusals.
// ===========================================================================

/// X attaches evidence, a mass function and a trace to a WORLD claim; the rows
/// are X's (migration 114). Another writer W, and an unstamped app session,
/// DELETE each by id and remove nothing, although both can READ all three
/// (they are public). X itself then deletes all three.
#[sqlx::test(migrations = "../../migrations")]
async fn another_writers_delete_of_a_writer_owned_row_removes_nothing(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (x, x_group) = fixture::seed_agent_with_group(&pool, "writer-x").await;
    let (w, _) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let claim = fixture::seed_public_claim(&pool, author, "a world claim").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (ev, mf, tr, seen_by_w, by_w, by_unstamped) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, x).await;
            let ev = insert_evidence(&mut conn, claim, "x").await;
            let mf = store_bba(&mut conn, claim, bt, x, None).await;
            let tr = insert_trace(&mut conn, claim).await;

            stamp(&mut conn, &p, w).await;
            // Calibration: W can READ every one of them, so a 0 below is the
            // DELETE rule and not the read rule.
            let mut seen_by_w = 0_i64;
            for (t, id) in [
                ("evidence", ev),
                ("mass_functions", mf),
                ("reasoning_traces", tr),
            ] {
                let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {t} WHERE id = $1"))
                    .bind(id)
                    .fetch_one(&mut *conn)
                    .await
                    .expect("read as W");
                seen_by_w += n;
            }
            let mut by_w = Vec::new();
            for (t, id) in [
                ("evidence", ev),
                ("mass_functions", mf),
                ("reasoning_traces", tr),
            ] {
                by_w.push(delete_by_id(&mut conn, t, id).await);
            }
            unstamp(&mut conn).await;
            let mut by_unstamped = Vec::new();
            for (t, id) in [
                ("evidence", ev),
                ("mass_functions", mf),
                ("reasoning_traces", tr),
            ] {
                by_unstamped.push(delete_by_id(&mut conn, t, id).await);
            }
            (conn, (ev, mf, tr, seen_by_w, by_w, by_unstamped))
        })
        .await;

    assert_eq!(seen_by_w, 3, "calibration: W reads all three public rows");
    assert_eq!(
        by_w,
        vec![0, 0, 0],
        "another writer deletes none of X's rows"
    );
    assert_eq!(
        by_unstamped,
        vec![0, 0, 0],
        "an unstamped app session deletes none"
    );
    for (t, id) in [
        ("evidence", ev),
        ("mass_functions", mf),
        ("reasoning_traces", tr),
    ] {
        assert!(exists(&pool, t, id).await, "{t} {id} survived");
        assert_eq!(
            writer_owned(&pool, t, id).await,
            (x_group, true),
            "fixture shape: {t} is X's writer-owned row"
        );
    }

    // The owner's own delete still works.
    let p = pool.clone();
    let by_x = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, x).await;
        let mut n = Vec::new();
        for (t, id) in [
            ("evidence", ev),
            ("mass_functions", mf),
            ("reasoning_traces", tr),
        ] {
            n.push(delete_by_id(&mut conn, t, id).await);
        }
        (conn, n)
    })
    .await;
    assert_eq!(by_x, vec![1, 1, 1], "X deletes its own rows");
}

/// A WORLD-owned claim, its world-owned `claim_frames` assignment and a
/// world-owned registry row are not deletable by any application session --
/// the world group is memberless, so it is in nobody's writable set. The
/// superuser harness connection (a privileged session) still deletes all
/// three, unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn a_world_owned_row_is_not_deletable_from_the_app_role(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, _) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let claim = fixture::seed_public_claim(&pool, author, "a world claim").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let spare = seed_frame(&pool, "a spare registry frame").await;
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim)
    .bind(bt)
    .execute(&pool)
    .await
    .expect("seed the claim's frame assignment");
    let owners: (Uuid, Uuid, Uuid) = sqlx::query_as(
        "SELECT (SELECT owner_group_id FROM claims WHERE id = $1), \
                (SELECT owner_group_id FROM claim_frames WHERE claim_id = $1), \
                (SELECT owner_group_id FROM frames WHERE id = $2)",
    )
    .bind(claim)
    .bind(spare)
    .fetch_one(&pool)
    .await
    .expect("owners");
    assert_eq!(
        owners,
        (WORLD, WORLD, WORLD),
        "fixture shape: all world-owned"
    );
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (claim_n, cf_n, frame_n) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let cf_n = sqlx::query("DELETE FROM claim_frames WHERE claim_id = $1")
            .bind(claim)
            .execute(&mut *conn)
            .await
            .expect("delete claim_frames")
            .rows_affected();
        let claim_n = delete_by_id(&mut conn, "claims", claim).await;
        let frame_n = delete_by_id(&mut conn, "frames", spare).await;
        (conn, (claim_n, cf_n, frame_n))
    })
    .await;
    assert_eq!((claim_n, cf_n, frame_n), (0, 0, 0));
    assert!(exists(&pool, "claims", claim).await);
    assert!(exists(&pool, "frames", spare).await);

    // Privileged: unchanged.
    let n = sqlx::query("DELETE FROM claims WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("superuser delete")
        .rows_affected();
    assert_eq!(
        n, 1,
        "the harness (superuser) session deletes a world claim as before"
    );
}

// ===========================================================================
// 2. The owner's delete, and the edges that point at what it deletes.
// ===========================================================================

/// W owns a public claim P. Another public (world) claim Q links to and from
/// it, so both edges are world-owned (070 stamps an edge between two public
/// endpoints `('public', world)`), and X has attached evidence to P. W deletes
/// P: the claim goes, X's evidence goes with it (FK cascade), and BOTH edges go
/// -- including Q -> P, whose source W cannot write, because the node-delete
/// trigger runs as a definer now. Before 115 that trigger ran as the invoker and
/// would have left Q -> P pointing at a deleted row.
#[sqlx::test(migrations = "../../migrations")]
async fn an_owner_deletes_its_own_claim_and_every_edge_pointing_at_it(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "owner-w").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "writer-x").await;
    let p_claim = seed_public_claim_owned_by(&pool, w, w_group, "W's claim").await;
    let q_claim = fixture::seed_public_claim(&pool, author, "a world claim").await;
    let q_to_p = fixture::seed_edge(&pool, q_claim, p_claim).await;
    let p_to_q = fixture::seed_edge(&pool, p_claim, q_claim).await;
    for e in [q_to_p, p_to_q] {
        let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM edges WHERE id = $1")
            .bind(e)
            .fetch_one(&pool)
            .await
            .expect("edge owner");
        assert_eq!(
            owner, WORLD,
            "fixture shape: a public-public edge is world-owned"
        );
    }
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (x_ev, deleted) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, x).await;
        let x_ev = insert_evidence(&mut conn, p_claim, "x on W's claim").await;
        stamp(&mut conn, &p, w).await;
        let deleted = delete_by_id(&mut conn, "claims", p_claim).await;
        (conn, (x_ev, deleted))
    })
    .await;
    assert_eq!(deleted, 1, "the owner deletes its own claim");
    assert!(!exists(&pool, "claims", p_claim).await);
    assert!(
        !exists(&pool, "evidence", x_ev).await,
        "X's evidence went with the claim"
    );
    assert!(!exists(&pool, "edges", p_to_q).await, "P -> Q went");
    assert!(
        !exists(&pool, "edges", q_to_p).await,
        "Q -> P went too: the node-delete trigger is not bounded by the deleter's edge rule"
    );
}

/// An edge nobody owns (both endpoints public) is deletable by the writer of
/// its SOURCE, and by nobody else: the `workflow_steps.rs` step rewire shape.
/// A group-owned edge is deletable by its owner's writers.
#[sqlx::test(migrations = "../../migrations")]
async fn a_world_owned_edge_is_deletable_by_its_sources_writer_only(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "source-writer").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "bystander").await;
    let mine = seed_public_claim_owned_by(&pool, w, w_group, "W's public claim").await;
    let world = fixture::seed_public_claim(&pool, author, "a world claim").await;
    let private = fixture::seed_group_claim(&pool, w, w_group, "W's private claim").await;
    let out_edge = fixture::seed_edge(&pool, mine, world).await;
    let in_edge = fixture::seed_edge(&pool, world, mine).await;
    let group_edge = fixture::seed_edge(&pool, world, private).await;
    let group_owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM edges WHERE id = $1")
        .bind(group_edge)
        .fetch_one(&pool)
        .await
        .expect("group edge owner");
    assert_eq!(group_owner, w_group, "fixture shape: the meet is W's group");
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (x_out, w_in, w_out, w_group_edge) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, x).await;
            let x_out = delete_by_id(&mut conn, "edges", out_edge).await;
            stamp(&mut conn, &p, w).await;
            let w_in = delete_by_id(&mut conn, "edges", in_edge).await;
            let w_out = delete_by_id(&mut conn, "edges", out_edge).await;
            let w_group_edge = delete_by_id(&mut conn, "edges", group_edge).await;
            (conn, (x_out, w_in, w_out, w_group_edge))
        })
        .await;
    assert_eq!(
        x_out, 0,
        "a bystander cannot delete W's outgoing world-owned edge"
    );
    assert_eq!(
        w_in, 0,
        "W cannot delete a world-owned edge whose source it cannot write"
    );
    assert_eq!(
        w_out, 1,
        "W deletes the world-owned edge its own claim sources"
    );
    assert_eq!(w_group_edge, 1, "W deletes an edge its group owns");
    assert!(exists(&pool, "edges", in_edge).await);
}

// ===========================================================================
// 3. The three cascades, for their legitimate actor.
// ===========================================================================

/// The dedup's retracted collision edge (migration 117). W marks its duplicate
/// D of a WORLD canonical C. D -> T collides with C -> T, so the repair
/// retracts D -> T and drops its edge-keyed BBA -- which lives on T and is X's
/// writer-owned row. W's ACT lands on the application role; the REPAIR does
/// not (it refuses a non-privileged session, and leaves every row as it was),
/// and lands on the maintenance connection, where it is idempotent. The
/// definer is never entered, so it writes no definer audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dedup_repair_is_the_maintenance_connections_and_drops_the_collision_bba(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "dedup-w").await;
    let (x, x_group) = fixture::seed_agent_with_group(&pool, "writer-x").await;
    let dup = seed_public_claim_owned_by(&pool, w, w_group, "the duplicate").await;
    let canonical = fixture::seed_public_claim(&pool, author, "world canonical").await;
    let third = fixture::seed_public_claim(&pool, author, "world third claim").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let dup_edge = fixture::seed_edge(&pool, dup, third).await;
    let _canon_edge = fixture::seed_edge(&pool, canonical, third).await;
    seed_perspective(&pool, dup_edge).await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (bba, act, repair_by_w) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, x).await;
        let bba = store_bba(&mut conn, third, bt, w, Some(dup_edge)).await;
        stamp(&mut conn, &p, w).await;
        let act = epigraph_db::ClaimRepository::mark_duplicate_act_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(canonical),
        )
        .await;
        let repair_by_w = epigraph_db::ClaimRepository::repair_marked_duplicate_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, (bba, act, repair_by_w))
    })
    .await;
    act.expect("the duplicate's writer marks its own duplicate on the app role");
    let e = repair_by_w.expect_err("the repair is not the duplicate writer's to run");
    assert!(e.to_string().contains("privileged"), "{e}");
    assert_eq!(
        writer_owned(&pool, "mass_functions", bba).await,
        (x_group, true),
        "fixture shape: X's writer-owned row, untouched by the refused repair"
    );
    let open: bool = sqlx::query_scalar("SELECT valid_to IS NULL FROM edges WHERE id = $1")
        .bind(dup_edge)
        .fetch_one(&pool)
        .await
        .expect("dup edge");
    assert!(open, "the refused repair retracted nothing");

    let repair = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = epigraph_db::ClaimRepository::repair_marked_duplicate_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, r)
    })
    .await
    .expect("the maintenance connection repairs the dedup");
    assert_eq!(repair.retracted_edges, vec![dup_edge]);
    assert_eq!(
        repair.deleted_bbas, 1,
        "the retracted edge's BBA was dropped"
    );
    assert!(!exists(&pool, "mass_functions", bba).await);
    let retracted: bool =
        sqlx::query_scalar("SELECT valid_to IS NOT NULL FROM edges WHERE id = $1")
            .bind(dup_edge)
            .fetch_one(&pool)
            .await
            .expect("dup edge");
    assert!(retracted, "the collision edge was retracted, not deleted");

    let again = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = epigraph_db::ClaimRepository::repair_marked_duplicate_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, r)
    })
    .await
    .expect("a replay of the repair is harmless");
    assert!(
        again.retracted_edges.is_empty() && again.deleted_bbas == 0,
        "the repair is idempotent: {again:?}"
    );
    assert!(
        cascade_audit(&pool).await.is_empty(),
        "a privileged session never enters the definer"
    );
}

/// The supersede-shaped retraction cascade after migration 117. W writes Y (the
/// replacement), and Y -> T's edge-keyed BBA on the world claim T is X's
/// writer-owned row attributed to W. 115's `source_writer` arm let W remove
/// it; that arm is gone. W, a bystander and an unstamped session are all
/// REFUSED with an error (CD02), not a silent 0, and the row survives. The
/// maintenance connection removes it with the plain statement.
#[sqlx::test(migrations = "../../migrations")]
async fn the_retraction_cascade_refuses_every_non_owner_and_lands_on_maintenance(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "superseder-w").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "wirer-x").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "bystander-z").await;
    let replacement = seed_public_claim_owned_by(&pool, w, w_group, "the replacement").await;
    let target = fixture::seed_public_claim(&pool, author, "world target").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let edge = fixture::seed_edge(&pool, replacement, target).await;
    seed_perspective(&pool, edge).await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (bba, by_z, by_unstamped, by_w) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, x).await;
            let bba = store_bba(&mut conn, target, bt, w, Some(edge)).await;
            stamp(&mut conn, &p, z).await;
            let by_z = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
            unstamp(&mut conn).await;
            let by_unstamped =
                MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
            stamp(&mut conn, &p, w).await;
            let by_w = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
            (conn, (bba, by_z, by_unstamped, by_w))
        })
        .await;
    for (who, r) in [
        ("a bystander", by_z),
        ("an unstamped session", by_unstamped),
        (
            "the source's writer (115's source_writer arm is gone)",
            by_w,
        ),
    ] {
        let e = r.expect_err(&format!("{who} is refused"));
        assert!(e.to_string().contains("CD02"), "{who}: {e}");
    }
    assert!(
        exists(&pool, "mass_functions", bba).await,
        "nothing was deleted"
    );
    assert!(
        cascade_audit(&pool).await.is_empty(),
        "no refused call is audited"
    );

    let n = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let n = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
        (conn, n)
    })
    .await
    .expect("the maintenance connection invalidates");
    assert_eq!(n, 1);
    assert!(!exists(&pool, "mass_functions", bba).await);
}

/// The dedup cascade's phase 2 after migration 117. W's duplicate D had an
/// outgoing edge D -> T; the repair (on the maintenance connection) re-sources
/// it at the WORLD canonical C. Its BBA on T -- X's writer-owned row, frozen
/// from D and attributed to D's author W -- was invalidatable by W through 115's
/// "retired duplicate of the source" arm. That arm is gone: W and a bystander
/// are both refused (CD02), and the maintenance connection invalidates it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_resourced_edges_bba_is_the_maintenance_connections_to_invalidate(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "dedup-w").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "wirer-x").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "bystander-z").await;
    let dup = seed_public_claim_owned_by(&pool, w, w_group, "the duplicate").await;
    let canonical = fixture::seed_public_claim(&pool, author, "world canonical").await;
    let target = fixture::seed_public_claim(&pool, author, "world target").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let edge = fixture::seed_edge(&pool, dup, target).await;
    seed_perspective(&pool, edge).await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let bba = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, x).await;
        let bba = store_bba(&mut conn, target, bt, w, Some(edge)).await;
        stamp(&mut conn, &p, w).await;
        epigraph_db::ClaimRepository::mark_duplicate_act_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(canonical),
        )
        .await
        .expect("W's act");
        (conn, bba)
    })
    .await;
    let repair = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = epigraph_db::ClaimRepository::repair_marked_duplicate_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, r)
    })
    .await
    .expect("the maintenance connection repairs");
    assert_eq!(
        repair
            .resourced_edges
            .iter()
            .map(|(id, _, _)| *id)
            .collect::<Vec<_>>(),
        vec![edge],
        "fixture shape: the edge was re-sourced at the canonical"
    );

    let p = pool.clone();
    let (by_z, by_w) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, z).await;
        let by_z = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
        stamp(&mut conn, &p, w).await;
        let by_w = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
        (conn, (by_z, by_w))
    })
    .await;
    for (who, r) in [("a bystander", by_z), ("the duplicate's writer", by_w)] {
        let e = r.expect_err(&format!("{who} is refused"));
        assert!(e.to_string().contains("CD02"), "{who}: {e}");
    }
    assert!(exists(&pool, "mass_functions", bba).await);

    let n = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let n = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
        (conn, n)
    })
    .await
    .expect("maintenance invalidates");
    assert_eq!(n, 1);
    assert!(!exists(&pool, "mass_functions", bba).await);
    assert!(
        cascade_audit(&pool).await.is_empty(),
        "{:?}",
        cascade_audit(&pool).await
    );
}

/// The dedup's key collision with SOMEBODY ELSE's canonical-side row. W's
/// duplicate D carries a BBA keyed by edge S -> D; the WORLD canonical C already
/// carries X's writer-owned row with the same (frame, source agent,
/// perspective) key. The repair (on the maintenance connection, migration 117)
/// keeps the canonical's row and drops the duplicate's copy instead of
/// tripping the unique index, and counts the drop. The move definer 114 added
/// is no longer the application's to call.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_collision_with_another_writers_row_keeps_the_canonicals(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "dedup-w").await;
    let (x, x_group) = fixture::seed_agent_with_group(&pool, "writer-x").await;
    let dup = seed_public_claim_owned_by(&pool, w, w_group, "the duplicate").await;
    let canonical = fixture::seed_public_claim(&pool, author, "world canonical").await;
    let source = fixture::seed_public_claim(&pool, author, "world source").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let edge = fixture::seed_edge(&pool, source, dup).await;
    seed_perspective(&pool, edge).await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (x_row, w_row, direct_move) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, x).await;
            let x_row = store_bba(&mut conn, canonical, bt, author, Some(edge)).await;
            stamp(&mut conn, &p, w).await;
            let w_row = store_bba(&mut conn, dup, bt, author, Some(edge)).await;
            epigraph_db::ClaimRepository::mark_duplicate_act_conn(
                &mut conn,
                epigraph_core::ClaimId::from_uuid(dup),
                epigraph_core::ClaimId::from_uuid(canonical),
            )
            .await
            .expect("W's act");
            let direct_move = sqlx::query_scalar::<_, i64>(
                "SELECT public.epigraph_dedup_move_bbas($1, $2, ARRAY[$3]::uuid[])",
            )
            .bind(dup)
            .bind(canonical)
            .bind(edge)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| {
                e.as_database_error()
                    .and_then(|d| d.code())
                    .map(|c| c.to_string())
                    .unwrap_or_default()
            });
            (conn, (x_row, w_row, direct_move))
        })
        .await;
    assert_eq!(
        direct_move,
        Err("42501".to_string()),
        "117 revoked the dedup move definer from the application role"
    );
    let repair = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = epigraph_db::ClaimRepository::repair_marked_duplicate_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, r)
    })
    .await
    .expect("the repair lands instead of tripping the unique index");
    assert_eq!(
        repair.moved_bbas, 0,
        "the colliding copy was dropped, not moved"
    );
    assert_eq!(
        repair.dropped_duplicate_copies, 1,
        "and the drop is counted"
    );
    assert!(
        exists(&pool, "mass_functions", x_row).await,
        "the canonical keeps X's row"
    );
    assert_eq!(
        writer_owned(&pool, "mass_functions", x_row).await,
        (x_group, true)
    );
    assert!(
        !exists(&pool, "mass_functions", w_row).await,
        "the duplicate's copy is gone"
    );
}

/// Match-candidate retirement after migration 117: the ACT (flip to `stale`)
/// lands on an unstamped application session; the CASCADE (retract the
/// promoted matcher edge, drop its BBA -- X's writer-owned row) refuses that
/// session, refuses to run before the act, and lands on the maintenance
/// connection. The one-transaction `retire` refuses the application role.
#[sqlx::test(migrations = "../../migrations")]
async fn match_candidate_retirement_is_an_act_plus_a_maintenance_cascade(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "wirer-x").await;
    let c1 = fixture::seed_public_claim(&pool, author, "match side one").await;
    let c2 = fixture::seed_public_claim(&pool, author, "match side two").await;
    let (a, b) = if c1 < c2 { (c1, c2) } else { (c2, c1) };
    let bt = seed_frame(&pool, "binary_truth").await;
    let edge = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'corroborates', \
                 '{\"source\": \"cross_source_matcher\"}'::jsonb)",
    )
    .bind(edge)
    .bind(a)
    .bind(b)
    .execute(&pool)
    .await
    .expect("matcher edge");
    seed_perspective(&pool, edge).await;
    let cand = MatchCandidateRepo::new(pool.clone())
        .upsert(
            a,
            b,
            0.9,
            serde_json::json!({}),
            "promoted",
            None,
            None,
            None,
        )
        .await
        .expect("candidate");
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let bba = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, x).await;
        let bba = store_bba(&mut conn, b, bt, author, Some(edge)).await;
        (conn, bba)
    })
    .await;
    assert!(
        writer_owned(&pool, "mass_functions", bba).await.1,
        "fixture shape: X's writer-owned row"
    );

    let cascade = |pool: PgPool, role: &'static str| async move {
        fixture::as_role(&pool, role, |mut conn| async move {
            let r = MatchCandidateRepo::retract_candidate_edges_conn(&mut conn, cand.id).await;
            (conn, r)
        })
        .await
    };
    let early = cascade(pool.clone(), "epigraph_maintenance").await;
    assert!(
        early
            .as_ref()
            .is_err_and(|e| e.to_string().contains("not stale")),
        "the cascade runs only after the act: {early:?}"
    );

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let whole = MatchCandidateRepo::new(app.clone())
        .retire(cand.id, None)
        .await;
    assert!(
        whole
            .as_ref()
            .is_err_and(|e| e.to_string().contains("privileged")),
        "the one-transaction retire is not the application role's: {whole:?}"
    );
    let previous = MatchCandidateRepo::new(app)
        .mark_retired(cand.id, None)
        .await
        .expect("the act lands on an unstamped app session");
    assert_eq!(previous, "promoted");
    let by_app = cascade(pool.clone(), "epigraph_app").await;
    assert!(
        by_app
            .as_ref()
            .is_err_and(|e| e.to_string().contains("privileged")),
        "{by_app:?}"
    );
    assert!(exists(&pool, "mass_functions", bba).await);

    let outcome = cascade(pool.clone(), "epigraph_maintenance")
        .await
        .expect("the maintenance connection retracts");
    assert_eq!(outcome.edges_retracted, 1);
    assert_eq!(outcome.bbas_invalidated, 1);
    assert!(!exists(&pool, "mass_functions", bba).await);
    let again = cascade(pool.clone(), "epigraph_maintenance")
        .await
        .expect("a replay is harmless");
    assert_eq!((again.edges_retracted, again.bbas_invalidated), (0, 0));
    assert!(
        cascade_audit(&pool).await.is_empty(),
        "no definer, no definer audit"
    );
}

/// Maintenance and the superuser are unchanged: both remove another writer's
/// edge-keyed BBA with the plain statement, and no cascade audit row is written
/// (the definer is never entered).
#[sqlx::test(migrations = "../../migrations")]
async fn privileged_sessions_delete_edge_bbas_exactly_as_before(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "wirer-x").await;
    let s1 = fixture::seed_public_claim(&pool, author, "source one").await;
    let s2 = fixture::seed_public_claim(&pool, author, "source two").await;
    let target = fixture::seed_public_claim(&pool, author, "target").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let e1 = fixture::seed_edge(&pool, s1, target).await;
    let e2 = fixture::seed_edge(&pool, s2, target).await;
    for e in [e1, e2] {
        seed_perspective(&pool, e).await;
    }
    let p = pool.clone();
    let (b1, b2) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, x).await;
        let b1 = store_bba(&mut conn, target, bt, author, Some(e1)).await;
        let b2 = store_bba(&mut conn, target, bt, author, Some(e2)).await;
        (conn, (b1, b2))
    })
    .await;

    let mut su = pool.acquire().await.expect("acquire");
    let n = MassFunctionRepository::delete_for_perspective(&mut *su, e1)
        .await
        .expect("superuser");
    drop(su);
    assert_eq!(n, 1);
    assert!(!exists(&pool, "mass_functions", b1).await);

    let n = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let n = MassFunctionRepository::delete_for_perspective(&mut *conn, e2).await;
        (conn, n)
    })
    .await
    .expect("maintenance");
    assert_eq!(n, 1);
    assert!(!exists(&pool, "mass_functions", b2).await);
    assert!(
        cascade_audit(&pool).await.is_empty(),
        "no definer, no audit"
    );
}

// ===========================================================================
// 3a. The arms, one condition at a time.
// ===========================================================================

/// A claim row with an explicit `supersedes` / `is_current`, seeded on the
/// superuser harness connection: the shape a dedup leaves behind.
async fn seed_claim_row(
    pool: &PgPool,
    agent: Uuid,
    group: Uuid,
    supersedes: Option<Uuid>,
    is_current: bool,
    tag: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, $5, 'public', $6, $7)",
    )
    .bind(id)
    .bind(format!("owner-scoped delete fixture claim {tag}"))
    .bind(&hash)
    .bind(agent)
    .bind(is_current)
    .bind(group)
    .bind(supersedes)
    .execute(pool)
    .await
    .expect("seed a claim row");
    id
}

/// Make `agent` a READER (not a writer) of `group`.
async fn add_reader(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed reader membership");
}

/// A BBA stored on the superuser connection, so it inherits its claim's
/// tenancy (a privileged session takes 114's arm (b)).
async fn store_bba_privileged(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    source_agent: Uuid,
    perspective: Uuid,
) -> Uuid {
    let mut conn = pool.acquire().await.expect("acquire");
    store_bba(&mut conn, claim, frame, source_agent, Some(perspective)).await
}

fn is_cd02(r: &Result<u64, epigraph_db::DbError>) -> bool {
    matches!(r, Err(e) if e.to_string().contains("CD02"))
}

/// The DELETE rule is the WRITABLE set, not the read set. R is a `reader` of
/// W's group G: it reads G's public claim, G's private claim and W's evidence,
/// and deletes none of them. Through the cascade definer R cannot remove G's
/// edge-keyed BBA either (its owner arm is the writable set too): CD02.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_of_a_group_deletes_none_of_its_rows(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (r, _) = fixture::seed_agent_with_group(&pool, "reader-r").await;
    add_reader(&pool, g, r).await;
    let public_claim = seed_public_claim_owned_by(&pool, w, g, "G's public claim").await;
    let private_claim = fixture::seed_group_claim(&pool, w, g, "G's private claim").await;
    let source = fixture::seed_public_claim(&pool, author, "a world source").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let edge = fixture::seed_edge(&pool, source, public_claim).await;
    seed_perspective(&pool, edge).await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (ev, mf, seen, deleted, cascade) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let ev = insert_evidence(&mut conn, public_claim, "w").await;
            let mf = store_bba(&mut conn, public_claim, bt, author, Some(edge)).await;
            stamp(&mut conn, &p, r).await;
            // Calibration: R reads all four, so a 0 is the DELETE rule.
            let seen: i64 = sqlx::query_scalar(
                "SELECT (SELECT count(*) FROM claims WHERE id IN ($1, $2)) \
                      + (SELECT count(*) FROM evidence WHERE id = $3) \
                      + (SELECT count(*) FROM mass_functions WHERE id = $4)",
            )
            .bind(public_claim)
            .bind(private_claim)
            .bind(ev)
            .bind(mf)
            .fetch_one(&mut *conn)
            .await
            .expect("read as R");
            let mut deleted = Vec::new();
            for (t, id) in [
                ("evidence", ev),
                ("mass_functions", mf),
                ("claims", private_claim),
                ("claims", public_claim),
            ] {
                deleted.push(delete_by_id(&mut conn, t, id).await);
            }
            let cascade = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
            (conn, (ev, mf, seen, deleted, cascade))
        })
        .await;
    assert_eq!(seen, 4, "calibration: a reader reads every G row");
    assert_eq!(deleted, vec![0, 0, 0, 0], "a reader deletes no G row");
    assert!(is_cd02(&cascade), "{cascade:?}");
    assert_eq!(
        writer_owned(&pool, "mass_functions", mf).await,
        (g, false),
        "fixture shape: the BBA is G's own row"
    );
    for (t, id) in [
        ("evidence", ev),
        ("mass_functions", mf),
        ("claims", private_claim),
        ("claims", public_claim),
    ] {
        assert!(exists(&pool, t, id).await, "{t} {id} survived");
    }
}

/// 115's "retired duplicate of the source" arm is gone (migration 117). W
/// writes d1, which supersedes S1 and is RETIRED, authored by W, and the BBA
/// on S1's edge is attributed to W -- every condition the old arm checked. W
/// is still refused (CD02), as it is for d2's edge (another author's BBA). The
/// maintenance connection removes both.
#[sqlx::test(migrations = "../../migrations")]
async fn no_retired_duplicate_licenses_another_writers_bba_any_more(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, wg) = fixture::seed_agent_with_group(&pool, "dedup-w").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "writer-x").await;
    let s1 = fixture::seed_public_claim(&pool, author, "world source one").await;
    let s2 = fixture::seed_public_claim(&pool, author, "world source two").await;
    let target = fixture::seed_public_claim(&pool, author, "world target").await;
    let _d1 = seed_claim_row(&pool, w, wg, Some(s1), false, "retired dup of S1").await;
    let _d2 = seed_claim_row(&pool, w, wg, Some(s2), false, "retired dup of S2").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let e1 = fixture::seed_edge(&pool, s1, target).await;
    let e2 = fixture::seed_edge(&pool, s2, target).await;
    seed_perspective(&pool, e1).await;
    seed_perspective(&pool, e2).await;
    // Both rows are public world-owned (they inherit the world target), so
    // W reads them and the owner arm cannot admit them.
    let b1 = store_bba_privileged(&pool, target, bt, w, e1).await;
    let b2 = store_bba_privileged(&pool, target, bt, x, e2).await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (same_author, other_author) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let a = MassFunctionRepository::delete_for_perspective(&mut *conn, e1).await;
            let b = MassFunctionRepository::delete_for_perspective(&mut *conn, e2).await;
            (conn, (a, b))
        })
        .await;
    assert!(
        is_cd02(&same_author),
        "a retired duplicate by the BBA's own author no longer licenses it: {same_author:?}"
    );
    assert!(is_cd02(&other_author), "{other_author:?}");
    assert!(exists(&pool, "mass_functions", b1).await);
    assert!(exists(&pool, "mass_functions", b2).await);

    let n = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let a = MassFunctionRepository::delete_for_perspective(&mut *conn, e1).await;
        let b = MassFunctionRepository::delete_for_perspective(&mut *conn, e2).await;
        (conn, (a, b))
    })
    .await;
    assert_eq!((n.0.expect("e1"), n.1.expect("e2")), (1, 1));
    assert!(cascade_audit(&pool).await.is_empty());
}

/// The cascade definer only ever considers rows the SESSION can read. Z owns a
/// writer-owned BBA on a world claim, keyed on an edge that also keys group
/// H's PRIVATE BBA. Z's call removes its own row and leaves H's alone -- the
/// private row is neither deleted nor counted as a refusal, exactly as the
/// invoker statement always left it -- and it is audited once with the owner
/// arm.
#[sqlx::test(migrations = "../../migrations")]
async fn the_cascade_never_touches_a_row_the_session_cannot_read(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "private-h").await;
    let (z, zg) = fixture::seed_agent_with_group(&pool, "writer-z").await;
    let source = fixture::seed_public_claim(&pool, author, "world source").await;
    let target = fixture::seed_public_claim(&pool, author, "world target").await;
    let h_claim = fixture::seed_group_claim(&pool, h, hg, "H's private claim").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let edge = fixture::seed_edge(&pool, source, target).await;
    seed_perspective(&pool, edge).await;
    let private_bba = store_bba_privileged(&pool, h_claim, bt, author, edge).await;
    assert_eq!(
        writer_owned(&pool, "mass_functions", private_bba).await.0,
        hg,
        "fixture shape: H's private row"
    );
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (z_bba, n) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, z).await;
        let z_bba = store_bba(&mut conn, target, bt, author, Some(edge)).await;
        let n = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
        (conn, (z_bba, n))
    })
    .await;
    assert_eq!(n.expect("the owner arm"), 1, "only Z's own readable row");
    assert!(!exists(&pool, "mass_functions", z_bba).await);
    assert!(
        exists(&pool, "mass_functions", private_bba).await,
        "a row Z cannot read is not Z's to cascade-delete"
    );
    let audit = cascade_audit(&pool).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].0, Some(z));
    assert_eq!(audit[0].3["owner"], 1, "{:?}", audit[0].3);
    let _ = zg;
}

/// The CO-owner of an edge deletes it. C's own group is the co-owner of an
/// edge from W's private claim (owner G1) to C's private claim (co-owner
/// G2); C is also a reader of G1, so it READS the edge (072's intersection)
/// while writing only the co-owner.
#[sqlx::test(migrations = "../../migrations")]
async fn an_edges_co_owner_deletes_it(pool: PgPool) {
    let (w, g1) = fixture::seed_agent_with_group(&pool, "owner-w").await;
    let (c, g2) = fixture::seed_agent_with_group(&pool, "co-owner-c").await;
    add_reader(&pool, g1, c).await;
    let from = fixture::seed_group_claim(&pool, w, g1, "W's private claim").await;
    let to = fixture::seed_group_claim(&pool, c, g2, "C's private claim").await;
    let edge = fixture::seed_edge(&pool, from, to).await;
    let shape: (Uuid, Option<Uuid>) =
        sqlx::query_as("SELECT owner_group_id, co_owner_group_id FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .expect("edge shape");
    assert_eq!(
        shape,
        (g1, Some(g2)),
        "fixture shape: owned by G1, co-owned by G2"
    );
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (seen, deleted) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, c).await;
        let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE id = $1")
            .bind(edge)
            .fetch_one(&mut *conn)
            .await
            .expect("read as C");
        let deleted = delete_by_id(&mut conn, "edges", edge).await;
        (conn, (seen, deleted))
    })
    .await;
    assert_eq!(seen, 1, "calibration: C reads the co-owned edge");
    assert_eq!(deleted, 1, "the co-owner's writer deletes the edge");
}

// ===========================================================================
// 3b. The owner cannot be moved first (section 7).
// ===========================================================================

/// The DELETE rule reads `owner_group_id`, so it holds only while a
/// non-privileged session cannot rewrite that column. A bystander Z tries to
/// move each world-owned row into its own group and then delete it: a world
/// claim carrying X's writer-owned BBA, a registry frame (whose FK cascade
/// would take every BBA on it), the claim's `claim_frames` row, and a
/// public-public edge (its owner, and its co-owner). Every re-own is refused
/// with 42501, every follow-up DELETE removes 0, and every row survives. The
/// harness superuser (a privileged session, as the operator re-own and
/// privatization paths are) still re-owns the claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_privileged_session_cannot_reown_a_row_and_then_delete_it(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "writer-x").await;
    let (z, z_group) = fixture::seed_agent_with_group(&pool, "bystander-z").await;
    let claim = fixture::seed_public_claim(&pool, author, "a world claim").await;
    let other = fixture::seed_public_claim(&pool, author, "another world claim").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(claim)
    .bind(bt)
    .execute(&pool)
    .await
    .expect("seed the claim's frame assignment");
    let edge = fixture::seed_edge(&pool, claim, other).await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (mf, seen, outcomes) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, x).await;
        let mf = store_bba(&mut conn, claim, bt, x, None).await;
        stamp(&mut conn, &p, z).await;
        // Calibration: Z reads every target, so a 0 below is not the read rule.
        let seen: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM claims WHERE id = $1) \
                  + (SELECT count(*) FROM frames WHERE id = $2) \
                  + (SELECT count(*) FROM claim_frames WHERE claim_id = $1) \
                  + (SELECT count(*) FROM edges WHERE id = $3)",
        )
        .bind(claim)
        .bind(bt)
        .bind(edge)
        .fetch_one(&mut *conn)
        .await
        .expect("read as Z");
        let mut outcomes = Vec::new();
        // `claim_frames` has no `id`; the claim has exactly one assignment.
        for (table, key, set, id) in [
            ("claims", "id", "owner_group_id = $2", claim),
            ("frames", "id", "owner_group_id = $2", bt),
            ("claim_frames", "claim_id", "owner_group_id = $2", claim),
            ("edges", "id", "owner_group_id = $2", edge),
            (
                "edges",
                "id",
                "visibility = 'group', co_owner_group_id = $2",
                edge,
            ),
        ] {
            let reown = sqlx::query(&format!("UPDATE {table} SET {set} WHERE {key} = $1"))
                .bind(id)
                .bind(z_group)
                .execute(&mut *conn)
                .await
                .map(|r| r.rows_affected())
                // The SQLSTATE alone would not say WHICH rule refused: an RLS
                // WITH CHECK violation is 42501 too (the co-owner re-own also
                // fails 077's check). The guard's message pins section 7.
                .map_err(|e| match e.as_database_error() {
                    Some(d) if d.message().contains("only a maintenance session re-owns") => {
                        format!("{} owner guard", d.code().unwrap_or_default())
                    }
                    Some(d) => format!("{} {}", d.code().unwrap_or_default(), d.message()),
                    None => e.to_string(),
                });
            let deleted = sqlx::query(&format!("DELETE FROM {table} WHERE {key} = $1"))
                .bind(id)
                .execute(&mut *conn)
                .await
                .unwrap_or_else(|e| panic!("DELETE FROM {table}: {e}"))
                .rows_affected();
            outcomes.push((table, set, reown, deleted));
        }
        (conn, (mf, seen, outcomes))
    })
    .await;

    assert_eq!(seen, 4, "calibration: Z reads all four world-owned rows");
    for (table, set, reown, deleted) in &outcomes {
        // `frames` and `edges` carry 117's restrictive UPDATE policy: a row the
        // session does not own is invisible to its UPDATE, so the re-own
        // matches nothing before the guard is reached. The other two are
        // refused by 115's guard.
        let want = if matches!(*table, "frames" | "edges") {
            Ok(0)
        } else {
            Err("42501 owner guard".to_string())
        };
        assert_eq!(
            reown, &want,
            "{table} SET {set}: a non-privileged re-own is refused"
        );
        assert_eq!(*deleted, 0, "{table}: the follow-up DELETE removes nothing");
    }
    for (table, id) in [
        ("claims", claim),
        ("frames", bt),
        ("edges", edge),
        ("mass_functions", mf),
    ] {
        assert!(exists(&pool, table, id).await, "{table} {id} survived");
    }
    let cf_left: i64 = sqlx::query_scalar("SELECT count(*) FROM claim_frames WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("claim_frames");
    assert_eq!(cf_left, 1, "the claim's frame assignment survived");

    // Privileged: the operator re-own shape still lands.
    let n = sqlx::query("UPDATE claims SET owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(z_group)
        .execute(&pool)
        .await
        .expect("superuser re-own")
        .rows_affected();
    assert_eq!(n, 1, "a privileged session re-owns as before");
}

async fn insert_harvester_source(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harvester_sources (id, content_hash, modality) VALUES ($1, $2, 'text')",
    )
    .bind(id)
    .bind(id.as_bytes().to_vec())
    .execute(pool)
    .await
    .expect("seed harvester source");
    id
}

/// A fragment declared `('public', owner)`, written on the superuser pool (the
/// only kind of session that may name a sentinel owner).
async fn insert_public_fragment(pool: &PgPool, source: Uuid, owner: Uuid, text: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harvester_fragments \
             (id, source_id, content_hash, content_text, visibility, owner_group_id) \
         VALUES ($1, $2, $3, $4, 'public', $5)",
    )
    .bind(id)
    .bind(source)
    .bind(id.as_bytes().to_vec())
    .bind(text)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed a sentinel-owned fragment");
    id
}

async fn fragment_tenancy(pool: &PgPool, id: Uuid) -> (Uuid, String) {
    sqlx::query_as("SELECT owner_group_id, visibility::text FROM harvester_fragments WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("read fragment {id}: {e}"))
}

/// Section 9: an INSERT cannot do what section 7 forbids an UPDATE to do.
///
/// 089's fragment stamp is a maintenance-owned definer, so section 7's guard
/// admits the re-own it performs. Before section 9 a bystander T, writable only
/// on its own group, cited three sentinel-owned fragments from its own claims
/// (one already cited by another author's world claim, one uncited, one on the
/// seed sentinel cited from T's PRIVATE claim), came to own all three, deleted
/// them, and the FK cascade removed the other author's provenance row. Now each
/// provenance INSERT succeeds (calibration: the write itself is not refused),
/// every fragment keeps its sentinel tenancy, T's DELETE removes nothing, and the
/// other author's provenance survives. The same INSERT on the superuser pool
/// still stamps, so the gate is scoped to the session and 089 is not off.
#[sqlx::test(migrations = "../../migrations")]
async fn a_provenance_insert_does_not_hand_a_session_a_world_fragment(pool: PgPool) {
    const SEED: Uuid = Uuid::from_u128(0xdead);
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (t, t_group) = fixture::seed_agent_with_group(&pool, "bystander-t").await;
    let world_claim = fixture::seed_public_claim(&pool, author, "another author's claim").await;
    let t_public = seed_public_claim_owned_by(&pool, t, t_group, "t's public claim").await;
    let t_private = fixture::seed_group_claim(&pool, t, t_group, "t's private claim").await;
    let source = insert_harvester_source(&pool).await;
    let cited = insert_public_fragment(&pool, source, WORLD, "cited by another author").await;
    let uncited = insert_public_fragment(&pool, source, WORLD, "cited by nobody").await;
    let seeded = insert_public_fragment(&pool, source, SEED, "seed-sentinel fragment").await;
    sqlx::query("INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)")
        .bind(world_claim)
        .bind(cited)
        .execute(&pool)
        .await
        .expect("the other author's provenance row");
    assert_app_role_does_not_bypass(&pool).await;
    let frags = [cited, uncited, seeded];

    let p = pool.clone();
    let (linked, deleted) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, t).await;
        let mut linked = 0;
        for (claim, frag) in [(t_public, cited), (t_public, uncited), (t_private, seeded)] {
            linked += sqlx::query(
                "INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)",
            )
            .bind(claim)
            .bind(frag)
            .execute(&mut *conn)
            .await
            .expect("T links a fragment to its own claim")
            .rows_affected();
        }
        let deleted = sqlx::query("DELETE FROM harvester_fragments WHERE id = ANY($1)")
            .bind(&frags[..])
            .execute(&mut *conn)
            .await
            .expect("T's DELETE")
            .rows_affected();
        (conn, (linked, deleted))
    })
    .await;

    assert_eq!(linked, 3, "calibration: each provenance INSERT landed");
    for (frag, owner) in [(cited, WORLD), (uncited, WORLD), (seeded, SEED)] {
        assert_eq!(
            fragment_tenancy(&pool, frag).await,
            (owner, "public".to_string()),
            "fragment {frag}: a non-privileged provenance INSERT leaves its tenancy alone"
        );
    }
    assert_eq!(deleted, 0, "T owns none of the fragments, so deletes none");
    let others: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM harvester_claim_provenance WHERE claim_id = $1 AND fragment_id = $2",
    )
    .bind(world_claim)
    .bind(cited)
    .fetch_one(&pool)
    .await
    .expect("read provenance");
    assert_eq!(others, 1, "the other author's provenance row survived");

    // Privileged: the identical INSERT still stamps (089's own case).
    sqlx::query("INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)")
        .bind(t_private)
        .bind(uncited)
        .execute(&pool)
        .await
        .expect("superuser link");
    assert_eq!(
        fragment_tenancy(&pool, uncited).await,
        (t_group, "group".to_string()),
        "a privileged session's provenance INSERT still stamps the fragment"
    );
}

// ===========================================================================
// 3c. The privileged writers, on a NON-superuser maintenance member.
// ===========================================================================

/// Every row the round trip below can touch, keyed `(table, primary key)`,
/// as `to_jsonb(row)`. `claims.updated_at` is the one column removed: 001's
/// unconditional `claims_updated_at` trigger restamps it on every UPDATE, and
/// the operator module documents it as the column neither `reown-claims` nor
/// `reown-reverse` can put back.
async fn round_trip_snapshot(
    pool: &PgPool,
    claims: &[Uuid],
    edges: &[Uuid],
    frags: &[Uuid],
) -> Vec<(String, String, serde_json::Value)> {
    sqlx::query_as(
        "SELECT 'claims', id::text, to_jsonb(t) - 'updated_at' FROM claims t \
          WHERE id = ANY($1) \
         UNION ALL SELECT 'claim_frames', concat_ws(',', claim_id, frame_id), to_jsonb(t) \
           FROM claim_frames t WHERE claim_id = ANY($1) \
         UNION ALL SELECT 'claim_versions', id::text, to_jsonb(t) \
           FROM claim_versions t WHERE claim_id = ANY($1) \
         UNION ALL SELECT 'mass_functions', id::text, to_jsonb(t) \
           FROM mass_functions t WHERE claim_id = ANY($1) \
         UNION ALL SELECT 'harvester_claim_provenance', concat_ws(',', claim_id, fragment_id), \
                          to_jsonb(t) \
           FROM harvester_claim_provenance t WHERE claim_id = ANY($1) \
         UNION ALL SELECT 'harvester_fragments', id::text, to_jsonb(t) \
           FROM harvester_fragments t WHERE id = ANY($3) \
         UNION ALL SELECT 'edges', id::text, to_jsonb(t) FROM edges t WHERE id = ANY($2) \
         ORDER BY 1, 2",
    )
    .bind(claims)
    .bind(edges)
    .bind(frags)
    .fetch_all(pool)
    .await
    .expect("round-trip snapshot")
}

/// `epigraph-cli`'s `operator::tables::write_tenancy`, verbatim but for the
/// table-spec plumbing: the statement `reown-claims --derived keep-writer`
/// uses to put a derived row back, and `reown-reverse` uses to write a row's
/// recorded tenancy. `scope` is `t.claim_id = ANY($2)` for a derived table and
/// `t.id = ANY($2)` for `edges`; on `edges` the SET list also names
/// `co_owner_group_id`, which is what arms `edges_owner_immutable` for it.
async fn write_tenancy_shape(
    conn: &mut PgConnection,
    table: &str,
    scope: &str,
    bind_ids: &[Uuid],
    rows: &[(Uuid, Uuid, &str, Option<Uuid>)],
) -> u64 {
    let edges = table == "edges";
    let payload: Vec<serde_json::Value> = rows
        .iter()
        .map(|(pk, o, v, co)| serde_json::json!({"pk": pk.to_string(), "o": o, "v": v, "co": co}))
        .collect();
    let (set_co, cmp_co, m_co) = if edges {
        (
            ", co_owner_group_id = m.co",
            ", t.co_owner_group_id",
            ", m.co",
        )
    } else {
        ("", "", "")
    };
    let sql = format!(
        "UPDATE \"{table}\" AS t SET owner_group_id = m.o, visibility = m.v{set_co} \
           FROM jsonb_to_recordset($1::jsonb) AS m(pk text, o uuid, v text, co uuid) \
          WHERE {scope} AND t.\"id\"::text = m.pk \
            AND (t.owner_group_id, t.visibility::text{cmp_co}) IS DISTINCT FROM (m.o, m.v{m_co})"
    );
    sqlx::query(&sql)
        .bind(serde_json::Value::Array(payload))
        .bind(bind_ids)
        .execute(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("write_tenancy shape on {table}: {e}"))
        .rows_affected()
}

/// Section 7's guard exempts a privileged session through
/// `epigraph_session_is_privileged_writer()`. Every other positive arm of it in
/// this suite runs as the harness SUPERUSER, which satisfies the `rolsuper`
/// arm before the two a real maintenance login would use are reached. Here a
/// fresh NOLOGIN role that is only a MEMBER of `epigraph_maintenance` (not a
/// superuser, not BYPASSRLS) runs, in one transaction, the operator's write
/// shapes and the privatization job's:
///
/// * `reown-claims`: its `UPDATE claims SET owner_group_id` (the trigger
///   carries it into `claim_frames`, `claim_versions`, `mass_functions`,
///   `harvester_claim_provenance` and the fragment), then its keep-writer
///   `write_tenancy` on `claim_versions`, and a `write_tenancy` that moves an
///   edge's owner AND co-owner;
/// * `reown-reverse`: its `UPDATE claims ... FROM jsonb_to_recordset`, and the
///   `write_tenancy` that restores the edge's recorded tenancy;
/// * privatization: the real `begin_batch_conn`, `restrict_claims_conn` and
///   `recompute_boundary_meet_conn` (which re-owns both edges, one of them
///   gaining a co-owner), then `restore_claims_conn` (which sets the
///   declassify GUC `SET LOCAL`, hence the explicit transaction) and the meet
///   again.
///
/// Each shape must land (a guard refusal would abort the transaction) and move
/// exactly the rows expected of it. Seven of them re-own a row through the
/// session's OWN statement (the two claims UPDATEs, the restrict, the restore,
/// the keep-writer and edge `write_tenancy`, and the widening meet), so the
/// exemption is exercised for each guarded table they name; the rest are
/// carried by the definer triggers. After COMMIT every touched row is
/// identical to its pre-image bar `claims.updated_at`.
///
/// The two non-superuser arms of `epigraph_session_is_privileged_writer()` (a
/// maintenance-member `session_user`, a maintenance-member `current_user`) are
/// BOTH true for this session, so removing either one alone leaves this test
/// green; removing both makes every re-own here fail with the guard's 42501.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_superuser_maintenance_member_reowns_privatizes_and_restores_exactly(pool: PgPool) {
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (writer, _) = fixture::seed_agent_with_group(&pool, "writer").await;
    let (_operator, op_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (_b, b_group) = fixture::seed_agent_with_group(&pool, "private-b").await;
    let (_p, p_group) = fixture::seed_agent_with_group(&pool, "privatizer").await;
    let c1 = fixture::seed_public_claim(&pool, author, "the claim that moves").await;
    let c2 = fixture::seed_group_claim(&pool, author, b_group, "a private neighbour").await;
    let c3 = fixture::seed_public_claim(&pool, author, "a public neighbour").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) VALUES ($1, $2, 0)",
    )
    .bind(c1)
    .bind(bt)
    .execute(&pool)
    .await
    .expect("claim_frames row");
    sqlx::query(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, created_by) \
         VALUES ($1, 1, 'v1', 0.5, $2)",
    )
    .bind(c1)
    .bind(writer)
    .execute(&pool)
    .await
    .expect("claim_versions row");
    let version: Uuid = sqlx::query_scalar("SELECT id FROM claim_versions WHERE claim_id = $1")
        .bind(c1)
        .fetch_one(&pool)
        .await
        .expect("version id");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        store_bba(&mut conn, c1, bt, writer, None).await;
    }
    let source = insert_harvester_source(&pool).await;
    let frag = insert_public_fragment(&pool, source, WORLD, "a fragment of the claim").await;
    sqlx::query("INSERT INTO harvester_claim_provenance (claim_id, fragment_id) VALUES ($1, $2)")
        .bind(c1)
        .bind(frag)
        .execute(&pool)
        .await
        .expect("provenance");
    let e_private = fixture::seed_edge(&pool, c1, c2).await;
    let e_public = fixture::seed_edge(&pool, c1, c3).await;
    let (e_owner, e_co): (Uuid, Option<Uuid>) =
        sqlx::query_as("SELECT owner_group_id, co_owner_group_id FROM edges WHERE id = $1")
            .bind(e_private)
            .fetch_one(&pool)
            .await
            .expect("edge tenancy");
    assert_eq!(
        (e_owner, e_co),
        (b_group, None),
        "calibration: the meet of a public and a private endpoint"
    );
    // The plan row exists only for `restore_claims_conn`'s join to its frozen
    // pre-image. 081's plan guards (target age, co-admins, instance admin) are
    // not under test here, so the two rows are written with triggers off, on
    // a superuser transaction that ends before anything under test runs.
    let plan = Uuid::new_v4();
    {
        let mut tx = pool.begin().await.expect("begin plan seed");
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .expect("triggers off for the plan seed");
        sqlx::query(
            "INSERT INTO privatization_plans (id, mode, target_group_id, selector, created_by) \
             VALUES ($1, 'restrict', $2, '{}'::jsonb, $3)",
        )
        .bind(plan)
        .bind(p_group)
        .bind(author)
        .execute(&mut *tx)
        .await
        .expect("seed a plan");
        sqlx::query(
            "INSERT INTO privatization_plan_items (plan_id, kind, entity_id, depth, via, \
                 before_visibility, before_owner_group_id, before_had_embedding) \
             SELECT $1, 'claim', id, 0, 'seed', visibility, owner_group_id, false \
               FROM claims WHERE id = $2",
        )
        .bind(plan)
        .bind(c1)
        .execute(&mut *tx)
        .await
        .expect("freeze the plan item");
        tx.commit().await.expect("commit plan seed");
    }

    let claims = [c1, c2, c3];
    let edges = [e_private, e_public];
    let frags = [frag];
    let before = round_trip_snapshot(&pool, &claims, &edges, &frags).await;
    assert_eq!(before.len(), 10, "fixture rows: {before:#?}");

    let role = format!("w9_maint_member_{}", Uuid::new_v4().simple());
    for stmt in [
        format!("CREATE ROLE {role} NOLOGIN"),
        format!("GRANT epigraph_maintenance TO {role}"),
    ] {
        sqlx::query(&stmt)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }

    let steps = fixture::as_role(&pool, &role, |mut conn| async move {
        let (sup, bypassrls, bypass): (bool, bool, bool) = sqlx::query_as(
            "SELECT r.rolsuper, r.rolbypassrls, public.epigraph_bypass() \
               FROM pg_roles r WHERE r.rolname = session_user",
        )
        .fetch_one(&mut *conn)
        .await
        .expect("calibrate the member session");
        let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
        let mut steps: Vec<(&str, u64)> = Vec::new();

        // reown-claims (`operator::reown`), follow-claim.
        let n = sqlx::query(
            "UPDATE claims SET owner_group_id = $2 \
              WHERE id = ANY($1) AND owner_group_id IS DISTINCT FROM $2",
        )
        .bind(&[c1][..])
        .bind(op_group)
        .execute(&mut *tx)
        .await
        .expect("reown UPDATE claims")
        .rows_affected();
        steps.push(("reown claims", n));
        // keep-writer: put the version row back where it was.
        let n = write_tenancy_shape(
            &mut tx,
            "claim_versions",
            "t.claim_id = ANY($2)",
            &[c1],
            &[(version, WORLD, "public", None)],
        )
        .await;
        steps.push(("keep-writer claim_versions", n));
        let n = write_tenancy_shape(
            &mut tx,
            "edges",
            "t.id = ANY($2)",
            &[e_private],
            &[(e_private, op_group, "group", Some(b_group))],
        )
        .await;
        steps.push(("write_tenancy edges (owner + co-owner)", n));

        // reown-reverse (`operator::reverse`).
        let n = sqlx::query(
            "UPDATE claims c SET owner_group_id = m.o \
               FROM jsonb_to_recordset($1::jsonb) AS m(id uuid, o uuid) \
              WHERE c.id = m.id AND c.owner_group_id = $2 AND c.owner_group_id <> m.o",
        )
        .bind(serde_json::json!([{"id": c1, "o": WORLD}]))
        .bind(op_group)
        .execute(&mut *tx)
        .await
        .expect("reverse UPDATE claims")
        .rows_affected();
        steps.push(("reverse claims", n));
        let n = write_tenancy_shape(
            &mut tx,
            "edges",
            "t.id = ANY($2)",
            &[e_private],
            &[(e_private, b_group, "group", None)],
        )
        .await;
        steps.push(("reverse edges (recorded tenancy)", n));

        // Privatization: apply, then revert.
        PrivatizationRepository::begin_batch_conn(&mut tx)
            .await
            .expect("begin_batch_conn");
        let moved = PrivatizationRepository::restrict_claims_conn(&mut tx, &[c1], p_group)
            .await
            .expect("restrict_claims_conn");
        steps.push(("restrict", moved.len() as u64));
        let n = PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &[c1])
            .await
            .expect("recompute_boundary_meet_conn (apply)");
        steps.push(("meet after restrict", n));
        let n = PrivatizationRepository::restore_claims_conn(&mut tx, plan, &[c1], p_group)
            .await
            .expect("restore_claims_conn");
        steps.push(("restore", n));
        let n = PrivatizationRepository::recompute_boundary_meet_conn(&mut tx, &[c1])
            .await
            .expect("recompute_boundary_meet_conn (revert)");
        steps.push(("meet after restore", n));

        tx.commit().await.expect("commit");

        // 115 section 8: the unseal's ciphertext DELETE is NOT something this
        // role can run. It holds no DELETE grant on the sealed-content tables,
        // so the unseal works only on a maintenance DSN whose login has one (a
        // superuser today). Outside the transaction, so the refusal aborts
        // nothing above.
        let unseal = sqlx::query(
            "DELETE FROM public.claim_encryption WHERE claim_id = ANY($1) AND group_id = $2",
        )
        .bind(&[c1][..])
        .bind(p_group)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| match e.as_database_error() {
            Some(d) => format!("{} {}", d.code().unwrap_or_default(), d.message()),
            None => e.to_string(),
        });
        (conn, (sup, bypassrls, bypass, steps, unseal))
    })
    .await;
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&pool)
        .await
        .expect("drop the probe role");

    let (sup, bypassrls, bypass, steps, unseal) = steps;
    assert_eq!(
        unseal,
        Err("42501 permission denied for table claim_encryption".to_string()),
        "the NOLOGIN maintenance role cannot run the unseal's ciphertext DELETE"
    );
    assert!(
        !sup && !bypassrls && bypass,
        "calibration: a member session, neither superuser nor BYPASSRLS \
         (rolsuper {sup}, rolbypassrls {bypassrls}, epigraph_bypass {bypass})"
    );
    assert_eq!(
        steps,
        vec![
            ("reown claims", 1),
            ("keep-writer claim_versions", 1),
            ("write_tenancy edges (owner + co-owner)", 1),
            ("reverse claims", 1),
            // 0: the reverse's claims UPDATE already re-ran the edge meet
            // (072's propagation), so the recorded tenancy is in place; the
            // statement is the module's no-op for a row the trigger restored.
            ("reverse edges (recorded tenancy)", 0),
            ("restrict", 1),
            // 0: the restrict's propagation already narrowed both edges.
            ("meet after restrict", 0),
            ("restore", 1),
            // 1: the one WIDENING (the public-public edge back to world),
            // which 072's propagation refuses and only this statement does.
            ("meet after restore", 1),
        ],
        "every shape landed; the counts are what each is expected to move"
    );
    let after = round_trip_snapshot(&pool, &claims, &edges, &frags).await;
    assert_eq!(
        after, before,
        "every touched row is back to its pre-image (bar claims.updated_at)"
    );
}

// ===========================================================================
// 4. The catalog.
// ===========================================================================

/// The ratchet: every relation carrying both tenancy columns under row
/// security, bar the principal-keyed `recall_events`, has a RESTRICTIVE
/// FOR DELETE policy, and a BEFORE UPDATE row trigger that keeps its owner
/// immutable to a non-privileged session (115's `<t>_owner_immutable`, or
/// 114's `<t>_writer_owner_guard`), without which the policy can be walked
/// around by re-owning the row first. A 25th such table added without both
/// fails here.
#[sqlx::test(migrations = "../../migrations")]
async fn every_public_admitting_table_has_a_restrictive_delete_policy(pool: PgPool) {
    let rows: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT c.relname::text, \
                EXISTS (SELECT 1 FROM pg_policy p \
                         WHERE p.polrelid = c.oid AND p.polcmd = 'd' AND NOT p.polpermissive), \
                EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc f ON f.oid = t.tgfoid \
                         WHERE t.tgrelid = c.oid AND NOT t.tgisinternal AND t.tgenabled <> 'D' \
                           AND f.proname IN ('epigraph_owner_immutable_guard', \
                                             'epigraph_writer_owner_guard')) \
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relrowsecurity \
            AND c.relname <> 'recall_events' \
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid \
                         AND a.attname = 'owner_group_id' AND NOT a.attisdropped) \
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid \
                         AND a.attname = 'visibility' AND NOT a.attisdropped) \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    assert_eq!(
        rows.len(),
        24,
        "the tier-A set changed size; decide its DELETE rule: {rows:?}"
    );
    let missing: Vec<&String> = rows
        .iter()
        .filter(|(_, has, _)| !has)
        .map(|(t, _, _)| t)
        .collect();
    assert!(
        missing.is_empty(),
        "no restrictive DELETE policy on {missing:?}"
    );
    let unguarded: Vec<&String> = rows
        .iter()
        .filter(|(_, _, guarded)| !guarded)
        .map(|(t, _, _)| t)
        .collect();
    assert!(
        unguarded.is_empty(),
        "owner_group_id is re-ownable by a non-privileged UPDATE on {unguarded:?}"
    );

    // Existence is not the rule: a `USING (true)`, or one keyed on the READ
    // set, would satisfy the check above. Each table's restrictive DELETE
    // policy must key the owner on the WRITABLE set and must not name the
    // read set at all.
    let quals: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, pg_get_expr(p.polqual, p.polrelid) \
           FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid \
          WHERE p.polcmd = 'd' AND NOT p.polpermissive \
            AND p.polname = c.relname || '_delete_owner' \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("delete policy quals");
    assert_eq!(quals.len(), 24, "{quals:?}");
    for (table, qual) in &quals {
        assert!(
            qual.contains("owner_group_id = ANY") && qual.contains("epigraph_writable_groups()"),
            "{table}_delete_owner must key the owner on the writable set: {qual}"
        );
        assert!(
            !qual.contains("epigraph_session_groups()"),
            "{table}_delete_owner must not admit on the read set: {qual}"
        );
    }
}

/// The broader ratchet (115 section 8): outside tier A too, no table the
/// application may DELETE from lets its READ set license a delete. Every table
/// whose permissive DELETE-covering policy admits on `epigraph_session_groups()`
/// must carry a restrictive DELETE policy, unless it is on the allow-list with
/// the reason it is safe.
#[sqlx::test(migrations = "../../migrations")]
async fn no_app_deletable_table_admits_delete_on_the_read_set(pool: PgPool) {
    // `groups`: `groups_block_delete` refuses every row delete (asserted below).
    const ALLOWED: &[&str] = &["groups"];
    let open: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT c.relname::text \
           FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid \
           JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relrowsecurity \
            AND p.polpermissive AND p.polcmd IN ('*', 'd') \
            AND pg_get_expr(p.polqual, p.polrelid) LIKE '%epigraph_session_groups()%' \
            AND has_table_privilege('epigraph_app', c.oid, 'DELETE') \
            AND NOT EXISTS (SELECT 1 FROM pg_policy r WHERE r.polrelid = c.oid \
                             AND r.polcmd = 'd' AND NOT r.polpermissive) \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    let unexplained: Vec<&String> = open
        .iter()
        .filter(|t| !ALLOWED.contains(&t.as_str()))
        .collect();
    assert!(
        unexplained.is_empty(),
        "these tables let a READ-only member delete: {unexplained:?}"
    );
    let blocked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public.groups'::regclass \
                         AND tgname = 'groups_block_delete' AND tgenabled <> 'D')",
    )
    .fetch_one(&pool)
    .await
    .expect("groups trigger");
    assert!(
        blocked,
        "the `groups` allow-list entry relies on groups_block_delete"
    );
}

/// Section 8's behaviour: a `reader` of W's group reads the group's sealed
/// claim row and a key epoch and deletes neither; W, a writer of the group,
/// deletes both.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_cannot_delete_its_groups_sealed_rows(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer-w").await;
    let (r, _) = fixture::seed_agent_with_group(&pool, "reader-r").await;
    add_reader(&pool, g, r).await;
    let sealed = fixture::seed_group_claim(&pool, w, g, "a sealed claim").await;
    // One active epoch per group (`group_key_epochs_one_active`).
    for (epoch, status) in [(0_i32, "active"), (1, "retired")] {
        sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, $2, $3)")
            .bind(g)
            .bind(epoch)
            .bind(status)
            .execute(&pool)
            .await
            .expect("seed key epoch");
    }
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)",
    )
    .bind(sealed)
    .bind(g)
    .execute(&pool)
    .await
    .expect("seed the sealed row");
    assert_app_role_does_not_bypass(&pool).await;

    let delete_sealed = "DELETE FROM claim_encryption WHERE claim_id = $1";
    let delete_epoch = "DELETE FROM group_key_epochs WHERE group_id = $1 AND epoch = 1";
    let p = pool.clone();
    let (seen, by_reader, by_writer) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, r).await;
            let seen: i64 = sqlx::query_scalar(
                "SELECT (SELECT count(*) FROM claim_encryption WHERE claim_id = $1) \
                      + (SELECT count(*) FROM group_key_epochs WHERE group_id = $2 AND epoch = 1)",
            )
            .bind(sealed)
            .bind(g)
            .fetch_one(&mut *conn)
            .await
            .expect("read as R");
            let mut by_reader = Vec::new();
            for (sql, id) in [(delete_sealed, sealed), (delete_epoch, g)] {
                by_reader.push(
                    sqlx::query(sql)
                        .bind(id)
                        .execute(&mut *conn)
                        .await
                        .expect("reader delete")
                        .rows_affected(),
                );
            }
            stamp(&mut conn, &p, w).await;
            let mut by_writer = Vec::new();
            for (sql, id) in [(delete_sealed, sealed), (delete_epoch, g)] {
                by_writer.push(
                    sqlx::query(sql)
                        .bind(id)
                        .execute(&mut *conn)
                        .await
                        .expect("writer delete")
                        .rows_affected(),
                );
            }
            (conn, (seen, by_reader, by_writer))
        })
        .await;
    assert_eq!(seen, 2, "calibration: the reader reads both rows");
    assert_eq!(by_reader, vec![0, 0], "a reader deletes neither");
    assert_eq!(by_writer, vec![1, 1], "the group's writer deletes both");
}

/// The exact register of FK `ON DELETE CASCADE` paths into a tier-A table from
/// a parent the application may DELETE with no owner-scoped DELETE policy of
/// its own. A referential action consults no policy, so each is a way to
/// remove tier-A rows around 115; each listed one is a materialization (see
/// 115 section 1). A new pair fails here until it is gated or listed.
#[sqlx::test(migrations = "../../migrations")]
async fn every_unscoped_fk_cascade_into_tier_a_is_listed(pool: PgPool) {
    const ACCEPTED: &[(&str, &str)] = &[
        ("experiment_entities", "experiment_entity_mentions"),
        ("experiment_entities", "experiment_triples"),
        ("graph_clusters", "claim_cluster_membership"),
        ("graph_neighborhoods", "claim_neighborhood_membership"),
        ("harvester_sources", "harvester_fragments"),
    ];
    let pairs: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT pc.relname::text, cc.relname::text \
           FROM pg_constraint k \
           JOIN pg_class cc ON cc.oid = k.conrelid \
           JOIN pg_class pc ON pc.oid = k.confrelid \
          WHERE k.contype = 'f' AND k.confdeltype = 'c' \
            AND EXISTS (SELECT 1 FROM pg_policy r WHERE r.polrelid = cc.oid \
                         AND r.polname = cc.relname || '_delete_owner') \
            AND has_table_privilege('epigraph_app', pc.oid, 'DELETE') \
            AND NOT EXISTS (SELECT 1 FROM pg_policy r WHERE r.polrelid = pc.oid \
                             AND r.polcmd = 'd' AND NOT r.polpermissive) \
          ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .expect("catalog");
    let got: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    assert_eq!(
        got, ACCEPTED,
        "the unscoped FK cascades into tier-A tables changed; gate the new one or list it"
    );
}

/// The register of application-code DELETEs of a node table outside tier A
/// whose `<node>_cascade_edges` trigger keeps 001's INVOKER body (115 section
/// 5). After 115 such a delete removes only the edges the session may delete,
/// so a new one must decide what happens to the others. Keyed on
/// `(file, table, count)` over `crates/*/src`, so a new call site is a visible
/// diff here.
#[test]
fn no_application_path_deletes_a_non_tier_a_edge_node() {
    const NODE_TABLES: &[&str] = &[
        "agents",
        "analyses",
        "events",
        "experiment_results",
        "experiments",
        "papers",
        "tasks",
        "workflows",
    ];
    const REGISTER: &[(&str, &str, usize, &str)] = &[
        (
            "epigraph-api/src/routes/reasoning.rs",
            "agents",
            1,
            "#[cfg(test)] fixture cleanup",
        ),
        (
            "epigraph-db/src/repos/agent.rs",
            "agents",
            1,
            "AgentRepository::delete: `agents` has row security and no DELETE policy, \
             so a non-privileged session deletes nothing",
        ),
        (
            "epigraph-db/src/repos/claim.rs",
            "agents",
            2,
            "#[cfg(test)] fixture cleanup",
        ),
        (
            "epigraph-db/src/repos/recall_event.rs",
            "events",
            1,
            "prune_telemetry_events: telemetry event rows are not edge endpoints",
        ),
    ];
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .to_path_buf();
    let mut found: Vec<(String, String, usize)> = Vec::new();
    let mut crate_dirs: Vec<_> = std::fs::read_dir(&crates)
        .expect("read crates")
        .map(|e| e.expect("entry").path())
        .collect();
    crate_dirs.sort();
    for krate in crate_dirs {
        let src = krate.join("src");
        if !src.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        walk(&src, &mut files);
        files.sort();
        for file in files {
            let text = std::fs::read_to_string(&file).expect("read source");
            let lower = text.to_lowercase();
            for table in NODE_TABLES {
                let mut n = 0;
                for prefix in ["delete from ", "delete from public."] {
                    let needle = format!("{prefix}{table}");
                    let mut at = 0;
                    while let Some(i) = lower[at..].find(&needle) {
                        let end = at + i + needle.len();
                        let next = lower[end..].chars().next();
                        if !next.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                            n += 1;
                        }
                        at = end;
                    }
                }
                if n > 0 {
                    let rel = file
                        .strip_prefix(&crates)
                        .expect("under crates")
                        .to_string_lossy()
                        .replace('\\', "/");
                    found.push((rel, (*table).to_string(), n));
                }
            }
        }
    }
    let expected: Vec<(String, String, usize)> = REGISTER
        .iter()
        .map(|(f, t, n, _)| ((*f).to_string(), (*t).to_string(), *n))
        .collect();
    assert_eq!(
        found, expected,
        "an application DELETE of a non-tier-A edge node changed; see 115 section 5"
    );
}

/// The five definers 115 installs or redefines are owned by the maintenance role, not
/// executable by PUBLIC; the three a statement names are executable by the app;
/// the three tier-A node triggers run the definer body.
#[sqlx::test(migrations = "../../migrations")]
async fn the_115_functions_are_maintenance_owned_definers(pool: PgPool) {
    for (f, app_exec) in [
        ("epigraph_session_writes_node(uuid, text)", true),
        ("epigraph_cascade_delete_edge_bbas(uuid[], text)", true),
        // 117 revoked it from the application role: the dedup move is part of
        // the administrative repair now.
        ("epigraph_dedup_move_bbas(uuid, uuid, uuid[])", false),
        ("epigraph_cascade_delete_node_edges()", false),
        // Redefined by 115 (section 9); CREATE OR REPLACE kept 089's owner and ACL.
        ("epigraph_inherit_fragment_tenancy_stmt()", false),
    ] {
        let (secdef, owner, public_exec, app): (bool, String, bool, bool) = sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                    has_function_privilege('public', p.oid, 'EXECUTE'), \
                    has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
               FROM pg_proc p WHERE p.oid = ('public.' || $1)::regprocedure",
        )
        .bind(f)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{f}: {e}"));
        assert!(secdef, "{f} must be SECURITY DEFINER");
        assert_eq!(owner, "epigraph_maintenance", "{f} owner");
        assert!(!public_exec, "{f} must not be executable by PUBLIC");
        assert_eq!(app, app_exec, "{f}: epigraph_app EXECUTE");
    }
    let triggers: Vec<(String, String)> = sqlx::query_as(
        "SELECT t.tgrelid::regclass::text, p.proname::text \
           FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid \
          WHERE t.tgname IN ('claims_cascade_edges', 'evidence_cascade_edges', \
                             'traces_cascade_edges') \
          ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("triggers");
    assert_eq!(triggers.len(), 3, "{triggers:?}");
    for (table, func) in triggers {
        assert_eq!(func, "epigraph_cascade_delete_node_edges", "{table}");
    }
}

// ===========================================================================
// W10 revision: each administrative repair is bound to a committed act of the
// caller's, runs only on a privileged session, and a reader cannot dedup into
// its group's private claim through the repair.
// ===========================================================================

/// A READER of a group may not dedup its own claim onto that group's
/// non-public claim (FA04 at the act): the administrative repair would move
/// the duplicate's derived rows into the group as the group's own. Nothing is
/// written. The group's writer may.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_cannot_dedup_onto_its_groups_private_claim(pool: PgPool) {
    let (a, g) = fixture::seed_agent_with_group(&pool, "group-writer-a").await;
    let (r, r_group) = fixture::seed_agent_with_group(&pool, "reader-r").await;
    add_reader(&pool, g, r).await;
    let k = fixture::seed_group_claim(&pool, a, g, "G's private canonical").await;
    let d = seed_public_claim_owned_by(&pool, r, r_group, "R's duplicate").await;
    let d2 = seed_public_claim_owned_by(&pool, a, g, "A's duplicate").await;
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let (by_reader, by_writer) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, r).await;
        let by_reader = epigraph_db::ClaimRepository::mark_duplicate_act_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(d),
            epigraph_core::ClaimId::from_uuid(k),
        )
        .await;
        stamp(&mut conn, &p, a).await;
        let by_writer = epigraph_db::ClaimRepository::mark_duplicate_act_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(d2),
            epigraph_core::ClaimId::from_uuid(k),
        )
        .await;
        (conn, (by_reader, by_writer))
    })
    .await;
    let e = by_reader.expect_err("a reader's dedup onto the group's private claim is refused");
    assert!(e.to_string().contains("FA04"), "{e}");
    let (current, sup): (bool, Option<Uuid>) =
        sqlx::query_as("SELECT is_current, supersedes FROM claims WHERE id = $1")
            .bind(d)
            .fetch_one(&pool)
            .await
            .expect("d");
    assert_eq!(
        (current, sup),
        (true, None),
        "the refused act wrote nothing"
    );
    by_writer.expect("the group's writer dedups onto its own group's claim");
}
