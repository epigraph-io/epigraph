//! Migration 115: DELETE is owner-scoped on every tier-A table.
//!
//! 077's FOR ALL policies used the READ predicate as DELETE's USING, so the
//! rows a session could remove were the rows it could read. 115 adds one
//! RESTRICTIVE, FOR DELETE policy per table (owner in the writable set; for
//! `edges` also the co-owner, and the source's writer for an edge nobody owns),
//! and moves the three cascades that remove other writers' edge-keyed BBAs
//! behind an audited definer.
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
//! node-delete trigger), `claim_cluster_membership` (the bridge-cluster GC;
//! the memberships of a deleted run also go through the `graph_clusters` FK
//! cascade, which consults no policy). No application path deletes a registry
//! row (`frames`, `contexts`, `perspectives`, `communities`).

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

/// The dedup's retracted collision edge. W marks its duplicate D of a WORLD
/// canonical C. D -> T collides with C -> T, so the dedup retracts D -> T and
/// drops its edge-keyed BBA -- which lives on T and is X's writer-owned row. It
/// lands for W through the definer, and is audited once with W as the actor.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dedup_drops_another_writers_bba_of_a_retracted_collision_edge(pool: PgPool) {
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
    let (bba, repair) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, x).await;
        let bba = store_bba(&mut conn, third, bt, w, Some(dup_edge)).await;
        stamp(&mut conn, &p, w).await;
        let repair = epigraph_db::ClaimRepository::mark_duplicate_with_repair_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, (bba, repair))
    })
    .await;
    // `bba` is already gone, so the fixture shape is asserted on the audit's
    // owner list below rather than on the row.
    let repair = repair.expect("the dedup lands for the duplicate's writer");
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
    assert!(
        retracted,
        "fixture shape: the collision edge was retracted, not deleted"
    );
    let audit = cascade_audit(&pool).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(
        audit[0].0,
        Some(w),
        "attributed to the deduplicating writer"
    );
    assert_eq!(audit[0].1, "dedup_retracted_edge");
    assert_eq!(audit[0].2, 1);
    assert_eq!(audit[0].3["retracted_edge"], 1, "{:?}", audit[0].3);
    let owners: serde_json::Value = sqlx::query_scalar(
        "SELECT details->'owner_group_ids' FROM security_events \
          WHERE event_type = 'derived.cascade_bba_delete'",
    )
    .fetch_one(&pool)
    .await
    .expect("owners");
    assert_eq!(
        owners,
        serde_json::json!([x_group]),
        "fixture shape: the dropped BBA was X's writer-owned row, not W's"
    );
}

/// The supersede-shaped retraction cascade. W writes Y (the replacement), and
/// Y -> T's edge-keyed BBA on the world claim T is X's writer-owned row
/// attributed to W. W invalidates it (arm `source_writer`); a bystander and an
/// unstamped session are REFUSED with an error (CD02), not a silent 0, so the
/// cascade reports it instead of skipping the edge as BBA-free.
#[sqlx::test(migrations = "../../migrations")]
async fn the_retraction_cascade_invalidates_for_the_sources_writer_and_refuses_others(
    pool: PgPool,
) {
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
    ] {
        let e = r.expect_err(&format!("{who} is refused"));
        assert!(e.to_string().contains("CD02"), "{who}: {e}");
    }
    assert_eq!(by_w.expect("the source's writer invalidates"), 1);
    assert!(!exists(&pool, "mass_functions", bba).await);
    let audit = cascade_audit(&pool).await;
    assert_eq!(
        audit.len(),
        1,
        "only the admitted call is audited: {audit:?}"
    );
    assert_eq!(audit[0].0, Some(w));
    assert_eq!(audit[0].1, "retraction_cascade");
    assert_eq!(audit[0].3["source_writer"], 1, "{:?}", audit[0].3);
}

/// The dedup cascade's phase 2. W's duplicate D had an outgoing edge D -> T;
/// the dedup re-sources it at the WORLD canonical C, which W cannot write. Its
/// BBA on T (X's writer-owned row, frozen from D and attributed to D's author
/// W) is invalidated by W through the "retired duplicate of the source" arm. A
/// bystander is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dedup_cascade_invalidates_a_resourced_edge_for_the_duplicates_writer(pool: PgPool) {
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
    let (bba, repair, by_z, by_w) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, x).await;
            let bba = store_bba(&mut conn, target, bt, w, Some(edge)).await;
            stamp(&mut conn, &p, w).await;
            let repair = epigraph_db::ClaimRepository::mark_duplicate_with_repair_conn(
                &mut conn,
                epigraph_core::ClaimId::from_uuid(dup),
                epigraph_core::ClaimId::from_uuid(canonical),
            )
            .await;
            stamp(&mut conn, &p, z).await;
            let by_z = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
            stamp(&mut conn, &p, w).await;
            let by_w = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
            (conn, (bba, repair, by_z, by_w))
        })
        .await;
    let repair = repair.expect("the dedup lands");
    assert_eq!(
        repair
            .resourced_edges
            .iter()
            .map(|(id, _, _)| *id)
            .collect::<Vec<_>>(),
        vec![edge],
        "fixture shape: the edge was re-sourced at the canonical"
    );
    let e = by_z.expect_err("a bystander is refused");
    assert!(e.to_string().contains("CD02"), "{e}");
    assert_eq!(by_w.expect("the duplicate's writer invalidates"), 1);
    assert!(!exists(&pool, "mass_functions", bba).await);
    let audit = cascade_audit(&pool).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].3["source_writer"], 1, "{:?}", audit[0].3);
}

/// The dedup's key collision with SOMEBODY ELSE's canonical-side row. W's
/// duplicate D carries a BBA keyed by edge S -> D; the WORLD canonical C already
/// carries X's writer-owned row with the same (frame, source agent,
/// perspective) key. The owner-scoped pre-delete cannot remove X's row, so the
/// dedup move keeps the canonical's row and drops the duplicate's copy instead
/// of tripping the unique index; the drop is counted in the move's audit row.
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
    let (x_row, w_row, repair) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, x).await;
        let x_row = store_bba(&mut conn, canonical, bt, author, Some(edge)).await;
        stamp(&mut conn, &p, w).await;
        let w_row = store_bba(&mut conn, dup, bt, author, Some(edge)).await;
        let repair = epigraph_db::ClaimRepository::mark_duplicate_with_repair_conn(
            &mut conn,
            epigraph_core::ClaimId::from_uuid(dup),
            epigraph_core::ClaimId::from_uuid(canonical),
        )
        .await;
        (conn, (x_row, w_row, repair))
    })
    .await;
    let repair = repair.expect("the dedup lands instead of tripping the unique index");
    assert_eq!(
        repair.moved_bbas, 0,
        "the colliding copy was dropped, not moved"
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
    let dropped: Option<i64> = sqlx::query_scalar(
        "SELECT (details->'after'->>'dropped_duplicate_copies')::bigint FROM security_events \
          WHERE event_type = 'claims.foreign_aggregate_write' \
            AND details->>'action' = 'dedup_bba_move' AND details->>'claim_id' = $1::text",
    )
    .bind(canonical)
    .fetch_optional(&pool)
    .await
    .expect("move audit");
    assert_eq!(dropped, Some(1), "the drop is in the move's audit row");
}

/// Match-candidate retirement runs on an UNSTAMPED connection. It retracts the
/// promoted matcher edge and then drops the edge's BBA -- X's writer-owned row
/// -- through the definer's retracted-edge arm, audited with no principal.
#[sqlx::test(migrations = "../../migrations")]
async fn match_candidate_retirement_drops_the_retracted_edges_bba_unstamped(pool: PgPool) {
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

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let outcome = MatchCandidateRepo::new(app)
        .retire(cand.id, None)
        .await
        .expect("retirement lands on an unstamped app session");
    assert_eq!(outcome.edges_retracted, 1);
    assert_eq!(outcome.bbas_invalidated, 1);
    assert!(!exists(&pool, "mass_functions", bba).await);
    let audit = cascade_audit(&pool).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(
        audit[0].0, None,
        "no principal on the retirement connection"
    );
    assert_eq!(audit[0].1, "match_candidate_retire");
    assert_eq!(audit[0].3["retracted_edge"], 1, "{:?}", audit[0].3);
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

/// The "retired duplicate of the source" arm needs all three of its
/// conditions. W writes d1, which supersedes S1 but is still CURRENT, and d2,
/// which is retired and supersedes S2 but was authored by W while the BBA on
/// S2's edge is attributed to X. W is refused (CD02) on both edges. Once d1 is
/// retired, the same call on S1's edge lands: the refusal was the
/// `NOT is_current` condition, not the fixture.
#[sqlx::test(migrations = "../../migrations")]
async fn the_retired_duplicate_arm_needs_a_retired_duplicate_by_the_same_author(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (w, wg) = fixture::seed_agent_with_group(&pool, "dedup-w").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "writer-x").await;
    let s1 = fixture::seed_public_claim(&pool, author, "world source one").await;
    let s2 = fixture::seed_public_claim(&pool, author, "world source two").await;
    let target = fixture::seed_public_claim(&pool, author, "world target").await;
    let d1 = seed_claim_row(&pool, w, wg, Some(s1), true, "current dup of S1").await;
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
    let (current_dup, other_author) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, &p, w).await;
            let a = MassFunctionRepository::delete_for_perspective(&mut *conn, e1).await;
            let b = MassFunctionRepository::delete_for_perspective(&mut *conn, e2).await;
            (conn, (a, b))
        })
        .await;
    assert!(
        is_cd02(&current_dup),
        "a CURRENT claim superseding S is not a retired duplicate: {current_dup:?}"
    );
    assert!(
        is_cd02(&other_author),
        "a retired duplicate by another author does not license X's row: {other_author:?}"
    );
    assert!(exists(&pool, "mass_functions", b1).await);
    assert!(exists(&pool, "mass_functions", b2).await);

    // Calibration: retire d1, and the same call lands through the arm.
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(d1)
        .execute(&pool)
        .await
        .expect("retire d1");
    let p = pool.clone();
    let retired = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, w).await;
        let n = MassFunctionRepository::delete_for_perspective(&mut *conn, e1).await;
        (conn, n)
    })
    .await;
    assert_eq!(retired.expect("the retired duplicate's author"), 1);
    assert!(!exists(&pool, "mass_functions", b1).await);
    let audit = cascade_audit(&pool).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].3["source_writer"], 1, "{:?}", audit[0].3);
}

/// The cascade definer only ever considers rows the SESSION can read. On a
/// retracted edge a bystander Z removes the public BBA through the
/// retracted-edge arm, and leaves the private BBA of group H keyed on the same
/// edge alone, exactly as the invoker statement always did.
#[sqlx::test(migrations = "../../migrations")]
async fn the_cascade_never_touches_a_row_the_session_cannot_read(pool: PgPool) {
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "private-h").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "bystander-z").await;
    let source = fixture::seed_public_claim(&pool, author, "world source").await;
    let target = fixture::seed_public_claim(&pool, author, "world target").await;
    let h_claim = fixture::seed_group_claim(&pool, h, hg, "H's private claim").await;
    let bt = seed_frame(&pool, "binary_truth").await;
    let edge = fixture::seed_edge(&pool, source, target).await;
    seed_perspective(&pool, edge).await;
    let public_bba = store_bba_privileged(&pool, target, bt, author, edge).await;
    let private_bba = store_bba_privileged(&pool, h_claim, bt, author, edge).await;
    assert_eq!(
        writer_owned(&pool, "mass_functions", private_bba).await.0,
        hg,
        "fixture shape: H's private row"
    );
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 minute' WHERE id = $1")
        .bind(edge)
        .execute(&pool)
        .await
        .expect("retract the edge");
    assert_app_role_does_not_bypass(&pool).await;

    let p = pool.clone();
    let n = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, z).await;
        let n = MassFunctionRepository::delete_for_perspective(&mut *conn, edge).await;
        (conn, n)
    })
    .await;
    assert_eq!(
        n.expect("the retracted-edge arm"),
        1,
        "only the readable row"
    );
    assert!(!exists(&pool, "mass_functions", public_bba).await);
    assert!(
        exists(&pool, "mass_functions", private_bba).await,
        "a row Z cannot read is not Z's to cascade-delete"
    );
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
                .map_err(|e| {
                    e.as_database_error()
                        .and_then(|d| d.code().map(|c| c.to_string()))
                        .unwrap_or_else(|| e.to_string())
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
        assert_eq!(
            reown,
            &Err("42501".to_string()),
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

/// The four functions are definers owned by the maintenance role, not
/// executable by PUBLIC; the two a statement names are executable by the app;
/// the three tier-A node triggers run the definer body.
#[sqlx::test(migrations = "../../migrations")]
async fn the_115_functions_are_maintenance_owned_definers(pool: PgPool) {
    for (f, app_exec) in [
        ("epigraph_session_writes_node(uuid, text)", true),
        ("epigraph_cascade_delete_edge_bbas(uuid[], text)", true),
        ("epigraph_dedup_move_bbas(uuid, uuid, uuid[])", true),
        ("epigraph_cascade_delete_node_edges()", false),
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
