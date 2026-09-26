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
// 4. The catalog.
// ===========================================================================

/// The ratchet: every relation carrying both tenancy columns under row
/// security, bar the principal-keyed `recall_events`, has a RESTRICTIVE
/// FOR DELETE policy. A 25th such table added without one fails here.
#[sqlx::test(migrations = "../../migrations")]
async fn every_public_admitting_table_has_a_restrictive_delete_policy(pool: PgPool) {
    let rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT c.relname::text, \
                EXISTS (SELECT 1 FROM pg_policy p \
                         WHERE p.polrelid = c.oid AND p.polcmd = 'd' AND NOT p.polpermissive) \
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
        .filter(|(_, has)| !has)
        .map(|(t, _)| t)
        .collect();
    assert!(
        missing.is_empty(),
        "no restrictive DELETE policy on {missing:?}"
    );
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
