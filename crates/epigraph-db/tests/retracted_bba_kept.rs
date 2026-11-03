//! SPEC §11 phase 1, K4a: a RETRACTED mass function (migration 184, rulings
//! R-79 / R-103: "excluded from every fold, kept for audit") survives every
//! repository path that deletes or moves `mass_functions` rows. Each path
//! deletes or moves only LIVE rows; a retracted row stays where it is.
//!
//! Every retracted row here is made by migration 184's definer on the
//! application role (`support/retracted_bba_fixture.rs`). Every privileged
//! path runs on a NOSUPERUSER `epigraph_maintenance` session (SPEC §12), whose
//! `epigraph_session_is_privileged_writer()` is checked before the act, so a
//! green run is not the superuser harness deleting nothing.
//!
//! The application-session arm of `delete_edge_bbas` (117's
//! `epigraph_cascade_delete_edge_bbas`) is NOT tested here: its re-body is
//! slot 194's (SPEC §10.1 S-1), not this release's.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "support/retracted_bba_fixture.rs"]
mod retracted;

use epigraph_core::ClaimId;
use epigraph_db::repos::experiment::ExperimentRepository;
use epigraph_db::repos::mass_function::{delete_edge_bbas, EdgeBbaCascade};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, EdgeRepository, MassFunctionRepository};
use retracted::{retract_through_definer, row_state};
use sqlx::PgPool;
use uuid::Uuid;

/// A NOSUPERUSER maintenance pool, checked privileged and not superuser.
async fn maintenance(pool: &PgPool) -> PgPool {
    let m = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let (superuser, privileged): (bool, bool) = sqlx::query_as(
        "SELECT r.rolsuper, public.epigraph_session_is_privileged_writer() \
           FROM pg_roles r WHERE r.rolname = current_user",
    )
    .fetch_one(&m)
    .await
    .expect("read the maintenance session's role");
    assert!(
        !superuser,
        "the maintenance session must not be a superuser"
    );
    assert!(
        privileged,
        "the maintenance session must take the privileged arm, or the delete under test is \
         not the one K4a guards"
    );
    m
}

async fn frame(pool: &PgPool, tag: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("k4a-{tag}-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// A public claim owned by `group`, authored by `agent`.
async fn claim(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("k4a fixture {tag} {id}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A claim-to-claim edge and its edge-factor perspective (what
/// `ensure_edge_perspective` writes when a BBA is wired on it).
async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("seed edge");
    sqlx::query(
        "INSERT INTO perspectives (id, name, perspective_type) VALUES ($1, 'edge_factor', 'edge')",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("seed the edge's perspective");
    id
}

/// `agent`'s BBA on (claim, frame), keyed on `perspective`, through the
/// repository upsert every BBA writer uses.
async fn bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Option<Uuid>,
    perspective: Option<Uuid>,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        agent,
        perspective,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA")
}

/// Site 1: `delete_edge_bbas`' privileged `own` CTE deletes the edge's live
/// rows and keeps its retracted one. Before K4a it deleted both.
#[sqlx::test(migrations = "../../migrations")]
async fn a_privileged_edge_bba_delete_keeps_a_retracted_row(pool: PgPool) {
    let maint = maintenance(&pool).await;
    let (owner, g) = fixture::seed_agent_with_group(&pool, "k4a-s1-owner").await;
    let (other, og) = fixture::seed_agent_with_group(&pool, "k4a-s1-other").await;
    let s = claim(&pool, other, og, "s1 source").await;
    let t = claim(&pool, owner, g, "s1 target").await;
    let e = edge(&pool, s, t, "supports").await;
    let (f1, f2) = (frame(&pool, "s1a").await, frame(&pool, "s1b").await);
    let live = bba(&pool, t, f1, Some(other), Some(e)).await;
    let gone_unless_kept = bba(&pool, t, f2, Some(owner), Some(e)).await;
    retract_through_definer(&pool, gone_unless_kept).await;

    let n = delete_edge_bbas(&maint, &[e], EdgeBbaCascade::RetractionCascade)
        .await
        .expect("the privileged delete");
    assert_eq!(
        row_state(&pool, gone_unless_kept).await,
        Some((t, true)),
        "the retracted row is kept for audit (R-79), not deleted with its edge's live rows"
    );
    assert_eq!(
        row_state(&pool, live).await,
        None,
        "the live row is deleted"
    );
    assert_eq!(n, 1, "only the live row is counted");
}

/// Site 7: `delete_for_claim` deletes the claim's live rows and keeps a
/// retracted one, and the kept row is not a refusal (the readability probe
/// counts the same rows the delete may take).
#[sqlx::test(migrations = "../../migrations")]
async fn delete_for_claim_keeps_a_retracted_row(pool: PgPool) {
    let maint = maintenance(&pool).await;
    let (owner, g) = fixture::seed_agent_with_group(&pool, "k4a-s7").await;
    let c = claim(&pool, owner, g, "s7").await;
    let (f1, f2) = (frame(&pool, "s7a").await, frame(&pool, "s7b").await);
    let live = bba(&pool, c, f1, Some(owner), None).await;
    let kept = bba(&pool, c, f2, Some(owner), None).await;
    retract_through_definer(&pool, kept).await;

    let n = MassFunctionRepository::delete_for_claim(&maint, c)
        .await
        .expect("a claim whose only other row is retracted is not a refusal");
    assert_eq!(
        row_state(&pool, kept).await,
        Some((c, true)),
        "the retracted row is kept for audit"
    );
    assert_eq!(
        row_state(&pool, live).await,
        None,
        "the live row is deleted"
    );
    assert_eq!(n, 1, "only the live row is counted");
}

/// Site 6: the hypothesis promotion's retire step, called with the id of a
/// row that was retracted after the route read it (the route reads the row
/// outside the promotion's transaction), deletes nothing and answers `false`,
/// which every caller treats as a refusal of the whole promotion. A live row
/// is still retired (calibration: the call shape deletes).
#[sqlx::test(migrations = "../../migrations")]
async fn a_promotion_retire_refuses_a_row_retracted_since_the_read(pool: PgPool) {
    let (owner, g) = fixture::seed_agent_with_group(&pool, "k4a-s6").await;
    let h = claim(&pool, owner, g, "s6 hypothesis").await;
    let (hf, hf2) = (frame(&pool, "s6a").await, frame(&pool, "s6b").await);
    let raced = bba(&pool, h, hf, Some(owner), None).await;
    let control = bba(&pool, h, hf2, Some(owner), None).await;
    retract_through_definer(&pool, raced).await;

    let viewer = Viewer::resolve(&pool, owner).await.expect("viewer");
    let groups = viewer.group_bind().expect("scoped").to_vec();
    let writable = viewer.writable_groups().to_vec();
    let v = viewer;
    let (raced_out, control_out) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let csv = |ids: &[Uuid]| {
            ids.iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        sqlx::query(
            "SELECT set_config('epigraph.group_ids', $1, false), \
                    set_config('epigraph.writable_group_ids', $2, false), \
                    set_config('epigraph.principal_id', $3, false)",
        )
        .bind(csv(&groups))
        .bind(csv(&writable))
        .bind(owner.to_string())
        .execute(&mut *conn)
        .await
        .expect("stamp the owner");
        let a = ExperimentRepository::retire_promoted_hypothesis_bba(&mut *conn, &v, raced, h, hf)
            .await
            .expect("the retire statement runs");
        let b =
            ExperimentRepository::retire_promoted_hypothesis_bba(&mut *conn, &v, control, h, hf2)
                .await
                .expect("the retire statement runs");
        (conn, (a, b))
    })
    .await;
    assert!(
        !raced_out,
        "a retracted source row is not retired: the promotion is refused"
    );
    assert_eq!(
        row_state(&pool, raced).await,
        Some((h, true)),
        "and the retracted row is kept"
    );
    assert!(control_out, "calibration: a live source row is retired");
    assert_eq!(row_state(&pool, control).await, None);
}

/// Site 5: the maintenance replay of an edge retraction removes the withdrawn
/// edge's live rows and keeps its retracted one, and the one-shot legacy
/// sweep's enumerator stops listing an edge that then holds only retracted
/// rows (it has nothing left to remove, and under its LIMIT it would crowd out
/// edges that do).
#[sqlx::test(migrations = "../../migrations")]
async fn the_withdrawn_edge_replay_keeps_a_retracted_row_and_the_sweep_stops_listing_it(
    pool: PgPool,
) {
    let maint = maintenance(&pool).await;
    let (owner, g) = fixture::seed_agent_with_group(&pool, "k4a-s5-owner").await;
    let (other, og) = fixture::seed_agent_with_group(&pool, "k4a-s5-other").await;
    let s = claim(&pool, other, og, "s5 source").await;
    let t = claim(&pool, owner, g, "s5 target").await;
    let e = edge(&pool, s, t, "supports").await;
    let (f1, f2) = (frame(&pool, "s5a").await, frame(&pool, "s5b").await);
    let live = bba(&pool, t, f1, Some(other), Some(e)).await;
    let kept = bba(&pool, t, f2, Some(owner), Some(e)).await;
    retract_through_definer(&pool, kept).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 minute' WHERE id = $1")
        .bind(e)
        .execute(&pool)
        .await
        .expect("withdraw the edge");

    let mut conn = maint.acquire().await.expect("acquire");
    let listed = EdgeRepository::withdrawn_edges_with_bbas_conn(&mut conn, 1000)
        .await
        .expect("enumerate");
    assert!(
        listed.contains(&e),
        "calibration: a withdrawn edge with a live row is listed"
    );
    let out = EdgeRepository::remove_withdrawn_edge_bbas_conn(&mut conn, e)
        .await
        .expect("the replay's removal");
    assert_eq!(
        row_state(&pool, kept).await,
        Some((t, true)),
        "the retracted row is kept for audit"
    );
    assert_eq!(
        row_state(&pool, live).await,
        None,
        "the live row is removed"
    );
    assert_eq!(
        (out.withdrawn, out.deleted),
        (true, 1),
        "only the live row is counted"
    );
    let listed = EdgeRepository::withdrawn_edges_with_bbas_conn(&mut conn, 1000)
        .await
        .expect("enumerate again");
    assert!(
        !listed.contains(&e),
        "an edge holding only a retracted row has nothing for the sweep to remove"
    );
}

/// Site 2 (and part 1's revert snapshot): the dedup repair on the privileged
/// maintenance session, over one re-targeted edge `e_in` (T -> dup) whose
/// BBAs collide with rows the canonical holds under the same key, and one
/// collision-retracted edge `e_dia` (S -> dup, S -> canonical):
///
/// | frame | dup copy on `e_in` | canonical holder | after the repair |
/// |-------|--------------------|------------------|------------------|
/// | f1    | live               | retracted        | the live copy stays on dup, reported |
/// | f2    | retracted          | live             | the retracted copy stays on dup |
/// | f3    | live               | live             | the dup copy is dropped (calibration) |
/// | f4    | live               | none             | moved onto the canonical (calibration) |
///
/// On `e_dia` the live row is deleted with its edge and the retracted one is
/// kept; the revert record's deleted rows name exactly the two rows that went.
/// The repair has no savepoint, so any raise would fail it: it must complete.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dedup_repair_keeps_retracted_rows_and_the_live_copies_a_retracted_holder_blocks(
    pool: PgPool,
) {
    let maint = maintenance(&pool).await;
    let (owner, g) = fixture::seed_agent_with_group(&pool, "k4a-s2-owner").await;
    let (citer, cg) = fixture::seed_agent_with_group(&pool, "k4a-s2-citer").await;
    let canonical = claim(&pool, owner, g, "s2 canonical").await;
    let dup = claim(&pool, owner, g, "s2 duplicate").await;
    let t = claim(&pool, citer, cg, "s2 citer").await;
    let s = claim(&pool, citer, cg, "s2 diamond source").await;
    let e_in = edge(&pool, t, dup, "supports").await;
    let e_dia = edge(&pool, s, dup, "refutes").await;
    edge(&pool, s, canonical, "refutes").await;
    let f: Vec<Uuid> = {
        let mut v = Vec::new();
        for i in 0..4 {
            v.push(frame(&pool, &format!("s2-{i}")).await);
        }
        v
    };

    let d1 = bba(&pool, dup, f[0], Some(citer), Some(e_in)).await;
    let d2 = bba(&pool, dup, f[1], Some(citer), Some(e_in)).await;
    let d3 = bba(&pool, dup, f[2], Some(citer), Some(e_in)).await;
    let d4 = bba(&pool, dup, f[3], Some(citer), Some(e_in)).await;
    let c1 = bba(&pool, canonical, f[0], Some(citer), Some(e_in)).await;
    let c2 = bba(&pool, canonical, f[1], Some(citer), Some(e_in)).await;
    let c3 = bba(&pool, canonical, f[2], Some(citer), Some(e_in)).await;
    let p_live = bba(&pool, dup, f[0], Some(citer), Some(e_dia)).await;
    let p_ret = bba(&pool, dup, f[1], Some(citer), Some(e_dia)).await;
    for id in [c1, d2, p_ret] {
        retract_through_definer(&pool, id).await;
    }

    let repair = ClaimRepository::mark_duplicate_with_repair(
        &maint,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("the dedup repair completes (it has no savepoint; a raise would fail it)");

    // K4a: nothing retracted is deleted, and a live copy the canonical's
    // retracted holder blocks stays on the duplicate.
    assert_eq!(
        row_state(&pool, d1).await,
        Some((dup, false)),
        "a live duplicate copy whose canonical holder is retracted is kept on the duplicate"
    );
    assert_eq!(
        row_state(&pool, d2).await,
        Some((dup, true)),
        "a retracted duplicate copy is kept where it is"
    );
    assert_eq!(
        row_state(&pool, p_ret).await,
        Some((dup, true)),
        "a retracted row on a collision-retracted edge is kept"
    );
    assert_eq!(
        row_state(&pool, c1).await,
        Some((canonical, true)),
        "the canonical's retracted holder is untouched"
    );
    assert_eq!(
        repair.kept_on_duplicate_by_retracted_holder,
        vec![d1],
        "the kept live copy is reported"
    );
    let snapshot: Vec<Uuid> = {
        let mut v: Vec<Uuid> = repair
            .revert
            .deleted_bbas
            .iter()
            .map(|r| {
                r["id"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .expect("a snapshot row's id")
            })
            .collect();
        v.sort_unstable();
        v
    };
    let mut went = vec![d3, p_live];
    went.sort_unstable();
    assert_eq!(
        snapshot, went,
        "the revert record names exactly the rows that were deleted, never a kept retracted one"
    );

    // Calibration: the live rules still act.
    assert_eq!(
        row_state(&pool, d3).await,
        None,
        "a live copy of a live holder is dropped"
    );
    assert_eq!(row_state(&pool, c2).await, Some((canonical, false)));
    assert_eq!(row_state(&pool, c3).await, Some((canonical, false)));
    assert_eq!(
        row_state(&pool, d4).await,
        Some((canonical, false)),
        "a row the canonical does not hold moves with its edge"
    );
    assert_eq!(
        row_state(&pool, p_live).await,
        None,
        "a live row on a collision-retracted edge goes with it"
    );
    assert_eq!(
        (
            repair.dropped_duplicate_copies,
            repair.moved_bbas,
            repair.deleted_bbas
        ),
        (1, 1, 1),
        "one copy dropped, one row moved, one row deleted with its edge"
    );
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e_in)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, canonical, "the edge itself was re-targeted");
}
