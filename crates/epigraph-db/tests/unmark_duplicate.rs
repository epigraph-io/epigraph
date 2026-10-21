//! B4: an un-mark puts a dedup back exactly.
//!
//! A mark followed by an un-mark (from the repair's revert record) must leave
//! every edge, BBA, frame binding and the duplicate's own row as they were
//! before the mark: edges re-pointed back, the collision-retracted edge in
//! force again with its deleted BBA restored (same id, same tenancy), moved
//! and pooled BBAs back on the duplicate with their old tenancy, the frame
//! binding the repair added to the canonical gone. The identity edge is the
//! one row that stays, retracted, as the record that the mark happened.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, DuplicateProvenance, FrameRepository, MassFunctionRepository};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

async fn stamp(conn: &mut PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let groups = csv(v.group_bind().expect("scoped viewer"));
    let writable = csv(v.writable_groups());
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

/// A public claim its writer's group owns: the shape the write path gives a
/// claim its own author submits publicly.
async fn public_claim_owned_by(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("unmark fixture {tag}"))
    .bind(&hash)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a public claim owned by a group");
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', $4)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(rel)
    .execute(pool)
    .await
    .expect("seed edge");
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("edge {id}"))
        .execute(pool)
        .await
        .expect("seed edge perspective");
    id
}

async fn bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Option<Uuid>,
    perspective: Option<Uuid>,
    m: serde_json::Value,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        agent,
        perspective,
        &m,
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

/// Every row a dedup can touch around `claims`, as comparable tuples. The
/// dedup identity edge is left out: it is the one row an un-mark keeps.
async fn snapshot(pool: &PgPool, claims: &[Uuid]) -> Vec<String> {
    let mut out: Vec<String> = sqlx::query_scalar(
        "SELECT format('edge %s %s->%s %s in_force=%s %s/%s', id, source_id, target_id, \
                       relationship, valid_to IS NULL, visibility, owner_group_id) \
           FROM edges \
          WHERE (source_id = ANY($1) OR target_id = ANY($1)) \
            AND NOT (relationship = 'same_as' AND properties ? 'dedup') \
          ORDER BY id",
    )
    .bind(claims)
    .fetch_all(pool)
    .await
    .expect("edges");
    out.extend(
        sqlx::query_scalar::<_, String>(
            "SELECT format('bba %s on %s frame %s agent %s persp %s masses %s %s/%s wo=%s', \
                           id, claim_id, frame_id, source_agent_id, perspective_id, masses, \
                           visibility, owner_group_id, writer_owned) \
               FROM mass_functions WHERE claim_id = ANY($1) \
                 OR perspective_id IN (SELECT id FROM edges \
                                        WHERE source_id = ANY($1) OR target_id = ANY($1)) \
              ORDER BY id",
        )
        .bind(claims)
        .fetch_all(pool)
        .await
        .expect("bbas"),
    );
    out.extend(
        sqlx::query_scalar::<_, String>(
            "SELECT format('frame %s %s idx %s', claim_id, frame_id, hypothesis_index) \
               FROM claim_frames WHERE claim_id = ANY($1) ORDER BY claim_id, frame_id",
        )
        .bind(claims)
        .fetch_all(pool)
        .await
        .expect("frames"),
    );
    out.extend(
        sqlx::query_scalar::<_, String>(
            "SELECT format('claim %s supersedes %s current %s labels %s', \
                           id, supersedes, is_current, labels) \
               FROM claims WHERE id = ANY($1) ORDER BY id",
        )
        .bind(claims)
        .fetch_all(pool)
        .await
        .expect("claims"),
    );
    out
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_then_unmark_restores_every_row_the_dedup_touched(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "other-writer").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "duplicate").await;
    let supporter = fixture::seed_public_claim(&pool, b, "supporter").await;
    let supported = fixture::seed_public_claim(&pool, b, "supported").await;
    let diamond = fixture::seed_public_claim(&pool, b, "diamond source").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['an-index-family'] WHERE id = $1")
        .bind(dup)
        .execute(&pool)
        .await
        .expect("label the duplicate");
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        None,
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;
    FrameRepository::assign_claim(&pool, dup, frame, Some(0))
        .await
        .expect("bind dup");
    let m = serde_json::json!({"0": 0.6, "0,1": 0.4});

    // Retargeted (and its BBA moved), re-sourced, collision-retracted (and its
    // BBA deleted), pooled, and kept (the canonical already counts agent a).
    let e_in = edge(&pool, supporter, dup, "supports").await;
    bba(&pool, dup, frame, Some(b), Some(e_in), m.clone()).await;
    let e_out = edge(&pool, dup, supported, "supports").await;
    bba(&pool, supported, frame, Some(a), Some(e_out), m.clone()).await;
    let e_dia_dup = edge(&pool, diamond, dup, "corroborates").await;
    edge(&pool, diamond, canonical, "corroborates").await;
    bba(&pool, dup, frame, Some(b), Some(e_dia_dup), m.clone()).await;
    bba(&pool, dup, frame, None, None, m.clone()).await;
    bba(&pool, dup, frame, Some(a), None, m.clone()).await;
    bba(&pool, canonical, frame, Some(a), None, m).await;

    let claims = [canonical, dup, supporter, supported, diamond];
    let before = snapshot(&pool, &claims).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let repair = ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
        &DuplicateProvenance::new("test", DuplicateProvenance::RULE_CALLER_ASSERTED),
    )
    .await
    .expect("mark");
    // Calibration: the mark changed every class of row the snapshot covers.
    assert_eq!(repair.retargeted_edges, vec![e_in]);
    assert_eq!(repair.retracted_edges, vec![e_dia_dup]);
    assert_eq!(repair.resourced_edges.len(), 1);
    assert_eq!(repair.pooled_bbas.len(), 1);
    assert_eq!(repair.kept_on_duplicate.len(), 1);
    assert_eq!(repair.revert.copied_frames, vec![frame]);
    assert_eq!(repair.revert.deleted_bbas.len(), 1);
    let marked = snapshot(&pool, &claims).await;
    assert_ne!(before, marked, "the mark must change the snapshot");

    let (unmarked, reversal) = ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        &repair.revert,
    )
    .await
    .expect("unmark");
    assert_eq!(unmarked.canonical, canonical);
    assert_eq!(Some(unmarked.identity_edge), repair.revert.identity_edge);
    assert!(
        reversal.drifted.is_empty(),
        "nothing drifted: {:?}",
        reversal.drifted
    );

    let after = snapshot(&pool, &claims).await;
    let lost: Vec<&String> = before.iter().filter(|r| !after.contains(r)).collect();
    let gained: Vec<&String> = after.iter().filter(|r| !before.contains(r)).collect();
    assert!(
        lost.is_empty() && gained.is_empty(),
        "mark -> unmark is not the identity.\nmissing: {lost:#?}\nextra: {gained:#?}"
    );

    let (in_force, props): (bool, serde_json::Value) =
        sqlx::query_as("SELECT valid_to IS NULL, properties FROM edges WHERE id = $1")
            .bind(unmarked.identity_edge)
            .fetch_one(&pool)
            .await
            .expect("identity edge");
    assert!(!in_force, "the identity edge stays, retracted");
    assert_eq!(props["dedup"]["tool"], "test");

    // The duplicate can be marked again, and that mark has its own identity
    // edge and its own record.
    let again = ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
        &DuplicateProvenance::new("test", DuplicateProvenance::RULE_CALLER_ASSERTED),
    )
    .await
    .expect("re-mark after unmark");
    assert_ne!(again.revert.identity_edge, repair.revert.identity_edge);
    // And the first mark's record no longer matches the duplicate.
    let err = ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        &repair.revert,
    )
    .await
    .expect_err("a stale record is refused");
    assert!(format!("{err:?}").contains("another mark"), "{err:?}");
}

/// Only a dedup-marked duplicate can be un-marked: a current claim, and a
/// claim retired by a consolidation (which has `supersedes` set and is not
/// current, exactly like a duplicate, but has no identity edge), are refused
/// with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn unmark_refuses_a_claim_no_dedup_marked(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let current = fixture::seed_public_claim(&pool, a, "a current claim").await;
    let s1 = fixture::seed_public_claim(&pool, a, "source one").await;
    let s2 = fixture::seed_public_claim(&pool, a, "source two").await;
    let merged = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "the merged claim",
        0.5,
        epigraph_db::ConsolidateMode::Merge,
        "test",
        a,
    )
    .await
    .expect("consolidate");
    let (sup, cur): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(s1)
            .fetch_one(&pool)
            .await
            .expect("source");
    assert_eq!(
        (sup, cur),
        (Some(merged.merged_id), false),
        "calibration: looks marked"
    );

    let mut conn = pool.acquire().await.expect("acquire");
    for (what, id) in [("a current claim", current), ("a consolidated source", s1)] {
        let err = ClaimRepository::unmark_duplicate_act_conn(&mut conn, ClaimId::from_uuid(id))
            .await
            .expect_err(what);
        assert!(
            format!("{err:?}").contains("nothing was written"),
            "{what}: {err:?}"
        );
    }
    let (sup, cur): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(s1)
            .fetch_one(&pool)
            .await
            .expect("source");
    assert_eq!((sup, cur), (Some(merged.merged_id), false), "untouched");
}

/// The un-mark's act lands on the writer's stamped application session for a
/// group-private duplicate and for a public one (whose identity edge the
/// writer wrote between two public claims), and is refused for a stranger.
#[sqlx::test(migrations = "../../migrations")]
async fn the_unmark_act_lands_on_the_app_role_for_the_writer_only(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let pairs = [
        (
            fixture::seed_group_claim(&pool, w, g, "group dup").await,
            fixture::seed_group_claim(&pool, w, g, "group canonical").await,
        ),
        (
            public_claim_owned_by(&pool, w, g, "public dup").await,
            public_claim_owned_by(&pool, w, g, "public canonical").await,
        ),
    ];
    let p = pool.clone();
    let results = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let mut out = Vec::new();
        for (dup, canonical) in pairs {
            stamp(&mut conn, &p, w).await;
            ClaimRepository::mark_duplicate_act_conn(
                &mut conn,
                ClaimId::from_uuid(dup),
                ClaimId::from_uuid(canonical),
            )
            .await
            .expect("the writer marks");
            stamp(&mut conn, &p, stranger).await;
            let by_stranger =
                ClaimRepository::unmark_duplicate_act_conn(&mut conn, ClaimId::from_uuid(dup))
                    .await;
            stamp(&mut conn, &p, w).await;
            let by_writer =
                ClaimRepository::unmark_duplicate_act_conn(&mut conn, ClaimId::from_uuid(dup))
                    .await;
            out.push((dup, by_stranger.is_err(), by_writer));
        }
        (conn, out)
    })
    .await;
    for (dup, stranger_refused, by_writer) in results {
        assert!(stranger_refused, "a stranger cannot un-mark {dup}");
        by_writer.expect("the writer un-marks its own duplicate on the app role");
        let (sup, cur): (Option<Uuid>, bool) =
            sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
                .bind(dup)
                .fetch_one(&pool)
                .await
                .expect("dup");
        assert_eq!((sup, cur), (None, true));
    }
}

/// A collision-retracted edge comes back only while its retraction is still
/// the repair's. If a later write re-decided it (here: reinstated, then
/// retracted again by its owner at a different moment), the un-mark leaves it
/// retracted and reports it drifted, rather than resurrecting a withdrawal.
#[sqlx::test(migrations = "../../migrations")]
async fn unmark_does_not_resurrect_an_edge_retracted_again_after_the_mark(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "other-writer").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "duplicate").await;
    let diamond = fixture::seed_public_claim(&pool, b, "diamond source").await;
    let e_dup = edge(&pool, diamond, dup, "corroborates").await;
    edge(&pool, diamond, canonical, "corroborates").await;

    let mut conn = pool.acquire().await.expect("acquire");
    let repair = ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
        &DuplicateProvenance::new("test", DuplicateProvenance::RULE_CALLER_ASSERTED),
    )
    .await
    .expect("mark");
    assert_eq!(repair.retracted_edges, vec![e_dup], "calibration");
    sqlx::query("UPDATE edges SET valid_to = valid_to + interval '1 minute' WHERE id = $1")
        .bind(e_dup)
        .execute(&pool)
        .await
        .expect("a later, different retraction");

    let (_, reversal) = ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        &repair.revert,
    )
    .await
    .expect("unmark");
    let in_force: bool = sqlx::query_scalar("SELECT valid_to IS NULL FROM edges WHERE id = $1")
        .bind(e_dup)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert!(!in_force, "a later retraction is not the repair's to undo");
    assert_eq!(reversal.drifted, vec![e_dup]);
}
