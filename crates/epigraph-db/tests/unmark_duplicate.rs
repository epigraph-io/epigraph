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

/// The bypass viewer a privileged (harness superuser) session acts with.
async fn bypass_viewer(pool: &PgPool) -> Viewer {
    fixture::bypass(pool).await.1
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
    let (a, ga) = fixture::seed_agent_with_group(&pool, "author").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "other-writer").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    // Owned by a's group (the canonical is world-owned), so every BBA moved
    // onto the canonical changes tenancy (writer-owned) and the snapshot's
    // tenancy columns see whether the un-mark puts it back.
    let dup = public_claim_owned_by(&pool, a, ga, "duplicate").await;
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
    let pooled = bba(&pool, dup, frame, None, None, m.clone()).await;
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
    let wo: (Uuid, bool) =
        sqlx::query_as("SELECT claim_id, writer_owned FROM mass_functions WHERE id = $1")
            .bind(pooled)
            .fetch_one(&pool)
            .await
            .expect("pooled row");
    assert_eq!(
        wo,
        (canonical, true),
        "calibration: the move changed the row's tenancy"
    );

    let (unmarked, reversal) = ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        &bypass_viewer(&pool).await,
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
        &bypass_viewer(&pool).await,
        ClaimId::from_uuid(dup),
        &repair.revert,
    )
    .await
    .expect_err("a stale record is refused");
    assert!(format!("{err:?}").contains("another mark"), "{err:?}");
    let (sup, cur): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("dup");
    assert_eq!(
        (sup, cur),
        (Some(canonical), false),
        "the refusal left the second mark"
    );
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
        let err = ClaimRepository::unmark_duplicate_act_conn(
            &mut conn,
            &bypass_viewer(&pool).await,
            ClaimId::from_uuid(id),
        )
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
            let stranger_viewer = Viewer::resolve(&p, stranger).await.expect("viewer");
            let by_stranger = ClaimRepository::unmark_duplicate_act_conn(
                &mut conn,
                &stranger_viewer,
                ClaimId::from_uuid(dup),
            )
            .await;
            let after_stranger: (Option<Uuid>, bool) =
                sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
                    .bind(dup)
                    .fetch_one(&p)
                    .await
                    .expect("dup");
            assert_eq!(
                after_stranger,
                (Some(canonical), false),
                "a stranger's refused un-mark wrote nothing"
            );
            stamp(&mut conn, &p, w).await;
            let writer_viewer = Viewer::resolve(&p, w).await.expect("viewer");
            let by_writer = ClaimRepository::unmark_duplicate_act_conn(
                &mut conn,
                &writer_viewer,
                ClaimId::from_uuid(dup),
            )
            .await;
            out.push((dup, by_stranger.is_err(), by_writer));
        }
        (conn, out)
    })
    .await;
    for (dup, stranger_refused, by_writer) in results {
        assert!(stranger_refused, "a stranger cannot un-mark {dup}");
        let unmarked = by_writer.expect("the writer un-marks its own duplicate on the app role");
        let retracted: bool =
            sqlx::query_scalar("SELECT valid_to IS NOT NULL FROM edges WHERE id = $1")
                .bind(unmarked.identity_edge)
                .fetch_one(&pool)
                .await
                .expect("identity edge");
        assert!(retracted, "the act retracted the identity edge");
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
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        None,
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;
    let e_dup_bba = bba(
        &pool,
        dup,
        frame,
        Some(b),
        Some(e_dup),
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;

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
        &bypass_viewer(&pool).await,
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
    let restored: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE id = $1")
        .bind(e_dup_bba)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        restored, 0,
        "no BBA is restored onto an edge that stays retracted"
    );
    let mut expected = vec![e_dup, e_dup_bba];
    expected.sort_unstable();
    assert_eq!(reversal.drifted, expected);
}

/// Chained dedups, the normal case for a repeated dedup run: D1 is marked onto
/// C1, then C1 itself onto C2. D1's identity edge must keep naming the claim
/// D1 supersedes (C1) rather than following C1's repair onto C2; un-marking D1
/// while C1 is retired is refused with the order to follow; un-marking C1 and
/// then D1 restores everything.
#[sqlx::test(migrations = "../../migrations")]
async fn a_chain_of_dedups_unmarks_in_reverse_order(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "other-writer").await;
    let c2 = fixture::seed_public_claim(&pool, a, "newest canonical").await;
    let c1 = fixture::seed_public_claim(&pool, a, "first canonical").await;
    let d1 = fixture::seed_public_claim(&pool, a, "first duplicate").await;
    let supporter = fixture::seed_public_claim(&pool, b, "supporter").await;
    let e = edge(&pool, supporter, d1, "supports").await;
    let claims = [c2, c1, d1, supporter];
    let before = snapshot(&pool, &claims).await;
    let prov = DuplicateProvenance::new("test", DuplicateProvenance::RULE_CALLER_ASSERTED);

    let mut conn = pool.acquire().await.expect("acquire");
    let r1 = ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(d1),
        ClaimId::from_uuid(c1),
        &prov,
    )
    .await
    .expect("mark d1 onto c1");
    let r2 = ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(c1),
        ClaimId::from_uuid(c2),
        &prov,
    )
    .await
    .expect("mark c1 onto c2");
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(r1.revert.identity_edge.expect("d1's identity edge"))
        .fetch_one(&pool)
        .await
        .expect("identity edge");
    assert_eq!(
        target, c1,
        "d1's identity edge keeps naming the claim it supersedes"
    );
    let on: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(
        on, c2,
        "calibration: the supporter's edge followed the chain to c2"
    );

    let err = ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        &bypass_viewer(&pool).await,
        ClaimId::from_uuid(d1),
        &r1.revert,
    )
    .await
    .expect_err("d1 cannot be un-marked while c1 is retired");
    assert!(format!("{err:?}").contains("first"), "{err:?}");

    ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        &bypass_viewer(&pool).await,
        ClaimId::from_uuid(c1),
        &r2.revert,
    )
    .await
    .expect("un-mark c1");
    let (_, reversal) = ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        &bypass_viewer(&pool).await,
        ClaimId::from_uuid(d1),
        &r1.revert,
    )
    .await
    .expect("then un-mark d1");
    assert!(reversal.drifted.is_empty(), "{:?}", reversal.drifted);
    let after = snapshot(&pool, &claims).await;
    let lost: Vec<&String> = before.iter().filter(|r| !after.contains(r)).collect();
    let gained: Vec<&String> = after.iter().filter(|r| !before.contains(r)).collect();
    assert!(
        lost.is_empty() && gained.is_empty(),
        "the chain is not undone.\nmissing: {lost:#?}\nextra: {gained:#?}"
    );
}

async fn bba_tenancy(pool: &PgPool, id: Uuid) -> (Uuid, String, Uuid, bool) {
    sqlx::query_as(
        "SELECT claim_id, visibility::text, owner_group_id, writer_owned \
           FROM mass_functions WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("bba")
}

async fn mark(pool: &PgPool, dup: Uuid, canonical: Uuid) -> epigraph_db::DedupRepair {
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
        &DuplicateProvenance::new("test", DuplicateProvenance::RULE_CALLER_ASSERTED),
    )
    .await
    .expect("mark")
}

async fn unmark(
    pool: &PgPool,
    dup: Uuid,
    record: &epigraph_db::DedupRevert,
) -> epigraph_db::DedupReversal {
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        &bypass_viewer(pool).await,
        ClaimId::from_uuid(dup),
        record,
    )
    .await
    .expect("unmark")
    .1
}

/// A BBA returns to the duplicate with the tenancy the record kept only while
/// that is still the duplicate's audience: a duplicate that went private after
/// the mark gets its returned row as the claim's own (group, its group, not
/// writer-owned), never a public row on a private claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_returned_bba_takes_the_duplicates_audience_if_it_narrowed(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let canonical = fixture::seed_public_claim(&pool, author, "world canonical").await;
    let dup = public_claim_owned_by(&pool, w, g, "duplicate").await;
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        None,
        &["TRUE".into(), "FALSE".into()],
    )
    .await
    .expect("frame")
    .id;
    let row = bba(
        &pool,
        dup,
        frame,
        Some(w),
        None,
        serde_json::json!({"0": 0.6, "0,1": 0.4}),
    )
    .await;
    let repair = mark(&pool, dup, canonical).await;
    assert_eq!(repair.pooled_bbas, vec![row], "calibration: pooled");
    assert_eq!(
        bba_tenancy(&pool, row).await,
        (canonical, "public".into(), g, true)
    );
    sqlx::query("UPDATE claims SET visibility = 'group' WHERE id = $1")
        .bind(dup)
        .execute(&pool)
        .await
        .expect("the duplicate goes private");
    let reversal = unmark(&pool, dup, &repair.revert).await;
    assert_eq!(reversal.returned_bbas, vec![row]);
    assert_eq!(
        bba_tenancy(&pool, row).await,
        (dup, "group".into(), g, false),
        "the returned row is the private claim's own"
    );
}

/// An edge re-pointed onto a group-private canonical is re-stamped private by
/// the edge tenancy trigger; re-pointed back, the trigger's no-widening arm
/// would keep it private. The un-mark gives it back the tenancy it had.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repointed_edge_gets_its_tenancy_back(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer").await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "other").await;
    let dup = public_claim_owned_by(&pool, w, g, "public duplicate").await;
    let canonical = fixture::seed_group_claim(&pool, w, g, "private canonical").await;
    let supporter = fixture::seed_public_claim(&pool, x, "public supporter").await;
    let e = edge(&pool, supporter, dup, "supports").await;
    let tenancy = |pool: PgPool| async move {
        sqlx::query_as::<_, (String, Uuid, Option<Uuid>)>(
            "SELECT visibility::text, owner_group_id, co_owner_group_id FROM edges WHERE id = $1",
        )
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge")
    };
    let before = tenancy(pool.clone()).await;
    assert_eq!(before.0, "public", "calibration: a public edge");
    let repair = mark(&pool, dup, canonical).await;
    assert_eq!(repair.retargeted_edges, vec![e]);
    assert_eq!(
        tenancy(pool.clone()).await.0,
        "group",
        "calibration: re-stamped private"
    );
    unmark(&pool, dup, &repair.revert).await;
    assert_eq!(
        tenancy(pool.clone()).await,
        before,
        "the edge's own tenancy is back"
    );
}

/// A BBA the repair deleted cites an evidence row that is deleted after the
/// mark. The un-mark cannot restore it (its foreign key is gone): it reports
/// the row drifted and restores everything else, rather than failing forever.
#[sqlx::test(migrations = "../../migrations")]
async fn a_restore_whose_evidence_is_gone_drifts_instead_of_failing(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "other").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "duplicate").await;
    let diamond = fixture::seed_public_claim(&pool, b, "diamond").await;
    let e_dup = edge(&pool, diamond, dup, "corroborates").await;
    edge(&pool, diamond, canonical, "corroborates").await;
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        None,
        &["TRUE".into(), "FALSE".into()],
    )
    .await
    .expect("frame")
    .id;
    let ev = fixture::seed_evidence(&pool, dup, "observation").await;
    let cited = MassFunctionRepository::store_with_perspective(
        &pool,
        dup,
        frame,
        Some(b),
        Some(e_dup),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("test"),
        None,
        None,
        "unknown",
        Some(ev),
    )
    .await
    .expect("bba citing evidence");
    let repair = mark(&pool, dup, canonical).await;
    assert_eq!(
        repair.revert.deleted_bbas.len(),
        1,
        "calibration: deleted with its edge"
    );
    sqlx::query("DELETE FROM evidence WHERE id = $1")
        .bind(ev)
        .execute(&pool)
        .await
        .expect("the evidence row goes");
    let reversal = unmark(&pool, dup, &repair.revert).await;
    assert_eq!(reversal.drifted, vec![cited], "reported, not fatal");
    assert_eq!(
        reversal.unretracted_edges,
        vec![e_dup],
        "the rest is restored"
    );
}

/// The recorded edge tenancy is put back only where the trigger cannot derive
/// it (both endpoints public): if an endpoint went private after the mark, the
/// edge keeps the meet of its endpoints NOW, never a recorded group that would
/// show it to a group that may not read the endpoint.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repointed_edge_keeps_the_current_meet_when_an_endpoint_narrowed(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer").await;
    let (x, h) = fixture::seed_agent_with_group(&pool, "other").await;
    let dup = fixture::seed_group_claim(&pool, w, g, "private duplicate").await;
    let canonical = fixture::seed_group_claim(&pool, w, g, "private canonical").await;
    let supporter = fixture::seed_public_claim(&pool, x, "public supporter").await;
    let e = edge(&pool, supporter, dup, "supports").await;
    let tenancy = |pool: PgPool| async move {
        sqlx::query_as::<_, (String, Uuid, Option<Uuid>)>(
            "SELECT visibility::text, owner_group_id, co_owner_group_id FROM edges WHERE id = $1",
        )
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge")
    };
    assert_eq!(
        tenancy(pool.clone()).await,
        ("group".into(), g, None),
        "calibration"
    );
    let repair = mark(&pool, dup, canonical).await;
    assert_eq!(repair.retargeted_edges, vec![e]);
    // The supporter goes private to another group after the mark.
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(supporter)
        .bind(h)
        .execute(&pool)
        .await
        .expect("the supporter narrows");
    unmark(&pool, dup, &repair.revert).await;
    assert_eq!(
        tenancy(pool.clone()).await,
        ("group".into(), h, Some(g)),
        "co-owned by both groups (the trigger's meet), not the recorded G-only edge"
    );
}

/// A claim retired with a PLAIN `same_as` edge (no `dedup` key) to the claim it
/// supersedes is not a dedup-marked duplicate, and an unknown id is not found.
#[sqlx::test(migrations = "../../migrations")]
async fn unmark_refuses_a_plain_same_as_and_an_unknown_claim(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let target = fixture::seed_public_claim(&pool, a, "target").await;
    let retired = fixture::seed_public_claim(&pool, a, "retired").await;
    sqlx::query(
        "UPDATE claims SET supersedes = $2, is_current = false, embedding = NULL WHERE id = $1",
    )
    .bind(retired)
    .bind(target)
    .execute(&pool)
    .await
    .expect("retire");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'same_as')",
    )
    .bind(retired)
    .bind(target)
    .execute(&pool)
    .await
    .expect("a plain same_as");
    let mut conn = pool.acquire().await.expect("acquire");
    let err = ClaimRepository::unmark_duplicate_act_conn(
        &mut conn,
        &bypass_viewer(&pool).await,
        ClaimId::from_uuid(retired),
    )
    .await
    .expect_err("not a dedup mark");
    assert!(
        format!("{err:?}").contains("no dedup identity edge"),
        "{err:?}"
    );
    let err = ClaimRepository::unmark_duplicate_act_conn(
        &mut conn,
        &bypass_viewer(&pool).await,
        ClaimId::from_uuid(Uuid::new_v4()),
    )
    .await
    .expect_err("unknown");
    assert!(
        matches!(err, epigraph_db::DbError::NotFound { .. }),
        "{err:?}"
    );
}

/// The reversal leaves alone, and reports, rows a later write changed: a frame
/// binding the canonical now needs for an input of its own, a pooled row a
/// later write moved elsewhere, and a re-pointed edge retracted since.
#[sqlx::test(migrations = "../../migrations")]
async fn unmark_reports_and_leaves_rows_a_later_write_changed(pool: PgPool) {
    let (a, ga) = fixture::seed_agent_with_group(&pool, "author").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "other").await;
    let (c, _) = fixture::seed_agent_with_group(&pool, "later writer").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let dup = public_claim_owned_by(&pool, a, ga, "duplicate").await;
    let elsewhere = fixture::seed_public_claim(&pool, c, "elsewhere").await;
    let supporter = fixture::seed_public_claim(&pool, b, "supporter").await;
    let e = edge(&pool, supporter, dup, "supports").await;
    let frame = FrameRepository::create(
        &pool,
        "binary_truth",
        None,
        &["TRUE".into(), "FALSE".into()],
    )
    .await
    .expect("frame")
    .id;
    FrameRepository::assign_claim(&pool, dup, frame, Some(0))
        .await
        .expect("bind dup");
    let m = serde_json::json!({"0": 0.6, "0,1": 0.4});
    let moved_later = bba(&pool, dup, frame, Some(a), None, m.clone()).await;
    let repair = mark(&pool, dup, canonical).await;
    assert_eq!(repair.revert.copied_frames, vec![frame], "calibration");
    assert_eq!(repair.retargeted_edges, vec![e], "calibration");

    // Later writes: an input of the canonical's own on that frame; the pooled
    // row moved to another claim; the re-pointed edge retracted.
    bba(&pool, canonical, frame, Some(c), None, m).await;
    sqlx::query("UPDATE mass_functions SET claim_id = $2 WHERE id = $1")
        .bind(moved_later)
        .bind(elsewhere)
        .execute(&pool)
        .await
        .expect("moved by a later write");
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(e)
        .execute(&pool)
        .await
        .expect("retracted later");

    let reversal = unmark(&pool, dup, &repair.revert).await;
    for id in [frame, moved_later, e] {
        assert!(
            reversal.drifted.contains(&id),
            "{id} reported drifted: {:?}",
            reversal.drifted
        );
    }
    let bound: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM claim_frames WHERE claim_id = $1 AND frame_id = $2)",
    )
    .bind(canonical)
    .bind(frame)
    .fetch_one(&pool)
    .await
    .expect("binding");
    assert!(bound, "the canonical keeps the binding its own input needs");
    let on: Uuid = sqlx::query_scalar("SELECT claim_id FROM mass_functions WHERE id = $1")
        .bind(moved_later)
        .fetch_one(&pool)
        .await
        .expect("row");
    assert_eq!(
        on, elsewhere,
        "the moved row stays where the later write put it"
    );
    let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(e)
        .fetch_one(&pool)
        .await
        .expect("edge");
    assert_eq!(target, canonical, "a retracted edge is not re-pointed");
}

/// The BP factors `edges_auto_factor` minted from `edge` (migration 038 keys
/// each one to its edge in `properties.source_edge_id`), as their sorted
/// variable pairs.
async fn factors_of_edge(pool: &PgPool, edge: Uuid) -> Vec<Vec<Uuid>> {
    sqlx::query_scalar(
        "SELECT variable_ids FROM factors WHERE properties->>'source_edge_id' = $1::text \
          ORDER BY id",
    )
    .bind(edge)
    .fetch_all(pool)
    .await
    .expect("factors")
}

fn sorted_pair(a: Uuid, b: Uuid) -> Vec<Uuid> {
    vec![a.min(b), a.max(b)]
}

/// A factor row as the BP engine reads it, every column but its id and
/// creation time: type, variables, potential, description, properties, frame.
type FactorRow = (
    String,
    Vec<Uuid>,
    serde_json::Value,
    Option<String>,
    serde_json::Value,
    Option<Uuid>,
);

/// Every factor keyed to `edge`, whole.
async fn factor_rows(pool: &PgPool, edge: Uuid) -> Vec<FactorRow> {
    sqlx::query_as(
        "SELECT factor_type, variable_ids, potential, description, properties, frame_id \
           FROM factors WHERE properties->>'source_edge_id' = $1::text ORDER BY id",
    )
    .bind(edge)
    .fetch_all(pool)
    .await
    .expect("factor rows")
}

/// The one factor keyed to `edge`'s `potential[key]`.
async fn strength_of(pool: &PgPool, edge: Uuid, key: &str) -> Option<f64> {
    let rows = factor_rows(pool, edge).await;
    assert_eq!(rows.len(), 1, "one factor keyed to edge {edge}");
    rows[0].2[key].as_f64()
}

/// An edge whose `properties` the insert trigger reads (the matcher override).
async fn edge_with_props(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    rel: &str,
    props: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'claim', $2, 'claim', $3, $4) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(rel)
    .bind(props)
    .fetch_one(pool)
    .await
    .expect("seed edge with properties")
}

/// Retiring the duplicate deletes every BP factor naming it
/// (`claims_deactivate_factors`); the un-mark makes it current again and puts
/// its edges back by UPDATE, which `edges_auto_factor` (INSERT only) never
/// sees. So the reversal re-mints them, and each re-minted row must be the
/// row the insert trigger minted, column for column, on every branch of the
/// trigger: a directional edge each way, a mutual exclusion, a constant
/// strength, the cross-source matcher's clamped score override (both clamps
/// and a numeric string, which the trigger's cast accepts), a `CORROBORATES`
/// edge not tagged by the matcher (constant strength despite its score), and
/// a redundant copy the mark retracted rather than moved. The canonical's own
/// copy keeps its one factor.
#[sqlx::test(migrations = "../../migrations")]
async fn unmark_restores_the_duplicates_bp_factors(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "duplicate").await;
    let mut other = Vec::new();
    for tag in [
        "supporter",
        "supported",
        "rival",
        "variant",
        "high matcher",
        "low matcher",
        "string matcher",
        "manual corroborator",
        "twin",
    ] {
        other.push(fixture::seed_public_claim(&pool, a, tag).await);
    }
    let matcher = |score: serde_json::Value| serde_json::json!({"source": "cross_source_matcher", "score": score});
    let e_in = edge(&pool, other[0], dup, "supports").await;
    let e_out = edge(&pool, dup, other[1], "supports").await;
    let e_con = edge(&pool, dup, other[2], "contradicts").await;
    let e_var = edge(&pool, other[3], dup, "variant_of").await;
    let e_hi = edge_with_props(
        &pool,
        other[4],
        dup,
        "CORROBORATES",
        matcher(serde_json::json!(1.7)),
    )
    .await;
    let e_lo = edge_with_props(
        &pool,
        dup,
        other[5],
        "CORROBORATES",
        matcher(serde_json::json!(-0.5)),
    )
    .await;
    let e_str = edge_with_props(
        &pool,
        other[6],
        dup,
        "CORROBORATES",
        matcher(serde_json::json!("0.4")),
    )
    .await;
    let e_manual = edge_with_props(
        &pool,
        other[7],
        dup,
        "CORROBORATES",
        serde_json::json!({"score": 0.1}),
    )
    .await;
    let e_twin_dup = edge(&pool, other[8], dup, "supports").await;
    let e_twin_can = edge(&pool, other[8], canonical, "supports").await;
    let dup_edges = [
        e_in, e_out, e_con, e_var, e_hi, e_lo, e_str, e_manual, e_twin_dup,
    ];

    // Calibration: the insert trigger minted one row per edge, on each branch.
    let mut before = Vec::new();
    for e in dup_edges.iter().chain([&e_twin_can]) {
        let rows = factor_rows(&pool, *e).await;
        assert_eq!(
            rows.len(),
            1,
            "calibration: the trigger minted edge {e}'s factor"
        );
        before.push(rows);
    }
    assert_eq!(before[0][0].0, "directional_support");
    assert_eq!(before[2][0].0, "mutual_exclusion");
    assert_eq!(before[2][0].2, serde_json::json!({}));
    assert_eq!(strength_of(&pool, e_var, "strength").await, Some(0.65));
    assert_eq!(strength_of(&pool, e_hi, "strength").await, Some(1.0));
    assert_eq!(strength_of(&pool, e_lo, "strength").await, Some(0.0));
    assert_eq!(strength_of(&pool, e_str, "strength").await, Some(0.4));
    assert_eq!(strength_of(&pool, e_manual, "strength").await, Some(0.85));

    let repair = mark(&pool, dup, canonical).await;
    for e in &dup_edges {
        assert!(
            factor_rows(&pool, *e).await.is_empty(),
            "calibration: retiring the duplicate deleted edge {e}'s factor"
        );
    }
    let twin_in_force: bool =
        sqlx::query_scalar("SELECT valid_to IS NULL FROM edges WHERE id = $1")
            .bind(e_twin_dup)
            .fetch_one(&pool)
            .await
            .expect("twin edge");
    assert!(
        !twin_in_force,
        "calibration: the mark retracted the duplicate's redundant copy"
    );

    unmark(&pool, dup, &repair.revert).await;
    for (e, rows) in dup_edges.iter().chain([&e_twin_can]).zip(&before) {
        assert_eq!(
            &factor_rows(&pool, *e).await,
            rows,
            "the un-mark re-mints edge {e}'s factor exactly as the insert trigger minted it"
        );
    }
    let on_canonical_pair: i64 =
        sqlx::query_scalar("SELECT count(*) FROM factors WHERE variable_ids = $1")
            .bind(sorted_pair(other[8], canonical))
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(
        on_canonical_pair, 1,
        "the canonical's own copy keeps one factor"
    );
}

/// A chain un-marked in reverse order: each edge follows the chain back, and
/// its factor follows the edge, on both sides of the duplicate. Un-marking c1
/// re-mints the incoming and the outgoing edge's factors on c1 (the edges are
/// on c1 then); un-marking d1 moves them on to d1, so those factors are stale
/// and go, and d1's are minted. No factor keyed to an edge is left naming a
/// claim the edge no longer touches.
#[sqlx::test(migrations = "../../migrations")]
async fn a_chain_unmark_leaves_no_factor_on_a_claim_the_edge_left(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let c2 = fixture::seed_public_claim(&pool, a, "newest canonical").await;
    let c1 = fixture::seed_public_claim(&pool, a, "first canonical").await;
    let d1 = fixture::seed_public_claim(&pool, a, "first duplicate").await;
    let supporter = fixture::seed_public_claim(&pool, a, "supporter").await;
    let supported = fixture::seed_public_claim(&pool, a, "supported").await;
    let e = edge(&pool, supporter, d1, "supports").await;
    let e_out = edge(&pool, d1, supported, "supports").await;

    let r1 = mark(&pool, d1, c1).await;
    let r2 = mark(&pool, c1, c2).await;
    unmark(&pool, c1, &r2.revert).await;
    assert_eq!(
        factors_of_edge(&pool, e).await,
        vec![sorted_pair(supporter, c1)],
        "with the edge back on c1, c1 is in the factor graph through it"
    );
    assert_eq!(
        factors_of_edge(&pool, e_out).await,
        vec![sorted_pair(c1, supported)],
        "and through the outgoing edge"
    );
    unmark(&pool, d1, &r1.revert).await;
    assert_eq!(
        factors_of_edge(&pool, e).await,
        vec![sorted_pair(supporter, d1)],
        "the edge is on d1 again: one factor, on d1, and none left on c1"
    );
    assert_eq!(
        factors_of_edge(&pool, e_out).await,
        vec![sorted_pair(d1, supported)],
        "the outgoing edge too: re-sourced back, its factor on d1 and none on c1"
    );
}

/// The stale factor the chain un-mark deletes frees its `(type, pair)` slot
/// on the canonical. A parallel edge of the same factor type the canonical
/// gained meanwhile could not mint there (the unique slot was taken, and the
/// trigger's insert did nothing); it owns the slot now.
#[sqlx::test(migrations = "../../migrations")]
async fn a_freed_slot_on_the_canonical_goes_to_its_parallel_edge(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let c2 = fixture::seed_public_claim(&pool, a, "newest canonical").await;
    let c1 = fixture::seed_public_claim(&pool, a, "first canonical").await;
    let d1 = fixture::seed_public_claim(&pool, a, "first duplicate").await;
    let supporter = fixture::seed_public_claim(&pool, a, "supporter").await;
    let e = edge(&pool, supporter, d1, "supports").await;

    let r1 = mark(&pool, d1, c1).await;
    let r2 = mark(&pool, c1, c2).await;
    unmark(&pool, c1, &r2.revert).await;
    let parallel = edge(&pool, supporter, c1, "provides_evidence").await;
    assert!(
        factors_of_edge(&pool, parallel).await.is_empty(),
        "calibration: the slot was held by the un-marked edge's factor"
    );
    unmark(&pool, d1, &r1.revert).await;
    assert_eq!(
        factors_of_edge(&pool, e).await,
        vec![sorted_pair(supporter, d1)]
    );
    assert_eq!(
        factors_of_edge(&pool, parallel).await,
        vec![sorted_pair(supporter, c1)],
        "the freed slot on the canonical is re-minted for its parallel edge"
    );
}

/// The un-mark rebuilds the duplicate's factors and the slots it frees on the
/// canonical, and nothing else: a canonical edge whose factor something else
/// removed (here a `decomposes_to` factor, as a sweep of those would) stays
/// without one.
#[sqlx::test(migrations = "../../migrations")]
async fn unmark_leaves_the_canonicals_other_factors_as_it_found_them(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let atom = fixture::seed_public_claim(&pool, a, "atom").await;
    let dup = fixture::seed_public_claim(&pool, a, "duplicate").await;
    let supporter = fixture::seed_public_claim(&pool, a, "supporter").await;
    let e_dec = edge(&pool, canonical, atom, "decomposes_to").await;
    sqlx::query("DELETE FROM factors WHERE properties->>'source_edge_id' = $1::text")
        .bind(e_dec)
        .execute(&pool)
        .await
        .expect("remove the decomposition's factor");
    let e_sup = edge(&pool, supporter, dup, "supports").await;

    let repair = mark(&pool, dup, canonical).await;
    unmark(&pool, dup, &repair.revert).await;
    assert_eq!(
        factors_of_edge(&pool, e_sup).await,
        vec![sorted_pair(supporter, dup)],
        "calibration: the un-mark re-minted the duplicate's factor"
    );
    assert!(
        factors_of_edge(&pool, e_dec).await.is_empty(),
        "the un-mark mints nothing for a canonical edge it did not move"
    );
}

/// A matcher edge whose score was later changed to something the trigger's
/// cast would reject (properties can be patched after the INSERT the trigger
/// saw) does not make the un-mark fail: the re-mint falls back to the
/// constant strength, as the trigger does for a missing score.
#[sqlx::test(migrations = "../../migrations")]
async fn a_malformed_matcher_score_does_not_block_the_unmark(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "duplicate").await;
    let source = fixture::seed_public_claim(&pool, a, "matched source").await;
    let e = edge_with_props(
        &pool,
        source,
        dup,
        "CORROBORATES",
        serde_json::json!({"source": "cross_source_matcher", "score": 0.9}),
    )
    .await;
    sqlx::query(
        "UPDATE edges SET properties = jsonb_set(properties, '{score}', '\"high\"') WHERE id = $1",
    )
    .bind(e)
    .execute(&pool)
    .await
    .expect("patch the score");

    let repair = mark(&pool, dup, canonical).await;
    unmark(&pool, dup, &repair.revert).await;
    assert_eq!(strength_of(&pool, e, "strength").await, Some(0.85));
}

/// A patched matcher score that is decimal-shaped but whose exponent
/// overflows `numeric` (e.g. "1e999999") must not abort the un-mark either:
/// the cast would raise "value overflows numeric format", so the shape guard
/// has to reject it and the re-mint falls back to the constant strength.
#[sqlx::test(migrations = "../../migrations")]
async fn an_overflowing_matcher_score_exponent_does_not_block_the_unmark(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "duplicate").await;
    let source = fixture::seed_public_claim(&pool, a, "matched source").await;
    let e = edge_with_props(
        &pool,
        source,
        dup,
        "CORROBORATES",
        serde_json::json!({"source": "cross_source_matcher", "score": 0.9}),
    )
    .await;
    sqlx::query(
        "UPDATE edges SET properties = jsonb_set(properties, '{score}', '\"1e999999\"') WHERE id = $1",
    )
    .bind(e)
    .execute(&pool)
    .await
    .expect("patch the score");

    let repair = mark(&pool, dup, canonical).await;
    unmark(&pool, dup, &repair.revert).await;
    assert_eq!(strength_of(&pool, e, "strength").await, Some(0.85));
}
