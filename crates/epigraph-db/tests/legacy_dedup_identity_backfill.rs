//! The identity-edge backfill for duplicates the legacy raw-SQL
//! `fuzzy_dedup_claims` marked (backlog d5781a48).
//!
//! Before 2026-10 `scripts/fuzzy_dedup_claims.py` retired a duplicate with its
//! own `UPDATE claims` (`supersedes = canonical`, `is_current = false`, both
//! embeddings NULL, the `deduped` label and `properties.deduped_into /
//! deduped_by / deduped_at`) and wrote no `same_as` identity edge. Every reader
//! of the dedup identity keys on that edge: the index view
//! (`marked_duplicates_of`) does not list such a duplicate under its canonical,
//! and the un-mark refuses it (naming the backfill that would make it
//! un-markable, operator ruling R-7).
//!
//! `ClaimRepository::backfill_legacy_dedup_identity_edges_conn` writes the
//! missing edge for exactly those rows: dry run unless `apply`, idempotent, and
//! nothing else is touched (a consolidation source, a dedup-act mark, a
//! soft-marked duplicate still current, a mark whose canonical moved on).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

const DEDUPED_AT: &str = "2026-09-14 08:15:02.123456+00";

/// Retire `dup` onto `canonical` exactly as the legacy script's step 7 did.
async fn legacy_mark(pool: &PgPool, dup: Uuid, canonical: Uuid, deduped_by: &str, current: bool) {
    sqlx::query(
        "UPDATE claims \
            SET supersedes = CASE WHEN $4 THEN NULL ELSE $1 END, \
                is_current = $4, \
                embedding = CASE WHEN $4 THEN embedding END, \
                embedding_3072 = CASE WHEN $4 THEN embedding_3072 END, \
                updated_at = NOW(), \
                labels = array_append(COALESCE(labels, ARRAY[]::text[]), 'deduped'), \
                properties = COALESCE(properties, '{}'::jsonb) \
                           || jsonb_build_object('deduped_into', $1::text, \
                                                 'deduped_by', $3::text, \
                                                 'deduped_at', $5::text) \
          WHERE id = $2",
    )
    .bind(canonical)
    .bind(dup)
    .bind(deduped_by)
    .bind(current)
    .bind(DEDUPED_AT)
    .execute(pool)
    .await
    .expect("legacy mark");
}

/// Every in-force `same_as` edge out of `dup`, with its properties.
async fn identity_edges(pool: &PgPool, dup: Uuid) -> Vec<(Uuid, Uuid, serde_json::Value)> {
    sqlx::query_as(
        "SELECT id, target_id, properties FROM edges \
          WHERE source_id = $1 AND relationship = 'same_as' AND valid_to IS NULL \
          ORDER BY created_at, id",
    )
    .bind(dup)
    .fetch_all(pool)
    .await
    .expect("identity edges")
}

async fn listed_under(pool: &PgPool, canonical: Uuid) -> Vec<Uuid> {
    let viewer = fixture::bypass(pool).await.1;
    ClaimRepository::marked_duplicates_of(pool, &viewer, &[canonical], 50)
        .await
        .expect("index view")
        .rows
        .into_iter()
        .map(|r| r.id)
        .collect()
}

async fn backfill(pool: &PgPool, apply: bool) -> epigraph_db::repos::claim::LegacyIdentityBackfill {
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::backfill_legacy_dedup_identity_edges_conn(&mut conn, apply)
        .await
        .expect("backfill")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_fuzzy_dedup_mark_gets_its_identity_edge_once(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "d5781a48").await;
    let canonical = fixture::seed_public_claim(&pool, a, "legacy canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "legacy duplicate").await;
    legacy_mark(&pool, dup, canonical, "fuzzy_dedup_claims", false).await;
    assert!(
        listed_under(&pool, canonical).await.is_empty(),
        "calibration: the index view cannot see a legacy mark"
    );

    // Dry run: found, nothing written.
    let dry = backfill(&pool, false).await;
    assert!(!dry.applied);
    assert_eq!(dry.inserted, 0);
    assert_eq!(
        dry.duplicates
            .iter()
            .map(|d| (d.duplicate, d.canonical, d.identity_edge))
            .collect::<Vec<_>>(),
        vec![(dup, canonical, None)]
    );
    assert!(
        identity_edges(&pool, dup).await.is_empty(),
        "a dry run writes nothing"
    );

    // Apply: one identity edge, attributed to the legacy mark.
    let applied = backfill(&pool, true).await;
    assert!(applied.applied);
    assert_eq!(applied.inserted, 1);
    let edges = identity_edges(&pool, dup).await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    let (id, target, props) = &edges[0];
    assert_eq!(*target, canonical);
    assert_eq!(applied.duplicates[0].identity_edge, Some(*id));
    let dedup = &props["dedup"];
    assert_eq!(dedup["tool"], "fuzzy_dedup_claims", "{props}");
    assert_eq!(dedup["run_tag"], "legacy_identity_backfill", "{props}");
    // The mark's own instant, not the backfill's, re-encoded as the dedup
    // act writes `marked_at` (`to_jsonb(now())`: ISO 8601), not the legacy
    // `now()::text` spelling it was stored in.
    let marked_at = dedup["marked_at"].as_str().expect("marked_at text");
    assert!(
        marked_at.contains('T') && marked_at != DEDUPED_AT,
        "marked_at is in the act's encoding, not the legacy text: {props}"
    );
    let same_instant: bool = sqlx::query_scalar("SELECT $1::timestamptz = $2::timestamptz")
        .bind(marked_at)
        .bind(DEDUPED_AT)
        .fetch_one(&pool)
        .await
        .expect("compare instants");
    assert!(same_instant, "the mark's own instant: {props}");
    assert!(
        dedup.get("marked_by").is_none(),
        "the legacy mark recorded no agent, and none is invented: {props}"
    );
    assert!(dedup["backfilled_at"].is_string(), "{props}");
    assert_eq!(
        listed_under(&pool, canonical).await,
        vec![dup],
        "the index view now lists the legacy duplicate under its canonical"
    );
    let factors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM factors WHERE $1 = ANY(variable_ids) AND $2 = ANY(variable_ids)",
    )
    .bind(dup)
    .bind(canonical)
    .fetch_one(&pool)
    .await
    .expect("factors");
    assert_eq!(factors, 0, "the identity edge never becomes a BP factor");

    // Idempotent: a second run finds nothing and writes nothing.
    let again = backfill(&pool, true).await;
    assert_eq!(again.inserted, 0);
    assert!(again.duplicates.is_empty(), "{again:?}");
    assert_eq!(identity_edges(&pool, dup).await.len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_backfill_leaves_every_other_retirement_alone(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "d5781a48-other").await;
    let claim = |tag: &'static str| {
        let pool = pool.clone();
        async move { fixture::seed_public_claim(&pool, a, tag).await }
    };
    let canonical = claim("canonical").await;

    // A consolidation source / plain supersession: retired, no dedup marker.
    let consolidated = claim("consolidated source").await;
    sqlx::query(
        "UPDATE claims SET supersedes = $1, is_current = false, embedding = NULL, \
                           embedding_3072 = NULL WHERE id = $2",
    )
    .bind(canonical)
    .bind(consolidated)
    .execute(&pool)
    .await
    .expect("retire a consolidation source");
    // A soft-marked duplicate the legacy script left CURRENT.
    let soft = claim("soft-marked, still current").await;
    legacy_mark(&pool, soft, canonical, "fuzzy_dedup_claims", true).await;
    // Another tool's marker.
    let other_tool = claim("another tool's mark").await;
    legacy_mark(&pool, other_tool, canonical, "some_other_script", false).await;
    // A legacy mark whose duplicate was later re-pointed elsewhere.
    let elsewhere = claim("re-pointed elsewhere").await;
    legacy_mark(&pool, elsewhere, canonical, "fuzzy_dedup_claims", false).await;
    let third = claim("a third claim").await;
    sqlx::query("UPDATE claims SET supersedes = $1 WHERE id = $2")
        .bind(third)
        .bind(elsewhere)
        .execute(&pool)
        .await
        .expect("re-point");
    // A dedup act's mark: it has its identity edge already.
    let acted = claim("dedup act duplicate").await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_with_repair_conn(
        &mut conn,
        epigraph_core::ClaimId::from_uuid(acted),
        epigraph_core::ClaimId::from_uuid(canonical),
    )
    .await
    .expect("dedup act");
    drop(conn);
    // And one the backfill is for, so the run is not vacuous.
    let legacy = claim("legacy duplicate").await;
    legacy_mark(&pool, legacy, canonical, "fuzzy_dedup_claims", false).await;

    let report = backfill(&pool, true).await;
    assert_eq!(
        report
            .duplicates
            .iter()
            .map(|d| d.duplicate)
            .collect::<Vec<_>>(),
        vec![legacy],
        "only the legacy fuzzy_dedup_claims mark is selected"
    );
    assert_eq!(report.inserted, 1);
    for untouched in [consolidated, soft, other_tool, elsewhere] {
        assert!(
            identity_edges(&pool, untouched).await.is_empty(),
            "no identity edge for {untouched}"
        );
    }
    assert_eq!(
        identity_edges(&pool, acted).await.len(),
        1,
        "the dedup act's own identity edge is the only one it has"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_backfill_refuses_a_non_privileged_session(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "d5781a48-app").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "duplicate").await;
    legacy_mark(&pool, dup, canonical, "fuzzy_dedup_claims", false).await;
    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let mut conn = app.acquire().await.expect("acquire");
    for apply in [false, true] {
        let err = ClaimRepository::backfill_legacy_dedup_identity_edges_conn(&mut conn, apply)
            .await
            .expect_err("an application session would see a fraction of the corpus");
        assert!(err.to_string().contains("privileged"), "{err}");
    }
    assert!(identity_edges(&pool, dup).await.is_empty());
}

/// A legacy `deduped_at` that is not a timestamp does not abort the run (one
/// transaction for the whole corpus): the edge is written without a
/// `marked_at`, and the stray text is not copied into the act's field.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stray_legacy_deduped_at_is_left_out_not_fatal(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "d5781a48-stray").await;
    let canonical = fixture::seed_public_claim(&pool, a, "canonical").await;
    let dup = fixture::seed_public_claim(&pool, a, "duplicate").await;
    let good = fixture::seed_public_claim(&pool, a, "well-formed duplicate").await;
    legacy_mark(&pool, dup, canonical, "fuzzy_dedup_claims", false).await;
    legacy_mark(&pool, good, canonical, "fuzzy_dedup_claims", false).await;
    sqlx::query(
        "UPDATE claims SET properties = properties || '{\"deduped_at\": \"yesterday-ish\"}' \
          WHERE id = $1",
    )
    .bind(dup)
    .execute(&pool)
    .await
    .expect("stray deduped_at");

    let report = backfill(&pool, true).await;
    assert_eq!(report.inserted, 2, "{report:?}");
    let stray = identity_edges(&pool, dup).await;
    assert_eq!(stray.len(), 1, "{stray:?}");
    let dedup = &stray[0].2["dedup"];
    assert!(dedup.get("marked_at").is_none(), "{dedup}");
    assert_eq!(dedup["tool"], "fuzzy_dedup_claims", "{dedup}");
    let well_formed = identity_edges(&pool, good).await;
    assert!(
        well_formed[0].2["dedup"]["marked_at"].is_string(),
        "calibration: a well-formed deduped_at is carried in the same run: {well_formed:?}"
    );
}

/// The function runs on the `epigraph_maintenance` login itself (not only a
/// superuser): its `SELECT ... FOR UPDATE OF c` on claims and its INSERT on
/// edges are within that role's grants and row security, over a GROUP-private
/// mark in a group the session has no part in.
#[sqlx::test(migrations = "../../migrations")]
async fn the_backfill_runs_on_the_maintenance_login(pool: PgPool) {
    let (a, group) = fixture::seed_agent_with_group(&pool, "d5781a48-maint").await;
    let canonical = fixture::seed_group_claim(&pool, a, group, "private canonical").await;
    let dup = fixture::seed_group_claim(&pool, a, group, "private duplicate").await;
    legacy_mark(&pool, dup, canonical, "fuzzy_dedup_claims", false).await;
    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let mut conn = maint.acquire().await.expect("acquire");
    let dry = ClaimRepository::backfill_legacy_dedup_identity_edges_conn(&mut conn, false)
        .await
        .expect("dry run as epigraph_maintenance");
    assert_eq!(
        dry.duplicates
            .iter()
            .map(|d| d.duplicate)
            .collect::<Vec<_>>(),
        vec![dup],
        "the group-private mark is selected on the maintenance login"
    );
    let applied = ClaimRepository::backfill_legacy_dedup_identity_edges_conn(&mut conn, true)
        .await
        .expect("apply as epigraph_maintenance");
    assert_eq!(applied.inserted, 1, "{applied:?}");
    drop(conn);
    let edges = identity_edges(&pool, dup).await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert_eq!(edges[0].1, canonical);
}

/// The un-mark's refusal of a legacy mark WITHOUT an identity edge says which
/// of the two it is (operator ruling R-7): one the backfill can still
/// reconstruct (an operator runs it, then the mark is an ordinary dedup
/// record), and one it cannot (and why). A mark the backfill reconstructed is
/// un-marked: `epigraph-engine/tests/unmark_duplicate_cascade.rs`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreconstructed_legacy_mark_is_refused_with_its_reason(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "r7-refusal").await;
    let canonical = fixture::seed_public_claim(&pool, a, "r7 legacy canonical").await;
    let pending = fixture::seed_public_claim(&pool, a, "r7 not yet backfilled").await;
    legacy_mark(&pool, pending, canonical, "fuzzy_dedup_claims", false).await;
    let repointed = fixture::seed_public_claim(&pool, a, "r7 re-pointed since").await;
    legacy_mark(&pool, repointed, canonical, "fuzzy_dedup_claims", false).await;
    let elsewhere = fixture::seed_public_claim(&pool, a, "r7 the claim it now supersedes").await;
    sqlx::query("UPDATE claims SET supersedes = $1 WHERE id = $2")
        .bind(elsewhere)
        .bind(repointed)
        .execute(&pool)
        .await
        .expect("re-point the duplicate");
    let unlabelled = fixture::seed_public_claim(&pool, a, "r7 label removed since").await;
    legacy_mark(&pool, unlabelled, canonical, "fuzzy_dedup_claims", false).await;
    sqlx::query("UPDATE claims SET labels = array_remove(labels, 'deduped') WHERE id = $1")
        .bind(unlabelled)
        .execute(&pool)
        .await
        .expect("drop the label");

    let viewer = fixture::bypass(&pool).await.1;
    let refusal = |dup: Uuid| {
        let pool = pool.clone();
        let viewer = &viewer;
        async move {
            let mut conn = pool.acquire().await.expect("acquire");
            let e = ClaimRepository::unmark_duplicate_act_conn(
                &mut conn,
                viewer,
                epigraph_core::ClaimId::from_uuid(dup),
            )
            .await
            .expect_err("no identity edge: refused");
            e.to_string()
        }
    };

    let e = refusal(pending).await;
    assert!(
        e.contains("legacy fuzzy_dedup_claims mark")
            && e.contains("backfill_dedup_identity_edges --apply")
            && e.contains("not been reconstructed"),
        "a reconstructable legacy mark names the backfill that makes it un-markable: {e}"
    );
    let e = refusal(repointed).await;
    assert!(
        e.contains("legacy fuzzy_dedup_claims mark")
            && e.contains("cannot reconstruct")
            && e.contains(&format!("supersedes {elsewhere}"))
            && e.contains(&format!("deduped_into {canonical}")),
        "a re-pointed legacy mark says why the backfill cannot reconstruct it: {e}"
    );
    let e = refusal(unlabelled).await;
    assert!(
        e.contains("cannot reconstruct") && e.contains("`deduped` label"),
        "an unlabelled legacy mark says why the backfill cannot reconstruct it: {e}"
    );

    // CALIBRATION: the classification is the backfill's own selection.
    let selected: Vec<Uuid> = backfill(&pool, false)
        .await
        .duplicates
        .iter()
        .map(|d| d.duplicate)
        .collect();
    assert_eq!(selected, vec![pending]);
    for dup in [pending, repointed, unlabelled] {
        let still: (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("read");
        assert!(!still.0, "a refused un-mark changes nothing");
    }
}

/// A legacy mark without its identity edge whose canonical is ITSELF retired
/// (here with no replacement) is refused with the legacy reason, not with the
/// canonical chain's: the missing edge is what blocks the un-mark first, and
/// the chain's remedy ("no current canonical to restore it against") would
/// send an operator after the wrong fix (operator ruling R-7's clear, specific
/// message).
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_mark_over_a_retired_canonical_is_refused_with_the_legacy_reason(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "r7-order").await;
    let canonical = fixture::seed_public_claim(&pool, a, "r7 canonical retired since").await;
    let dup = fixture::seed_public_claim(&pool, a, "r7 legacy mark over it").await;
    legacy_mark(&pool, dup, canonical, "fuzzy_dedup_claims", false).await;
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
          WHERE id = $1",
    )
    .bind(canonical)
    .execute(&pool)
    .await
    .expect("retire the canonical with no replacement");

    let viewer = fixture::bypass(&pool).await.1;
    let mut conn = pool.acquire().await.expect("acquire");
    let e = ClaimRepository::unmark_duplicate_act_conn(
        &mut conn,
        &viewer,
        epigraph_core::ClaimId::from_uuid(dup),
    )
    .await
    .expect_err("no identity edge: refused")
    .to_string();
    assert!(
        e.contains("legacy fuzzy_dedup_claims mark")
            && e.contains("backfill_dedup_identity_edges --apply")
            && !e.contains("no replacement"),
        "the missing identity edge is reported first, with the legacy remedy: {e}"
    );
    // The request paths resolve the same verdict, in the same order, before
    // they check the caller's authority over the chain.
    let verdict = ClaimRepository::unmark_chain_conn(&mut conn, &viewer, dup, canonical)
        .await
        .expect("read");
    let why = verdict.expect_err("refused");
    assert!(
        why.contains("legacy fuzzy_dedup_claims mark") && !why.contains("no replacement"),
        "{why}"
    );
    let still: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(dup)
        .fetch_one(&pool)
        .await
        .expect("read");
    assert!(!still, "a refused un-mark changes nothing");
}
