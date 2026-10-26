//! Edge writers store ONE spelling of a case-folded relationship (backlog
//! `3ce5e00c`, U014 PR-2).
//!
//! `edges.relationship` held `supports` / `contradicts` / `corroborates` /
//! `refutes` in two spellings: MCP `link_epistemic` wrote lower case, while the
//! HTTP edge route, the DS evidence writers and the cross-source matcher wrote
//! `SUPPORTS` / `CONTRADICTS` / `CORROBORATES`. The canonical spelling is lower
//! case (`epigraph_core::edge::relationships::canonical_relationship`).
//!
//! The tests below pin the three halves of that at the repository and schema:
//!
//! * every `EdgeRepository` insert stores the canonical spelling, whatever case
//!   the caller passed, and leaves a relationship outside the folded list alone;
//! * every dedup probe still finds a LEGACY upper-case row (seeded by raw SQL,
//!   as rows written before this change are), so re-asserting an old link in
//!   the new spelling is a dedup hit rather than a second row;
//! * migration 175: a lower-case `corroborates` / `refutes` claim/claim edge
//!   gets the same belief factor its upper-case spelling always got, and the
//!   matcher's symmetric unique index covers both spellings of one pair.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::EdgeRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// Insert one claim/claim edge by raw SQL with an exact spelling: the shape of
/// a row written before the canonical spelling existed.
async fn legacy_edge(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    relationship: &str,
    properties: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'claim', $2, 'claim', $3, $4) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .bind(properties)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed legacy {relationship} edge: {e}"))
}

async fn stored_relationship(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT relationship FROM edges WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Every row (any state, any spelling) over the unordered pair `{a, b}` whose
/// relationship folds to `lower`.
async fn pair_rows(pool: &PgPool, a: Uuid, b: Uuid, lower: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges \
          WHERE LEAST(source_id, target_id) = LEAST($1, $2) \
            AND GREATEST(source_id, target_id) = GREATEST($1, $2) \
            AND lower(relationship) = $3",
    )
    .bind(a)
    .bind(b)
    .bind(lower)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn claims(pool: &PgPool, label: &str, n: usize) -> Vec<Uuid> {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut out = Vec::new();
    for i in 0..n {
        out.push(fixture::seed_public_claim(pool, agent, &format!("{label} claim {i}")).await);
    }
    out
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_stores_the_canonical_spelling(pool: PgPool) {
    let c = claims(&pool, "canon-create", 4).await;

    let upper = EdgeRepository::create(
        &pool, c[0], "claim", c[1], "claim", "SUPPORTS", None, None, None,
    )
    .await
    .unwrap();
    let mixed = EdgeRepository::create(
        &pool,
        c[1],
        "claim",
        c[2],
        "claim",
        "Contradicts",
        None,
        None,
        None,
    )
    .await
    .unwrap();
    // A distinct relationship that differs from a lower-case one only by case
    // is NOT folded: `REFINES` (synthesis -> synthesis) is not `refines`.
    let refines = EdgeRepository::create(
        &pool, c[2], "claim", c[3], "claim", "REFINES", None, None, None,
    )
    .await
    .unwrap();

    assert_eq!(stored_relationship(&pool, upper).await, "supports");
    assert_eq!(stored_relationship(&pool, mixed).await, "contradicts");
    assert_eq!(stored_relationship(&pool, refines).await, "REFINES");
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_if_not_exists_finds_a_legacy_upper_case_row(pool: PgPool) {
    let c = claims(&pool, "canon-ifne", 2).await;
    let legacy = legacy_edge(&pool, c[0], c[1], "SUPPORTS", serde_json::json!({})).await;

    for asked in ["supports", "SUPPORTS"] {
        let (row, created) = EdgeRepository::create_if_not_exists(
            &pool, c[0], "claim", c[1], "claim", asked, None, None, None,
        )
        .await
        .unwrap();
        assert!(
            !created,
            "re-asserting the legacy SUPPORTS link as `{asked}` must be a dedup hit"
        );
        assert_eq!(row.id, legacy, "`{asked}` must return the legacy row");
    }
    assert_eq!(pair_rows(&pool, c[0], c[1], "supports").await, 1);

    // Control: a fresh pair inserts, in the canonical spelling.
    let c2 = claims(&pool, "canon-ifne-fresh", 2).await;
    let (row, created) = EdgeRepository::create_if_not_exists(
        &pool, c2[0], "claim", c2[1], "claim", "SUPPORTS", None, None, None,
    )
    .await
    .unwrap();
    assert!(created);
    assert_eq!(
        row.relationship, "supports",
        "the returned row is as stored"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn symmetric_link_writers_dedup_against_a_legacy_upper_case_reverse_row(pool: PgPool) {
    let c = claims(&pool, "canon-sym", 2).await;
    let (a, b) = (c[0], c[1]);
    // A legacy `B CONTRADICTS A`, written by the old HTTP route.
    let legacy = legacy_edge(&pool, b, a, "CONTRADICTS", serde_json::json!({})).await;

    let mut conn = pool.acquire().await.unwrap();
    // The HTTP route's form.
    let (row, created) = EdgeRepository::create_symmetric_if_absent_row_conn(
        &mut conn,
        a,
        b,
        "contradicts",
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(
        !created,
        "`A contradicts B` over legacy `B CONTRADICTS A` is one fact"
    );
    assert_eq!(row.id, legacy);
    // `link_epistemic`'s form.
    let up = EdgeRepository::create_symmetric_if_absent_oriented_conn(
        &mut conn,
        a,
        b,
        "contradicts",
        serde_json::json!({}),
    )
    .await
    .unwrap();
    assert!(!up.was_created);
    assert_eq!(up.edge_id, legacy);
    assert_eq!((up.source_id, up.target_id), (b, a), "stored orientation");
    drop(conn);

    assert_eq!(pair_rows(&pool, a, b, "contradicts").await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn matcher_symmetric_write_dedups_across_spellings_and_stores_lower_case(pool: PgPool) {
    let c = claims(&pool, "canon-matcher", 4).await;
    let marker = serde_json::json!({"source": "cross_source_matcher", "score": 0.9});
    legacy_edge(&pool, c[0], c[1], "CORROBORATES", marker.clone()).await;

    let created = EdgeRepository::create_symmetric_if_absent(
        &pool,
        c[1],
        c[0],
        "corroborates",
        marker.clone(),
    )
    .await
    .unwrap();
    assert!(
        !created,
        "a matcher `corroborates` over a pair holding the legacy `CORROBORATES` is a dedup hit"
    );
    assert_eq!(pair_rows(&pool, c[0], c[1], "corroborates").await, 1);

    // Control: a fresh pair inserts, stored lower case even when asked upper.
    let created =
        EdgeRepository::create_symmetric_if_absent(&pool, c[2], c[3], "CORROBORATES", marker)
            .await
            .unwrap();
    assert!(created);
    let rel: String = sqlx::query_scalar(
        "SELECT relationship FROM edges WHERE source_id = $1 AND target_id = $2",
    )
    .bind(c[2])
    .bind(c[3])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rel, "corroborates");
}

/// The factor `edges_auto_factor` materialised for edge `id`, if any.
async fn factor_type_for(pool: &PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT factor_type::text FROM factors WHERE properties->>'source_edge_id' = $1::text",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn lower_case_corroborates_and_refutes_get_the_upper_case_factor(pool: PgPool) {
    let c = claims(&pool, "canon-factor", 8).await;
    let pairs = [
        ("CORROBORATES", "evidential_support"),
        ("corroborates", "evidential_support"),
        ("REFUTES", "mutual_exclusion"),
        ("refutes", "mutual_exclusion"),
    ];
    for (i, (rel, want)) in pairs.iter().enumerate() {
        let id = legacy_edge(&pool, c[2 * i], c[2 * i + 1], rel, serde_json::json!({})).await;
        assert_eq!(
            factor_type_for(&pool, id).await.as_deref(),
            Some(*want),
            "a claim/claim `{rel}` edge must get a {want} factor"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn matcher_unique_index_covers_both_spellings_of_one_pair(pool: PgPool) {
    let c = claims(&pool, "canon-index", 2).await;
    let marker = serde_json::json!({"source": "cross_source_matcher"});
    legacy_edge(&pool, c[0], c[1], "CORROBORATES", marker.clone()).await;

    let second = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'claim', $2, 'claim', 'corroborates', $3)",
    )
    .bind(c[1])
    .bind(c[0])
    .bind(marker)
    .execute(&pool)
    .await;
    let code = second
        .as_ref()
        .err()
        .and_then(|e| e.as_database_error())
        .and_then(|d| d.code().map(|c| c.into_owned()));
    assert_eq!(
        code.as_deref(),
        Some("23505"),
        "a second in-force matcher corroboration of one pair, in the other spelling, must \
         violate edges_symmetric_relationship_uniq; got {second:?}"
    );
}

/// `EdgeRepository::list_filtered` (behind `GET /api/v1/edges?relationship=`)
/// returns a legacy upper-case row and a canonical lower-case row for one
/// relationship filter, whichever spelling the filter names. Before, the filter
/// was byte-exact, so the canonical spelling hid every legacy row and vice versa.
#[sqlx::test(migrations = "../../migrations")]
async fn list_filtered_matches_every_spelling_of_a_folded_relationship(pool: PgPool) {
    let c = claims(&pool, "canon-list", 3).await;
    let legacy = legacy_edge(&pool, c[0], c[1], "SUPPORTS", serde_json::json!({})).await;
    let canonical = legacy_edge(&pool, c[1], c[2], "supports", serde_json::json!({})).await;
    // Control: a different relationship over the same claims stays out.
    legacy_edge(&pool, c[0], c[2], "elaborates", serde_json::json!({})).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;

    for asked in ["supports", "SUPPORTS"] {
        let mut got: Vec<Uuid> = EdgeRepository::list_filtered(
            &pool,
            &viewer,
            None,
            None,
            Some(asked),
            Some("claim"),
            Some("claim"),
            100,
        )
        .await
        .unwrap()
        .into_iter()
        .filter(|r| c.contains(&r.source_id))
        .map(|r| r.id)
        .collect();
        got.sort();
        let mut want = vec![legacy, canonical];
        want.sort();
        assert_eq!(got, want, "relationship={asked} must return both spellings");
    }
}
