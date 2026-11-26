//! Migration 351 (backlog cc71759f): the bare-DOI miss path of the `papers`
//! document-key lookup is an index probe under `papers`' row security.
//!
//! `document_key_rows_in_sql` looks a key up by its exact spellings, and only
//! when none matches (a new paper's first ingest) by a case-variant arm that
//! folds both sides. `papers` is FORCE RLS (246), so for the application role
//! the lookup runs under its policy, and a qual that is not LEAKPROOF can be
//! no index condition there. `pg_catalog.lower` is not leakproof, so 351
//! indexes a LEAKPROOF wrapper of it, and the arm folds with that wrapper.
//!
//! The plans are read under `SET ROLE epigraph_app` with `enable_seqscan`
//! off: on the superuser pool row security never applies, so a plan read
//! there would pass whatever the index could do for the application.

use epigraph_db::repos::paper::{
    document_key_first_in_sql, document_key_spellings, DOCUMENT_KEY_FOLD,
};
use sqlx::PgPool;
use uuid::Uuid;

/// The scope `PaperRepository::get_or_create` passes
/// (`repos::paper::in_scope_predicate(2, 3)`), bound here to the public scope.
const SCOPE: &str = "visibility = $2::text AND ($2::text = 'public' OR owner_group_id = $3::uuid)";

/// `EXPLAIN (COSTS OFF)` of the get_or_create lookup for a bare DOI no row
/// holds, on `conn` as it is (role and settings).
async fn explain_miss(conn: &mut sqlx::PgConnection, sql: &str) -> String {
    let spellings = document_key_spellings(&format!("10.5555/fold.miss.{}", Uuid::new_v4()));
    assert!(spellings.len() > 1, "a bare DOI takes the case-variant arm");
    sqlx::query_scalar::<_, String>(&format!("EXPLAIN (COSTS OFF) {sql}"))
        .bind(&spellings)
        .bind("public")
        .bind(Uuid::nil())
        .fetch_all(conn)
        .await
        .unwrap_or_else(|e| panic!("EXPLAIN {sql}: {e}"))
        .join("\n")
}

/// A plan line `Index Cond: ...` that compares `needle`.
fn index_cond_on(plan: &str, needle: &str) -> bool {
    plan.lines()
        .any(|l| l.contains("Index Cond:") && l.contains(needle))
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_bare_doi_miss_path_is_an_index_probe_under_row_security(pool: PgPool) {
    let mut conn = pool.acquire().await.expect("acquire");
    for stmt in ["SET ROLE epigraph_app", "SET enable_seqscan = off"] {
        sqlx::query(stmt)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }
    let plan = explain_miss(&mut conn, &document_key_first_in_sql("id", 1, SCOPE)).await;
    assert!(
        plan.contains("papers_doi_fold_idx")
            && index_cond_on(&plan, "epigraph_document_key_fold(doi)"),
        "under papers' row security the case-variant arm must probe 351's index with \
         the folded key as an index condition. Plan:\n{plan}"
    );
}

/// CALIBRATION, and the record of why 351 indexes a wrapper: with a plain
/// `lower(doi)` index and the arm folding with `lower`, the comparison is no
/// index condition under the application role's row security. Built in a
/// transaction that is rolled back.
#[sqlx::test(migrations = "../../migrations")]
async fn a_plain_lower_doi_index_is_no_index_condition_under_row_security(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    for stmt in [
        "CREATE INDEX papers_lower_doi_calibration ON public.papers (lower(doi))",
        "SET LOCAL ROLE epigraph_app",
        "SET LOCAL enable_seqscan = off",
    ] {
        sqlx::query(stmt)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }
    let plain = document_key_first_in_sql("id", 1, SCOPE).replace(DOCUMENT_KEY_FOLD, "lower");
    assert!(!plain.contains("epigraph_document_key_fold"), "{plain}");
    let plan = explain_miss(&mut tx, &plain).await;
    assert!(
        plan.contains("lower(")
            && !index_cond_on(&plan, "lower(doi)")
            && !index_cond_on(&plan, "lower(papers"),
        "CALIBRATION: a non-leakproof `lower` is no index condition under row security. \
         Plan:\n{plan}"
    );
    tx.rollback().await.expect("rollback");
}

/// 351's fold is `lower`, LEAKPROOF (what lets its index serve the arm under
/// row security), IMMUTABLE (what lets it be indexed) and pins its
/// `search_path` (what keeps it from being inlined back to the bare `lower`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_document_key_fold_is_a_leakproof_non_inlined_lower(pool: PgPool) {
    let (leakproof, volatility, config): (bool, String, Option<Vec<String>>) = sqlx::query_as(
        "SELECT proleakproof, provolatile::text, proconfig FROM pg_proc \
          WHERE oid = to_regprocedure('public.epigraph_document_key_fold(text)')",
    )
    .fetch_one(&pool)
    .await
    .expect("351's fold");
    assert!(leakproof, "351's fold is LEAKPROOF");
    assert_eq!(volatility, "i", "351's fold is IMMUTABLE");
    assert_eq!(
        config.as_deref(),
        Some(&["search_path=pg_catalog, pg_temp".to_string()][..]),
        "351's fold pins its search_path"
    );
    let folded: Option<String> = sqlx::query_scalar(&format!("SELECT {DOCUMENT_KEY_FOLD}($1)"))
        .bind("HTTPS://DOI.ORG/10.5555/Ab.C")
        .fetch_one(&pool)
        .await
        .expect("fold");
    assert_eq!(folded.as_deref(), Some("https://doi.org/10.5555/ab.c"));
    let null: Option<String> = sqlx::query_scalar(&format!("SELECT {DOCUMENT_KEY_FOLD}(NULL)"))
        .fetch_one(&pool)
        .await
        .expect("fold NULL");
    assert_eq!(null, None);
}
