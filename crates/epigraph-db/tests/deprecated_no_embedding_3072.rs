//! `chk_deprecated_no_embedding` must cover BOTH ANN columns.
//!
//! Migration 052 added `CHECK (is_current OR embedding IS NULL)` and said of
//! the sibling column that `embedding_3072` "is always NULL in practice". That
//! premise stopped holding once `epigraph-cli reembed` started populating the
//! 3072-d column for ordinary claims, and recall at `centroid_dim = 3072`
//! (`ClaimRepository::search_by_embedding_since`) has no `is_current` filter —
//! so a retired claim still carrying a 3072 vector stays retrievable, and the
//! database said nothing. Migration 144 backfills the leftovers and widens the
//! guard under the SAME constraint name.
//!
//! The assertions are on the SQLSTATE and the constraint NAME the database
//! reports, never on an error string, and each refusal is paired with the
//! admitted shape so a CHECK that refused everything would also fail.

use sqlx::PgPool;
use uuid::Uuid;

fn stub_vector(dim: usize) -> String {
    let mut v = vec!["0.0"; dim];
    v[0] = "0.1";
    format!("[{}]", v.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'chk-deprecated-3072', 'system', \
                 ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A CURRENT claim whose 1536 column is NULL and whose 3072 column holds a
/// vector — the shape `reembed` produced on rows the 1536 column never had,
/// and the only shape 052's single-column CHECK cannot see.
async fn seed_current_3072_only(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             embedding, embedding_3072) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, NULL, $3::vector) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(stub_vector(3072))
    .fetch_one(pool)
    .await
    .expect("seed current claim carrying only a 3072 vector")
}

#[sqlx::test(migrations = "../../migrations")]
async fn retiring_a_row_that_still_holds_a_3072_vector_is_refused(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let id = seed_current_3072_only(&pool, agent, "chk-3072 retire me").await;

    let err = sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect_err(
            "chk_deprecated_no_embedding must refuse a retirement that keeps embedding_3072",
        );
    let db = err
        .as_database_error()
        .expect("a database error, not a driver one");
    assert_eq!(db.code().as_deref(), Some("23514"), "check_violation");
    assert_eq!(db.constraint(), Some("chk_deprecated_no_embedding"));

    // The refused statement changed nothing.
    let still_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("re-read");
    assert!(still_current, "a refused retirement leaves the row current");

    // Calibration: the same retirement that nulls embedding_3072 in the SAME
    // statement is admitted — the CHECK is per statement, which is why every
    // retirement path nulls both columns in the UPDATE that flips is_current.
    sqlx::query("UPDATE claims SET is_current = false, embedding_3072 = NULL WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("a retirement that nulls both columns is admitted");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_guard_names_embedding_3072_and_head_has_no_violators(pool: PgPool) {
    // Schema shape, read back from the catalog: on a fresh database the
    // violator count below is trivially 0, so it cannot be the only assertion.
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
          WHERE conrelid = 'public.claims'::regclass \
            AND conname = 'chk_deprecated_no_embedding'",
    )
    .fetch_one(&pool)
    .await
    .expect("chk_deprecated_no_embedding exists on claims under its original name");
    assert!(
        def.contains("embedding_3072 IS NULL"),
        "chk_deprecated_no_embedding must constrain embedding_3072, got: {def}"
    );
    assert!(
        def.contains("embedding IS NULL"),
        "chk_deprecated_no_embedding must still constrain embedding, got: {def}"
    );

    let violators: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE NOT is_current AND embedding_3072 IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("count violators");
    assert_eq!(violators, 0);
}

/// Migration 144's own text, executed against the state it exists to repair.
const MIGRATION_144: &str =
    include_str!("../../../migrations/144_null_retired_claim_embedding_3072.sql");

/// The backfill, exercised for real. `#[sqlx::test]` has already applied 144
/// to an empty database, where the backfill trivially touches nothing. So this
/// test puts 052's single-column guard back, seeds the pre-144 damage (a
/// RETIRED claim carrying a 3072 vector, which 052 admits) beside a CURRENT
/// claim carrying one, replays the file's own text, and reads the rows back.
#[sqlx::test(migrations = "../../migrations")]
async fn replaying_144_over_pre_144_state_clears_retired_vectors_only(pool: PgPool) {
    sqlx::raw_sql(
        "ALTER TABLE claims DROP CONSTRAINT chk_deprecated_no_embedding; \
         ALTER TABLE claims ADD CONSTRAINT chk_deprecated_no_embedding \
             CHECK (is_current OR embedding IS NULL);",
    )
    .execute(&pool)
    .await
    .expect("restore 052's single-column guard");

    let agent = seed_agent(&pool).await;
    let live = seed_current_3072_only(&pool, agent, "chk-3072 replay live").await;
    let leaked = seed_current_3072_only(&pool, agent, "chk-3072 replay leaked").await;
    // How the leak arose: a retirement that nulled only `embedding` (pre-#490),
    // or a reembed run after the retirement. 052 admits it.
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(leaked)
        .execute(&pool)
        .await
        .expect("052 admits a retired row that still holds a 3072 vector");

    sqlx::raw_sql(MIGRATION_144)
        .execute(&pool)
        .await
        .expect("144 applies over a database holding a retired 3072 vector");

    let vec_of = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT embedding_3072 IS NOT NULL FROM claims WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read embedding_3072")
        }
    };
    assert!(
        !vec_of(leaked).await,
        "the backfill must null the retired claim's 3072 vector"
    );
    assert!(
        vec_of(live).await,
        "the backfill must leave a CURRENT claim's 3072 vector alone"
    );

    let def: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
          WHERE conrelid = 'public.claims'::regclass \
            AND conname = 'chk_deprecated_no_embedding'",
    )
    .fetch_one(&pool)
    .await
    .expect("constraint re-created under its original name");
    assert!(
        def.contains("embedding_3072 IS NULL"),
        "the replay must leave the widened guard in place, got: {def}"
    );
}
