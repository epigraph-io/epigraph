//! Migration 154 seeds the canonical `claim_validity` frame (U027F).
//!
//! `POST /api/v1/claims/:id/assess` resolves its default frame by the fixed id
//! of prod's row, `8a594393-c343-4f1a-b942-5c5b7862f792` (public, owned by the
//! nil world group, hypotheses `[supported, refuted, uncertain]`), and never
//! creates it at request time. So a fresh install must carry that row.

mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;

/// Prod's canonical `claim_validity` frame id, as a literal.
const CANONICAL: Uuid = Uuid::from_u128(0x8a59_4393_c343_4f1a_b942_5c5b_7862_f792);

type FrameShape = (String, Vec<String>, Option<String>, Option<Uuid>);

async fn canonical_row(pool: &PgPool) -> Option<FrameShape> {
    sqlx::query_as(
        "SELECT name, hypotheses, visibility::text, owner_group_id FROM frames WHERE id = $1",
    )
    .bind(CANONICAL)
    .fetch_optional(pool)
    .await
    .expect("read the canonical frame")
}

/// 9f2465e3: no migration creates the row, so this reads `None`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fresh_install_carries_the_canonical_claim_validity_frame(pool: PgPool) {
    let row = canonical_row(&pool).await;
    assert_eq!(
        row,
        Some((
            "claim_validity".to_string(),
            vec![
                "supported".to_string(),
                "refuted".to_string(),
                "uncertain".to_string()
            ],
            Some("public".to_string()),
            Some(Uuid::nil()),
        )),
        "a fresh install must carry prod's canonical claim_validity frame 8a594393"
    );
}

/// Migration 154's own text, replayed over the states it must handle.
/// `#[sqlx::test]` has already applied it once to an empty database.
const MIGRATION_154: &str = include_str!("../../../migrations/154_seed_claim_validity_frame.sql");

async fn replay_154(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::raw_sql(MIGRATION_154).execute(&mut *tx).await?;
    tx.commit().await.expect("commit");
    Ok(())
}

/// The whole canonical row, every column, as JSON.
async fn row_json(pool: &PgPool) -> Option<serde_json::Value> {
    sqlx::query_scalar("SELECT to_jsonb(f) FROM frames f WHERE id = $1")
        .bind(CANONICAL)
        .fetch_optional(pool)
        .await
        .expect("read the canonical row")
}

fn message(err: &sqlx::Error) -> String {
    match err {
        sqlx::Error::Database(db) => db.message().to_string(),
        other => other.to_string(),
    }
}

/// On prod the row predates 154 (created 2026-06-15, its own description).
/// Replaying 154 over such a row changes nothing in it, and adds no frame.
#[sqlx::test(migrations = "../../migrations")]
async fn replaying_154_over_prods_row_is_a_no_op(pool: PgPool) {
    sqlx::query(
        "UPDATE frames SET description = 'prod: canonical claim validity lens library', \
         created_at = '2026-06-15T00:00:00Z' WHERE id = $1",
    )
    .bind(CANONICAL)
    .execute(&pool)
    .await
    .expect("model prod's pre-existing row");
    let before = row_json(&pool).await.expect("CALIBRATION: the row exists");
    let frames_before: i64 = sqlx::query_scalar("SELECT count(*) FROM frames")
        .fetch_one(&pool)
        .await
        .expect("count frames");

    replay_154(&pool)
        .await
        .unwrap_or_else(|e| panic!("154 must apply over prod's canonical row: {e}"));

    assert_eq!(
        row_json(&pool).await,
        Some(before),
        "154 must never UPDATE an existing canonical row"
    );
    let frames_after: i64 = sqlx::query_scalar("SELECT count(*) FROM frames")
        .fetch_one(&pool)
        .await
        .expect("count frames");
    assert_eq!(frames_after, frames_before, "154 must add no frame here");
}

/// A row with the canonical id over other hypotheses is refused, not corrected.
#[sqlx::test(migrations = "../../migrations")]
async fn replaying_154_over_a_row_with_other_hypotheses_raises(pool: PgPool) {
    sqlx::query("UPDATE frames SET hypotheses = ARRAY['supported','unsupported'] WHERE id = $1")
        .bind(CANONICAL)
        .execute(&pool)
        .await
        .expect("corrupt the canonical row's axis");

    let err = replay_154(&pool)
        .await
        .expect_err("154 must refuse a canonical-id row over other hypotheses");
    assert!(
        message(&err).contains("is not the canonical claim_validity frame"),
        "154 must raise its own verify error, got: {err}"
    );
    let hyps: Vec<String> = sqlx::query_scalar("SELECT hypotheses FROM frames WHERE id = $1")
        .bind(CANONICAL)
        .fetch_one(&pool)
        .await
        .expect("read hypotheses");
    assert_eq!(
        hyps,
        vec!["supported".to_string(), "unsupported".to_string()],
        "154 must never rewrite the row's hypotheses"
    );
}

/// A row with the canonical id under another owner group is refused too.
#[sqlx::test(migrations = "../../migrations")]
async fn replaying_154_over_a_row_owned_by_another_group_raises(pool: PgPool) {
    let (_agent, group) = viewer_fixture::seed_agent_with_group(&pool, "154-other-owner").await;
    sqlx::query("UPDATE frames SET owner_group_id = $2 WHERE id = $1")
        .bind(CANONICAL)
        .bind(group)
        .execute(&pool)
        .await
        .expect("re-own the canonical row");

    let err = replay_154(&pool)
        .await
        .expect_err("154 must refuse a canonical-id row owned by another group");
    assert!(
        message(&err).contains("is not the canonical claim_validity frame"),
        "154 must raise its own verify error, got: {err}"
    );
}

/// Another id already holding the name `claim_validity` is refused with 154's
/// own message naming it, before the INSERT can hit the UNIQUE name as a bare
/// 23505.
#[sqlx::test(migrations = "../../migrations")]
async fn replaying_154_beside_a_name_squatter_raises_naming_it(pool: PgPool) {
    sqlx::query("DELETE FROM frames WHERE id = $1")
        .bind(CANONICAL)
        .execute(&pool)
        .await
        .expect("model a database without the canonical row");
    let squatter: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, visibility, owner_group_id) \
         VALUES ('claim_validity', ARRAY['supported','refuted','uncertain'], 'public', \
                 '00000000-0000-0000-0000-000000000000') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed a name squatter");

    let err = replay_154(&pool)
        .await
        .expect_err("154 must refuse to seed beside another claim_validity frame");
    let msg = message(&err);
    assert!(
        msg.contains("already holds the name claim_validity")
            && msg.contains(&squatter.to_string()),
        "154 must name the squatter in its own error, got: {err}"
    );
    assert_eq!(
        row_json(&pool).await,
        None,
        "nothing may be seeded beside a squatter"
    );
}

/// A row with the canonical id under ANOTHER name is refused too. The
/// pre-check does not see it (no other id holds `claim_validity`), so only the
/// verify's name clause can.
#[sqlx::test(migrations = "../../migrations")]
async fn replaying_154_over_a_renamed_canonical_row_raises(pool: PgPool) {
    sqlx::query("UPDATE frames SET name = 'not_claim_validity' WHERE id = $1")
        .bind(CANONICAL)
        .execute(&pool)
        .await
        .expect("rename the canonical row");

    let err = replay_154(&pool)
        .await
        .expect_err("154 must refuse a canonical-id row under another name");
    assert!(
        message(&err).contains("is not the canonical claim_validity frame"),
        "154 must raise its own verify error, got: {err}"
    );
}

/// The hypotheses are an ORDERED axis (index 0 = supported). The same three
/// names in another order are a different frame, and are refused.
#[sqlx::test(migrations = "../../migrations")]
async fn replaying_154_over_a_reordered_axis_raises(pool: PgPool) {
    sqlx::query(
        "UPDATE frames SET hypotheses = ARRAY['refuted','supported','uncertain'] WHERE id = $1",
    )
    .bind(CANONICAL)
    .execute(&pool)
    .await
    .expect("reorder the canonical row's axis");

    let err = replay_154(&pool)
        .await
        .expect_err("154 must refuse a canonical-id row over a reordered axis");
    assert!(
        message(&err).contains("is not the canonical claim_validity frame"),
        "154 must raise its own verify error, got: {err}"
    );
}
