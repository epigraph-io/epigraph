//! Migration 154 seeds the canonical `claim_validity` frame (U027F).
//!
//! `POST /api/v1/claims/:id/assess` resolves its default frame by the fixed id
//! of prod's row, `8a594393-c343-4f1a-b942-5c5b7862f792` (public, owned by the
//! nil world group, hypotheses `[supported, refuted, uncertain]`), and never
//! creates it at request time. So a fresh install must carry that row.

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
