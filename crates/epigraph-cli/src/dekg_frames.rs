//! The frame-assignment write of `dekg migrate create-frames`.
//!
//! `create-frames` clusters claim embeddings, creates one frame per cluster,
//! then binds the cluster's claims to that frame in `claim_frames`. The
//! binding loop lives here, apart from the clustering, so it can be driven
//! with a fixed assignment (no embeddings) and its two promises tested:
//!
//! * the count it returns is rows WRITTEN, not rows attempted: a binding that
//!   already exists (`ON CONFLICT DO NOTHING`) is not counted;
//! * a failed insert (a frame or claim that does not exist, a refused row)
//!   stops the run with an error instead of being discarded and the loop
//!   continuing, so the operator's "assigned N claims" can be trusted.
//!
//! `tests/dekg_create_frames_assign.rs` pins both on a fresh database.

use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

/// Bind each `(row_index, claim_id)` of one cluster to `frame_id`.
///
/// `row_index` is the claim's position in the clustering input, and the
/// stored `hypothesis_index` is `row_index % hypothesis_count` (the
/// arithmetic `create-frames` has always used). Each insert is
/// `ON CONFLICT DO NOTHING`, and the return value is the number of rows
/// actually inserted.
///
/// # Errors
/// `hypothesis_count` is zero, or any insert fails. The first failure is
/// returned at once: the bindings before it stay written (each insert is its
/// own statement on `pool`) and none after it is attempted.
pub async fn assign_claims_to_frame(
    pool: &PgPool,
    frame_id: Uuid,
    assignments: &[(usize, Uuid)],
    hypothesis_count: usize,
) -> Result<u64> {
    if hypothesis_count == 0 {
        anyhow::bail!("frame {frame_id} has no hypotheses to assign claims to");
    }
    let mut inserted_total = 0u64;
    for (row_index, claim_id) in assignments {
        let inserted = sqlx::query(
            "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(claim_id)
        .bind(frame_id)
        .bind(*row_index as i32 % hypothesis_count as i32)
        .execute(pool)
        .await
        .context("insert claim_frames assignment")?;
        inserted_total += inserted.rows_affected();
    }
    Ok(inserted_total)
}
