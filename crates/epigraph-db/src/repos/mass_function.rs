//! Mass function (BBA) repository
//!
//! Stores and retrieves Dempster-Shafer mass functions per (claim, frame, agent).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the mass_functions table
#[derive(Debug, Clone, FromRow)]
pub struct MassFunctionRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub source_agent_id: Option<Uuid>,
    pub perspective_id: Option<Uuid>,
    pub masses: serde_json::Value,
    pub conflict_k: Option<f64>,
    pub combination_method: Option<String>,
    pub source_strength: Option<f64>, // NEW: Shafer reliability discount weight
    pub evidence_type: Option<String>, // NEW: evidence classification tag
    /// Locality classification of this BBA's evidence vs. its claim's
    /// asserting paper. Values: 'intra', 'cross', 'unknown'. Populated
    /// by `wire_evidential_edge_factor` (via `auto_wire_ds_for_edge`)
    /// when the source claim's evidence DOI matches the target's paper.
    /// Defaults to 'unknown' on the column; not nullable. See issue #197
    /// and migration 045_mass_functions_locality_tag.sql.
    pub locality_tag: String,
    pub created_at: DateTime<Utc>,
}

/// Repository for mass function (BBA) operations
pub struct MassFunctionRepository;

impl MassFunctionRepository {
    /// Store a mass function for a (claim, frame, agent, perspective) tuple
    ///
    /// Uses ON CONFLICT to update existing entries.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, masses_json))]
    pub async fn store(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
        source_agent_id: Option<Uuid>,
        masses_json: &serde_json::Value,
        conflict_k: Option<f64>,
        combination_method: Option<&str>,
        locality_tag: &str, // 'intra' | 'cross' | 'unknown' (issue #197)
    ) -> Result<Uuid, DbError> {
        Self::store_with_perspective(
            pool,
            claim_id,
            frame_id,
            source_agent_id,
            None,
            masses_json,
            conflict_k,
            combination_method,
            None,
            None,
            locality_tag,
        )
        .await
    }

    /// Store a mass function with an optional perspective association
    ///
    /// Uses ON CONFLICT on (claim_id, frame_id, source_agent_id, perspective_id) to update.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, masses_json))]
    pub async fn store_with_perspective(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
        source_agent_id: Option<Uuid>,
        perspective_id: Option<Uuid>,
        masses_json: &serde_json::Value,
        conflict_k: Option<f64>,
        combination_method: Option<&str>,
        source_strength: Option<f64>, // Shafer reliability discount weight
        evidence_type: Option<&str>,  // evidence classification tag
        locality_tag: &str, // 'intra' | 'cross' | 'unknown'; column NOT NULL default 'unknown' (issue #197)
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO mass_functions
                (claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (claim_id, frame_id, source_agent_id, perspective_id) DO UPDATE
            SET masses = EXCLUDED.masses,
                conflict_k = EXCLUDED.conflict_k,
                combination_method = EXCLUDED.combination_method,
                source_strength = EXCLUDED.source_strength,
                evidence_type = EXCLUDED.evidence_type,
                locality_tag = EXCLUDED.locality_tag,
                created_at = NOW()
            RETURNING id
            "#,
        )
        .bind(claim_id)
        .bind(frame_id)
        .bind(source_agent_id)
        .bind(perspective_id)
        .bind(masses_json)
        .bind(conflict_k)
        .bind(combination_method)
        .bind(source_strength)
        .bind(evidence_type)
        .bind(locality_tag)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get all mass functions for a (claim, frame) pair
    ///
    /// Returns all source BBAs that can be combined.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_for_claim_frame(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let rows: Vec<MassFunctionRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, created_at
            FROM mass_functions
            WHERE claim_id = $1 AND frame_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(claim_id)
        .bind(frame_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get a mass function by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<MassFunctionRow>, DbError> {
        let row: Option<MassFunctionRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, created_at
            FROM mass_functions
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::from)?;

        Ok(row)
    }

    /// Get all mass functions for a claim (across all frames)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_for_claim(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let rows: Vec<MassFunctionRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, created_at
            FROM mass_functions
            WHERE claim_id = $1
            ORDER BY frame_id, created_at ASC
            "#,
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get mass functions for a (claim, frame) filtered by perspective
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_for_claim_frame_perspective(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
        perspective_id: Uuid,
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let rows: Vec<MassFunctionRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, created_at
            FROM mass_functions
            WHERE claim_id = $1 AND frame_id = $2 AND perspective_id = $3
            ORDER BY created_at ASC
            "#,
        )
        .bind(claim_id)
        .bind(frame_id)
        .bind(perspective_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get mass functions for a (claim, frame) from any of the given perspectives
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, perspective_ids))]
    pub async fn get_for_claim_frame_perspectives(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
        perspective_ids: &[Uuid],
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let rows: Vec<MassFunctionRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, created_at
            FROM mass_functions
            WHERE claim_id = $1 AND frame_id = $2 AND perspective_id = ANY($3)
            ORDER BY created_at ASC
            "#,
        )
        .bind(claim_id)
        .bind(frame_id)
        .bind(perspective_ids)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Delete all mass functions for a claim
    ///
    /// Returns the number of rows deleted.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete_for_claim(pool: &PgPool, claim_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query(
            r#"
            DELETE FROM mass_functions
            WHERE claim_id = $1
            "#,
        )
        .bind(claim_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Update a claim's belief, plausibility, and pignistic probability columns
    ///
    /// Called after combining mass functions to persist the computed interval.
    /// Values are clamped to `[0, 1]` at the write boundary via
    /// `epigraph_ds::measures::clamp_claim_belief_measures` so floating-point
    /// drift accumulated upstream cannot trip the
    /// `claims_{belief,plausibility,mass_on_empty,mass_on_missing,pignistic_prob}_bounds`
    /// CHECK constraints.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn update_claim_belief(
        pool: &PgPool,
        claim_id: Uuid,
        belief: f64,
        plausibility: f64,
        mass_on_empty: f64,
        pignistic_prob: Option<f64>,
        mass_on_missing: f64,
    ) -> Result<(), DbError> {
        // claims_{belief,plausibility,mass_empty}_bounds — see helper at
        // epigraph_ds::measures::clamp_claim_belief_measures.
        // Note: helper threads pignistic_prob between plausibility and mass_on_empty;
        // this function's parameter order differs, so arguments are threaded explicitly.
        let (belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing) =
            epigraph_ds::measures::clamp_claim_belief_measures(
                belief,
                plausibility,
                pignistic_prob,
                mass_on_empty,
                mass_on_missing,
            );

        sqlx::query(
            r#"
            UPDATE claims
            SET belief = $1, plausibility = $2, mass_on_empty = $3,
                pignistic_prob = $4, mass_on_missing = $5,
                updated_at = NOW()
            WHERE id = $6
            "#,
        )
        .bind(belief)
        .bind(plausibility)
        .bind(mass_on_empty)
        .bind(pignistic_prob)
        .bind(mass_on_missing)
        .bind(claim_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Count mass functions for a claim-frame pair
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count_for_claim_frame(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
    ) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2",
        )
        .bind(claim_id)
        .bind(frame_id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Get all mass functions for a frame (across all claims and agents).
    ///
    /// Used for frame-level combination and conflict computation.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_all_for_frame(
        pool: &PgPool,
        frame_id: Uuid,
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let rows: Vec<MassFunctionRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, created_at
            FROM mass_functions
            WHERE frame_id = $1
            ORDER BY claim_id, created_at ASC
            "#,
        )
        .bind(frame_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Batch-load mass functions for multiple claims.
    ///
    /// Returns all mass function rows for the given claim IDs,
    /// ordered by claim_id then created_at. The caller groups by claim_id.
    #[instrument(skip(pool, claim_ids))]
    pub async fn get_for_claims(
        pool: &PgPool,
        claim_ids: &[Uuid],
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let rows: Vec<MassFunctionRow> = sqlx::query_as(
            r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id,
                   masses, conflict_k, combination_method,
                   source_strength, evidence_type, locality_tag, created_at
            FROM mass_functions
            WHERE claim_id = ANY($1)
            ORDER BY claim_id, created_at ASC
            "#,
        )
        .bind(claim_ids)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_get_all_for_frame(pool: sqlx::PgPool) {
        // Create our own test agent
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'test-mass-frame-agent', 'system', ARRAY['test'])
             RETURNING id"
        ).fetch_one(&pool).await.unwrap();

        let frame_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO frames (name, hypotheses) VALUES ($1, '{\"supported\",\"contradicted\"}') RETURNING id",
        ).bind(format!("test-frame-all-{}", Uuid::new_v4()))
        .fetch_one(&pool).await.unwrap();

        let claim1_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id) VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
        ).bind(format!("test-mass-frame-1-{}", Uuid::new_v4())).bind(agent_id)
        .fetch_one(&pool).await.unwrap();

        let claim2_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id) VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
        ).bind(format!("test-mass-frame-2-{}", Uuid::new_v4())).bind(agent_id)
        .fetch_one(&pool).await.unwrap();

        let masses = serde_json::json!({"0": 0.6, "0,1": 0.4});
        MassFunctionRepository::store(
            &pool,
            claim1_id,
            frame_id,
            Some(agent_id),
            &masses,
            None,
            Some("test"),
            "unknown",
        )
        .await
        .unwrap();
        MassFunctionRepository::store(
            &pool,
            claim2_id,
            frame_id,
            Some(agent_id),
            &masses,
            None,
            Some("test"),
            "unknown",
        )
        .await
        .unwrap();

        let all = MassFunctionRepository::get_all_for_frame(&pool, frame_id)
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|r| r.claim_id == claim1_id));
        assert!(all.iter().any(|r| r.claim_id == claim2_id));
    }

    /// Regression test for the NULL-perspective upsert bug fixed by
    /// migration 034. Before the migration, the unique constraint was
    /// NULL-distinct, so two `store_with_perspective(.., None, ..)` calls
    /// for the same (claim, frame, agent) inserted two rows instead of
    /// upserting. This silently amplified structural belief on hub claims.
    #[sqlx::test(migrations = "../../migrations")]
    async fn null_perspective_upsert_collapses_to_single_row(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'null-persp-upsert', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let frame_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO frames (name, hypotheses) VALUES ($1, '{\"supported\",\"contradicted\"}') RETURNING id",
        )
        .bind(format!("null-persp-upsert-{}", Uuid::new_v4()))
        .fetch_one(&pool)
        .await
        .unwrap();

        let claim_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id) VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
        )
        .bind(format!("null-persp-upsert-{}", Uuid::new_v4()))
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let first = serde_json::json!({"0": 0.5, "0,1": 0.5});
        let second = serde_json::json!({"0": 0.8, "0,1": 0.2});

        MassFunctionRepository::store_with_perspective(
            &pool,
            claim_id,
            frame_id,
            Some(agent_id),
            None,
            &first,
            None,
            Some("first"),
            Some(0.7),
            Some("auto_wire"),
            "unknown",
        )
        .await
        .unwrap();

        MassFunctionRepository::store_with_perspective(
            &pool,
            claim_id,
            frame_id,
            Some(agent_id),
            None,
            &second,
            None,
            Some("second"),
            Some(0.9),
            Some("auto_wire"),
            "unknown",
        )
        .await
        .unwrap();

        let rows = MassFunctionRepository::get_for_claim_frame(&pool, claim_id, frame_id)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "NULL-perspective upsert must collapse to one row"
        );
        assert_eq!(rows[0].masses, second, "Latest write must win on conflict");
        assert_eq!(rows[0].combination_method.as_deref(), Some("second"));
    }

    /// Anti-foot-gun ratchet: pins `update_claim_belief`'s parameter ordering
    /// to its SQL `UPDATE` column ordering.
    ///
    /// The function calls `epigraph_ds::measures::clamp_claim_belief_measures`,
    /// whose parameter order differs (`pignistic_prob` is 3rd in the helper
    /// but 4th in `update_claim_belief`). A future swap that routes
    /// `mass_on_empty` into the `pignistic_prob` column (or any similar
    /// reshuffle) would ship silently without this test.
    ///
    /// Five distinct in-range values + one ULP-drifted `belief` lock both
    /// the column-to-arg mapping and the clamp behaviour through the helper.
    #[sqlx::test(migrations = "../../migrations")]
    async fn update_claim_belief_persists_each_field_to_its_own_column(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'update-claim-belief-cols', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        // Seed in-range starting state. The seed itself doesn't matter — what
        // we're testing is the column→arg mapping for update_claim_belief's
        // inputs.
        let claim_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (
                 content, content_hash, truth_value, agent_id,
                 belief, plausibility, mass_on_empty, pignistic_prob, mass_on_missing
             )
             VALUES ($1, sha256($1::bytea), 0.5, $2, 0.5, 0.5, 0.0, 0.5, 0.0)
             RETURNING id",
        )
        .bind(format!("update-claim-belief-cols-{}", Uuid::new_v4()))
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        // Canonical summation drift: 0.05 * 20 sums to ~1.0000000000000002
        // (one ULP above 1.0). Confirms the helper's f64::clamp actually
        // applies on the write path.
        //
        // Drift is applied to `plausibility` (not `belief`) because the
        // `claims_bel_pl_order` CHECK requires `belief <= plausibility`;
        // a drifted-belief of 1.0 with plausibility=0.7 would trip the
        // constraint before reaching the column-mapping assertions. The
        // anti-swap and drift-clamp invariants are unchanged.
        let drifted_plausibility: f64 = [0.05_f64; 20].iter().sum();
        assert!(
            drifted_plausibility > 1.0,
            "test precondition: 0.05 summed 20× must drift above 1.0 (got {drifted_plausibility})"
        );

        // Five field-identifying values. A parameter swap that lands
        // `mass_on_empty=0.1` in the `pignistic_prob` column would fail
        // the `pignistic_prob == Some(0.6)` assertion with "got 0.1".
        // A `belief ↔ plausibility` swap would land 1.0 in belief and 0.7
        // in plausibility, tripping `claims_bel_pl_order` (bonus catch).
        MassFunctionRepository::update_claim_belief(
            &pool,
            claim_id,
            0.7,                  // belief
            drifted_plausibility, // plausibility (drift; expect clamp to 1.0)
            0.1,                  // mass_on_empty
            Some(0.6),            // pignistic_prob
            0.05,                 // mass_on_missing
        )
        .await
        .expect("update_claim_belief must succeed for in-range / drifted inputs");

        let (belief, plausibility, mass_on_empty, pignistic_prob, mass_on_missing): (
            f64,
            f64,
            f64,
            Option<f64>,
            f64,
        ) = sqlx::query_as(
            "SELECT belief, plausibility, mass_on_empty, pignistic_prob, mass_on_missing
             FROM claims WHERE id = $1",
        )
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        // Exact-equality passthrough — helper is a no-op for in-range f64.
        assert_eq!(belief, 0.7, "belief column must receive arg 1");
        // Drift case — helper's clamp must collapse 1.0000000000000002 → 1.0
        // before the bind. A regression that bypassed the helper would
        // persist the drifted value and trip claims_plausibility_bounds.
        assert_eq!(
            plausibility, 1.0,
            "plausibility drift must be clamped to 1.0 by the helper (got {plausibility})"
        );
        assert_eq!(
            mass_on_empty, 0.1,
            "mass_on_empty column must receive arg 3"
        );
        assert_eq!(
            pignistic_prob,
            Some(0.6),
            "pignistic_prob column must receive arg 4 (anti-swap ratchet)"
        );
        assert_eq!(
            mass_on_missing, 0.05,
            "mass_on_missing column must receive arg 5"
        );
    }

    #[test]
    fn mass_function_row_has_expected_fields() {
        let _row = MassFunctionRow {
            id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            source_agent_id: Some(Uuid::new_v4()),
            perspective_id: Some(Uuid::new_v4()),
            masses: serde_json::json!({"0": 0.7, "0,1": 0.3}),
            conflict_k: Some(0.1),
            combination_method: Some("dempster".to_string()),
            source_strength: Some(0.9),
            evidence_type: Some("rct".to_string()),
            locality_tag: "unknown".to_string(),
            created_at: Utc::now(),
        };
    }
}
