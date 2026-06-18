//! Triple repository for RDF-style structured knowledge queries

use crate::errors::DbError;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A row from the triples table with joined entity names
#[derive(Debug, Clone, serde::Serialize)]
pub struct TripleRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub subject_id: Uuid,
    pub subject_name: String,
    pub predicate: String,
    pub object_id: Option<Uuid>,
    pub object_name: Option<String>,
    pub object_literal: Option<String>,
    pub confidence: f64,
    pub extractor: String,
    pub properties: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A row from the entity_mentions table
#[derive(Debug, Clone, serde::Serialize)]
pub struct MentionRow {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub claim_id: Uuid,
    pub surface_form: String,
    pub mention_role: String,
    pub confidence: f64,
    pub extractor: String,
    pub span_start: Option<i32>,
    pub span_end: Option<i32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Aggregate row counts for the structured triple/entity index.
///
/// Surfaces the health of the RDF layer (`triples`, `entities`,
/// `entity_mentions`) so an unpopulated index is observable rather than
/// indistinguishable from "no matches" in the `query_triples` /
/// `search_triples` / `entity_neighborhood` tools. See backlog ae2784a9.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct IndexCounts {
    pub triples: i64,
    pub entities: i64,
    pub entity_mentions: i64,
}

/// Repository for triple and entity mention operations
pub struct TripleRepository;

impl TripleRepository {
    /// Batch insert entity mentions.
    ///
    /// Inserts each mention individually and collects the returned IDs.
    /// This is deliberately non-transactional at the repository level — callers
    /// that need atomicity should wrap in a transaction before calling.
    ///
    /// # Arguments
    /// Each tuple is: (entity_id, claim_id, surface_form, mention_role,
    ///                 confidence, extractor, span_start, span_end)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any insert fails.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(pool, mentions_data))]
    pub async fn batch_create_mentions(
        pool: &PgPool,
        mentions_data: Vec<(
            Uuid,
            Uuid,
            String,
            String,
            f64,
            String,
            Option<i32>,
            Option<i32>,
        )>,
    ) -> Result<Vec<Uuid>, DbError> {
        let mut ids = Vec::with_capacity(mentions_data.len());

        for (
            entity_id,
            claim_id,
            surface_form,
            mention_role,
            confidence,
            extractor,
            span_start,
            span_end,
        ) in mentions_data
        {
            let row = sqlx::query!(
                r#"
                INSERT INTO entity_mentions
                    (entity_id, claim_id, surface_form, mention_role, confidence, extractor,
                     span_start, span_end)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id
                "#,
                entity_id,
                claim_id,
                surface_form,
                mention_role,
                confidence,
                extractor,
                span_start,
                span_end
            )
            .fetch_one(pool)
            .await?;

            ids.push(row.id);
        }

        Ok(ids)
    }

    /// Batch insert triples.
    ///
    /// Inserts each triple individually and collects the returned IDs.
    /// Callers that need atomicity should wrap in a transaction before calling.
    ///
    /// # Arguments
    /// Each tuple is: (claim_id, subject_id, predicate, object_id, object_literal,
    ///                 confidence, extractor, properties)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any insert fails.
    #[allow(clippy::type_complexity)]
    #[instrument(skip(pool, triples_data))]
    pub async fn batch_create_triples(
        pool: &PgPool,
        triples_data: Vec<(
            Uuid,
            Uuid,
            String,
            Option<Uuid>,
            Option<String>,
            f64,
            String,
            serde_json::Value,
        )>,
    ) -> Result<Vec<Uuid>, DbError> {
        let mut ids = Vec::with_capacity(triples_data.len());

        for (
            claim_id,
            subject_id,
            predicate,
            object_id,
            object_literal,
            confidence,
            extractor,
            properties,
        ) in triples_data
        {
            let row = sqlx::query!(
                r#"
                INSERT INTO triples
                    (claim_id, subject_id, predicate, object_id, object_literal,
                     confidence, extractor, properties)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id
                "#,
                claim_id,
                subject_id,
                predicate,
                object_id,
                object_literal,
                confidence,
                extractor,
                properties
            )
            .fetch_one(pool)
            .await?;

            ids.push(row.id);
        }

        Ok(ids)
    }

    /// Query triples with optional filters.
    ///
    /// Joins entities for subject_name and object_name. Filters to current claims
    /// and canonical subject entities only. Uses pg_trgm similarity for fuzzy
    /// predicate matching when a predicate pattern is supplied.
    ///
    /// # Arguments
    /// * `subject_id`        - Optional subject entity filter
    /// * `predicate_pattern` - Optional fuzzy predicate pattern (similarity >= 0.3)
    /// * `object_id`         - Optional object entity filter
    /// * `min_confidence`    - Minimum triple confidence (inclusive)
    /// * `limit`             - Maximum number of results
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn query(
        pool: &PgPool,
        subject_id: Option<Uuid>,
        predicate_pattern: Option<&str>,
        object_id: Option<Uuid>,
        min_confidence: f64,
        limit: i64,
    ) -> Result<Vec<TripleRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT t.id,
                   t.claim_id,
                   t.subject_id,
                   se.canonical_name  AS "subject_name!",
                   t.predicate,
                   t.object_id        AS "object_id?",
                   oe.canonical_name  AS "object_name?",
                   t.object_literal   AS "object_literal?",
                   t.confidence,
                   t.extractor,
                   t.properties,
                   t.created_at
            FROM triples t
            JOIN  entities se ON se.id = t.subject_id
            LEFT JOIN entities oe ON oe.id = t.object_id
            JOIN  claims c  ON c.id  = t.claim_id
            WHERE c.is_current        = true
              AND se.is_canonical     = true
              AND t.confidence       >= $4
              AND ($1::uuid IS NULL OR t.subject_id = $1)
              AND ($2::uuid IS NULL OR t.object_id  = $2)
              AND ($3::text IS NULL OR similarity(t.predicate, $3) >= 0.3)
            ORDER BY t.confidence DESC, t.created_at DESC
            LIMIT $5
            "#,
            subject_id as Option<Uuid>,
            object_id as Option<Uuid>,
            predicate_pattern as Option<&str>,
            min_confidence,
            limit
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| TripleRow {
                id: r.id,
                claim_id: r.claim_id,
                subject_id: r.subject_id,
                subject_name: r.subject_name,
                predicate: r.predicate,
                object_id: r.object_id,
                object_name: r.object_name,
                object_literal: r.object_literal,
                confidence: r.confidence,
                extractor: r.extractor,
                properties: r.properties,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Return all triples where `entity_id` appears as subject or object.
    ///
    /// This enables "everything about X" graph neighbourhood queries.
    /// Filters to current claims and canonical subject entities.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn entity_neighborhood(
        pool: &PgPool,
        entity_id: Uuid,
        limit: i64,
    ) -> Result<Vec<TripleRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT t.id,
                   t.claim_id,
                   t.subject_id,
                   se.canonical_name  AS "subject_name!",
                   t.predicate,
                   t.object_id        AS "object_id?",
                   oe.canonical_name  AS "object_name?",
                   t.object_literal   AS "object_literal?",
                   t.confidence,
                   t.extractor,
                   t.properties,
                   t.created_at
            FROM triples t
            JOIN  entities se ON se.id = t.subject_id
            LEFT JOIN entities oe ON oe.id = t.object_id
            JOIN  claims c  ON c.id  = t.claim_id
            WHERE c.is_current    = true
              AND se.is_canonical = true
              AND (t.subject_id = $1 OR t.object_id = $1)
            ORDER BY t.predicate, t.confidence DESC
            LIMIT $2
            "#,
            entity_id,
            limit
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| TripleRow {
                id: r.id,
                claim_id: r.claim_id,
                subject_id: r.subject_id,
                subject_name: r.subject_name,
                predicate: r.predicate,
                object_id: r.object_id,
                object_name: r.object_name,
                object_literal: r.object_literal,
                confidence: r.confidence,
                extractor: r.extractor,
                properties: r.properties,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Return all triples associated with a specific claim.
    ///
    /// Enables the embedding-fallback path in the `search_triples` MCP tool,
    /// where claims are located by embedding similarity and triples are retrieved
    /// by claim_id.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_claim(pool: &PgPool, claim_id: Uuid) -> Result<Vec<TripleRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT t.id,
                   t.claim_id,
                   t.subject_id,
                   se.canonical_name  AS "subject_name!",
                   t.predicate,
                   t.object_id        AS "object_id?",
                   oe.canonical_name  AS "object_name?",
                   t.object_literal   AS "object_literal?",
                   t.confidence,
                   t.extractor,
                   t.properties,
                   t.created_at
            FROM triples t
            JOIN  entities se ON se.id = t.subject_id
            LEFT JOIN entities oe ON oe.id = t.object_id
            WHERE t.claim_id = $1
            ORDER BY t.confidence DESC
            "#,
            claim_id
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| TripleRow {
                id: r.id,
                claim_id: r.claim_id,
                subject_id: r.subject_id,
                subject_name: r.subject_name,
                predicate: r.predicate,
                object_id: r.object_id,
                object_name: r.object_name,
                object_literal: r.object_literal,
                confidence: r.confidence,
                extractor: r.extractor,
                properties: r.properties,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Return `true` if at least one triple exists for the given claim.
    ///
    /// Used as an idempotency guard in extraction pipelines: if triples already
    /// exist for a claim, skip re-extraction.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn claim_has_triples(pool: &PgPool, claim_id: Uuid) -> Result<bool, DbError> {
        let row = sqlx::query!(
            r#"SELECT EXISTS(SELECT 1 FROM triples WHERE claim_id = $1) AS "exists!""#,
            claim_id
        )
        .fetch_one(pool)
        .await?;

        Ok(row.exists)
    }

    /// Return total row counts for the structured triple/entity index.
    ///
    /// One round-trip over the three index tables (`triples`, `entities`,
    /// `entity_mentions`). Exposed through `system_stats` so an empty /
    /// unpopulated index is observable: the three RDF query tools otherwise
    /// return `count = 0` / entity-not-found, which is indistinguishable from
    /// a populated-but-no-match result. See backlog ae2784a9.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn index_counts(pool: &PgPool) -> Result<IndexCounts, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT
              (SELECT COUNT(*) FROM triples)         AS "triples!",
              (SELECT COUNT(*) FROM entities)        AS "entities!",
              (SELECT COUNT(*) FROM entity_mentions) AS "entity_mentions!"
            "#
        )
        .fetch_one(pool)
        .await?;

        Ok(IndexCounts {
            triples: row.triples,
            entities: row.entities,
            entity_mentions: row.entity_mentions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityRepository;

    /// Helper: insert a minimal agent and claim, returning (agent_id, claim_id).
    async fn insert_agent_and_claim(pool: &sqlx::PgPool) -> (Uuid, Uuid) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels) \
             VALUES (sha256(gen_random_uuid()::text::bytea), 'triple-test-agent', 'system', ARRAY['test']) \
             RETURNING id",
        )
        .fetch_one(pool)
        .await
        .unwrap();

        let claim_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
             VALUES ($1, sha256($1::bytea), 0.7, $2) \
             RETURNING id",
        )
        .bind(format!("triple-test-claim-{}", Uuid::new_v4()))
        .bind(agent_id)
        .fetch_one(pool)
        .await
        .unwrap();

        (agent_id, claim_id)
    }

    /// Helper: insert a canonical entity, returning entity_id.
    async fn insert_entity(pool: &sqlx::PgPool, name: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO entities (canonical_name, entity_type, is_canonical) \
             VALUES ($1, 'Material', true) \
             RETURNING id",
        )
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn claim_has_triples_returns_false_when_empty(pool: sqlx::PgPool) {
        let (_agent_id, claim_id) = insert_agent_and_claim(&pool).await;
        let result = TripleRepository::claim_has_triples(&pool, claim_id)
            .await
            .unwrap();
        assert!(!result, "new claim should have no triples");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn claim_has_triples_returns_true_after_insert(pool: sqlx::PgPool) {
        let (_agent_id, claim_id) = insert_agent_and_claim(&pool).await;
        let subject_id = insert_entity(&pool, &format!("subject-{}", Uuid::new_v4())).await;

        TripleRepository::batch_create_triples(
            &pool,
            vec![(
                claim_id,
                subject_id,
                "is_a".to_string(),
                None,
                Some("TestObject".to_string()),
                0.9,
                "test".to_string(),
                serde_json::json!({}),
            )],
        )
        .await
        .unwrap();

        let result = TripleRepository::claim_has_triples(&pool, claim_id)
            .await
            .unwrap();
        assert!(result, "claim should have triples after batch_create_triples");
    }

    /// An unpopulated index reports zeros across all three tables — the exact
    /// state behind backlog ae2784a9 (query_triples/search_triples return
    /// count=0, entity_neighborhood resolves nothing). Pin it so the health
    /// signal stays observable and a future populate-path regression is caught.
    #[sqlx::test(migrations = "../../migrations")]
    async fn index_counts_empty_db_is_all_zero(pool: sqlx::PgPool) {
        let counts = TripleRepository::index_counts(&pool)
            .await
            .expect("index_counts query should succeed on an empty DB");
        assert_eq!(counts.triples, 0);
        assert_eq!(counts.entities, 0);
        assert_eq!(counts.entity_mentions, 0);
    }

    /// After inserting canonical entities (no FK dependencies), the entity
    /// count reflects them while triples/mentions stay zero — proving the three
    /// counts are independent per table, not one shared aggregate.
    #[sqlx::test(migrations = "../../migrations")]
    async fn index_counts_reflects_inserted_entities(pool: sqlx::PgPool) {
        EntityRepository::upsert(
            &pool,
            "silicon",
            "Material",
            None,
            None,
            serde_json::json!({}),
        )
        .await
        .expect("upsert silicon");
        EntityRepository::upsert(
            &pool,
            "DNA origami",
            "Material",
            None,
            None,
            serde_json::json!({}),
        )
        .await
        .expect("upsert DNA origami");

        let counts = TripleRepository::index_counts(&pool)
            .await
            .expect("index_counts should succeed");
        assert_eq!(counts.entities, 2, "two canonical entities inserted");
        assert_eq!(counts.triples, 0, "no triples inserted");
        assert_eq!(counts.entity_mentions, 0, "no mentions inserted");
    }
}
