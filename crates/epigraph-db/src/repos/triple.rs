//! Triple repository for RDF-style structured knowledge queries

use crate::errors::DbError;
use tracing::instrument;
use uuid::Uuid;

/// A row from the triples table with joined entity names
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
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
    /// Batch insert entity mentions on the caller's connection.
    ///
    /// ONE `INSERT ... SELECT FROM UNNEST(...)` for the whole batch (backlog
    /// 591b2f6f; it was one round trip per row). Returns one id per input
    /// tuple, in input order: the ids are minted here and inserted with their
    /// rows, so the order holds by construction rather than resting on the
    /// order of `RETURNING`, and the returned set is checked against them.
    ///
    /// It opens no transaction of its own: `routes/entities.rs` passes the ONE
    /// viewer-stamped transaction on which it has already authorized every
    /// target claim, so the batch commits or rolls back as a whole and
    /// `entity_mentions_tenancy`'s `WITH CHECK` applies to each row.
    ///
    /// # Arguments
    /// Each tuple is: (entity_id, claim_id, surface_form, mention_role,
    ///                 confidence, extractor, span_start, span_end)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the insert fails (no row is written).
    #[allow(clippy::type_complexity)]
    #[instrument(skip(conn, mentions_data))]
    pub async fn batch_create_mentions(
        conn: &mut sqlx::PgConnection,
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
        if mentions_data.is_empty() {
            return Ok(Vec::new());
        }
        let n = mentions_data.len();
        let ids: Vec<Uuid> = (0..n).map(|_| Uuid::new_v4()).collect();
        let mut entity_ids = Vec::with_capacity(n);
        let mut claim_ids = Vec::with_capacity(n);
        let mut surface_forms = Vec::with_capacity(n);
        let mut mention_roles = Vec::with_capacity(n);
        let mut confidences = Vec::with_capacity(n);
        let mut extractors = Vec::with_capacity(n);
        let mut span_starts = Vec::with_capacity(n);
        let mut span_ends = Vec::with_capacity(n);
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
            entity_ids.push(entity_id);
            claim_ids.push(claim_id);
            surface_forms.push(surface_form);
            mention_roles.push(mention_role);
            confidences.push(confidence);
            extractors.push(extractor);
            span_starts.push(span_start);
            span_ends.push(span_end);
        }

        let returned: Vec<Uuid> = sqlx::query_scalar(
            r#"
            INSERT INTO entity_mentions
                (id, entity_id, claim_id, surface_form, mention_role, confidence, extractor,
                 span_start, span_end)
            SELECT u.id, u.entity_id, u.claim_id, u.surface_form, u.mention_role,
                   u.confidence, u.extractor, u.span_start, u.span_end
            FROM UNNEST($1::uuid[], $2::uuid[], $3::uuid[], $4::text[], $5::text[],
                        $6::float8[], $7::text[], $8::int4[], $9::int4[])
                 WITH ORDINALITY
                 AS u(id, entity_id, claim_id, surface_form, mention_role, confidence,
                      extractor, span_start, span_end, ord)
            ORDER BY u.ord
            RETURNING id
            "#,
        )
        .bind(&ids)
        .bind(&entity_ids)
        .bind(&claim_ids)
        .bind(&surface_forms)
        .bind(&mention_roles)
        .bind(&confidences)
        .bind(&extractors)
        .bind(&span_starts)
        .bind(&span_ends)
        .fetch_all(&mut *conn)
        .await?;

        Self::check_returned(&ids, returned, "entity_mentions")?;
        Ok(ids)
    }

    /// Batch insert triples on the caller's connection.
    ///
    /// ONE `INSERT ... SELECT FROM UNNEST(...)` for the whole batch, ids in
    /// input order, exactly as [`Self::batch_create_mentions`]. Like it, it
    /// opens no transaction of its own; the route passes its viewer-stamped
    /// transaction.
    ///
    /// # Arguments
    /// Each tuple is: (claim_id, subject_id, predicate, object_id, object_literal,
    ///                 confidence, extractor, properties)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the insert fails (no row is written).
    #[allow(clippy::type_complexity)]
    #[instrument(skip(conn, triples_data))]
    pub async fn batch_create_triples(
        conn: &mut sqlx::PgConnection,
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
        if triples_data.is_empty() {
            return Ok(Vec::new());
        }
        let n = triples_data.len();
        let ids: Vec<Uuid> = (0..n).map(|_| Uuid::new_v4()).collect();
        let mut claim_ids = Vec::with_capacity(n);
        let mut subject_ids = Vec::with_capacity(n);
        let mut predicates = Vec::with_capacity(n);
        let mut object_ids = Vec::with_capacity(n);
        let mut object_literals = Vec::with_capacity(n);
        let mut confidences = Vec::with_capacity(n);
        let mut extractors = Vec::with_capacity(n);
        let mut properties_list = Vec::with_capacity(n);
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
            claim_ids.push(claim_id);
            subject_ids.push(subject_id);
            predicates.push(predicate);
            object_ids.push(object_id);
            object_literals.push(object_literal);
            confidences.push(confidence);
            extractors.push(extractor);
            properties_list.push(properties);
        }

        let returned: Vec<Uuid> = sqlx::query_scalar(
            r#"
            INSERT INTO triples
                (id, claim_id, subject_id, predicate, object_id, object_literal,
                 confidence, extractor, properties)
            SELECT u.id, u.claim_id, u.subject_id, u.predicate, u.object_id, u.object_literal,
                   u.confidence, u.extractor, u.properties
            FROM UNNEST($1::uuid[], $2::uuid[], $3::uuid[], $4::text[], $5::uuid[],
                        $6::text[], $7::float8[], $8::text[], $9::jsonb[])
                 WITH ORDINALITY
                 AS u(id, claim_id, subject_id, predicate, object_id, object_literal,
                      confidence, extractor, properties, ord)
            ORDER BY u.ord
            RETURNING id
            "#,
        )
        .bind(&ids)
        .bind(&claim_ids)
        .bind(&subject_ids)
        .bind(&predicates)
        .bind(&object_ids)
        .bind(&object_literals)
        .bind(&confidences)
        .bind(&extractors)
        .bind(&properties_list)
        .fetch_all(&mut *conn)
        .await?;

        Self::check_returned(&ids, returned, "triples")?;
        Ok(ids)
    }

    /// The batch inserts mint their ids, so `RETURNING` must name exactly
    /// those ids. Anything else means the statement wrote something other than
    /// the batch, and the caller's transaction must not commit it.
    fn check_returned(
        minted: &[Uuid],
        mut returned: Vec<Uuid>,
        table: &'static str,
    ) -> Result<(), DbError> {
        let mut want = minted.to_vec();
        want.sort_unstable();
        returned.sort_unstable();
        if want == returned {
            Ok(())
        } else {
            Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "{table} batch insert returned {} ids for {} rows, or ids it was not given",
                    returned.len(),
                    minted.len()
                )),
            })
        }
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
    #[instrument(skip(executor, viewer))]
    #[allow(clippy::too_many_arguments)]
    pub async fn query<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        subject_id: Option<Uuid>,
        predicate_pattern: Option<&str>,
        object_id: Option<Uuid>,
        min_confidence: f64,
        limit: i64,
    ) -> Result<Vec<TripleRow>, DbError> {
        // MACRO SITE — static bypass-bool spelling; `sqlx::query!` cannot be
        // spliced. BOTH `t` and `c` are filtered: `triples` carries its own
        // tenancy columns (062) and a triple is a structured restatement of its
        // claim's content, so either alone leaves a path to the other's rows.
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
              AND ($6::bool OR t.visibility = 'public' OR t.owner_group_id = ANY($7::uuid[]))
              AND ($6::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($7::uuid[]))
            ORDER BY t.confidence DESC, t.created_at DESC
            LIMIT $5
            "#,
            subject_id as Option<Uuid>,
            object_id as Option<Uuid>,
            predicate_pattern as Option<&str>,
            min_confidence,
            limit,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
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
    #[instrument(skip(executor, viewer))]
    pub async fn entity_neighborhood<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        entity_id: Uuid,
        limit: i64,
    ) -> Result<Vec<TripleRow>, DbError> {
        // MACRO SITE — static bypass-bool spelling; `sqlx::query!` cannot be
        // spliced. BOTH `t` and `c` are filtered: `triples` carries its own
        // tenancy columns (062) and a triple is a structured restatement of its
        // claim's content, so either alone leaves a path to the other's rows.
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
              AND ($3::bool OR t.visibility = 'public' OR t.owner_group_id = ANY($4::uuid[]))
              AND ($3::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($4::uuid[]))
            ORDER BY t.predicate, t.confidence DESC
            LIMIT $2
            "#,
            entity_id,
            limit,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
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
    /// The single-claim form of [`Self::get_by_claims`], which the
    /// `search_triples` MCP tool's embedding-fallback path uses (claims located
    /// by embedding similarity, their triples retrieved by claim_id).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<TripleRow>, DbError> {
        // MACRO SITE — static bypass-bool spelling. Unlike `query` and
        // `entity_neighborhood` this one does not join `claims`, so the only
        // alias to filter is `t`.
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
              AND ($2::bool OR t.visibility = 'public' OR t.owner_group_id = ANY($3::uuid[]))
            ORDER BY t.confidence DESC
            "#,
            claim_id,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
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

    /// The triples of several claims in ONE statement (backlog d69a4d24).
    ///
    /// The answer is [`Self::get_by_claim`] called for each id in
    /// `claim_ids` in turn, concatenated and cut at `limit`: the claims in
    /// the order given, each claim's triples by confidence, highest first.
    /// `search_triples` (MCP) used to make exactly those calls, one round trip
    /// per embedding hit, and truncate afterwards.
    ///
    /// Filters `t` through the viewer splice, as `get_by_claim` does (it joins
    /// no `claims`, so `t` is the only alias).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, claim_ids))]
    pub async fn get_by_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_ids: &[Uuid],
        limit: i64,
    ) -> Result<Vec<TripleRow>, DbError> {
        if claim_ids.is_empty() || limit <= 0 {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            r#"
            SELECT t.id,
                   t.claim_id,
                   t.subject_id,
                   se.canonical_name  AS subject_name,
                   t.predicate,
                   t.object_id,
                   oe.canonical_name  AS object_name,
                   t.object_literal,
                   t.confidence,
                   t.extractor,
                   t.properties,
                   t.created_at
            FROM unnest($1::uuid[]) WITH ORDINALITY AS want(claim_id, ord)
            JOIN  triples t   ON t.claim_id = want.claim_id
            JOIN  entities se ON se.id = t.subject_id
            LEFT JOIN entities oe ON oe.id = t.object_id
            WHERE true /* {VISIBILITY:t} */
            ORDER BY want.ord, t.confidence DESC
            LIMIT $2
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, TripleRow>(&sql)
            .bind(claim_ids)
            .bind(limit);
        if let Some(groups) = viewer.group_bind() {
            q = q.bind(groups);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Return `true` if at least one triple exists for the given claim.
    ///
    /// Used as an idempotency guard in extraction pipelines: if triples already
    /// exist for a claim, skip re-extraction.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn claim_has_triples<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<bool, DbError> {
        // MACRO SITE. A bare boolean is still an existence oracle.
        let row = sqlx::query!(
            r#"SELECT EXISTS(
                   SELECT 1 FROM triples
                   WHERE claim_id = $1
                     AND ($2::bool OR visibility = 'public'
                          OR owner_group_id = ANY($3::uuid[]))
               ) AS "exists!""#,
            claim_id,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_one(executor)
        .await?;

        Ok(row.exists)
    }

    /// Return `true` if at least one triple is visible to `viewer`.
    ///
    /// The RDF read surfaces (`query_triples`, `search_triples`,
    /// `entity_neighborhood`, over MCP and HTTP) report this as
    /// `index_populated`. No pipeline populates the triple index today, so an
    /// empty answer from those reads usually means the index is empty, not that
    /// the corpus lacks the fact. This flag lets a caller tell the two apart.
    ///
    /// **Viewer-relative, unlike [`Self::index_counts`].** It is an `EXISTS`
    /// through the ordinary tenancy predicate, so it stops at the first visible
    /// row and cannot report that a row private to another group exists. On a
    /// viewer-stamped connection RLS narrows it the same way, which is what lets
    /// the HTTP handlers evaluate it on the connection they already hold.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn index_populated<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
    ) -> Result<bool, DbError> {
        let sql = viewer.splice(
            "SELECT EXISTS(SELECT 1 FROM triples t WHERE true /* {VISIBILITY:t} */)",
            1,
        );
        let mut q = sqlx::query_scalar::<_, bool>(&sql);
        if let Some(groups) = viewer.group_bind() {
            q = q.bind(groups);
        }
        Ok(q.fetch_one(executor).await?)
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
    /// Takes `_viewer` so the exemption is visible at every call site rather
    /// than only in this file.
    #[instrument(skip(executor, _viewer))]
    pub async fn index_counts<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        _viewer: &crate::visibility::Viewer,
    ) -> Result<IndexCounts, DbError> {
        let row = sqlx::query!(
            r#"
            -- VISIBILITY-EXEMPT: corpus-wide index cardinality. Three scalars
            -- leave this function and no row content does; the whole point of
            -- the numbers (surfaced through `system_stats`) is to distinguish
            -- "the RDF index is empty" from "your query matched nothing", which
            -- a per-viewer count cannot answer. Reconsider if these are ever
            -- exposed per-entity or per-claim.
            SELECT
              (SELECT COUNT(*) FROM triples)         AS "triples!",
              (SELECT COUNT(*) FROM entities)        AS "entities!",
              (SELECT COUNT(*) FROM entity_mentions) AS "entity_mentions!"
            "#
        )
        .fetch_one(executor)
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
            "INSERT INTO entities (canonical_name, type_top, is_canonical) \
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
        let result = TripleRepository::claim_has_triples(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            claim_id,
        )
        .await
        .unwrap();
        assert!(!result, "new claim should have no triples");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn claim_has_triples_returns_true_after_insert(pool: sqlx::PgPool) {
        let (_agent_id, claim_id) = insert_agent_and_claim(&pool).await;
        let subject_id = insert_entity(&pool, &format!("subject-{}", Uuid::new_v4())).await;

        let mut conn = pool.acquire().await.unwrap();
        TripleRepository::batch_create_triples(
            &mut conn,
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

        let result = TripleRepository::claim_has_triples(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            claim_id,
        )
        .await
        .unwrap();
        assert!(
            result,
            "claim should have triples after batch_create_triples"
        );
    }

    /// An unpopulated index reports zeros across all three tables — the exact
    /// state behind backlog ae2784a9 (query_triples/search_triples return
    /// count=0, entity_neighborhood resolves nothing). Pin it so the health
    /// signal stays observable and a future populate-path regression is caught.
    #[sqlx::test(migrations = "../../migrations")]
    async fn index_counts_empty_db_is_all_zero(pool: sqlx::PgPool) {
        let counts = TripleRepository::index_counts(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
        )
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

        let counts = TripleRepository::index_counts(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
        )
        .await
        .expect("index_counts should succeed");
        assert_eq!(counts.entities, 2, "two canonical entities inserted");
        assert_eq!(counts.triples, 0, "no triples inserted");
        assert_eq!(counts.entity_mentions, 0, "no mentions inserted");
    }
}
