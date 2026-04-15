//! Repository for experimental method operations.
//!
//! Methods represent measurement/analysis techniques with capabilities,
//! linked to source claims and analyses.

use sqlx::PgPool;
use uuid::Uuid;

/// Input record for inserting a method.
#[derive(Debug, Clone)]
pub struct MethodRecord {
    pub name: String,
    pub canonical_name: String,
    pub technique_type: String,
    pub measures: Option<String>,
    pub resolution: Option<String>,
    pub sensitivity: Option<String>,
    pub limitations: Vec<String>,
    pub required_equipment: Vec<String>,
    pub typical_conditions: Option<serde_json::Value>,
    pub source_claim_ids: Vec<Uuid>,
    pub properties: serde_json::Value,
    pub embedding: Option<Vec<f32>>,
}

/// Search result for methods (includes similarity score).
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodSearchResult {
    pub id: Uuid,
    pub name: String,
    pub canonical_name: String,
    pub technique_type: String,
    pub measures: Option<String>,
    pub resolution: Option<String>,
    pub sensitivity: Option<String>,
    pub limitations: Vec<String>,
    pub required_equipment: Vec<String>,
    pub typical_conditions: Option<serde_json::Value>,
    pub source_claim_ids: Vec<Uuid>,
    pub properties: serde_json::Value,
    pub similarity: f64,
}

/// A method capability with specificity and evidence count.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodCapability {
    pub capability: String,
    pub specificity: i16,
    pub evidence_count: i32,
}

/// A method that enables a specific capability.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodForCapability {
    pub method_id: Uuid,
    pub name: String,
    pub canonical_name: String,
    pub technique_type: String,
    pub capability: String,
    pub specificity: i16,
    pub evidence_count: i32,
}

/// Evidence strength summary for a method.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodEvidenceStrength {
    pub avg_belief: f64,
    pub claim_count: i64,
    pub source_count: i64,
}

/// A source paper for a method.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodSourcePaper {
    pub paper_id: Uuid,
    pub doi: Option<String>,
    pub title: Option<String>,
    pub pub_year: Option<i32>,
    pub source_type: Option<String>,
}

/// A usage example for a method from analyses.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodUsageExample {
    pub analysis_id: Uuid,
    pub role: String,
    pub conditions_used: Option<serde_json::Value>,
    pub analysis_type: String,
    pub method_description: Option<String>,
    pub paper_doi: Option<String>,
    pub paper_title: Option<String>,
}

/// Failure modes and limitations for a method.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodFailureModes {
    pub limitations: Vec<String>,
    pub contradictions: Vec<String>,
}

// ── Internal row types ──

#[derive(sqlx::FromRow)]
struct MethodSearchRow {
    id: Uuid,
    name: String,
    canonical_name: String,
    technique_type: String,
    measures: Option<String>,
    resolution: Option<String>,
    sensitivity: Option<String>,
    limitations: Option<Vec<String>>,
    required_equipment: Option<Vec<String>>,
    typical_conditions: Option<serde_json::Value>,
    source_claim_ids: Option<Vec<Uuid>>,
    properties: serde_json::Value,
    similarity: f64,
}

#[derive(sqlx::FromRow)]
struct MethodDetailRow {
    id: Uuid,
    name: String,
    canonical_name: String,
    technique_type: String,
    measures: Option<String>,
    resolution: Option<String>,
    sensitivity: Option<String>,
    limitations: Option<Vec<String>>,
    required_equipment: Option<Vec<String>>,
    typical_conditions: Option<serde_json::Value>,
    source_claim_ids: Option<Vec<Uuid>>,
    properties: serde_json::Value,
}

#[derive(sqlx::FromRow)]
struct MethodCapabilityRow {
    #[allow(dead_code)]
    method_id: Uuid,
    capability: String,
    specificity: i16,
    evidence_count: i32,
}

#[derive(sqlx::FromRow)]
struct MethodForCapabilityRow {
    id: Uuid,
    name: String,
    canonical_name: String,
    technique_type: String,
    capability: String,
    specificity: i16,
    evidence_count: i32,
}

#[derive(sqlx::FromRow)]
struct MethodEvidenceStrengthRow {
    avg_belief: Option<f64>,
    claim_count: i64,
    source_count: i64,
}

#[derive(sqlx::FromRow)]
struct MethodSourcePaperRow {
    id: Uuid,
    doi: Option<String>,
    title: Option<String>,
    pub_year: Option<i32>,
    source_type: Option<String>,
}

#[derive(sqlx::FromRow)]
struct MethodUsageRow {
    analysis_id: Uuid,
    role: String,
    conditions_used: Option<serde_json::Value>,
    analysis_type: String,
    method_description: Option<String>,
    paper_doi: Option<String>,
    paper_title: Option<String>,
}

pub struct MethodRepository;

impl MethodRepository {
    /// Insert a new method, optionally with embedding.
    pub async fn insert(pool: &PgPool, method: &MethodRecord) -> Result<Uuid, sqlx::Error> {
        let embedding_str = method.embedding.as_ref().map(|emb| {
            format!(
                "[{}]",
                emb.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        });

        let id: Uuid = if let Some(ref emb_str) = embedding_str {
            sqlx::query_scalar(
                "INSERT INTO methods (name, canonical_name, technique_type, measures, resolution, \
                 sensitivity, limitations, required_equipment, typical_conditions, source_claim_ids, \
                 properties, embedding) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::vector) \
                 RETURNING id",
            )
            .bind(&method.name)
            .bind(&method.canonical_name)
            .bind(&method.technique_type)
            .bind(&method.measures)
            .bind(&method.resolution)
            .bind(&method.sensitivity)
            .bind(&method.limitations)
            .bind(&method.required_equipment)
            .bind(&method.typical_conditions)
            .bind(&method.source_claim_ids)
            .bind(&method.properties)
            .bind(emb_str)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_scalar(
                "INSERT INTO methods (name, canonical_name, technique_type, measures, resolution, \
                 sensitivity, limitations, required_equipment, typical_conditions, source_claim_ids, \
                 properties) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                 RETURNING id",
            )
            .bind(&method.name)
            .bind(&method.canonical_name)
            .bind(&method.technique_type)
            .bind(&method.measures)
            .bind(&method.resolution)
            .bind(&method.sensitivity)
            .bind(&method.limitations)
            .bind(&method.required_equipment)
            .bind(&method.typical_conditions)
            .bind(&method.source_claim_ids)
            .bind(&method.properties)
            .fetch_one(pool)
            .await?
        };

        Ok(id)
    }

    /// Link a method to a capability (upsert).
    pub async fn link_capability(
        pool: &PgPool,
        method_id: Uuid,
        capability: &str,
        specificity: i16,
        evidence_count: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO method_capabilities (method_id, capability, specificity, evidence_count) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (method_id, capability) DO UPDATE SET \
                 evidence_count = method_capabilities.evidence_count + $4",
        )
        .bind(method_id)
        .bind(capability)
        .bind(specificity)
        .bind(evidence_count)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Semantic search for methods by embedding.
    pub async fn find_by_embedding(
        pool: &PgPool,
        query_embedding: &[f32],
        technique_type: Option<&str>,
        limit: i64,
    ) -> Result<Vec<MethodSearchResult>, sqlx::Error> {
        let vec_str = format!(
            "[{}]",
            query_embedding
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );

        let rows: Vec<MethodSearchRow> = if let Some(tt) = technique_type {
            sqlx::query_as(
                "WITH query_vec AS (SELECT $1::vector AS vec) \
                 SELECT m.id, m.name, m.canonical_name, m.technique_type, m.measures, \
                        m.resolution, m.sensitivity, m.limitations, m.required_equipment, \
                        m.typical_conditions, m.source_claim_ids, m.properties, \
                        1 - (m.embedding <=> q.vec) AS similarity \
                 FROM methods m, query_vec q \
                 WHERE m.embedding IS NOT NULL AND vector_norm(m.embedding) > 0 \
                   AND m.technique_type = $2 \
                 ORDER BY m.embedding <=> q.vec \
                 LIMIT $3",
            )
            .bind(&vec_str)
            .bind(tt)
            .bind(limit)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as(
                "WITH query_vec AS (SELECT $1::vector AS vec) \
                 SELECT m.id, m.name, m.canonical_name, m.technique_type, m.measures, \
                        m.resolution, m.sensitivity, m.limitations, m.required_equipment, \
                        m.typical_conditions, m.source_claim_ids, m.properties, \
                        1 - (m.embedding <=> q.vec) AS similarity \
                 FROM methods m, query_vec q \
                 WHERE m.embedding IS NOT NULL AND vector_norm(m.embedding) > 0 \
                 ORDER BY m.embedding <=> q.vec \
                 LIMIT $2",
            )
            .bind(&vec_str)
            .bind(limit)
            .fetch_all(pool)
            .await?
        };

        Ok(rows.into_iter().map(search_result_from_row).collect())
    }

    /// Get method by ID.
    pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<MethodSearchResult>, sqlx::Error> {
        let row: Option<MethodDetailRow> = sqlx::query_as(
            "SELECT id, name, canonical_name, technique_type, measures, resolution, \
             sensitivity, limitations, required_equipment, typical_conditions, \
             source_claim_ids, properties \
             FROM methods WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| MethodSearchResult {
            id: r.id,
            name: r.name,
            canonical_name: r.canonical_name,
            technique_type: r.technique_type,
            measures: r.measures,
            resolution: r.resolution,
            sensitivity: r.sensitivity,
            limitations: r.limitations.unwrap_or_default(),
            required_equipment: r.required_equipment.unwrap_or_default(),
            typical_conditions: r.typical_conditions,
            source_claim_ids: r.source_claim_ids.unwrap_or_default(),
            properties: r.properties,
            similarity: 1.0,
        }))
    }

    /// Get capabilities for a method.
    pub async fn get_capabilities(
        pool: &PgPool,
        method_id: Uuid,
    ) -> Result<Vec<MethodCapability>, sqlx::Error> {
        let rows: Vec<MethodCapabilityRow> = sqlx::query_as(
            "SELECT method_id, capability, specificity, evidence_count \
             FROM method_capabilities WHERE method_id = $1 \
             ORDER BY evidence_count DESC",
        )
        .bind(method_id)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| MethodCapability {
                capability: r.capability,
                specificity: r.specificity,
                evidence_count: r.evidence_count,
            })
            .collect())
    }

    /// Find methods that enable a specific capability (pattern match).
    pub async fn get_methods_for_capability(
        pool: &PgPool,
        capability_pattern: &str,
    ) -> Result<Vec<MethodForCapability>, sqlx::Error> {
        let like = format!("%{capability_pattern}%");
        let rows: Vec<MethodForCapabilityRow> = sqlx::query_as(
            "SELECT m.id, m.name, m.canonical_name, m.technique_type, \
                    mc.capability, mc.specificity, mc.evidence_count \
             FROM methods m \
             JOIN method_capabilities mc ON mc.method_id = m.id \
             WHERE mc.capability ILIKE $1 \
             ORDER BY mc.evidence_count DESC",
        )
        .bind(&like)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| MethodForCapability {
                method_id: r.id,
                name: r.name,
                canonical_name: r.canonical_name,
                technique_type: r.technique_type,
                capability: r.capability,
                specificity: r.specificity,
                evidence_count: r.evidence_count,
            })
            .collect())
    }

    /// Get average DS belief strength for claims linked to a method.
    pub async fn get_evidence_strength(
        pool: &PgPool,
        method_id: Uuid,
    ) -> Result<MethodEvidenceStrength, sqlx::Error> {
        let row: Option<MethodEvidenceStrengthRow> = sqlx::query_as(
            "SELECT \
                 AVG(COALESCE(c.pignistic_prob, c.truth_value)) AS avg_belief, \
                 COUNT(*) AS claim_count, \
                 COUNT(DISTINCT e.source_id) AS source_count \
             FROM methods m \
             CROSS JOIN LATERAL unnest(m.source_claim_ids) AS scid \
             JOIN claims c ON c.id = scid \
             LEFT JOIN edges e ON e.target_id = c.id AND e.source_type = 'paper' AND e.relationship = 'asserts' \
             WHERE m.id = $1",
        )
        .bind(method_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map_or(
            MethodEvidenceStrength {
                avg_belief: 0.0,
                claim_count: 0,
                source_count: 0,
            },
            |r| MethodEvidenceStrength {
                avg_belief: r.avg_belief.unwrap_or(0.0),
                claim_count: r.claim_count,
                source_count: r.source_count,
            },
        ))
    }

    /// Get source papers for a method.
    pub async fn get_source_papers(
        pool: &PgPool,
        method_id: Uuid,
    ) -> Result<Vec<MethodSourcePaper>, sqlx::Error> {
        let rows: Vec<MethodSourcePaperRow> = sqlx::query_as(
            "SELECT DISTINCT p.id, p.doi, p.title, \
                    (p.properties->>'year')::int AS pub_year, \
                    p.properties->>'source_type' AS source_type \
             FROM methods m \
             CROSS JOIN LATERAL unnest(m.source_claim_ids) AS scid \
             JOIN edges e ON e.target_id = scid AND e.source_type = 'paper' AND e.relationship = 'asserts' \
             JOIN papers p ON p.id = e.source_id \
             WHERE m.id = $1 \
             ORDER BY pub_year DESC NULLS LAST",
        )
        .bind(method_id)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| MethodSourcePaper {
                paper_id: r.id,
                doi: r.doi,
                title: r.title,
                pub_year: r.pub_year,
                source_type: r.source_type,
            })
            .collect())
    }

    /// Get usage examples for a method from analyses.
    pub async fn get_usage_examples(
        pool: &PgPool,
        method_id: Uuid,
        limit: i64,
    ) -> Result<Vec<MethodUsageExample>, sqlx::Error> {
        let rows: Vec<MethodUsageRow> = sqlx::query_as(
            "SELECT am.analysis_id, am.role, am.conditions_used, \
                    a.analysis_type, a.method_description, \
                    p.doi AS paper_doi, p.title AS paper_title \
             FROM analysis_methods am \
             JOIN analyses a ON a.id = am.analysis_id \
             LEFT JOIN edges e ON e.target_id = am.analysis_id AND e.source_type = 'paper' \
             LEFT JOIN papers p ON p.id = e.source_id \
             WHERE am.method_id = $1 \
             ORDER BY a.created_at DESC \
             LIMIT $2",
        )
        .bind(method_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| MethodUsageExample {
                analysis_id: r.analysis_id,
                role: r.role,
                conditions_used: r.conditions_used,
                analysis_type: r.analysis_type,
                method_description: r.method_description,
                paper_doi: r.paper_doi,
                paper_title: r.paper_title,
            })
            .collect())
    }

    /// Link a method to an analysis.
    pub async fn link_analysis(
        pool: &PgPool,
        analysis_id: Uuid,
        method_id: Uuid,
        role: &str,
        conditions_used: Option<serde_json::Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO analysis_methods (analysis_id, method_id, role, conditions_used) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (analysis_id, method_id) DO NOTHING",
        )
        .bind(analysis_id)
        .bind(method_id)
        .bind(role)
        .bind(conditions_used)
        .execute(pool)
        .await?;
        Ok(())
    }
}

fn search_result_from_row(r: MethodSearchRow) -> MethodSearchResult {
    MethodSearchResult {
        id: r.id,
        name: r.name,
        canonical_name: r.canonical_name,
        technique_type: r.technique_type,
        measures: r.measures,
        resolution: r.resolution,
        sensitivity: r.sensitivity,
        limitations: r.limitations.unwrap_or_default(),
        required_equipment: r.required_equipment.unwrap_or_default(),
        typical_conditions: r.typical_conditions,
        source_claim_ids: r.source_claim_ids.unwrap_or_default(),
        properties: r.properties,
        similarity: r.similarity,
    }
}
