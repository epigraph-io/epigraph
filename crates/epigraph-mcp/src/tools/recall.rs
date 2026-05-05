//! `recall_with_context` MCP tool — paragraph-primary semantic search with
//! batched structural context. See docs/superpowers/specs/2026-05-05-recall-with-context-design.md.

use rmcp::model::{CallToolResult, Content};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

async fn detect_centroid_dim(pool: &sqlx::PgPool) -> Result<u32, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE embedding_3072 IS NOT NULL)::float8
              / NULLIF(COUNT(*), 0)::float8 AS frac_3072
        FROM claims
        WHERE (properties->>'level')::int = 2
        "#
    )
    .fetch_one(pool)
    .await?;

    Ok(if row.frac_3072.unwrap_or(0.0) >= 0.5 {
        3072
    } else {
        1536
    })
}

async fn compute_corpus_scope(pool: &sqlx::PgPool) -> Result<CorpusScope, sqlx::Error> {
    // Per spec §3.1 / Locked-in 5.5: corpus_scope always populated on success.
    // One round-trip with subselects to avoid four separate COUNT queries.
    let row = sqlx::query!(
        r#"
        SELECT
          (SELECT COUNT(*) FROM claims) AS claims_total,
          (SELECT COUNT(*) FROM claims WHERE (properties->>'level')::int = 2) AS paragraph_total,
          (SELECT COUNT(*) FROM papers) AS paper_total,
          (SELECT COUNT(*) FROM claim_themes) AS themes_total
        "#
    )
    .fetch_one(pool)
    .await?;
    Ok(CorpusScope {
        claims_total: row.claims_total.unwrap_or(0).max(0) as usize,
        paragraph_total: row.paragraph_total.unwrap_or(0).max(0) as usize,
        paper_total: row.paper_total.unwrap_or(0).max(0) as usize,
        themes_total: row.themes_total.unwrap_or(0).max(0) as usize,
    })
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RecallWithContextParams {
    pub query: String,
    pub limit: Option<u32>,
    pub min_truth: Option<f64>,
    pub centroid_dim: Option<u32>,
    pub paper_doi_filter: Option<String>,
    pub siblings_limit: Option<u32>,
    pub corroborates_limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecallWithContextResponse {
    pub results: Vec<RecallHit>,
    pub corpus_scope: CorpusScope,
    pub centroid_dim_used: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecallHit {
    pub paragraph_id: Uuid,
    pub paragraph_content: String,
    pub similarity: f64,
    pub truth_value: f64,
    pub paper: PaperMeta,
    pub section: Option<SectionMeta>,
    pub atoms: Vec<AtomChild>,
    pub atoms_total: usize,
    pub atoms_truncated: bool,
    pub siblings: Vec<SiblingParagraph>,
    pub siblings_total: usize,
    pub siblings_truncated: bool,
    pub corroborates: Vec<CorroboratesEdge>,
    pub corroborates_total: usize,
    pub corroborates_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaperMeta {
    pub paper_id: Uuid,
    pub doi: Option<String>,
    pub title: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionMeta {
    pub section_id: Uuid,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AtomChild {
    pub atom_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub bridge_to_paragraphs: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiblingParagraph {
    pub paragraph_id: Uuid,
    pub content: String,
    pub truth_value: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorroboratesEdge {
    pub claim_id: Uuid,
    pub content: String,
    pub similarity: f64,
    pub paper_doi: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorpusScope {
    pub claims_total: usize,
    pub paragraph_total: usize,
    pub paper_total: usize,
    pub themes_total: usize,
}

pub async fn recall_with_context(
    server: &EpiGraphMcpFull,
    params: RecallWithContextParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let min_truth = params.min_truth.unwrap_or(0.3);
    let siblings_limit = params.siblings_limit.unwrap_or(8);
    let corroborates_limit = params.corroborates_limit.unwrap_or(4);

    // Stage 1: pick centroid_dim (request hint OR auto-detect via population threshold).
    let centroid_dim = match params.centroid_dim {
        Some(d) if d == 1536 || d == 3072 => d,
        Some(d) => {
            return Err(invalid_params(format!(
                "centroid_dim must be 1536 or 3072 (got {d})"
            )));
        }
        None => detect_centroid_dim(&server.pool)
            .await
            .map_err(|e| internal_error(format!("auto-detect centroid_dim: {e}")))?,
    };

    // Stage 2: embed query at the right model (1536 -> -small, 3072 -> -large).
    let query_embedding = server
        .embedder
        .generate_at_dim(&params.query, centroid_dim)
        .await
        .map_err(|e| internal_error(format!("embed query: {e}")))?;
    let pgvec = crate::embed::format_pgvector(&query_embedding);

    // Stage 3: paragraph-primary kNN (level=2 only, optional paper_doi pre-filter).
    let raw_hits = epigraph_db::ClaimRepository::search_by_embedding(
        &server.pool,
        &pgvec,
        centroid_dim,
        i64::from(limit),
        params.paper_doi_filter.as_deref(),
    )
    .await
    .map_err(|e| internal_error(format!("kNN: {e}")))?;

    if raw_hits.is_empty() {
        // Empty result still returns corpus_scope (#52 Finding 2).
        let corpus_scope = compute_corpus_scope(&server.pool)
            .await
            .map_err(|e| internal_error(format!("corpus_scope: {e}")))?;
        return success_json(&RecallWithContextResponse {
            results: vec![],
            corpus_scope,
            centroid_dim_used: centroid_dim,
        });
    }

    // Stage 5: batch context fetches.
    let paragraph_ids: Vec<Uuid> = raw_hits.iter().map(|h| h.claim_id).collect();
    let ctx = fetch_batched_context(
        &server.pool,
        &paragraph_ids,
        siblings_limit,
        corroborates_limit,
    )
    .await
    .map_err(|e| internal_error(format!("batch fetch: {e}")))?;

    // Stage 4 + 6: filter min_truth, drop paragraphs missing core or paper, assemble.
    let mut results = Vec::with_capacity(raw_hits.len());
    for hit in raw_hits {
        let paragraph_id = hit.claim_id;
        let core = match ctx.paragraph_meta.get(&paragraph_id) {
            Some(c) => c,
            None => continue, // paragraph deleted between kNN and batch fetch
        };
        if core.truth_value < min_truth {
            continue;
        }
        let paper = match ctx.paper_meta.get(&paragraph_id) {
            Some(p) => p.clone(),
            None => continue, // paragraph with no paper attribution — drop
        };

        let atoms = ctx
            .atoms_by_paragraph
            .get(&paragraph_id)
            .cloned()
            .unwrap_or_default();
        let atoms_total = ctx
            .atoms_total_by_paragraph
            .get(&paragraph_id)
            .copied()
            .unwrap_or(atoms.len());
        let atoms_truncated = atoms_total > atoms.len();

        let siblings = ctx
            .siblings_by_paragraph
            .get(&paragraph_id)
            .cloned()
            .unwrap_or_default();
        let siblings_total = ctx
            .siblings_total_by_paragraph
            .get(&paragraph_id)
            .copied()
            .unwrap_or(siblings.len());
        let siblings_truncated = siblings_total > siblings.len();

        let corroborates = ctx
            .corroborates_by_paragraph
            .get(&paragraph_id)
            .cloned()
            .unwrap_or_default();
        let corroborates_total = ctx
            .corroborates_total_by_paragraph
            .get(&paragraph_id)
            .copied()
            .unwrap_or(corroborates.len());
        let corroborates_truncated = corroborates_total > corroborates.len();

        results.push(RecallHit {
            paragraph_id,
            paragraph_content: core.content.clone(),
            similarity: hit.similarity,
            truth_value: core.truth_value,
            paper,
            section: ctx.section_meta.get(&paragraph_id).cloned(),
            atoms,
            atoms_total,
            atoms_truncated,
            siblings,
            siblings_total,
            siblings_truncated,
            corroborates,
            corroborates_total,
            corroborates_truncated,
        });
    }

    let corpus_scope = compute_corpus_scope(&server.pool)
        .await
        .map_err(|e| internal_error(format!("corpus_scope: {e}")))?;

    success_json(&RecallWithContextResponse {
        results,
        corpus_scope,
        centroid_dim_used: centroid_dim,
    })
}

pub struct ParagraphCore {
    pub content: String,
    pub truth_value: f64,
}

pub struct BatchedContext {
    pub paragraph_meta: std::collections::HashMap<Uuid, ParagraphCore>,
    pub paper_meta: std::collections::HashMap<Uuid, PaperMeta>,
    pub paragraph_to_section: std::collections::HashMap<Uuid, Uuid>,
    pub section_meta: std::collections::HashMap<Uuid, SectionMeta>,
    pub atoms_by_paragraph: std::collections::HashMap<Uuid, Vec<AtomChild>>,
    pub atoms_total_by_paragraph: std::collections::HashMap<Uuid, usize>,
    pub siblings_by_paragraph: std::collections::HashMap<Uuid, Vec<SiblingParagraph>>,
    pub siblings_total_by_paragraph: std::collections::HashMap<Uuid, usize>,
    pub corroborates_by_paragraph: std::collections::HashMap<Uuid, Vec<CorroboratesEdge>>,
    pub corroborates_total_by_paragraph: std::collections::HashMap<Uuid, usize>,
}

pub async fn fetch_batched_context(
    pool: &sqlx::PgPool,
    paragraph_ids: &[Uuid],
    siblings_limit: u32,
    corroborates_limit: u32,
) -> Result<BatchedContext, sqlx::Error> {
    let mut paragraph_meta: std::collections::HashMap<Uuid, ParagraphCore> = Default::default();
    let mut paper_meta: std::collections::HashMap<Uuid, PaperMeta> = Default::default();
    let mut paragraph_to_section: std::collections::HashMap<Uuid, Uuid> = Default::default();
    let mut section_meta: std::collections::HashMap<Uuid, SectionMeta> = Default::default();
    let mut atoms_by_paragraph: std::collections::HashMap<Uuid, Vec<AtomChild>> =
        Default::default();
    let mut atoms_total_by_paragraph: std::collections::HashMap<Uuid, usize> = Default::default();
    let mut siblings_by_paragraph: std::collections::HashMap<Uuid, Vec<SiblingParagraph>> =
        Default::default();
    let mut siblings_total_by_paragraph: std::collections::HashMap<Uuid, usize> =
        Default::default();
    let mut corroborates_by_paragraph: std::collections::HashMap<Uuid, Vec<CorroboratesEdge>> =
        Default::default();
    let mut corroborates_total_by_paragraph: std::collections::HashMap<Uuid, usize> =
        Default::default();

    if paragraph_ids.is_empty() {
        return Ok(BatchedContext {
            paragraph_meta,
            paper_meta,
            paragraph_to_section,
            section_meta,
            atoms_by_paragraph,
            atoms_total_by_paragraph,
            siblings_by_paragraph,
            siblings_total_by_paragraph,
            corroborates_by_paragraph,
            corroborates_total_by_paragraph,
        });
    }

    // 1. Paragraphs themselves (content + truth_value).
    {
        let rows = sqlx::query!(
            "SELECT id, content, truth_value FROM claims WHERE id = ANY($1)",
            paragraph_ids
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            paragraph_meta.insert(
                r.id,
                ParagraphCore {
                    content: r.content,
                    truth_value: r.truth_value,
                },
            );
        }
    }

    // 2. Papers via paper-attribution asserts edge.
    {
        let rows = sqlx::query!(
            r#"
            SELECT
                e.target_id AS paragraph_id,
                p.id AS paper_id,
                p.doi,
                COALESCE(p.title, '') AS "title!"
            FROM edges e
            JOIN papers p ON p.id = e.source_id
            WHERE e.target_id = ANY($1)
              AND e.relationship = 'asserts'
              AND e.source_type = 'paper'
            "#,
            paragraph_ids
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            paper_meta.insert(
                r.paragraph_id,
                PaperMeta {
                    paper_id: r.paper_id,
                    doi: Some(r.doi),
                    title: r.title,
                },
            );
        }
    }

    // 3. Section parents (level=1 via decomposes_to incoming).
    {
        let rows = sqlx::query!(
            r#"
            SELECT e.target_id AS paragraph_id, c.id AS section_id, c.content
            FROM edges e
            JOIN claims c ON c.id = e.source_id
            WHERE e.target_id = ANY($1)
              AND e.relationship = 'decomposes_to'
              AND (c.properties->>'level')::int = 1
            "#,
            paragraph_ids
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            paragraph_to_section.insert(r.paragraph_id, r.section_id);
            section_meta.insert(
                r.paragraph_id,
                SectionMeta {
                    section_id: r.section_id,
                    content: r.content,
                },
            );
        }
    }

    // 4. Atoms (level=3) — windowed by paragraph; cap at 50 atoms per paragraph.
    let atoms_per_paragraph_cap: i64 = 50;
    {
        let rows = sqlx::query!(
            r#"
            WITH ranked AS (
                SELECT
                    e.source_id AS paragraph_id,
                    c.id AS atom_id,
                    c.content,
                    c.truth_value,
                    ROW_NUMBER() OVER (PARTITION BY e.source_id ORDER BY c.created_at) AS rn,
                    COUNT(*) OVER (PARTITION BY e.source_id) AS total
                FROM edges e
                JOIN claims c ON c.id = e.target_id
                WHERE e.source_id = ANY($1)
                  AND e.relationship = 'decomposes_to'
                  AND (c.properties->>'level')::int = 3
            )
            SELECT
                paragraph_id AS "paragraph_id!",
                atom_id AS "atom_id!",
                content AS "content!",
                truth_value AS "truth_value!",
                total AS "total!"
            FROM ranked
            WHERE rn <= $2
            "#,
            paragraph_ids,
            atoms_per_paragraph_cap
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            atoms_total_by_paragraph
                .entry(r.paragraph_id)
                .or_insert_with(|| r.total.max(0) as usize);
            atoms_by_paragraph
                .entry(r.paragraph_id)
                .or_default()
                .push(AtomChild {
                    atom_id: r.atom_id,
                    content: r.content,
                    truth_value: r.truth_value,
                    bridge_to_paragraphs: vec![],
                });
        }
    }

    // 5. bridge_to_paragraphs: for each atom in atoms_by_paragraph, find OTHER parents.
    {
        let atom_ids: Vec<Uuid> = atoms_by_paragraph
            .values()
            .flat_map(|v| v.iter().map(|a| a.atom_id))
            .collect();
        if !atom_ids.is_empty() {
            let rows = sqlx::query!(
                r#"
                SELECT e.target_id AS atom_id, e.source_id AS parent_paragraph_id
                FROM edges e
                WHERE e.target_id = ANY($1)
                  AND e.relationship = 'decomposes_to'
                "#,
                &atom_ids
            )
            .fetch_all(pool)
            .await?;
            let mut all_parents: std::collections::HashMap<Uuid, Vec<Uuid>> = Default::default();
            for r in rows {
                all_parents
                    .entry(r.atom_id)
                    .or_default()
                    .push(r.parent_paragraph_id);
            }
            for (paragraph_id, atoms) in atoms_by_paragraph.iter_mut() {
                for atom in atoms.iter_mut() {
                    if let Some(parents) = all_parents.get(&atom.atom_id) {
                        atom.bridge_to_paragraphs = parents
                            .iter()
                            .filter(|p| **p != *paragraph_id)
                            .copied()
                            .collect();
                    }
                }
            }
        }
    }

    // 6. Sibling paragraphs (level=2 sharing the same section).
    {
        let section_ids: Vec<Uuid> = paragraph_to_section.values().copied().collect();
        if !section_ids.is_empty() {
            let rows = sqlx::query!(
                r#"
                SELECT
                    e.source_id AS section_id,
                    e.target_id AS paragraph_id,
                    c.content,
                    c.truth_value
                FROM edges e
                JOIN claims c ON c.id = e.target_id
                WHERE e.source_id = ANY($1)
                  AND e.relationship = 'decomposes_to'
                  AND (c.properties->>'level')::int = 2
                "#,
                &section_ids
            )
            .fetch_all(pool)
            .await?;

            // Group by section_id.
            let mut by_section: std::collections::HashMap<Uuid, Vec<(Uuid, String, f64)>> =
                Default::default();
            for r in rows {
                by_section.entry(r.section_id).or_default().push((
                    r.paragraph_id,
                    r.content,
                    r.truth_value,
                ));
            }

            for (paragraph_id, section_id) in &paragraph_to_section {
                if let Some(group) = by_section.get(section_id) {
                    let other_siblings: Vec<&(Uuid, String, f64)> = group
                        .iter()
                        .filter(|(pid, _, _)| pid != paragraph_id)
                        .collect();
                    siblings_total_by_paragraph.insert(*paragraph_id, other_siblings.len());
                    let truncated: Vec<SiblingParagraph> = other_siblings
                        .iter()
                        .take(siblings_limit as usize)
                        .map(|(pid, content, tv)| SiblingParagraph {
                            paragraph_id: *pid,
                            content: content.clone(),
                            truth_value: *tv,
                        })
                        .collect();
                    siblings_by_paragraph.insert(*paragraph_id, truncated);
                }
            }
        }
    }

    // 7. CORROBORATES: paragraph → ANY direction. Sort by edge strength desc, tie-break truth_value desc.
    {
        let rows = sqlx::query!(
            r#"
            WITH neighbors AS (
                SELECT
                    CASE WHEN e.source_id = ANY($1) THEN e.source_id ELSE e.target_id END AS paragraph_id,
                    CASE WHEN e.source_id = ANY($1) THEN e.target_id ELSE e.source_id END AS neighbor_id,
                    COALESCE((e.properties->>'strength')::float8, 0.0) AS strength
                FROM edges e
                WHERE (e.source_id = ANY($1) OR e.target_id = ANY($1))
                  AND e.relationship = 'CORROBORATES'
            ),
            joined AS (
                SELECT
                    n.paragraph_id, n.neighbor_id, n.strength,
                    c.content, c.truth_value,
                    p.doi AS paper_doi
                FROM neighbors n
                JOIN claims c ON c.id = n.neighbor_id
                LEFT JOIN edges asserts_e
                  ON asserts_e.target_id = c.id
                  AND asserts_e.relationship = 'asserts'
                  AND asserts_e.source_type = 'paper'
                LEFT JOIN papers p ON p.id = asserts_e.source_id
            ),
            ranked AS (
                SELECT *,
                    ROW_NUMBER() OVER (PARTITION BY paragraph_id ORDER BY strength DESC, truth_value DESC) AS rn,
                    COUNT(*) OVER (PARTITION BY paragraph_id) AS total
                FROM joined
            )
            SELECT
                paragraph_id AS "paragraph_id!",
                neighbor_id AS "neighbor_id!",
                content AS "content!",
                strength AS "strength!",
                truth_value AS "truth_value!",
                paper_doi AS "paper_doi?",
                total AS "total!"
            FROM ranked
            WHERE rn <= $2
            "#,
            paragraph_ids,
            i64::from(corroborates_limit)
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            corroborates_total_by_paragraph
                .entry(r.paragraph_id)
                .or_insert_with(|| r.total.max(0) as usize);
            corroborates_by_paragraph
                .entry(r.paragraph_id)
                .or_default()
                .push(CorroboratesEdge {
                    claim_id: r.neighbor_id,
                    content: r.content,
                    similarity: r.strength,
                    paper_doi: r.paper_doi,
                });
        }
    }

    Ok(BatchedContext {
        paragraph_meta,
        paper_meta,
        paragraph_to_section,
        section_meta,
        atoms_by_paragraph,
        atoms_total_by_paragraph,
        siblings_by_paragraph,
        siblings_total_by_paragraph,
        corroborates_by_paragraph,
        corroborates_total_by_paragraph,
    })
}

#[doc(hidden)]
pub mod __test_only {
    pub use super::{fetch_batched_context, BatchedContext, ParagraphCore};
}
