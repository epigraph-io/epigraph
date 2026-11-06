//! Which document ingest CREATED a claim, and every ingest that has asserted
//! it since: recorded by the document walk when it writes the claim, never
//! inferred afterwards from `asserts` edges or from content convergence.
//!
//! # Why a record, and why written at creation
//!
//! Atoms are content-addressed: a claim someone filed directly, or a claim an
//! earlier document created, is the SAME row a later document's extraction
//! converges on. So "this paper asserts the claim" (a `paper -asserts-> claim`
//! edge) cannot say whose statement the claim is. Only the walk knows, at the
//! moment it persists the claim, whether it created the row or found it. It
//! writes that here.
//!
//! # Storage: one edge per (paper, claim, ingester)
//!
//! `paper --ingested_claim--> claim`, with properties
//! * [`INGESTED_BY_PROPERTY`]: the ingesting agent (the walk's write
//!   identity, `claims.agent_id` of a claim it creates), as a UUID string;
//! * [`CREATED_CLAIM_PROPERTY`]: `true` only on the ingest that created the
//!   claim, `false` on every later ingest that converged on it;
//! * `tool` (`ingest_document` / `ingest_document_spine`) and `pipeline` (the
//!   walk's pipeline stamp), for the operator.
//!
//! Deduplicated on (paper, claim, ingester): a re-run of the same ingest adds
//! nothing, a second document or a second ingester of the same document adds
//! its own record. An edge, not a new table, so the record carries the
//! tenancy every other edge carries without new machinery: its endpoints are
//! the paper and the claim, so its visibility is the same meet as the paper's
//! `asserts` edge onto the claim (migration 120), it is administrative
//! (`('public', world)` between public endpoints, which no application
//! session may patch or retract), privatization re-meets it, and the
//! elevation arms already cover `edges`. Its endpoints never include the
//! ingester, so a public record names no private paper.
//!
//! Only the walk writes it: `POST /api/v1/edges` and the staged-edge promote
//! refuse [`INGEST_RECORD_RELATIONSHIP`] (with `paper -asserts->` and
//! `authored -> paper`), and no MCP tool writes an arbitrary relationship.
//!
//! # The read contract ([`ClaimIngestRepository::for_claims`])
//!
//! A record counts only while the SAME paper's `asserts` edge onto the claim
//! is in force and readable by the caller: a record without its assertion
//! (the assertion retracted, or hidden from this caller) is not listed.
//! `creator` is the record with `created_claim: true`, when there is one. A
//! claim with no creator record was not created by a document ingest that
//! recorded it (a directly filed claim, or one ingested before this record
//! existed): its filer is its author, and every listed paper corroborates.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::edge::{EdgeRepository, EDGE_IN_FORCE};
use crate::repos::EdgeSigningKey;
use crate::visibility::Viewer;

/// The record's relationship: `paper --ingested_claim--> claim`.
pub const INGEST_RECORD_RELATIONSHIP: &str = "ingested_claim";
/// Record property: the ingesting agent, a UUID string.
pub const INGESTED_BY_PROPERTY: &str = "ingested_by";
/// Record property: `true` only on the ingest that created the claim.
pub const CREATED_CLAIM_PROPERTY: &str = "created_claim";

/// Most claims one [`ClaimIngestRepository::for_claims`] call reads.
pub const FOR_CLAIMS_CAP: usize = 200;
/// Most records listed per claim (oldest first).
pub const RECORDS_PER_CLAIM_CAP: i64 = 50;

/// One ingest of a claim, as [`ClaimIngestRepository::for_claims`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimIngestRecord {
    /// The document whose ingest asserted the claim.
    pub paper_id: Uuid,
    /// The ingesting agent (its human is read from the binding at
    /// `recorded_at` by whoever shows it).
    pub ingested_by: Uuid,
    /// This ingest created the claim (its document's authors are the
    /// claim's primary authors); `false`: it converged on an existing claim.
    pub created_claim: bool,
    /// When the record was written (the ingest's transaction time).
    pub recorded_at: DateTime<Utc>,
}

/// Every readable ingest of one claim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimIngests {
    /// The ingest that created the claim, when it is recorded and readable.
    pub creator: Option<ClaimIngestRecord>,
    /// Every readable record, the creator's included, oldest first, at most
    /// [`RECORDS_PER_CLAIM_CAP`].
    pub records: Vec<ClaimIngestRecord>,
    /// More records exist than were listed.
    pub truncated: bool,
}

pub struct ClaimIngestRepository;

impl ClaimIngestRepository {
    /// Record that `ingested_by`'s ingest of `paper_id` asserted `claim_id`,
    /// and whether it CREATED the claim. Runs on the walk's own transaction,
    /// after the paper's `asserts` edge onto the claim, so the record commits
    /// with the claim and the assertion or not at all. Returns `true` when a
    /// record was written, `false` when this (paper, claim, ingester) was
    /// already recorded (a re-run).
    ///
    /// The dedup probe reads in any state, so a re-run never writes a second
    /// record, and a later re-run never turns a `created_claim: false` record
    /// into a creator.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the probe or the INSERT fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_conn(
        conn: &mut sqlx::PgConnection,
        key: Option<EdgeSigningKey<'_>>,
        paper_id: Uuid,
        claim_id: Uuid,
        ingested_by: Uuid,
        created_claim: bool,
        tool: &str,
        pipeline: &str,
    ) -> Result<bool, DbError> {
        use sqlx::Acquire;
        let mut tx = conn.begin().await?;
        let existing = sqlx::query_scalar::<_, Uuid>(&format!(
            "-- VISIBILITY-EXEMPT: dedup probe inside a WRITE path (the reason \
             `create_if_not_exists_conn` gives): it must see an existing record \
             whoever is asking, or every re-run writes a duplicate.\n\
             SELECT id FROM edges \
              WHERE source_id = $1 AND source_type = 'paper' \
                AND target_id = $2 AND target_type = 'claim' \
                AND relationship = '{INGEST_RECORD_RELATIONSHIP}' \
                AND properties ->> '{INGESTED_BY_PROPERTY}' = $3 \
              LIMIT 1"
        ))
        .bind(paper_id)
        .bind(claim_id)
        .bind(ingested_by.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        if existing.is_some() {
            tx.commit().await?;
            return Ok(false);
        }
        EdgeRepository::create_signed_conn(
            &mut tx,
            key,
            paper_id,
            "paper",
            claim_id,
            "claim",
            INGEST_RECORD_RELATIONSHIP,
            Some(serde_json::json!({
                INGESTED_BY_PROPERTY: ingested_by.to_string(),
                CREATED_CLAIM_PROPERTY: created_claim,
                "tool": tool,
                "pipeline": pipeline,
            })),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Every ingest record of each of `claim_ids` that `viewer` may read
    /// (module doc, "The read contract"). A claim with no readable record
    /// maps to an empty [`ClaimIngests`]. At most [`FOR_CLAIMS_CAP`] claims
    /// per call (the rest are not read).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn for_claims(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, ClaimIngests>, DbError> {
        let ids = &claim_ids[..claim_ids.len().min(FOR_CLAIMS_CAP)];
        let mut out: HashMap<Uuid, ClaimIngests> = ids
            .iter()
            .map(|id| (*id, ClaimIngests::default()))
            .collect();
        if ids.is_empty() {
            return Ok(out);
        }
        let in_force = |alias: &str| EDGE_IN_FORCE.replace("e.", &format!("{alias}."));
        let sql = viewer.splice(
            &format!(
                "SELECT k.claim_id, k.paper_id, k.ingested_by, k.created_claim, \
                        k.recorded_at, k.total \
                   FROM (SELECT r.target_id AS claim_id, r.source_id AS paper_id, \
                                (r.properties ->> '{by}')::uuid AS ingested_by, \
                                COALESCE(r.properties ->> '{created}' = 'true', false) \
                                    AS created_claim, \
                                r.created_at AS recorded_at, \
                                row_number() OVER (PARTITION BY r.target_id \
                                                   ORDER BY r.created_at, r.id) AS n, \
                                count(*) OVER (PARTITION BY r.target_id) AS total \
                           FROM edges r \
                          WHERE r.target_id = ANY($1::uuid[]) AND r.target_type = 'claim' \
                            AND r.source_type = 'paper' \
                            AND r.relationship = '{rel}' \
                            AND r.properties ->> '{by}' ~ \
                                '^[0-9a-fA-F]{{8}}-([0-9a-fA-F]{{4}}-){{3}}[0-9a-fA-F]{{12}}$' \
                            AND {in_force_r} \
                            AND EXISTS ( \
                                SELECT 1 FROM edges a \
                                 WHERE a.source_id = r.source_id AND a.source_type = 'paper' \
                                   AND a.target_id = r.target_id AND a.target_type = 'claim' \
                                   AND a.relationship = 'asserts' AND {in_force_a} \
                                   /* {{EDGE_VISIBILITY:a}} */) \
                            /* {{EDGE_VISIBILITY:r}} */) k \
                  WHERE k.n <= $2 OR k.created_claim \
                  ORDER BY k.claim_id, k.recorded_at, k.paper_id",
                by = INGESTED_BY_PROPERTY,
                created = CREATED_CLAIM_PROPERTY,
                rel = INGEST_RECORD_RELATIONSHIP,
                in_force_r = in_force("r"),
                in_force_a = in_force("a"),
            ),
            3,
        );
        type Row = (Uuid, Uuid, Uuid, bool, DateTime<Utc>, i64);
        let mut q = sqlx::query_as::<_, Row>(&sql)
            .bind(ids)
            .bind(RECORDS_PER_CLAIM_CAP);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        for (claim, paper_id, ingested_by, created_claim, recorded_at, total) in
            q.fetch_all(&mut *conn).await?
        {
            let Some(entry) = out.get_mut(&claim) else {
                continue;
            };
            let record = ClaimIngestRecord {
                paper_id,
                ingested_by,
                created_claim,
                recorded_at,
            };
            if created_claim && entry.creator.is_none() {
                entry.creator = Some(record.clone());
            }
            let listed = i64::try_from(entry.records.len()).unwrap_or(i64::MAX);
            if listed < RECORDS_PER_CLAIM_CAP {
                entry.records.push(record);
            }
            entry.truncated = total > RECORDS_PER_CLAIM_CAP;
        }
        Ok(out)
    }

    /// [`Self::for_claims`] for one claim.
    ///
    /// # Errors
    /// As [`Self::for_claims`].
    pub async fn for_claim(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
    ) -> Result<ClaimIngests, DbError> {
        Ok(Self::for_claims(conn, viewer, &[claim_id])
            .await?
            .remove(&claim_id)
            .unwrap_or_default())
    }
}

/// The relationships a generic edge writer (`POST /api/v1/edges`, the
/// staged-edge promote) may never write, because readers trust them as the
/// document ingest's own record: the paper's `asserts` onto a claim, any
/// `authored` edge into a paper, and [`INGEST_RECORD_RELATIONSHIP`].
/// Matched case-insensitively. Returns the refusal text, or `None`.
#[must_use]
pub fn ingest_only_edge_refusal(
    source_type: &str,
    target_type: &str,
    relationship: &str,
) -> Option<&'static str> {
    let rel = relationship.to_ascii_lowercase();
    let ingest_only = rel == INGEST_RECORD_RELATIONSHIP
        || (rel == "asserts" && source_type == "paper")
        || (rel == "authored" && target_type == "paper");
    ingest_only.then_some(INGEST_ONLY_REFUSAL)
}

/// The refusal [`ingest_only_edge_refusal`] answers.
pub const INGEST_ONLY_REFUSAL: &str =
    "a paper's asserts edge onto a claim, an authored edge into a paper and the \
     ingested_claim record are written only by the document ingest \
     (ingest_document / ingest_document_spine), which records who ingested the \
     document; nothing was written";

/// An edge that attributes words or authorship TO an agent: `asserts` or
/// `authored` (any case) with an `agent` source. A generic writer accepts it
/// only from that agent itself or the human operating it
/// ([`crate::AgentRepository::speaks_for`]).
#[must_use]
pub fn is_agent_attribution(source_type: &str, relationship: &str) -> bool {
    source_type == "agent"
        && (relationship.eq_ignore_ascii_case("asserts")
            || relationship.eq_ignore_ascii_case("authored"))
}

/// The refusal for an agent attribution the caller does not speak for.
pub const AGENT_ATTRIBUTION_REFUSAL: &str =
    "an asserts or AUTHORED edge from an agent may be written only by that agent \
     itself or by the human who operates it through a live binding; nothing was \
     written";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ingest_only_relationships_are_matched_in_any_case_and_nothing_else() {
        for (s, t, r) in [
            ("paper", "claim", "asserts"),
            ("paper", "claim", "ASSERTS"),
            ("paper", "claim", "ingested_claim"),
            ("agent", "claim", "Ingested_Claim"),
            ("agent", "paper", "authored"),
            ("agent", "paper", "AUTHORED"),
            ("claim", "paper", "authored"),
        ] {
            assert!(ingest_only_edge_refusal(s, t, r).is_some(), "{s} {r} {t}");
        }
        for (s, t, r) in [
            ("agent", "claim", "asserts"),
            ("agent", "claim", "AUTHORED"),
            ("claim", "claim", "supports"),
            ("paper", "agent", "processed_by"),
        ] {
            assert!(ingest_only_edge_refusal(s, t, r).is_none(), "{s} {r} {t}");
        }
        assert!(is_agent_attribution("agent", "Asserts"));
        assert!(is_agent_attribution("agent", "AUTHORED"));
        assert!(!is_agent_attribution("paper", "asserts"));
        assert!(!is_agent_attribution("agent", "supports"));
    }
}
