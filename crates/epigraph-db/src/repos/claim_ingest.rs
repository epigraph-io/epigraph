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
//! A record counts only while it carries the ingest-written marker
//! ([`crate::INGEST_WRITTEN_PROPERTY`], naming the same ingester as
//! [`INGESTED_BY_PROPERTY`]) and the SAME paper's `asserts` edge onto the
//! claim, written by the SAME ingest principal (its marker names the
//! record's ingester, `crate::same_ingest_sql`), is in force and readable by
//! the caller. Every ingest principal keeps its own assertion of a fact, so
//! a record is read only on its own ingester's word: a record without it (the
//! assertion retracted, hidden from this caller, or only another principal's)
//! is not listed. A re-ingest whose own assertion could not be written (an
//! unmarked legacy row, or a retracted row, of the same fact stops the
//! writer) therefore records nothing readable.
//!
//! The record is about the row that ingest created or found, never its
//! successor: the supersede, dedup and merge cascades leave every
//! ingest-written edge (the record, the paper's assertion) on the retired row
//! (`claim.rs`, `INGEST_WRITTEN_FROZEN`), so the retired claim keeps its
//! record and its paper, and the successor reads none. Any other UPDATE that
//! re-points one strips its marker (migration 198), so it would not be listed
//! on the claim it then points at.
//!
//! `creator` is the record with `created_claim: true` whose `ingested_by` is
//! the claim's filer (`claims.agent_id`; the walk files every claim it
//! creates), when there is one. A
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

/// The refusal for an application edge write whose `properties` carry
/// [`INGESTED_BY_PROPERTY`] or [`CREATED_CLAIM_PROPERTY`]
/// (`crate::reserved_edge_property_refusal`).
pub const INGEST_RECORD_KEYS_RESERVED: &str =
    "properties.ingested_by and properties.created_claim are reserved for the document \
     ingest's own records (which ingest created a claim, who ingested a document); \
     nothing was written";

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
    /// claim's primary authors): the record says so AND names the claim's
    /// filer as its ingester. `false`: it converged on an existing claim.
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
    /// into a creator. It matches only a record MARKED as this ingester's: an
    /// unmarked row naming the ingester never stops its marked record.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the probe or the INSERT fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_signed_conn(
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
        // Only this ingester's own MARKED record stops the write: an unmarked
        // row naming it (a hand write, or a record re-pointed by an UPDATE,
        // which strips the marker) is not the walk's, and must never withhold
        // the real record.
        let existing = sqlx::query_scalar::<_, Uuid>(&format!(
            "-- VISIBILITY-EXEMPT: dedup probe inside a WRITE path (the reason \
             `create_if_not_exists_conn` gives): it must see an existing record \
             whoever is asking, or every re-run writes a duplicate.\n\
             SELECT e.id FROM edges e \
              WHERE e.source_id = $1 AND e.source_type = 'paper' \
                AND e.target_id = $2 AND e.target_type = 'claim' \
                AND e.relationship = '{INGEST_RECORD_RELATIONSHIP}' \
                AND e.properties ->> '{INGESTED_BY_PROPERTY}' = $3 \
                AND {marker_by} = $3 \
              LIMIT 1",
            marker_by = crate::repos::ingest_written::ingest_written_by_sql("e"),
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
        // Marked as the ingest's (migration 198's guard admits the key only
        // under the declaration, for this INSERT alone), so a record that a
        // cascade later re-points onto another claim loses the mark and stops
        // counting (the read contract).
        crate::repos::ingest_written::declare_ingest_written(&mut tx, true).await?;
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
                (crate::repos::ingest_written::INGEST_WRITTEN_PROPERTY):
                    crate::repos::ingest_written::ingest_written_marker(tool, ingested_by),
            })),
            None,
            None,
        )
        .await?;
        crate::repos::ingest_written::declare_ingest_written(&mut tx, false).await?;
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
                                (COALESCE(r.properties ->> '{created}' = 'true', false) \
                                 AND c.agent_id = (r.properties ->> '{by}')::uuid) \
                                    AS created_claim, \
                                r.created_at AS recorded_at, \
                                row_number() OVER (PARTITION BY r.target_id \
                                                   ORDER BY r.created_at, r.id) AS n, \
                                count(*) OVER (PARTITION BY r.target_id) AS total \
                           FROM edges r \
                           JOIN claims c ON c.id = r.target_id \
                          WHERE r.target_id = ANY($1::uuid[]) AND r.target_type = 'claim' \
                            AND r.source_type = 'paper' \
                            AND r.relationship = '{rel}' \
                            AND r.properties ->> '{by}' ~ \
                                '^[0-9a-fA-F]{{8}}-([0-9a-fA-F]{{4}}-){{3}}[0-9a-fA-F]{{12}}$' \
                            AND {marked_r} \
                            AND {marker_by_r} = r.properties ->> '{by}' \
                            AND {in_force_r} \
                            AND EXISTS ( \
                                SELECT 1 FROM edges a \
                                 WHERE a.source_id = r.source_id AND a.source_type = 'paper' \
                                   AND a.target_id = r.target_id AND a.target_type = 'claim' \
                                   AND a.relationship = 'asserts' AND {in_force_a} \
                                   AND {marked_a} AND {same_ingest_ar} \
                                   /* {{EDGE_VISIBILITY:a}} */) \
                            /* {{EDGE_VISIBILITY:r}} */ \
                            /* {{VISIBILITY:c}} */) k \
                  WHERE k.n <= $2 OR k.created_claim \
                  ORDER BY k.claim_id, k.recorded_at, k.paper_id",
                by = INGESTED_BY_PROPERTY,
                created = CREATED_CLAIM_PROPERTY,
                rel = INGEST_RECORD_RELATIONSHIP,
                in_force_r = in_force("r"),
                in_force_a = in_force("a"),
                marked_r = crate::repos::ingest_written::ingest_written_edge_sql("r"),
                marker_by_r = crate::repos::ingest_written::ingest_written_by_sql("r"),
                marked_a = crate::repos::ingest_written::ingest_written_edge_sql("a"),
                same_ingest_ar = crate::repos::ingest_written::same_ingest_sql("a", "r"),
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
/// document ingest's own record: the paper's `asserts` onto a claim (or its
/// `authored`, a paper being the source of neither in any other writer), any
/// `authored` edge into a paper, and [`INGEST_RECORD_RELATIONSHIP`]. Matched
/// case-insensitively. Returns the refusal text, or `None`.
#[must_use]
pub fn ingest_only_edge_refusal(
    source_type: &str,
    target_type: &str,
    relationship: &str,
) -> Option<&'static str> {
    let rel = relationship.to_ascii_lowercase();
    let ingest_only = rel == INGEST_RECORD_RELATIONSHIP
        || (source_type == "paper" && (rel == "asserts" || rel == "authored"))
        || (rel == "authored" && target_type == "paper");
    ingest_only.then_some(INGEST_ONLY_REFUSAL)
}

/// The refusal [`ingest_only_edge_refusal`] answers.
pub const INGEST_ONLY_REFUSAL: &str =
    "a paper's asserts or authored edge, an authored edge into a paper and the \
     ingested_claim record are written only by the document ingest \
     (ingest_document / ingest_document_spine), which records who ingested the \
     document; nothing was written";

/// Relationships (lower-cased) that, FROM an `agent`, credit that agent with
/// the target's content: it asserted, authored or generated it.
pub const AGENT_SOURCE_AUTHORSHIP: &[&str] = &["asserts", "authored", "generated"];

/// Relationships (lower-cased) that, TO an `agent`, credit that agent with
/// the source's content: the source is attributed to, authored by,
/// originated by, amplified (repeated or endorsed) by, generated by or
/// interpreted by the agent. The reverse spellings of the same fact as
/// [`AGENT_SOURCE_AUTHORSHIP`], and what `GET /api/v1/agents/:id/claims`
/// (`attributed_to`) and the political-monitoring reads (`ORIGINATED_BY`,
/// `AMPLIFIED_BY`) list as the agent's.
pub const AGENT_TARGET_AUTHORSHIP: &[&str] = &[
    "attributed_to",
    "authored_by",
    "originated_by",
    "amplified_by",
    "generated_by",
    "interpreted_by",
];

/// Which endpoint of an edge an authorship-bearing relationship credits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditedEnd {
    /// The source agent ([`AGENT_SOURCE_AUTHORSHIP`]).
    Source,
    /// The target agent ([`AGENT_TARGET_AUTHORSHIP`]).
    Target,
}

/// The agent endpoint an edge credits with content, when it does: an
/// [`AGENT_SOURCE_AUTHORSHIP`] relationship from an `agent`, or an
/// [`AGENT_TARGET_AUTHORSHIP`] relationship to one (any case). A generic
/// writer accepts such an edge only from that agent itself or the human
/// operating it ([`crate::AgentRepository::speaks_for`]); the staged promote,
/// which has no caller to ask, refuses it.
#[must_use]
pub fn credited_agent_end(
    source_type: &str,
    target_type: &str,
    relationship: &str,
) -> Option<CreditedEnd> {
    let rel = relationship.to_ascii_lowercase();
    if source_type == "agent" && AGENT_SOURCE_AUTHORSHIP.contains(&rel.as_str()) {
        Some(CreditedEnd::Source)
    } else if target_type == "agent" && AGENT_TARGET_AUTHORSHIP.contains(&rel.as_str()) {
        Some(CreditedEnd::Target)
    } else {
        None
    }
}

/// An edge that attributes words or authorship TO an agent through its
/// source: [`credited_agent_end`] is [`CreditedEnd::Source`]. Kept for the
/// callers that ask only about the source.
#[must_use]
pub fn is_agent_attribution(source_type: &str, relationship: &str) -> bool {
    source_type == "agent"
        && AGENT_SOURCE_AUTHORSHIP.contains(&relationship.to_ascii_lowercase().as_str())
}

/// The refusal for an authorship-bearing edge ([`credited_agent_end`]) whose
/// credited agent the caller does not speak for.
pub const AGENT_ATTRIBUTION_REFUSAL: &str =
    "an edge that credits an agent with content (asserts, authored or generated \
     from it; attributed_to, authored_by, originated_by, amplified_by, \
     generated_by or interpreted_by onto it) may be written only by that agent \
     itself or by the human who operates it through a live binding; attribute a \
     third party's document through the document ingest, which records it as \
     pending their countersignature; nothing was written";

/// The operator link's own edge (`agent -OPERATED_BY-> human`): written only
/// when a link is recorded, never by a generic writer.
pub const OPERATED_BY_RELATIONSHIP: &str = "operated_by";

/// The refusal for a generic write of [`OPERATED_BY_RELATIONSHIP`].
pub const OPERATED_BY_REFUSAL: &str =
    "OPERATED_BY edges are written only when an operator link is recorded; a generic \
     edge writer never writes one (whoever operates an agent is read from the link \
     itself); nothing was written";

/// SQL over the unaliased columns of a staged edge (`source_type`,
/// `target_type`, `relationship`): true for every row a generic promote must
/// refuse as provenance only the ingest, the link path or the credited agent
/// writes. The same sets as [`ingest_only_edge_refusal`],
/// [`credited_agent_end`] and [`OPERATED_BY_RELATIONSHIP`].
#[must_use]
pub fn staged_provenance_refusal_sql() -> String {
    let list = |xs: &[&str]| {
        xs.iter()
            .map(|x| format!("'{x}'"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "(lower(relationship) IN ('{rec}', '{op}') \
          OR (source_type = 'paper' AND lower(relationship) IN ('asserts', 'authored')) \
          OR (target_type = 'paper' AND lower(relationship) = 'authored') \
          OR (source_type = 'agent' AND lower(relationship) IN ({src})) \
          OR (target_type = 'agent' AND lower(relationship) IN ({tgt})))",
        rec = INGEST_RECORD_RELATIONSHIP,
        op = OPERATED_BY_RELATIONSHIP,
        src = list(AGENT_SOURCE_AUTHORSHIP),
        tgt = list(AGENT_TARGET_AUTHORSHIP),
    )
}

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
            ("paper", "claim", "AUTHORED"),
            ("paper", "agent", "Authored"),
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
        for key in [INGESTED_BY_PROPERTY, CREATED_CLAIM_PROPERTY] {
            assert_eq!(
                crate::reserved_edge_property_refusal(&serde_json::json!({ key: true })),
                Some(INGEST_RECORD_KEYS_RESERVED),
                "{key} is reserved for generic writers"
            );
            assert!(crate::RESERVED_EDGE_PROPERTIES.contains(&key), "{key}");
        }
        assert_eq!(
            crate::reserved_edge_property_refusal(&serde_json::json!({ "note": 1 })),
            None
        );
        assert!(is_agent_attribution("agent", "Asserts"));
        assert!(is_agent_attribution("agent", "AUTHORED"));
        assert!(!is_agent_attribution("paper", "asserts"));
        assert!(!is_agent_attribution("agent", "supports"));
    }

    #[test]
    fn every_spelling_of_an_agents_authorship_names_the_credited_end() {
        for (s, t, r) in [
            ("agent", "claim", "asserts"),
            ("agent", "claim", "AUTHORED"),
            ("agent", "claim", "generated"),
        ] {
            assert_eq!(
                credited_agent_end(s, t, r),
                Some(CreditedEnd::Source),
                "{s} {r} {t}"
            );
        }
        for r in [
            "attributed_to",
            "ATTRIBUTED_TO",
            "authored_by",
            "ORIGINATED_BY",
            "AMPLIFIED_BY",
            "GENERATED_BY",
            "interpreted_by",
        ] {
            assert_eq!(
                credited_agent_end("claim", "agent", r),
                Some(CreditedEnd::Target),
                "{r}"
            );
        }
        for (s, t, r) in [
            ("claim", "agent", "asserts"),
            ("agent", "claim", "attributed_to"),
            ("claim", "claim", "GENERATED_BY"),
            ("activity", "agent", "associated_with"),
            ("agent", "agent", "AFFILIATED_WITH"),
            ("span", "claim", "generated"),
        ] {
            assert_eq!(credited_agent_end(s, t, r), None, "{s} {r} {t}");
        }
        let sql = staged_provenance_refusal_sql();
        for needle in [
            "'ingested_claim'",
            "'operated_by'",
            "'generated'",
            "'amplified_by'",
        ] {
            assert!(sql.contains(needle), "{needle} in {sql}");
        }
    }
}
