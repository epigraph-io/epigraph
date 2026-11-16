//! The rows behind one Atlas leaf's flow weights (Atlas W7, backlog
//! 7a03f5e4): the read half. The weighting itself is pure and lives in
//! `epigraph_engine::atlas_flow`, beside the belief engine's per-relationship
//! factor it falls back to.
//!
//! Given a leaf W3 assembled ([`LeafNodeSet`]), [`AtlasFlowRepository::read_flow_inputs`]
//! reads, under the map's audience:
//!
//! * the stored strength (`edges.properties -> 'strength'`, raw) of every
//!   stored claim-to-claim edge row of the leaf. A claim-to-claim weight is
//!   the link's strength times its sign and nothing else, so this read selects
//!   no claim column and no belief of any kind;
//! * the evidence-keyed mass rows (`mass_functions.evidence_id`) behind each
//!   evidence-to-claim edge of the leaf: live (not retracted) rows the map's
//!   audience may read, with their frame's hypothesis count and the claim's
//!   hypothesis index on that frame.
//!
//! # Scope: only what the map's audience may read
//!
//! As in [`crate::repos::atlas_leaf`], the build reads on the maintenance
//! connection with a bypass viewer, so every statement carries the MAP
//! predicate as well as the viewer splice:
//!
//! * edges: `visibility = 'public' OR (visibility = 'group' AND
//!   owner_group_id = T AND co_owner_group_id IS NULL)`, the leaf's own edge
//!   rule. The edge ids arrive already filtered by W3; reading them again
//!   under the same rule keeps this read correct on its own, and an id the
//!   read does not return is an error rather than a silent fallback;
//! * `mass_functions`, `frames` and `claim_frames`: `visibility = 'public' OR
//!   (visibility = 'group' AND owner_group_id = T)`. A mass row carries its
//!   own owner: the claim's, or the writer's group for a row attached to a
//!   public claim its writer could not write (migration 114). A row the map's
//!   audience cannot read never contributes;
//! * the public map binds T as NULL, so only public rows pass.
//!
//! Call it on the build's transaction, after
//! [`crate::AtlasMapRepository::begin_build_snapshot`], so the rows come from
//! the snapshot the leaf was read from.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::atlas_leaf::{map_team, LeafEdgeOrigin, LeafNodeKind, LeafNodeSet};
use crate::repos::atlas_map::AtlasMap;
use crate::visibility::Viewer;

/// One evidence-keyed mass row behind an evidence-to-claim edge of a leaf.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceMassRow {
    /// `mass_functions.id`, for a deterministic order.
    pub id: Uuid,
    pub evidence: Uuid,
    pub claim: Uuid,
    pub frame: Uuid,
    /// The frame's number of hypotheses.
    pub hypothesis_count: i32,
    /// `claim_frames.hypothesis_index` for (claim, frame), when the map's
    /// audience may read that row and it holds one.
    pub hypothesis_index: Option<i32>,
    /// `mass_functions.masses` as stored (focal-element keys, `"0"`, `"1"`,
    /// `"0,1"`, ...).
    pub masses: serde_json::Value,
}

/// What the weighting of one leaf reads from the database. Built by
/// [`AtlasFlowRepository::read_flow_inputs`], or by hand in a test.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FlowInputs {
    /// Every stored claim-to-claim edge row of the leaf, by id, with its raw
    /// `properties -> 'strength'` (`None` when the key is absent).
    pub link_strengths: BTreeMap<Uuid, Option<serde_json::Value>>,
    /// The live, readable mass rows keyed by an evidence node of the leaf and
    /// one of its claim nodes that a stored edge links them, sorted by id.
    pub evidence_masses: Vec<EvidenceMassRow>,
}

/// The read half of the leaf flow weights. See the module documentation.
pub struct AtlasFlowRepository;

/// One mass row as the read selects it.
type MassRow = (
    Uuid,
    Uuid,
    Uuid,
    Uuid,
    Option<i32>,
    Option<i32>,
    serde_json::Value,
);

impl AtlasFlowRepository {
    /// The stored link strengths and evidence masses of `set`, read on `conn`
    /// (the build's snapshot transaction) for `map`, spliced on `viewer`. Two
    /// set-based statements, whatever the leaf's size.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if a statement fails; `DbError::InvalidData` if
    /// a stored claim-to-claim edge id of `set` is not readable on `map` (the
    /// set was not read from this map, or not on this snapshot).
    pub async fn read_flow_inputs(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        set: &LeafNodeSet,
    ) -> Result<FlowInputs, DbError> {
        let team = map_team(map);

        let mut claim_edge_ids: BTreeSet<Uuid> = BTreeSet::new();
        let mut pairs: BTreeSet<(Uuid, Uuid)> = BTreeSet::new();
        for e in &set.edges {
            let LeafEdgeOrigin::Stored { edge_ids } = &e.origin else {
                continue;
            };
            match (e.source.kind, e.target.kind) {
                (LeafNodeKind::Claim, LeafNodeKind::Claim) => {
                    claim_edge_ids.extend(edge_ids.iter().copied());
                }
                (LeafNodeKind::Evidence, LeafNodeKind::Claim) => {
                    pairs.insert((e.source.id, e.target.id));
                }
                _ => {}
            }
        }

        // 1. The stored strength of each claim-to-claim edge row: the row's
        //    own property, never a claim or belief column.
        let mut link_strengths: BTreeMap<Uuid, Option<serde_json::Value>> = BTreeMap::new();
        if !claim_edge_ids.is_empty() {
            let ids: Vec<Uuid> = claim_edge_ids.iter().copied().collect();
            let sql = viewer.splice(
                "SELECT e.id, e.properties -> 'strength' \
                   FROM edges e \
                  WHERE e.id = ANY($1) \
                    AND e.source_type = 'claim' AND e.target_type = 'claim' \
                    AND (e.valid_to IS NULL OR e.valid_to > now()) \
                    AND (e.visibility = 'public' \
                         OR ($2::uuid IS NOT NULL AND e.visibility = 'group' \
                             AND e.owner_group_id = $2 AND e.co_owner_group_id IS NULL)) \
                    /* {EDGE_VISIBILITY:e} */",
                3,
            );
            let mut q = sqlx::query_as::<_, (Uuid, Option<serde_json::Value>)>(&sql)
                .bind(&ids)
                .bind(team);
            if let Some(g) = viewer.group_bind() {
                q = q.bind(g);
            }
            link_strengths = q.fetch_all(&mut *conn).await?.into_iter().collect();
            let missing = claim_edge_ids
                .iter()
                .filter(|id| !link_strengths.contains_key(id))
                .count();
            if missing > 0 {
                return Err(DbError::InvalidData {
                    reason: format!(
                        "{missing} claim-to-claim edge row(s) of the Atlas leaf are not \
                         readable on this map; was the leaf read from another map or snapshot?"
                    ),
                });
            }
        }

        // 2. The evidence-keyed mass rows: live, readable by the map's
        //    audience, with the frame's size and the claim's hypothesis index.
        let mut evidence_masses = Vec::new();
        if !pairs.is_empty() {
            let evidence: Vec<Uuid> = pairs.iter().map(|p| p.0).collect();
            let claims: Vec<Uuid> = pairs.iter().map(|p| p.1).collect();
            let sql = viewer.splice(
                "SELECT mf.id, mf.evidence_id, mf.claim_id, mf.frame_id, \
                        array_length(f.hypotheses, 1), cf.hypothesis_index, mf.masses \
                   FROM mass_functions mf \
                   JOIN unnest($1::uuid[], $2::uuid[]) AS p(ev, claim) \
                     ON p.ev = mf.evidence_id AND p.claim = mf.claim_id \
                   JOIN frames f ON f.id = mf.frame_id \
                    AND (f.visibility = 'public' \
                         OR ($3::uuid IS NOT NULL AND f.visibility = 'group' \
                             AND f.owner_group_id = $3)) \
                    /* {VISIBILITY:f} */ \
                   LEFT JOIN claim_frames cf \
                     ON cf.claim_id = mf.claim_id AND cf.frame_id = mf.frame_id \
                    AND (cf.visibility = 'public' \
                         OR ($3::uuid IS NOT NULL AND cf.visibility = 'group' \
                             AND cf.owner_group_id = $3)) \
                    /* {VISIBILITY:cf} */ \
                  WHERE mf.retracted_at IS NULL \
                    AND (mf.visibility = 'public' \
                         OR ($3::uuid IS NOT NULL AND mf.visibility = 'group' \
                             AND mf.owner_group_id = $3)) \
                    /* {VISIBILITY:mf} */ \
                  ORDER BY mf.id",
                4,
            );
            let mut q = sqlx::query_as::<_, MassRow>(&sql)
                .bind(&evidence)
                .bind(&claims)
                .bind(team);
            if let Some(g) = viewer.group_bind() {
                q = q.bind(g);
            }
            for (id, ev, claim, frame, count, index, masses) in q.fetch_all(&mut *conn).await? {
                evidence_masses.push(EvidenceMassRow {
                    id,
                    evidence: ev,
                    claim,
                    frame,
                    // `frames_not_empty` keeps it at 2 or more; 0 reads as "no
                    // usable frame" downstream.
                    hypothesis_count: count.unwrap_or(0),
                    hypothesis_index: index,
                    masses,
                });
            }
        }

        Ok(FlowInputs {
            link_strengths,
            evidence_masses,
        })
    }
}
