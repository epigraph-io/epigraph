//! The two audited widening acts of migration 206 (re-stated by 215),
//! `publicize_claims` and `share_claims_with_team`, with the moved claims'
//! cached belief refolded for their new audience in the same transaction
//! (backlog 31285392; spec `docs/tenancy/share-with-team.md` section 4.6,
//! "The DS cache").
//!
//! # Why the act is not done when the definer returns
//!
//! A claim's cached belief (`claims.belief`, `plausibility`, `pignistic_prob`,
//! `mass_on_empty`, `mass_on_missing`, `classification`) is read by everyone
//! who can read the claim, so it may fold a BBA only when every source of that
//! BBA is at least as widely readable as the claim
//! ([`crate::derivation_scope::retain_for_cache`]). Both acts widen the
//! claim's audience: publicize to every reader, share from the home group to
//! a team. A value folded under the OLD tenancy can include a BBA citing
//! evidence that stays behind (a pinned row, migration 110) or an edge-factor
//! BBA from a source the new audience cannot read, and serving it leaks the
//! direction and weight of that source through the number.
//!
//! The fold runs in Rust, so the definer cannot do it (migration 114 records
//! why a definer takes cache values from its caller). These functions are the
//! ONE entry point both transports call (MCP `tools::visibility`, REST
//! `routes::claim_visibility`): the definer, then, for every moved claim,
//! [`edge_factor::recompute_widened_claim_cached_belief`], whose fold of the
//! cache-owner frame admits only what the moved claim's new audience may
//! read. The owner is the frame the cache records, kept through the act and
//! not re-elected. When the owner frame has inputs and none of them is
//! admissible, the cache is vacated (the full-ignorance value) even if ANOTHER
//! frame of the claim still has an admissible input: the cached value is the
//! owner frame's old fold, and the act has just widened who is served it. (An
//! ordinary recompute vacates only when no frame has an admissible input, and
//! its owner rule puts a frame with an admissible input first.) The caller
//! commits after both, so the act and the refold commit together or not at
//! all.
//!
//! # `truth_value`
//!
//! Several writers persist `claims.truth_value` as a copy of the fold they
//! just cached (`submit_claim`, `update_with_evidence`), and a later recompute
//! of the cache leaves that copy as it was. So `truth_value` can carry the
//! same inadmissible BBA as the old cache, and readers that order or filter
//! on it (recall's fallback among them) would serve its influence to the new
//! audience (backlog 0d9dfd24). Whenever the refold writes the cache, the act
//! therefore sets `truth_value` to the refolded BetP in the same transaction
//! (`ClaimRepository::mirror_refolded_cache_into_truth_conn`, which states
//! the claims it leaves alone). A copy is not told apart from an authored
//! value: an authored confidence (`memorize`) is replaced by the admissible
//! fold, which still contains the author's own seed BBA. Workflow, step and
//! procedural claims are written too: `report_workflow_outcome` persists the
//! same fold copy, and an outcome track kept without a BBA (the REST outcome
//! route) is derived from reports the new audience may not read. Only a
//! value at the deprecation marker (0.05) is kept, current or not: it is a
//! retirement or a step's soft delete, not a fold, and carries no input.
//!
//! # Scoped beliefs
//!
//! Migration 215 deletes a moved claim's `ds_combined_beliefs` and
//! `ds_bayesian_divergence` rows as folded for the old audience. The act then
//! writes the claim's `ds_combined_beliefs` rows afresh, at the keys it had
//! before the act and for the new audience
//! ([`crate::scoped_belief::refresh_scoped_beliefs`]: `global` and
//! `perspective` scopes, each best-effort under its own savepoint as the REST
//! route writes them), so a scoped read right after the act finds a value
//! (backlog 4d8df0cf). A key with nothing admissible left gets no row.
//!
//! # The Beta track
//!
//! The claim's Beta-Bernoulli track (`claims.beta_alpha` / `beta_beta`) is
//! read by everyone who can read the claim, and its posterior is what the
//! claim's next live evidence write returns to its writer and records in a
//! `ds_bayesian_divergence` row. It was accumulated from every BBA the OLD
//! audience could read, so it can count a BBA citing evidence that stays
//! behind (backlog 6e4ff46e). The act therefore rebuilds it for every moved
//! claim, in the same transaction: back to the `Beta(1, 1)` prior, then every
//! BBA a live writer counts that may enter the claim's cache under its new
//! tenancy, oldest first
//! ([`crate::ds_divergence::rebuild_beta_track`], which states where the
//! rebuilt track differs from the live count). A moved claim with nothing
//! admissible to count is back at the prior, so its next live write is a cold
//! start and records no divergence row.
//!
//! # An operated agent is refused in the definer (migration 242)
//!
//! Neither act runs on an operated agent's own authority (share-with-team
//! spec ruling R1, backlog ecd842bf): when the session principal belongs to
//! another agent (`epigraph_human_of(principal, false)`: a live or retired
//! operator link, or a client allowance), 242's definers classify every
//! readable claim `refused_not_human` and the call changes nothing,
//! whatever memberships the agent holds itself. Its human makes the same
//! call. That is the definer's decision, not this module's: both transports
//! reach it through these functions, and a caller that skipped them would
//! still meet it.
//!
//! # Fail closed when the session cannot write the moved claim
//!
//! The refold writes `claims` on the caller's stamped session, under row
//! security. If the session cannot write a moved claim after the move, the
//! refold would silently match nothing and the stale value would be served to
//! the new audience. Every moved claim must therefore be in the session's
//! writable groups; if one is not, the act is refused
//! ([`RefusalKind::Authority`]) and, because the caller then drops the
//! transaction, nothing is changed.
//!
//! Under 215 this was reachable: a share admitted a target team the caller
//! wrote only through its live human (`epigraph_writable_teams`
//! `via = 'operator'`), which the caller's own stamp does not carry. Under 242
//! the operated caller is refused first and share admits `via = 'own'` only,
//! so no shipped path reaches the check; it stays as a backstop against a
//! future definer that admits a target the session does not write.
//!
//! # What is not refolded here (residuals)
//!
//! * A claim with no cache-owner frame (only ingest template rows, or a
//!   non-procedural compound) is left as `recompute_claim_cached_belief` leaves
//!   it: unchanged.
//! * A claim whose owner frame has only inadmissible rows while ANOTHER frame
//!   still has an admissible one is vacated, not refolded from that other
//!   frame: the act keeps the recorded owner
//!   (`MassFunctionRepository::cache_owner_frame_keeping_recorded`). The
//!   claim's next ordinary recompute hands the cache to that other frame
//!   (the admissible-first owner rule, backlog 8d720490 (1)).
//! * `claims.truth_value` follows the refold only where the cache was
//!   written. A claim the refold leaves unchanged (the first item: a
//!   template-only claim, a non-procedural compound) keeps its `truth_value`,
//!   which can still carry an input the new audience cannot read (a value a
//!   propagation wrote); there is no admissible fold to replace it with here.
//!   A claim at the deprecation marker keeps it (see "`truth_value`").
//! * Claims moved by 206 before this ran keep the value folded then. Claims
//!   moved before the Beta-track rebuild existed keep the track they carried
//!   (see "The Beta track") until an operator runs the one-off
//!   [`rebuild_moved_beta_tracks`] (the `rebuild_moved_beta_tracks` binary):
//!   the act rebuilds only the claims it moves.
//! * A live evidence write racing the act. The act locks each claim row
//!   `FOR NO KEY UPDATE`, which does not block the evidence write's
//!   foreign-key check, so its `mass_functions` row can be stamped with the
//!   claim's OLD tenancy and its track increment then wait for the act and
//!   land on the rebuilt track: one inadmissible increment served to the new
//!   audience. The cache refold has the same window. The next act on the
//!   claim, or [`rebuild_moved_beta_tracks`] (which locks `FOR UPDATE`),
//!   clears it.
//! * A `community` scoped row is not written afresh: its fold reads the
//!   community's members and mass override on the raw pool. It stays absent
//!   until the next computation that stores it.
//! * `ds_bayesian_divergence` rows are not written afresh. A row records one
//!   evidence write (the BetP after it against the posterior after it), and
//!   the act is not one; the claim's next live evidence write records its row
//!   against the rebuilt track (see "The Beta track").
//!
//! # Selections and dry runs (backlog 02d9e9a1)
//!
//! Besides an explicit id list, either act takes a [`Selection`]: a root
//! claim, the edge types to follow (default `decomposes_to` and `supports`),
//! a direction (default `outgoing`) and a depth (default 3, at most 10).
//! [`plan`] walks it on the caller's own stamped connection, through
//! [`EdgeRepository::claim_neighbors_for_selection`] (the caller's viewer:
//! a claim or edge the caller cannot read is never followed or named), and
//! asks the act's own definer how it would classify every claim it reaches
//! ([`ClaimRepository::preview_publicize_conn`] /
//! [`ClaimRepository::preview_share_with_team_conn`], which never act). So the
//! walk decides nothing about authority: a claim the definer would move joins
//! the plan and the walk goes on from it (for publicize, an `already_public`
//! claim too); any other claim is a BOUNDARY, reported with the definer's
//! reason and not walked through, and so is a superseded claim
//! (`not_current`). Boundaries are reported, never moved.
//!
//! [`act`] then hands the planned claims to [`publicize_claims`] /
//! [`share_claims_with_team`] unchanged: the same definer, the same cascade
//! per claim, the same refold, all or nothing, one audit row naming every
//! moved id. A plan over [`MAX_ACT_CLAIMS`] claims, or a walk that reaches
//! more than [`MAX_WALK_CLAIMS`] claims in all, is refused whole. A root the
//! caller cannot read answers as a missing claim, exactly as the id form
//! does. `dry_run` returns the plan and changes nothing (the previews roll
//! back to a savepoint, and the transports drop the transaction). When the
//! act would run, the dry run also runs it once inside a savepoint it rolls
//! back, and reports what it did to the planned claims' edges and evidence
//! as far as the caller can read them ([`PlanEffects`]: edges widened or
//! kept as narrow, evidence moved or kept behind).
//!
//! Workflow lineages are not walked (their moves stay an operator act).

use std::collections::{HashMap, HashSet};

use epigraph_db::errors::RefusalKind;
use epigraph_db::{
    ClaimRepository, DbError, EdgeRepository, EvidenceRepository, ScopedBeliefRepository,
    VisibilityActOutcome,
};
use uuid::Uuid;

use crate::edge_factor;
use crate::scoped_belief::{self, ScopeKey};

/// Why [`publicize_claims`] or [`share_claims_with_team`] did not complete.
#[derive(Debug, thiserror::Error)]
pub enum VisibilityActError {
    /// The definer refused or failed, or the session cannot write a moved
    /// claim (a [`DbError::Refused`]). Map it as the transport maps any
    /// visibility refusal.
    #[error(transparent)]
    Db(#[from] DbError),
    /// The refold of a moved claim's cached belief, or the rebuild of its
    /// Beta track, failed. The act must not commit.
    #[error("cached belief recompute after the act: {0}")]
    Cache(String),
}

/// `publicize_claims` (migration 215 section 4), then the refold of every
/// claim it publicized. See the module doc.
///
/// # Errors
/// [`VisibilityActError::Db`] for every refusal of the act (nothing changed),
/// [`VisibilityActError::Cache`] when a refold fails. On either, the caller
/// must drop the transaction.
pub async fn publicize_claims(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_ids: &[Uuid],
    reason: &str,
) -> Result<Vec<VisibilityActOutcome>, VisibilityActError> {
    let scoped = scoped_keys(&mut *conn, viewer, claim_ids).await?;
    let outcomes = ClaimRepository::publicize_conn(&mut *conn, claim_ids, reason).await?;
    refold_moved(
        &mut *conn,
        viewer,
        "publicize_claims",
        &outcomes,
        "publicized",
        &scoped,
    )
    .await?;
    Ok(outcomes)
}

/// `share_claims_with_team` (migration 215 section 5), then the refold of
/// every claim it shared. See the module doc.
///
/// # Errors
/// As [`publicize_claims`].
pub async fn share_claims_with_team(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_ids: &[Uuid],
    group_id: Uuid,
    reason: &str,
) -> Result<Vec<VisibilityActOutcome>, VisibilityActError> {
    let scoped = scoped_keys(&mut *conn, viewer, claim_ids).await?;
    let outcomes =
        ClaimRepository::share_with_team_conn(&mut *conn, claim_ids, group_id, reason).await?;
    refold_moved(
        &mut *conn,
        viewer,
        "share_claims_with_team",
        &outcomes,
        "shared",
        &scoped,
    )
    .await?;
    Ok(outcomes)
}

/// The `ds_combined_beliefs` keys of each of `claim_ids` the caller reads,
/// before the act deletes them (migration 215), so that [`refold_moved`]
/// writes the same keys afresh for the new audience.
async fn scoped_keys(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<ScopeKey>>, VisibilityActError> {
    let mut keys: HashMap<Uuid, Vec<ScopeKey>> = HashMap::new();
    for &claim_id in claim_ids {
        if keys.contains_key(&claim_id) {
            continue;
        }
        let mut rows: Vec<ScopeKey> =
            ScopedBeliefRepository::list_for_claim(&mut *conn, viewer, claim_id)
                .await?
                .into_iter()
                .map(|r| (r.frame_id, r.scope_type, r.scope_id))
                .collect();
        rows.sort();
        rows.dedup();
        keys.insert(claim_id, rows);
    }
    Ok(keys)
}

/// Refold the cached belief of every claim the act reported `moved_outcome`
/// for, refusing first if the session cannot write one of them, then write
/// its scoped rows afresh at the keys it had before the act (`scoped`).
async fn refold_moved(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    act: &str,
    outcomes: &[VisibilityActOutcome],
    moved_outcome: &str,
    scoped: &HashMap<Uuid, Vec<ScopeKey>>,
) -> Result<(), VisibilityActError> {
    let moved: Vec<Uuid> = outcomes
        .iter()
        .filter(|o| o.outcome == moved_outcome)
        .map(|o| o.claim_id)
        .collect();
    if moved.is_empty() {
        return Ok(());
    }
    let unwritable = ClaimRepository::claims_not_writable_on_session(&mut *conn, &moved).await?;
    if !unwritable.is_empty() {
        let ids = unwritable
            .iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(DbError::Refused {
            kind: RefusalKind::Authority,
            message: format!(
                "{act}: refused, and nothing was changed: this session does not itself write \
                 the group that would own {ids}, so their cached belief cannot be recomputed \
                 for the new audience. Make the call as a member who writes that group."
            ),
        }
        .into());
    }
    for claim_id in moved {
        let written =
            edge_factor::recompute_widened_claim_cached_belief(&mut *conn, viewer, claim_id)
                .await
                .map_err(VisibilityActError::Cache)?;
        // The Beta track, rebuilt from the evidence the new audience may read
        // (see the module doc, "The Beta track"). For every moved claim, with
        // or without a cache-owner frame: the track is served either way.
        let track = crate::ds_divergence::rebuild_beta_track(&mut *conn, viewer, claim_id)
            .await
            .map_err(|e| VisibilityActError::Cache(format!("Beta track: {e}")))?;
        tracing::debug!(%claim_id, ?track, "{act}: Beta track rebuilt");
        // `truth_value` may be a copy of the cache as folded for the OLD
        // audience (see the module doc, "truth_value"): replace it with the
        // refolded value, which is admissible by construction.
        if written {
            ClaimRepository::mirror_refolded_cache_into_truth_conn(&mut *conn, viewer, claim_id)
                .await?;
        }
        // The scoped rows the definer deleted as stale, folded for the new
        // audience (see the module doc, "Scoped beliefs").
        if let Some(keys) = scoped.get(&claim_id).filter(|k| !k.is_empty()) {
            let report = scoped_belief::refresh_scoped_beliefs(&mut *conn, viewer, claim_id, keys)
                .await
                .map_err(VisibilityActError::Cache)?;
            tracing::debug!(%claim_id, ?report, "{act}: scoped beliefs recomputed");
        }
    }
    Ok(())
}

/// One moved claim's Beta track as [`rebuild_moved_beta_tracks`] found and
/// rebuilt it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct MovedTrack {
    /// The claim.
    pub claim_id: Uuid,
    /// `(beta_alpha, beta_beta)` before, a `NULL` read as the prior.
    pub before: (f64, f64),
    /// `(beta_alpha, beta_beta)` rebuilt.
    pub after: (f64, f64),
    /// BBAs the rebuild counted (admissible for the claim's audience).
    pub counted: usize,
    /// Counted-method BBAs the rebuild left out (inadmissible or unparsable).
    pub left_out: usize,
    /// `ds_bayesian_divergence` rows of the claim deleted.
    pub divergence_rows_cleared: u64,
}

/// What [`rebuild_moved_beta_tracks`] did.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MovedTracksReport {
    /// Whether the rebuilt tracks were committed (`false`: a dry run, every
    /// claim's transaction rolled back).
    pub applied: bool,
    /// Distinct claims the act audit rows name.
    pub moved_claims: usize,
    /// Every claim rebuilt (or, in a dry run, that would be).
    pub rebuilt: Vec<MovedTrack>,
    /// Claims an audit row names that no longer exist.
    pub missing: Vec<Uuid>,
    /// Claims whose rebuild failed, with the error; each rolled back alone.
    pub failed: Vec<(Uuid, String)>,
}

/// The one-off rebuild of the Beta track of every claim a widening act moved
/// BEFORE the act rebuilt it (backlog 6e4ff46e, "The Beta track" in the
/// module doc): claims an act moved before this code was deployed still carry
/// the track their old audience's evidence built, and serve it to the new
/// audience.
///
/// The claims are the ones named by the act audit rows
/// (`security_events`, `claim.publicized` and `claim.shared_with_team`,
/// `details.claim_ids`), restricted to acts recorded before `moved_before`
/// when it is given (the deploy time: a claim moved after it was rebuilt by
/// its act). For each, in its own transaction:
///
/// * the claim row is locked `FOR UPDATE`, which also blocks a live evidence
///   write's foreign-key check, so no increment lands between the rebuild's
///   read and its write;
/// * its track is rebuilt by [`crate::ds_divergence::rebuild_beta_track`],
///   the act's own rebuild, for the claim's CURRENT tenancy;
/// * every `ds_bayesian_divergence` row of the claim is deleted, as the
///   widening definers delete them when they move a claim (migration 242):
///   each row a live write recorded since the move compared against the
///   leaky track, and it is served to the new audience.
///
/// Without `apply` every transaction is rolled back, so the report states
/// what an applying run would write and nothing changes. A claim that no
/// longer exists is reported and skipped; a claim whose rebuild fails is
/// reported, rolled back alone, and the run goes on.
///
/// Must run on a maintenance connection with a bypass viewer: the audit rows,
/// the claims and their evidence span every owner.
///
/// # Errors
/// A refused (non-bypass) viewer, or a database error outside one claim's
/// rebuild (the audit read, a transaction that cannot begin or end).
pub async fn rebuild_moved_beta_tracks(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    moved_before: Option<chrono::DateTime<chrono::Utc>>,
    apply: bool,
) -> Result<MovedTracksReport, DbError> {
    use sqlx::Connection;
    if !viewer.is_bypass() {
        return Err(DbError::Refused {
            kind: RefusalKind::Authority,
            message: "rebuild_moved_beta_tracks runs across every owner: it needs a \
                      maintenance connection and a bypass viewer"
                .to_string(),
        });
    }
    let claim_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT c.id::uuid \
           FROM security_events e \
          CROSS JOIN LATERAL jsonb_array_elements_text( \
                CASE WHEN jsonb_typeof(e.details -> 'claim_ids') = 'array' \
                     THEN e.details -> 'claim_ids' ELSE '[]'::jsonb END) AS c(id) \
          WHERE e.event_type IN ('claim.publicized', 'claim.shared_with_team') \
            AND e.success \
            AND ($1::timestamptz IS NULL OR e.created_at < $1::timestamptz) \
          ORDER BY 1",
    )
    .bind(moved_before)
    .fetch_all(&mut *conn)
    .await?;

    let mut report = MovedTracksReport {
        applied: apply,
        moved_claims: claim_ids.len(),
        ..MovedTracksReport::default()
    };
    for claim_id in claim_ids {
        let mut tx = conn.begin().await?;
        let before: Option<(f64, f64)> = sqlx::query_as(
            "SELECT COALESCE(beta_alpha, 1.0)::float8, COALESCE(beta_beta, 1.0)::float8 \
               FROM claims WHERE id = $1 FOR UPDATE",
        )
        .bind(claim_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(before) = before else {
            tx.rollback().await?;
            report.missing.push(claim_id);
            continue;
        };
        let rebuilt =
            match crate::ds_divergence::rebuild_beta_track(&mut tx, viewer, claim_id).await {
                Ok(track) => track,
                Err(e) => {
                    tx.rollback().await?;
                    tracing::warn!(%claim_id, "moved-claim Beta-track rebuild failed: {e}");
                    report.failed.push((claim_id, e));
                    continue;
                }
            };
        let cleared = sqlx::query("DELETE FROM ds_bayesian_divergence WHERE claim_id = $1")
            .bind(claim_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if apply {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        report.rebuilt.push(MovedTrack {
            claim_id,
            before,
            after: rebuilt.params,
            counted: rebuilt.counted,
            left_out: rebuilt.left_out,
            divergence_rows_cleared: cleared,
        });
    }
    Ok(report)
}

// ── Selections and dry runs (backlog 02d9e9a1; module doc) ──────────────────

/// The most claims one act moves: the definers' own cap (migration 206).
pub const MAX_ACT_CLAIMS: usize = 500;

/// The most claims a selection walk reaches (moved and boundaries) before it
/// stops as capped. Bounds the walk's reads and previews.
pub const MAX_WALK_CLAIMS: usize = 2_000;

/// The deepest a selection walks.
pub const MAX_SELECTION_DEPTH: u32 = 10;

/// A selection's depth when it names none.
pub const DEFAULT_SELECTION_DEPTH: u32 = 3;

/// The edge types a selection follows when it names none.
pub const DEFAULT_SELECTION_EDGE_TYPES: &[&str] = &["decomposes_to", "supports"];

/// The claim-to-claim relationships a selection may follow: the structural
/// and epistemic links that put claims into one body of work. `supersedes`
/// (a version chain), the contradiction edges and the paper and workflow
/// links are not among them.
pub const SELECTION_EDGE_TYPES: &[&str] = &[
    "decomposes_to",
    "supports",
    "corroborates",
    "elaborates",
    "specializes",
    "generalizes",
    "refines",
    "section_follows",
    "continues_argument",
];

/// Which way a selection follows an edge from a claim it has reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectionDirection {
    /// From the edge's source to its target (`R decomposes_to C`: R to C).
    Outgoing,
    /// From the edge's target to its source (`E supports R`: R to E).
    Incoming,
    /// Both.
    Both,
}

impl SelectionDirection {
    /// `outgoing`, `incoming` or `both`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "outgoing" => Some(Self::Outgoing),
            "incoming" => Some(Self::Incoming),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    const fn outgoing(self) -> bool {
        matches!(self, Self::Outgoing | Self::Both)
    }

    const fn incoming(self) -> bool {
        matches!(self, Self::Incoming | Self::Both)
    }
}

/// A root claim and the closure to walk from it (module doc, "Selections").
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Selection {
    /// The claim the walk starts from; part of the plan if the act may move it.
    pub root: Uuid,
    /// Relationships followed, canonical spelling, each in
    /// [`SELECTION_EDGE_TYPES`].
    pub edge_types: Vec<String>,
    /// Which way edges are followed.
    pub direction: SelectionDirection,
    /// Edges followed from the root at most (0: the root alone).
    pub max_depth: u32,
}

impl Selection {
    /// A selection from a request's raw fields, with the defaults for those
    /// it omits.
    ///
    /// # Errors
    /// A message naming the bad field: an edge type outside
    /// [`SELECTION_EDGE_TYPES`], an empty `edge_types`, a direction other
    /// than `outgoing` / `incoming` / `both`, or a depth over
    /// [`MAX_SELECTION_DEPTH`].
    pub fn new(
        root: Uuid,
        edge_types: Option<&[String]>,
        direction: Option<&str>,
        max_depth: Option<u32>,
    ) -> Result<Self, String> {
        let edge_types: Vec<String> = match edge_types {
            None => DEFAULT_SELECTION_EDGE_TYPES
                .iter()
                .map(|t| (*t).to_string())
                .collect(),
            Some(raw) => {
                let mut out: Vec<String> = Vec::with_capacity(raw.len());
                for t in raw {
                    let canonical =
                        epigraph_core::edge::relationships::canonical_relationship(t.trim());
                    if !SELECTION_EDGE_TYPES.contains(&canonical) {
                        return Err(format!(
                            "selection.edge_types: {t:?} is not followed by a selection; \
                             use any of {}",
                            SELECTION_EDGE_TYPES.join(", ")
                        ));
                    }
                    if !out.iter().any(|o| o == canonical) {
                        out.push(canonical.to_string());
                    }
                }
                if out.is_empty() {
                    return Err(
                        "selection.edge_types: name at least one edge type, or omit \
                                it for decomposes_to and supports"
                            .to_string(),
                    );
                }
                out
            }
        };
        let direction = match direction.map(str::trim).filter(|d| !d.is_empty()) {
            None => SelectionDirection::Outgoing,
            Some(d) => SelectionDirection::parse(d).ok_or_else(|| {
                format!("selection.direction: {d:?} is not outgoing, incoming or both")
            })?,
        };
        let max_depth = max_depth.unwrap_or(DEFAULT_SELECTION_DEPTH);
        if max_depth > MAX_SELECTION_DEPTH {
            return Err(format!(
                "selection.max_depth: {max_depth} is deeper than {MAX_SELECTION_DEPTH}"
            ));
        }
        Ok(Self {
            root,
            edge_types,
            direction,
            max_depth,
        })
    }
}

/// Which widening act a plan is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideningAct {
    /// `publicize_claims`: group to public.
    Publicize,
    /// `share_claims_with_team` into `group_id`.
    ShareWithTeam {
        /// The team.
        group_id: Uuid,
    },
}

impl WideningAct {
    const fn name(self) -> &'static str {
        match self {
            Self::Publicize => "publicize_claims",
            Self::ShareWithTeam { .. } => "share_claims_with_team",
        }
    }

    /// The definer's own classification of `ids`, without acting.
    async fn preview(
        self,
        conn: &mut sqlx::PgConnection,
        ids: &[Uuid],
    ) -> Result<Vec<VisibilityActOutcome>, DbError> {
        match self {
            Self::Publicize => ClaimRepository::preview_publicize_conn(conn, ids).await,
            Self::ShareWithTeam { group_id } => {
                ClaimRepository::preview_share_with_team_conn(conn, ids, group_id).await
            }
        }
    }
}

/// Whether the definer would act on (or, `already_public`, accept) a claim
/// it classified so.
fn accepted(outcome: &str) -> bool {
    matches!(outcome, "publicize" | "already_public" | "share")
}

/// What an act takes: the explicit ids of #784, or a selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActTarget {
    /// 1 to [`MAX_ACT_CLAIMS`] claim ids.
    Ids(Vec<Uuid>),
    /// A root and the closure to walk from it.
    Selection(Selection),
}

/// A claim the act would take, and how the walk reached it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlannedClaim {
    /// The claim.
    pub claim_id: Uuid,
    /// Edges from the root (0 for the root and for an explicit id).
    pub depth: u32,
    /// The definer's classification: `publicize`, `already_public` or `share`.
    pub outcome: String,
    /// The claim the walk came from, absent at depth 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reached_from: Option<Uuid>,
    /// The relationship of the edge it came over, absent at depth 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
}

/// A claim the act would NOT take, and why: the walk stopped there. Never
/// moved by the act.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlanBoundary {
    /// The claim.
    pub claim_id: Uuid,
    /// Edges from the root.
    pub depth: u32,
    /// The definer's refusal (`refused_not_author`, `refused_not_private`,
    /// `refused_sealed`, `refused_not_admin`, `refused_not_team_writer`,
    /// `refused_not_human`), `not_found` (no longer readable), or
    /// `not_current` (a superseded claim, not walked into).
    pub reason: String,
    /// The reason in words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<&'static str>,
    /// The claim the walk came from, absent at depth 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reached_from: Option<Uuid>,
    /// The relationship of the edge it came over, absent at depth 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
}

/// What an act would do: the claims it would take and the boundaries where it
/// stops. Built by [`plan`] from the definer's own classification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VisibilityPlan {
    /// The selection walked, absent for an explicit id list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<Selection>,
    /// Claims the act would take, in the order reached.
    pub claims: Vec<PlannedClaim>,
    /// Claims where the walk stopped, in the order reached.
    pub boundaries: Vec<PlanBoundary>,
    /// The walk reached more than [`MAX_ACT_CLAIMS`] claims to take or more
    /// than [`MAX_WALK_CLAIMS`] in all, and stopped: the plan is incomplete
    /// and the act refuses it.
    pub capped: bool,
    /// On a dry run the act would carry out (claims to take, not capped, and
    /// for an id list no refused id): what it would do to the edges and
    /// evidence of the planned claims the caller can read, measured by
    /// running the act and rolling it back ([`PlanEffects`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effects: Option<PlanEffects>,
}

/// One stored tenancy: `visibility`, `owner_group_id`, `co_owner_group_id`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StoredTenancy {
    /// `group` or `public`.
    pub visibility: Option<String>,
    /// The owner group.
    pub owner_group_id: Option<Uuid>,
    /// An edge's co-owner group (the other endpoint's), when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub co_owner_group_id: Option<Uuid>,
}

/// An edge with a planned claim as an endpoint, before and after the act.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlannedEdge {
    /// The edge.
    pub edge_id: Uuid,
    /// Its source.
    pub source_id: Uuid,
    /// Its source's type.
    pub source_type: String,
    /// Its target.
    pub target_id: Uuid,
    /// Its target's type.
    pub target_type: String,
    /// Its relationship.
    pub relationship: String,
    /// Its tenancy now.
    pub before: StoredTenancy,
    /// Its tenancy after the act.
    pub after: StoredTenancy,
}

/// An evidence row of a planned claim, as the act would leave it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlannedEvidence {
    /// The evidence row.
    pub evidence_id: Uuid,
    /// Its claim.
    pub claim_id: Uuid,
    /// Its tenancy, now and after the act.
    pub tenancy: StoredTenancy,
}

/// What a dry run's trial of the act did to the edges and evidence of the
/// planned claims, as far as the caller can read them (backlog 02d9e9a1, the
/// plan's "edges that widen or stay narrowed, evidence that stays pinned").
/// The act's own cascade decided it (migration 206's re-meet, 110's pins,
/// 284's declared edges); the trial is rolled back.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PlanEffects {
    /// Incident edges the act widens: public after and not before, or no
    /// longer requiring a group they required (an edge is read by the
    /// members of its owner group AND of its co-owner group). Re-met to the
    /// moved claims' new audience.
    pub edges_widened: Vec<PlannedEdge>,
    /// Incident edges the act leaves as narrow as they were, or narrower:
    /// unchanged, or still requiring every group they required (an edge to a
    /// claim that stays behind keeps that claim's group; a declared edge
    /// keeps its declaration).
    pub edges_kept: Vec<PlannedEdge>,
    /// Evidence rows that move with their claim.
    pub evidence_moved: usize,
    /// Evidence rows that stay where they are (pinned private, migration
    /// 110).
    pub evidence_kept: Vec<PlannedEvidence>,
    /// More than [`MAX_EFFECT_ROWS`] incident edges or evidence rows: the
    /// lists cover the first of them by id only.
    pub truncated: bool,
}

/// The most incident edges, and evidence rows, a dry run's trial reports.
pub const MAX_EFFECT_ROWS: usize = 5_000;

impl VisibilityPlan {
    /// The ids of [`Self::claims`].
    #[must_use]
    pub fn claim_ids(&self) -> Vec<Uuid> {
        self.claims.iter().map(|c| c.claim_id).collect()
    }
}

/// An act's answer: the definer's outcomes when it ran, the plan when one was
/// made (a selection, or a dry run).
#[derive(Debug, Clone)]
pub struct ActReport {
    /// The plan, for a selection or a dry run; `None` for an explicit id list
    /// that was acted on (the #784 shape).
    pub plan: Option<VisibilityPlan>,
    /// The act's per-claim outcomes; empty on a dry run.
    pub results: Vec<VisibilityActOutcome>,
}

fn boundary(
    o: &VisibilityActOutcome,
    depth: u32,
    reached_from: Option<Uuid>,
    relationship: Option<String>,
) -> PlanBoundary {
    PlanBoundary {
        claim_id: o.claim_id,
        depth,
        reason: o.outcome.clone(),
        detail: o.refusal_text(),
        reached_from,
        relationship,
    }
}

/// What `act` would do on `target` for the caller on `conn` (its own stamped
/// transaction), without doing it. See the module doc, "Selections".
///
/// # Errors
/// [`VisibilityActError::Db`]: `NotFound` when the root (or an explicit id)
/// is a claim the caller cannot read or that does not exist, answered as the
/// act answers it; the definer's whole-call refusals (`VIS01`, `VIS03`); a
/// database fault.
pub async fn plan(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    act: WideningAct,
    target: &ActTarget,
) -> Result<VisibilityPlan, VisibilityActError> {
    let selection = match target {
        ActTarget::Ids(ids) => {
            let outcomes = act.preview(&mut *conn, ids).await?;
            if let Some(o) = outcomes.iter().find(|o| o.outcome == "not_found") {
                return Err(DbError::NotFound {
                    entity: "claim".to_string(),
                    id: o.claim_id,
                }
                .into());
            }
            let (claims, boundaries): (Vec<_>, Vec<_>) =
                outcomes.iter().partition(|o| accepted(&o.outcome));
            return Ok(VisibilityPlan {
                selection: None,
                claims: claims
                    .into_iter()
                    .map(|o| PlannedClaim {
                        claim_id: o.claim_id,
                        depth: 0,
                        outcome: o.outcome.clone(),
                        reached_from: None,
                        relationship: None,
                    })
                    .collect(),
                boundaries: boundaries
                    .into_iter()
                    .map(|o| boundary(o, 0, None, None))
                    .collect(),
                capped: ids.len() > MAX_ACT_CLAIMS,
                effects: None,
            });
        }
        ActTarget::Selection(s) => s,
    };

    let mut out = VisibilityPlan {
        selection: Some(selection.clone()),
        claims: Vec::new(),
        boundaries: Vec::new(),
        capped: false,
        effects: None,
    };
    // The root first: unreadable answers as missing, exactly as the id form.
    let root = act
        .preview(&mut *conn, std::slice::from_ref(&selection.root))
        .await?;
    let Some(root) = root.into_iter().find(|o| o.claim_id == selection.root) else {
        return Err(DbError::NotFound {
            entity: "claim".to_string(),
            id: selection.root,
        }
        .into());
    };
    if root.outcome == "not_found" {
        return Err(DbError::NotFound {
            entity: "claim".to_string(),
            id: selection.root,
        }
        .into());
    }
    let mut seen: HashSet<Uuid> = HashSet::from([selection.root]);
    let mut frontier: Vec<Uuid> = Vec::new();
    if accepted(&root.outcome) {
        out.claims.push(PlannedClaim {
            claim_id: root.claim_id,
            depth: 0,
            outcome: root.outcome,
            reached_from: None,
            relationship: None,
        });
        frontier.push(selection.root);
    } else {
        out.boundaries.push(boundary(&root, 0, None, None));
    }

    let types: Vec<&str> = selection.edge_types.iter().map(String::as_str).collect();
    let limit = i64::try_from(MAX_WALK_CLAIMS + 1).unwrap_or(i64::MAX);
    for depth in 1..=selection.max_depth {
        if frontier.is_empty() {
            break;
        }
        let rows = EdgeRepository::claim_neighbors_for_selection(
            &mut *conn,
            viewer,
            &frontier,
            &types,
            selection.direction.outgoing(),
            selection.direction.incoming(),
            limit,
        )
        .await?;
        if rows.len() > MAX_WALK_CLAIMS {
            out.capped = true;
            break;
        }
        // First edge to each claim not yet reached, in the read's order.
        let mut reached: Vec<(Uuid, Uuid, String)> = Vec::new();
        let mut superseded: Vec<(Uuid, Uuid, String)> = Vec::new();
        for (from, to, relationship, is_current) in rows {
            if !seen.insert(to) {
                continue;
            }
            if is_current {
                reached.push((to, from, relationship));
            } else {
                superseded.push((to, from, relationship));
            }
        }
        for (to, from, relationship) in superseded {
            out.boundaries.push(PlanBoundary {
                claim_id: to,
                depth,
                reason: "not_current".to_string(),
                detail: Some("the claim is superseded; a selection does not walk into it"),
                reached_from: Some(from),
                relationship: Some(relationship),
            });
        }
        let ids: Vec<Uuid> = reached.iter().map(|r| r.0).collect();
        let classified: HashMap<Uuid, VisibilityActOutcome> = act
            .preview(&mut *conn, &ids)
            .await?
            .into_iter()
            .map(|o| (o.claim_id, o))
            .collect();
        let mut next = Vec::new();
        for (to, from, relationship) in reached {
            let o = classified
                .get(&to)
                .cloned()
                .unwrap_or_else(|| VisibilityActOutcome {
                    claim_id: to,
                    outcome: "not_found".to_string(),
                });
            if accepted(&o.outcome) {
                out.claims.push(PlannedClaim {
                    claim_id: to,
                    depth,
                    outcome: o.outcome,
                    reached_from: Some(from),
                    relationship: Some(relationship),
                });
                next.push(to);
            } else {
                out.boundaries
                    .push(boundary(&o, depth, Some(from), Some(relationship)));
            }
        }
        if out.claims.len() > MAX_ACT_CLAIMS || seen.len() > MAX_WALK_CLAIMS {
            out.capped = true;
            break;
        }
        frontier = next;
    }
    Ok(out)
}

/// `act` on `target` for the caller on `conn`, or (`dry_run`) only its plan.
///
/// * An explicit id list, not a dry run: [`publicize_claims`] /
///   [`share_claims_with_team`] exactly as before, no plan.
/// * A dry run: [`plan`], and nothing changes.
/// * A selection: [`plan`], then the act on the planned claims, all or
///   nothing. Refused whole, with nothing changed, when the plan is capped or
///   when the root itself is a boundary (with the act's own refusal for it).
///
/// # Errors
/// As [`plan`] and [`publicize_claims`]; a capped selection is
/// [`RefusalKind::Input`].
pub async fn act(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    act: WideningAct,
    target: &ActTarget,
    reason: &str,
    dry_run: bool,
) -> Result<ActReport, VisibilityActError> {
    if let (ActTarget::Ids(ids), false) = (target, dry_run) {
        return Ok(ActReport {
            plan: None,
            results: apply(conn, viewer, act, ids, reason).await?,
        });
    }
    let planned = plan(&mut *conn, viewer, act, target).await?;
    if dry_run {
        let mut planned = planned;
        let would_act = !planned.capped
            && !planned.claims.is_empty()
            && (matches!(target, ActTarget::Selection(_)) || planned.boundaries.is_empty());
        if would_act {
            planned.effects =
                Some(trial(&mut *conn, viewer, act, &planned.claim_ids(), reason).await?);
        }
        return Ok(ActReport {
            plan: Some(planned),
            results: Vec::new(),
        });
    }
    if planned.capped {
        return Err(DbError::Refused {
            kind: RefusalKind::Input,
            message: format!(
                "{}: refused, and nothing was changed: the selection reaches more than \
                 {MAX_ACT_CLAIMS} claims to move (or more than {MAX_WALK_CLAIMS} claims in \
                 all). Narrow it (max_depth, edge_types) or move part of it by claim_ids.",
                act.name()
            ),
        }
        .into());
    }
    if planned.claims.is_empty() {
        // Only the root can leave the plan empty: it is a boundary. Refuse as
        // the act refuses it.
        let root: Vec<VisibilityActOutcome> = planned
            .boundaries
            .iter()
            .filter(|b| b.depth == 0)
            .map(|b| VisibilityActOutcome {
                claim_id: b.claim_id,
                outcome: b.reason.clone(),
            })
            .collect();
        return Err(epigraph_db::preview_refusal(act.name(), &root)
            .unwrap_or_else(|| DbError::Refused {
                kind: RefusalKind::State,
                message: format!("{}: refused, and nothing was changed", act.name()),
            })
            .into());
    }
    let results = apply(conn, viewer, act, &planned.claim_ids(), reason).await?;
    Ok(ActReport {
        plan: Some(planned),
        results,
    })
}

/// Run the act on `ids` inside a savepoint, read the incident edges and the
/// evidence of `ids` through the caller's viewer before and after, and roll
/// the savepoint back whatever happened: the dry run's report of what the act
/// would do to them ([`PlanEffects`]). An act that would fail fails the dry
/// run with the same error, with nothing changed.
async fn trial(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    act: WideningAct,
    ids: &[Uuid],
    reason: &str,
) -> Result<PlanEffects, VisibilityActError> {
    let limit = i64::try_from(MAX_EFFECT_ROWS + 1).unwrap_or(i64::MAX);
    let edges_before =
        EdgeRepository::tenancy_incident_to_claims(&mut *conn, viewer, ids, limit).await?;
    let evidence_before =
        EvidenceRepository::tenancy_for_claims(&mut *conn, viewer, ids, limit).await?;
    sqlx::query("SAVEPOINT epigraph_visibility_trial")
        .execute(&mut *conn)
        .await
        .map_err(DbError::from)?;
    let ran = trial_body(&mut *conn, viewer, act, ids, reason, limit).await;
    // Always back to before the act, whatever it did.
    sqlx::query("ROLLBACK TO SAVEPOINT epigraph_visibility_trial")
        .execute(&mut *conn)
        .await
        .map_err(DbError::from)?;
    sqlx::query("RELEASE SAVEPOINT epigraph_visibility_trial")
        .execute(&mut *conn)
        .await
        .map_err(DbError::from)?;
    let (edges_after, evidence_after) = ran?;

    let mut out = PlanEffects {
        truncated: edges_before.len() > MAX_EFFECT_ROWS || evidence_before.len() > MAX_EFFECT_ROWS,
        ..PlanEffects::default()
    };
    let after: HashMap<Uuid, &epigraph_db::IncidentEdgeTenancy> =
        edges_after.iter().map(|e| (e.id, e)).collect();
    let tenancy_of = |e: &epigraph_db::IncidentEdgeTenancy| StoredTenancy {
        visibility: e.visibility.clone(),
        owner_group_id: e.owner_group_id,
        co_owner_group_id: e.co_owner_group_id,
    };
    for e in edges_before.iter().take(MAX_EFFECT_ROWS) {
        let before = tenancy_of(e);
        let after = after
            .get(&e.id)
            .map_or_else(|| before.clone(), |a| tenancy_of(a));
        let planned = PlannedEdge {
            edge_id: e.id,
            source_id: e.source_id,
            source_type: e.source_type.clone(),
            target_id: e.target_id,
            target_type: e.target_type.clone(),
            relationship: e.relationship.clone(),
            before: before.clone(),
            after: after.clone(),
        };
        if widens(&before, &after) {
            out.edges_widened.push(planned);
        } else {
            out.edges_kept.push(planned);
        }
    }
    let after: HashMap<Uuid, epigraph_db::EvidenceTenancy> =
        evidence_after.into_iter().map(|e| (e.id, e)).collect();
    for ev in evidence_before.into_iter().take(MAX_EFFECT_ROWS) {
        let moved = after.get(&ev.id).is_some_and(|a| {
            a.visibility != ev.visibility || a.owner_group_id != ev.owner_group_id
        });
        if moved {
            out.evidence_moved += 1;
        } else {
            out.evidence_kept.push(PlannedEvidence {
                evidence_id: ev.id,
                claim_id: ev.claim_id,
                tenancy: StoredTenancy {
                    visibility: ev.visibility,
                    owner_group_id: ev.owner_group_id,
                    co_owner_group_id: None,
                },
            });
        }
    }
    Ok(out)
}

/// Whether an edge's audience may grow from `before` to `after`: it becomes
/// public, or a group it required (owner or co-owner) is no longer
/// required. An edge that only gains a required group narrows.
fn widens(before: &StoredTenancy, after: &StoredTenancy) -> bool {
    let public = |t: &StoredTenancy| t.visibility.as_deref() == Some("public");
    if public(before) {
        return false;
    }
    if public(after) {
        return true;
    }
    let required = |t: &StoredTenancy| -> HashSet<Uuid> {
        [t.owner_group_id, t.co_owner_group_id]
            .into_iter()
            .flatten()
            .collect()
    };
    !required(before).is_subset(&required(after))
}

/// [`trial`]'s act and its reads after, inside the savepoint.
async fn trial_body(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    act: WideningAct,
    ids: &[Uuid],
    reason: &str,
    limit: i64,
) -> Result<
    (
        Vec<epigraph_db::IncidentEdgeTenancy>,
        Vec<epigraph_db::EvidenceTenancy>,
    ),
    VisibilityActError,
> {
    apply(&mut *conn, viewer, act, ids, reason).await?;
    let edges = EdgeRepository::tenancy_incident_to_claims(&mut *conn, viewer, ids, limit).await?;
    let evidence = EvidenceRepository::tenancy_for_claims(&mut *conn, viewer, ids, limit).await?;
    Ok((edges, evidence))
}

async fn apply(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    act: WideningAct,
    ids: &[Uuid],
    reason: &str,
) -> Result<Vec<VisibilityActOutcome>, VisibilityActError> {
    match act {
        WideningAct::Publicize => publicize_claims(conn, viewer, ids, reason).await,
        WideningAct::ShareWithTeam { group_id } => {
            share_claims_with_team(conn, viewer, ids, group_id, reason).await
        }
    }
}
