//! Mass function (BBA) repository
//!
//! Stores and retrieves Dempster-Shafer mass functions per (claim, frame, agent).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// Why an edge-keyed BBA is being invalidated: the `p_cause` migration 115's
/// `epigraph_cascade_delete_edge_bbas` records in its audit row, and refuses
/// when it is anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeBbaCascade {
    /// `ClaimRepository::mark_duplicate_with_repair_conn` retracted the
    /// duplicate's colliding edges.
    DedupRetractedEdge,
    /// `epigraph_engine::retraction_cascade` re-derives the BBAs of edges a
    /// supersede or a dedup re-sourced.
    RetractionCascade,
    /// `MatchCandidateRepo::retire` retracted a promoted matcher edge.
    MatchCandidateRetire,
}

impl EdgeBbaCascade {
    /// The literal the definer accepts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DedupRetractedEdge => "dedup_retracted_edge",
            Self::RetractionCascade => "retraction_cascade",
            Self::MatchCandidateRetire => "match_candidate_retire",
        }
    }
}

/// Delete every `mass_functions` row keyed `perspective_id = <one of
/// edge_ids>`, returning how many went.
///
/// One statement, two paths, decided by migration 114's
/// `epigraph_session_is_privileged_writer()` (the test the attach trigger and
/// the dedup move already use):
///
/// * a PRIVILEGED session (superuser, BYPASSRLS, a maintenance member) runs the
///   plain `DELETE` it always ran;
/// * any other session calls `epigraph_cascade_delete_edge_bbas` (115, reduced
///   to its owner arm by migration 117), which deletes only the session's OWN
///   rows (owner group in its writable set), refuses the whole call with
///   `CD02` (42501) when a readable row is not the session's, and appends one
///   `security_events` row per call that deleted anything. Another writer's
///   rows are removed only by the administrative cascade on the maintenance
///   connection (`epigraph_engine::admin_cascade`).
///
/// `sqlx::Result` rather than `DbError` so the match-candidate repository,
/// which speaks `sqlx::Result`, calls it unchanged.
///
/// # Errors
/// The query's error, including the definer's `CD01` / `CD02` refusals.
pub async fn delete_edge_bbas<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    edge_ids: &[Uuid],
    cause: EdgeBbaCascade,
) -> sqlx::Result<u64> {
    if edge_ids.is_empty() {
        return Ok(0);
    }
    let n: i64 = sqlx::query_scalar(
        r#"
        WITH acc AS (SELECT public.epigraph_session_is_privileged_writer() AS priv),
        own AS (
            DELETE FROM mass_functions
             WHERE perspective_id = ANY($1) AND (SELECT priv FROM acc)
            RETURNING 1
        )
        SELECT CASE WHEN acc.priv THEN (SELECT count(*) FROM own)
                    ELSE public.epigraph_cascade_delete_edge_bbas($1, $2)
               END
          FROM acc
        "#,
    )
    .bind(edge_ids)
    .bind(cause.as_str())
    .fetch_one(executor)
    .await?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// The `combination_method` a belief writer stamps on its cached result when
/// it folded nothing: a lone input BBA leaves the fold's `reports` empty, so
/// there is no Dempster label to record. Without a label that row was
/// indistinguishable from an agent-less input BBA (backlog b5cb3efb).
pub const CACHED_COMBINATION_UNFOLDED: &str = "cached_unfolded";

/// The `combination_method` prefix of a cached result that went through the
/// cautious (dependent-source) arm: `format!("cautious+{adaptive}")`.
const CACHED_COMBINATION_CAUTIOUS_PREFIX: &str = "cautious+";

/// The label a belief writer records for a fold that ended on `method`:
/// `format!("{method:?}")`, spelled out so the list below cannot drift. A new
/// `CombinationMethod` variant fails to compile here until it is added, and
/// the unit test pins every arm to the `Debug` spelling the writers use.
const fn combination_method_label(method: epigraph_ds::CombinationMethod) -> &'static str {
    use epigraph_ds::CombinationMethod as M;
    match method {
        M::Conjunctive => "Conjunctive",
        M::Dempster => "Dempster",
        M::YagerOpen => "YagerOpen",
        M::YagerClosed => "YagerClosed",
        M::DuboisPrade => "DuboisPrade",
        M::Inagaki => "Inagaki",
        M::TbmConjunctive => "TbmConjunctive",
    }
}

/// The `combination_method` label of every [`epigraph_ds::CombinationMethod`]
/// (its `Debug` name). A cached combination row carries one, and so does a
/// `submit_ds_evidence` INPUT row (which has an agent), so a label alone does
/// not mark a cache. Public so the legacy evidence-type backfill recognises
/// these inputs by the same list.
pub const COMBINATION_METHOD_LABELS: [&str; 7] = {
    use epigraph_ds::CombinationMethod as M;
    [
        combination_method_label(M::Conjunctive),
        combination_method_label(M::Dempster),
        combination_method_label(M::YagerOpen),
        combination_method_label(M::YagerClosed),
        combination_method_label(M::DuboisPrade),
        combination_method_label(M::Inagaki),
        combination_method_label(M::TbmConjunctive),
    ]
};

/// Every `combination_method` label a cached combination row can carry, other
/// than the `cautious+…` family.
const CACHED_COMBINATION_LABELS: [&str; 8] = {
    let l = COMBINATION_METHOD_LABELS;
    [
        l[0],
        l[1],
        l[2],
        l[3],
        l[4],
        l[5],
        l[6],
        CACHED_COMBINATION_UNFOLDED,
    ]
};

/// The placeholder a combine-input query carries where
/// [`with_cached_combination_excluded`] installs its predicate.
const NOT_CACHED_COMBINATION_MARKER: &str = "/* {NOT_CACHED_COMBINATION} */";

/// Replace [`NOT_CACHED_COMBINATION_MARKER`] in `sql` with `AND <predicate>`,
/// the predicate excluding cached combination rows, with every column
/// qualified by `qualifier` (`""` or `"mf."`).
///
/// A cached combination row is what `routes::belief::submit_evidence` and
/// `routes::assess` store after folding a claim's inputs: no source agent, no
/// perspective, and a combination label (see [`CACHED_COMBINATION_LABELS`] or
/// the `cautious+` prefix). It is a DERIVED artifact of the very rows it sits
/// beside, so a reader that folds it again counts that evidence twice
/// (backlog b5cb3efb).
///
/// The agent test is what keeps real inputs: `submit_ds_evidence` stores an
/// input labelled `"Dempster"` too, but always with its agent. `COALESCE`
/// keeps a row whose label is NULL (`NOT NULL` would drop it).
///
/// The predicate also excludes RETRACTED rows ([`not_retracted_predicate`],
/// migration 184): a combine input is a live, non-cached row.
fn with_cached_combination_excluded(sql: &str, qualifier: &str) -> String {
    assert!(
        sql.contains(NOT_CACHED_COMBINATION_MARKER),
        "combine-input query has no {NOT_CACHED_COMBINATION_MARKER} marker:\n{sql}"
    );
    let predicate = format!(
        "AND NOT {} AND {}",
        cached_combination_predicate(qualifier),
        not_retracted_predicate(qualifier)
    );
    sql.replace(NOT_CACHED_COMBINATION_MARKER, &predicate)
}

/// The perspective that keys `owner`'s ONE assessment slot on any (claim,
/// frame): the `/claims/:id/assess` row is `(claim, frame, owner, this)`
/// (ruling Q-U027F-2: one assessment per claim, frame and owner, the owner being
/// the caller's human). Deterministic and domain-separated from every other
/// perspective id (random v4s, edge ids). Because it is computable, every other
/// evidence writer must refuse a row whose perspective is the slot of its own
/// source agent ([`is_assessment_slot`]): that pair is the only way to address
/// an owner's assessment from another route. `None` is the slot of a caller
/// with no principal.
#[must_use]
pub fn assessment_slot_perspective(owner: Option<Uuid>) -> Uuid {
    let owner = owner.map_or_else(|| "anonymous".to_string(), |o| o.to_string());
    let hash = blake3::hash(format!("epigraph/assess-slot/v1/{owner}").as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    Uuid::from_bytes(bytes)
}

/// Whether a BBA keyed `(source_agent_id, perspective_id)` would sit in an
/// assessment slot (see [`assessment_slot_perspective`]). Writers other than
/// `/claims/:id/assess` refuse such a row.
#[must_use]
pub fn is_assessment_slot(source_agent_id: Option<Uuid>, perspective_id: Option<Uuid>) -> bool {
    perspective_id == Some(assessment_slot_perspective(source_agent_id))
}

/// A boolean SQL expression, TRUE exactly for a cached combination row (see
/// `with_cached_combination_excluded` for what that is), with every column
/// qualified by `qualifier` (`""` or `"mf."`). Never NULL: a row whose label
/// is NULL is not a cached combination by this test.
///
/// Public so a maintenance job that must leave cached rows alone (the
/// legacy evidence-type backfill, backlog bc06ec6f) uses the SAME predicate
/// the combine-input readers exclude, rather than a copy that could drift.
#[must_use]
pub fn cached_combination_predicate(qualifier: &str) -> String {
    let labels = CACHED_COMBINATION_LABELS
        .iter()
        .map(|l| format!("'{l}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let q = qualifier;
    format!(
        "COALESCE({q}source_agent_id IS NULL AND {q}perspective_id IS NULL \
         AND ({q}combination_method IN ({labels}) \
              OR {q}combination_method LIKE '{CACHED_COMBINATION_CAUTIOUS_PREFIX}%'), false)"
    )
}

/// A boolean SQL expression, TRUE exactly for a row that is NOT retracted
/// (migration 184, ruling R-79), with the column qualified by `qualifier`
/// (`""` or `"mf."`). Never NULL.
///
/// A retracted BBA is kept for audit and excluded from every fold and belief
/// read. This is the ONE spelling: every reader that folds, counts or
/// otherwise reads BBAs as evidence carries it (directly, through
/// [`with_retracted_excluded`], or through the combine-input predicate of
/// [`with_cached_combination_excluded`]), and
/// `epigraph-db/tests/bba_retract_read_lint.rs` refuses a new reader that
/// carries none of them.
#[must_use]
pub fn not_retracted_predicate(qualifier: &str) -> String {
    format!("{qualifier}retracted_at IS NULL")
}

/// The placeholder a BBA read carries where [`with_retracted_excluded`]
/// installs [`not_retracted_predicate`].
const NOT_RETRACTED_MARKER: &str = "/* {NOT_RETRACTED} */";

/// Replace [`NOT_RETRACTED_MARKER`] in `sql` with `AND <predicate>`
/// ([`not_retracted_predicate`] qualified by `qualifier`).
fn with_retracted_excluded(sql: &str, qualifier: &str) -> String {
    assert!(
        sql.contains(NOT_RETRACTED_MARKER),
        "BBA read has no {NOT_RETRACTED_MARKER} marker:\n{sql}"
    );
    let predicate = format!("AND {}", not_retracted_predicate(qualifier));
    sql.replace(NOT_RETRACTED_MARKER, &predicate)
}

/// What [`MassFunctionRepository::retract_conn`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbaRetractStatus {
    /// The row was live and is now retracted; one audit row was written.
    Retracted,
    /// The row was already retracted; nothing was written.
    AlreadyRetracted,
}

impl BbaRetractStatus {
    /// The wire value: `retracted` or `already_retracted`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retracted => "retracted",
            Self::AlreadyRetracted => "already_retracted",
        }
    }
}

/// Which authority admitted a retraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbaRetractArm {
    /// The caller writes the BBA's owning group.
    Owner,
    /// The caller holds a live `claims:admin` grant on its token's client.
    Admin,
}

impl BbaRetractArm {
    /// The wire value: `owner` or `admin`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
        }
    }
}

/// The retracted row's identity and retract columns, as the definer returns
/// them.
#[derive(Debug, Clone, PartialEq)]
pub struct BbaRetraction {
    pub status: BbaRetractStatus,
    pub mass_function_id: Uuid,
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub retracted_at: DateTime<Utc>,
    pub retracted_by: Uuid,
    pub retract_reason: String,
    pub arm: BbaRetractArm,
    /// Stored scoped beliefs (`ds_combined_beliefs`) of the row's (claim,
    /// frame) the retraction deleted as stale; 0 on a repeat.
    pub scoped_beliefs_cleared: i64,
}

/// Why [`MassFunctionRepository::retract_conn`] refused.
#[derive(Debug, thiserror::Error)]
pub enum BbaRetractError {
    /// RT02: no such row, or the session cannot read it (one answer for both).
    #[error("mass function {0} not found")]
    NotFound(Uuid),
    /// RT01 / RT03 / RT05: the session may not retract this row.
    #[error("retraction refused: {0}")]
    Forbidden(String),
    /// RT04: the reason is empty or too long.
    #[error("invalid retraction reason: {0}")]
    InvalidReason(String),
    /// Anything else.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// The frame every ingest template row sits on (see
/// [`ingest_template_predicate`]).
pub const INGEST_TEMPLATE_FRAME_NAME: &str = "research_validity";

/// The `source_strength` every ingest template row carries.
pub const INGEST_TEMPLATE_SOURCE_STRENGTH: f64 = 0.3;

/// The least mass an ingest template row puts on the whole frame
/// (`masses->>'0,1'`). The signature is `>=` this.
pub const INGEST_TEMPLATE_MIN_THETA: f64 = 0.80;

/// How far `source_strength` may sit from [`INGEST_TEMPLATE_SOURCE_STRENGTH`]
/// and still be the template: the column is a float written from a literal.
const INGEST_TEMPLATE_SOURCE_STRENGTH_TOLERANCE: f64 = 1e-6;

/// The placeholder a combine-input query carries where
/// [`with_ingest_template_excluded`] installs its predicate.
const NOT_INGEST_TEMPLATE_MARKER: &str = "/* {NOT_INGEST_TEMPLATE} */";

/// A boolean SQL expression, TRUE exactly for an **ingest template** row:
/// the near-vacuous BBA document ingest attached to a claim as a placeholder
/// assessment, not evidence about it. It is on the frame named
/// [`INGEST_TEMPLATE_FRAME_NAME`], has no `combination_method`, has a
/// `source_strength` within 1e-6 of [`INGEST_TEMPLATE_SOURCE_STRENGTH`], and
/// puts at least [`INGEST_TEMPLATE_MIN_THETA`] of its mass on the whole frame.
/// Every coordinate is required: a row that differs in any one of them is
/// somebody's assessment and stays an input.
///
/// `mf` qualifies the `mass_functions` columns and `f` the joined `frames`
/// row (`"mf."`, `"f."`). Never NULL.
///
/// This is the ONE spelling. Public so later readers that drop the template
/// from a fold use this predicate rather than a copy that could drift.
#[must_use]
pub fn ingest_template_predicate(mf: &str, f: &str) -> String {
    format!(
        "COALESCE({f}name = '{INGEST_TEMPLATE_FRAME_NAME}' \
         AND {mf}combination_method IS NULL \
         AND abs(COALESCE({mf}source_strength, 0) - {INGEST_TEMPLATE_SOURCE_STRENGTH}) \
             < {INGEST_TEMPLATE_SOURCE_STRENGTH_TOLERANCE} \
         AND COALESCE(({mf}masses->>'0,1')::float8, 0) >= {INGEST_TEMPLATE_MIN_THETA}, false)"
    )
}

/// The placeholder [`MassFunctionRepository::cache_owner_frame_for_claim`]
/// carries where [`with_frozen_compound_excluded`] installs the compound test.
const NOT_FROZEN_COMPOUND_MARKER: &str = "/* {NOT_FROZEN_COMPOUND} */";

/// Replace [`NOT_FROZEN_COMPOUND_MARKER`] in `sql` with a clause that is FALSE
/// when the claim bound as `$1` is a **compound**
/// ([`super::claim_role::IS_COMPOUND_SQL`], the one spelling of the role):
/// an in-force `decomposes_to` out-edge to a current claim, outside a
/// procedural tree and not a rule. Its cached belief is a query over its
/// leaves, not a fold of the BBAs that sit on it, so no recompute that
/// resolves its owner through
/// [`MassFunctionRepository::cache_owner_frame_for_claim`] may rewrite it.
/// Writers that fold a named frame directly (for example the post-removal
/// recompute of `backfill_factors`' edge re-wire, or the per-write
/// `recompute_claim_belief_on_frame` callers) do not pass through this check;
/// they are moved onto the single atom-cache writer separately.
///
/// A procedural node (every root above it is a workflow thesis authored by the
/// registered `workflow-ingest` system agent) is no compound and keeps today's
/// behaviour;
/// a cycle or a tree deeper than [`super::claim_role::ROLE_MAX_DEPTH`] finds
/// no procedural root, so its compounds stay frozen: the safe direction.
///
/// The role read carries no viewer splice (role is structure: a viewer that
/// cannot see a decomposition must not be able to refold the compound's
/// cache for everyone). That holds as written on a connection that bypasses
/// row security, which is how the bulk recomputers run; on an application
/// connection (the per-write `routes::assess` refresh) the server's row
/// security still filters the role read, as the
/// [`claim_role`](super::claim_role) module doc states.
fn with_frozen_compound_excluded(sql: &str) -> String {
    assert!(
        sql.contains(NOT_FROZEN_COMPOUND_MARKER),
        "owner query has no {NOT_FROZEN_COMPOUND_MARKER} marker:\n{sql}"
    );
    let predicate = format!(
        "AND NOT EXISTS (SELECT 1 FROM claims owner_role \
                          WHERE owner_role.id = $1 AND {})",
        super::claim_role::is_compound_sql("owner_role")
    );
    sql.replace(NOT_FROZEN_COMPOUND_MARKER, &predicate)
}

/// Replace [`NOT_INGEST_TEMPLATE_MARKER`] in `sql` with `AND NOT <predicate>`
/// ([`ingest_template_predicate`]), so the query reads no ingest template
/// row. The query must join `frames` (qualified by `f`) to the
/// `mass_functions` row (qualified by `mf`).
fn with_ingest_template_excluded(sql: &str, mf: &str, f: &str) -> String {
    assert!(
        sql.contains(NOT_INGEST_TEMPLATE_MARKER),
        "combine-input query has no {NOT_INGEST_TEMPLATE_MARKER} marker:\n{sql}"
    );
    let predicate = format!("AND NOT {}", ingest_template_predicate(mf, f));
    sql.replace(NOT_INGEST_TEMPLATE_MARKER, &predicate)
}

/// Whether a writer must NOT store its cached combination row for this pair,
/// because the row would overwrite an input.
///
/// `inputs` must come from a combine-input reader such as
/// [`MassFunctionRepository::get_for_claim_frame`], which has already
/// excluded the cached rows.
///
/// The cached row's key is (claim, frame, NULL agent, NULL perspective). The
/// unique key is `NULLS NOT DISTINCT` (migration 034), so this is ONE slot per
/// pair, and an agent-less, perspective-less INPUT lives in that slot too:
/// `/assess` stored its input there before ruling Q-U027F-2 (legacy rows
/// remain), and `/frames/:id/evidence` does when the body names neither an
/// agent nor a perspective. Writing the cache
/// would overwrite that input, and the readers would then drop it as a cached
/// row, losing the evidence (backlog b5cb3efb). When this returns `true` the
/// writer skips the cache. The input stays in the slot and is folded once.
///
/// A row in the slot counts as an input only if it carries a label: any label
/// that survived the reader's predicate is not a cached-combination label. An
/// UNLABELLED row is ambiguous. It is usually the copy that writers before
/// b5cb3efb cached for a lone BBA, so the writer keeps overwriting it and that
/// stale copy corrects itself, exactly as the writer always did.
#[must_use]
pub fn cached_combination_slot_holds_input(inputs: &[MassFunctionRow]) -> bool {
    inputs.iter().any(|row| {
        row.source_agent_id.is_none()
            && row.perspective_id.is_none()
            && row.combination_method.is_some()
    })
}

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
    /// FK to the specific evidence row that produced this BBA. NULL when:
    /// - the BBA was not derived from a single evidence row (edge_factor,
    ///   batch ds_auto, prior, combined system rows)
    /// - the evidence row that produced it was deleted (ON DELETE SET NULL)
    /// - legacy pre-Phase-3 row that the linking heuristic could not resolve
    ///
    /// When `Some`, locality is derivable directly: compare the evidence
    /// row's `properties->>'doi'` to the DOI of the paper asserting
    /// `claim_id`. See issue #197 Phase 3 and migration 046.
    pub evidence_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Repository for mass function (BBA) operations
pub struct MassFunctionRepository;

/// The cached Dempster-Shafer summary denormalized onto `claims`.
///
/// These six values are one logical unit — a single frame's combined belief — and
/// are always written together, so they travel as one value rather than six
/// positional floats.
///
/// `belief_frame_id` names the frame the other five summarize (backlog 696d3a1c,
/// migration 092). `claim_frames` is keyed `PRIMARY KEY (claim_id, frame_id)`, so a
/// claim legitimately holds different beliefs in different contexts; without this
/// field the cached number is an anonymous one-of-N that reads as authoritative.
#[derive(Debug, Clone, Copy)]
pub struct CachedBelief {
    pub belief: f64,
    pub plausibility: f64,
    pub mass_on_empty: f64,
    pub pignistic_prob: Option<f64>,
    pub mass_on_missing: f64,
    pub belief_frame_id: Option<Uuid>,
}

impl MassFunctionRepository {
    /// Store a mass function for a (claim, frame, agent, perspective) tuple
    ///
    /// Uses ON CONFLICT to update existing entries.
    ///
    /// `evidence_type` is the canonical evidence-type key the caller KNOWS for
    /// this BBA, or `None` when it does not (backlog bc06ec6f). It is a
    /// required parameter so every caller has to decide: this wrapper used to
    /// hard-code `None`, which is how every `store()` writer (praxis
    /// `interview_extraction`, the `error_derived` experiment loop) wrote
    /// untyped BBAs. A combined system row (`source_agent_id = None`, the
    /// result of folding several inputs) has no single type and must pass
    /// `None`.
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
        evidence_type: Option<&str>, // canonical evidence-type key, None when unknown (bc06ec6f)
        locality_tag: &str,          // 'intra' | 'cross' | 'unknown' (issue #197)
        evidence_id: Option<Uuid>, // FK to evidence(id), NULL for non-evidence BBAs (issue #197 Phase 3)
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
            evidence_type,
            locality_tag,
            evidence_id,
        )
        .await
    }

    /// Copy a stored BBA onto another frame for the same claim, keeping every
    /// provenance column: `source_agent_id`, `masses`, `conflict_k`,
    /// `combination_method`, `source_strength`, `evidence_type`,
    /// `locality_tag` and `evidence_id` (backlog bc06ec6f).
    ///
    /// Hypothesis promotion (`hypothesis_assessment` → `research_validity`)
    /// used a raw INSERT of `claim_id, frame_id, source_agent_id, masses,
    /// conflict_k, combination_method` only, so the promoted BBA lost its type,
    /// its reliability, its locality and its evidence link, and was then
    /// combined at the 0.5 unknown-type weight. `perspective_id` is not copied, exactly as before:
    /// the copy lands under the (claim, frame, agent, NULL) key, so re-promoting
    /// re-states one row instead of adding another.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, row), fields(claim_id = %row.claim_id, from = %row.frame_id))]
    pub async fn copy_to_frame<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        row: &MassFunctionRow,
        target_frame_id: Uuid,
    ) -> Result<Uuid, DbError> {
        Self::store_with_perspective(
            executor,
            row.claim_id,
            target_frame_id,
            row.source_agent_id,
            None,
            &row.masses,
            row.conflict_k,
            row.combination_method.as_deref(),
            row.source_strength,
            row.evidence_type.as_deref(),
            &row.locality_tag,
            row.evidence_id,
        )
        .await
    }

    /// Store a mass function with an optional perspective association
    ///
    /// Uses ON CONFLICT on (claim_id, frame_id, source_agent_id, perspective_id) to update.
    ///
    /// A RETRACTED row holds its key (migration 184, operator ruling R-103):
    /// a write to that key is refused by the database (RT07) and changes
    /// nothing, and the error is [`DbError::Refused`] with
    /// [`crate::RefusalKind::State`], naming the row. The upsert never touches
    /// the retract columns; only the explicit un-retract makes such a row
    /// live again.
    ///
    /// # The executor is generic, and that is what makes this table writable
    ///
    /// `mass_functions` is tier-A with 077's strict
    /// `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))` and no
    /// orphan `*_privacy` policy to fall back on, so on an unstamped application
    /// session this INSERT is refused with `42501`. That is why
    /// `mass_functions`' last successful production write was 2026-09-22 and why
    /// it stayed **0** through every e2e run. A stamped connection is a
    /// transaction (`ScopedPool::begin_as`), which a `&PgPool` parameter cannot
    /// accept; `&PgPool` and `&mut PgConnection` both satisfy
    /// [`sqlx::PgExecutor`], so [`Self::store`] and the CLI callers compile
    /// unchanged.
    ///
    /// The ON CONFLICT is what makes a stamped caller's RETRY safe after a
    /// failure further down its own pipeline: the row is keyed on
    /// `(claim_id, frame_id, source_agent_id, perspective_id)` and re-storing the
    /// same BBA updates it rather than combining mass twice.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(executor, masses_json))]
    pub async fn store_with_perspective<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        evidence_id: Option<Uuid>, // FK to evidence(id); Some(_) on the auto_wire_ds_update evidence write path, None otherwise (issue #197 Phase 3)
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO mass_functions
                (claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, evidence_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (claim_id, frame_id, source_agent_id, perspective_id) DO UPDATE
            SET masses = EXCLUDED.masses,
                conflict_k = EXCLUDED.conflict_k,
                combination_method = EXCLUDED.combination_method,
                source_strength = EXCLUDED.source_strength,
                evidence_type = EXCLUDED.evidence_type,
                locality_tag = EXCLUDED.locality_tag,
                evidence_id = EXCLUDED.evidence_id,
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
        .bind(evidence_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Retract ONE mass function (migration 184, ruling R-79): mark it
    /// retracted with `reason`, so every fold and belief read excludes it,
    /// and keep it for audit.
    ///
    /// Calls `public.epigraph_retract_mass_function`, a maintenance-owned
    /// SECURITY DEFINER, on `conn`, which must be a transaction stamped from
    /// the CALLER's own viewer (`ScopedPool::begin_as`): the retractor is the
    /// session principal, never a parameter. The caller may retract a row it
    /// can read when it writes the row's owning group, or when `admin` names
    /// a token whose client record holds a live `claims:admin` grant bound to
    /// the principal (re-checked by the definer, as migration 111 does). A
    /// first retraction writes one `security_events` row
    /// (`mass_functions.retract`) carrying the row as it was; a re-retraction
    /// writes nothing and reports [`BbaRetractStatus::AlreadyRetracted`].
    /// A first retraction also deletes the stored scoped beliefs
    /// (`ds_combined_beliefs`) of the row's (claim, frame), which folded it.
    ///
    /// The caller recomputes the claim's cached belief afterwards.
    ///
    /// # Errors
    /// [`BbaRetractError::NotFound`] for a missing or unreadable row (one
    /// answer for both), [`BbaRetractError::Forbidden`] when the session may
    /// not retract it, [`BbaRetractError::InvalidReason`] for an empty or
    /// over-long reason, [`BbaRetractError::Db`] otherwise.
    pub async fn retract_conn(
        conn: &mut sqlx::PgConnection,
        id: Uuid,
        reason: &str,
        admin: Option<super::claim::AdminToken>,
    ) -> Result<BbaRetraction, BbaRetractError> {
        let out: serde_json::Value =
            sqlx::query_scalar("SELECT public.epigraph_retract_mass_function($1, $2, $3, $4)")
                .bind(id)
                .bind(reason)
                .bind(admin.map(|a| a.client_id))
                .bind(admin.map(|a| a.jti))
                .fetch_one(&mut *conn)
                .await
                .map_err(|e| {
                    let (code, message) = match &e {
                        sqlx::Error::Database(d) => {
                            (d.code().map(|c| c.to_string()), d.message().to_string())
                        }
                        _ => (None, String::new()),
                    };
                    match code.as_deref() {
                        Some("P0002") => BbaRetractError::NotFound(id),
                        Some("42501") => BbaRetractError::Forbidden(
                            "only a writer of the mass function's owning group, or a live \
                     claims:admin holder, retracts it; nothing was written"
                                .to_string(),
                        ),
                        Some("22023") => BbaRetractError::InvalidReason(message),
                        _ => BbaRetractError::Db(DbError::from(e)),
                    }
                })?;
        let field = |k: &str| -> Result<&serde_json::Value, BbaRetractError> {
            out.get(k).ok_or_else(|| {
                BbaRetractError::Db(DbError::InvalidData {
                    reason: format!("epigraph_retract_mass_function returned no `{k}`"),
                })
            })
        };
        let uuid = |k: &str| -> Result<Uuid, BbaRetractError> {
            serde_json::from_value(field(k)?.clone()).map_err(|e| {
                BbaRetractError::Db(DbError::InvalidData {
                    reason: format!("epigraph_retract_mass_function `{k}`: {e}"),
                })
            })
        };
        let status = match field("status")?.as_str() {
            Some("retracted") => BbaRetractStatus::Retracted,
            Some("already_retracted") => BbaRetractStatus::AlreadyRetracted,
            other => {
                return Err(BbaRetractError::Db(DbError::InvalidData {
                    reason: format!("epigraph_retract_mass_function status {other:?}"),
                }))
            }
        };
        let arm = match field("arm")?.as_str() {
            Some("owner") => BbaRetractArm::Owner,
            Some("admin") => BbaRetractArm::Admin,
            other => {
                return Err(BbaRetractError::Db(DbError::InvalidData {
                    reason: format!("epigraph_retract_mass_function arm {other:?}"),
                }))
            }
        };
        Ok(BbaRetraction {
            status,
            mass_function_id: uuid("mass_function_id")?,
            claim_id: uuid("claim_id")?,
            frame_id: uuid("frame_id")?,
            retracted_at: serde_json::from_value(field("retracted_at")?.clone()).map_err(|e| {
                BbaRetractError::Db(DbError::InvalidData {
                    reason: format!("epigraph_retract_mass_function `retracted_at`: {e}"),
                })
            })?,
            retracted_by: uuid("retracted_by")?,
            retract_reason: field("retract_reason")?
                .as_str()
                .unwrap_or_default()
                .to_string(),
            arm,
            scoped_beliefs_cleared: field("scoped_beliefs_cleared")?.as_i64().unwrap_or(0),
        })
    }

    /// Get all mass functions for a (claim, frame) pair
    ///
    /// Returns all source BBAs that can be combined.
    ///
    /// Cached combination rows are excluded (see
    /// [`with_cached_combination_excluded`]), because a cached result folded
    /// again counts its inputs twice (backlog b5cb3efb). Most callers fold the
    /// rows. A few take only the LATEST row instead: `conflict_batch`, the
    /// hypothesis status reads and the promotion copy in the api and the cli.
    /// Those get the latest INPUT BBA, not the writers' cached combination.
    /// That is deliberate. The writers no longer cache a combination on a pair
    /// whose shared slot holds an input, so "latest including the cache" would
    /// mean the aggregate on some pairs and a single input on others. And a
    /// cached row copied to another frame would be dropped there by this
    /// predicate.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_for_claim_frame<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        frame_id: Uuid,
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let sql = viewer.splice(
            &with_cached_combination_excluded(
                r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, evidence_id, created_at
            FROM mass_functions
            WHERE claim_id = $1 AND frame_id = $2
              /* {NOT_CACHED_COMBINATION} */
              /* {VISIBILITY:mass_functions} */
            ORDER BY created_at ASC
            "#,
                "",
            ),
            3,
        );
        let mut vq = sqlx::query_as(&sql).bind(claim_id).bind(frame_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows: Vec<MassFunctionRow> = vq.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Get a mass function by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<MassFunctionRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, evidence_id, created_at
            FROM mass_functions
            WHERE id = $1
              /* {VISIBILITY:mass_functions} */
            "#,
            2,
        );
        let mut vq = sqlx::query_as(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let row: Option<MassFunctionRow> =
            vq.fetch_optional(executor).await.map_err(DbError::from)?;

        Ok(row)
    }

    /// Get all mass functions for a claim (across all frames)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_for_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let sql = viewer.splice(
            &with_retracted_excluded(
                r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, evidence_id, created_at
            FROM mass_functions
            WHERE claim_id = $1
              /* {NOT_RETRACTED} */
              /* {VISIBILITY:mass_functions} */
            ORDER BY frame_id, created_at ASC
            "#,
                "",
            ),
            2,
        );
        let mut vq = sqlx::query_as(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows: Vec<MassFunctionRow> = vq.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Get all mass functions for a claim that belong to exactly-2-hypothesis frames.
    ///
    /// Joins `mass_functions` with `frames` and restricts to frames whose
    /// `hypotheses` array has exactly 2 entries. This is the correct query for
    /// cross-frame combination in `auto_wire_ds_update`: including BBAs from
    /// frames with 3+ hypotheses would produce semantically wrong focal-element
    /// interpretation when parsed with the binary frame (index 0 and 1 are
    /// shared across frames, but `{0,1}` in a ternary frame ≠ Theta on binary).
    ///
    /// Cached combination rows are excluded (see
    /// [`with_cached_combination_excluded`]): every caller of this reader folds
    /// or reads its rows as INPUT evidence, and a cached result re-folded is
    /// that evidence counted twice (backlog b5cb3efb).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_for_claim_binary_frames<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let sql = viewer.splice(
            &with_cached_combination_excluded(
                r#"
            SELECT mf.id, mf.claim_id, mf.frame_id, mf.source_agent_id, mf.perspective_id,
                   mf.masses, mf.conflict_k, mf.combination_method, mf.source_strength,
                   mf.evidence_type, mf.locality_tag, mf.evidence_id, mf.created_at
            FROM mass_functions mf
            JOIN frames f ON mf.frame_id = f.id
            WHERE mf.claim_id = $1 AND array_length(f.hypotheses, 1) = 2
              /* {NOT_CACHED_COMBINATION} */
              /* {VISIBILITY:mf} */ /* {VISIBILITY:f} */
            ORDER BY mf.frame_id, mf.created_at ASC
            "#,
                "mf.",
            ),
            2,
        );
        let mut vq = sqlx::query_as(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows: Vec<MassFunctionRow> = vq.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Get mass functions for a (claim, frame) filtered by perspective
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_for_claim_frame_perspective<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        frame_id: Uuid,
        perspective_id: Uuid,
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let sql = viewer.splice(
            &with_retracted_excluded(
                r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, evidence_id, created_at
            FROM mass_functions
            WHERE claim_id = $1 AND frame_id = $2 AND perspective_id = $3
              /* {NOT_RETRACTED} */
              /* {VISIBILITY:mass_functions} */
            ORDER BY created_at ASC
            "#,
                "",
            ),
            4,
        );
        let mut vq = sqlx::query_as(&sql)
            .bind(claim_id)
            .bind(frame_id)
            .bind(perspective_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows: Vec<MassFunctionRow> = vq.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Get mass functions for a (claim, frame) from any of the given perspectives
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, perspective_ids, viewer))]
    pub async fn get_for_claim_frame_perspectives<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        frame_id: Uuid,
        perspective_ids: &[Uuid],
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let sql = viewer.splice(
            &with_retracted_excluded(
                r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, evidence_id, created_at
            FROM mass_functions
            WHERE claim_id = $1 AND frame_id = $2 AND perspective_id = ANY($3)
              /* {NOT_RETRACTED} */
              /* {VISIBILITY:mass_functions} */
            ORDER BY created_at ASC
            "#,
                "",
            ),
            4,
        );
        let mut vq = sqlx::query_as(&sql)
            .bind(claim_id)
            .bind(frame_id)
            .bind(perspective_ids);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows: Vec<MassFunctionRow> = vq.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Whether any mass function row has already been materialized for the
    /// given `perspective_id`.
    ///
    /// Edge-factor BBAs (see `epigraph_engine::edge_factor::auto_wire_ds_for_edge`)
    /// are persisted with `perspective_id = edge_id`, so this doubles as
    /// "has this edge ever been wired" — the existence check the
    /// edge-creation wake-up gate (backlog 8ef5cf61) uses to decide whether
    /// a re-asserted edge should attempt wiring even when `was_created` is
    /// `false` (e.g. the source claim was factorless on first write and has
    /// since acquired a belief interval).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn exists_for_perspective<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        perspective_id: Uuid,
    ) -> Result<bool, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM mass_functions WHERE perspective_id = $1 /* {VISIBILITY:mass_functions} */
            )
            "#,
            2,
        );
        let mut vq = sqlx::query_scalar(&sql).bind(perspective_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let exists: bool = vq.fetch_one(executor).await?;

        Ok(exists)
    }

    /// The id of a RETRACTED row holding the upsert key `(claim_id, frame_id,
    /// source_agent_id, perspective_id)` that `viewer` can read, if any.
    ///
    /// A retracted row holds its key (migration 184, operator ruling R-103):
    /// [`Self::store_with_perspective`] onto it is refused. An AUTOMATED
    /// writer whose write is a side effect (the evidence update's
    /// truth-value seed) asks this first and skips the write, so the
    /// retraction does not refuse the caller's own, unrelated write.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn retracted_row_at_key<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        frame_id: Uuid,
        source_agent_id: Option<Uuid>,
        perspective_id: Option<Uuid>,
    ) -> Result<Option<Uuid>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT id FROM mass_functions
             WHERE claim_id = $1 AND frame_id = $2
               AND source_agent_id IS NOT DISTINCT FROM $3
               AND perspective_id IS NOT DISTINCT FROM $4
               AND retracted_at IS NOT NULL /* {VISIBILITY:mass_functions} */
            "#,
            5,
        );
        let mut q = sqlx::query_scalar(&sql)
            .bind(claim_id)
            .bind(frame_id)
            .bind(source_agent_id)
            .bind(perspective_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor).await?)
    }

    /// Delete all mass functions for a claim
    ///
    /// Returns the number of rows deleted.
    ///
    /// # Errors
    /// `DbError::WriteRefused` when a readable BBA of the claim is not this
    /// session's to delete (then none is deleted: a partial delete would leave
    /// the claim's belief combining the survivors); `DbError::QueryFailed` if
    /// the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete_for_claim(pool: &PgPool, claim_id: Uuid) -> Result<u64, DbError> {
        // Checked: since 114 a claim's BBAs are routinely OTHER writers' rows,
        // which 115's owner-scoped DELETE skips without an error. Deleting only
        // the session's own and reporting the claim cleared would leave the
        // rest combining; refuse instead, and roll back the rows it could
        // delete (the transaction is dropped uncommitted).
        let mut tx = pool.begin().await?;
        let counts: (i64, i64) = sqlx::query_as(
            r#"
            WITH seen AS (SELECT 1 FROM mass_functions WHERE claim_id = $1),
                 done AS (DELETE FROM mass_functions WHERE claim_id = $1 RETURNING 1)
            SELECT (SELECT count(*) FROM seen), (SELECT count(*) FROM done)
            "#,
        )
        .bind(claim_id)
        .fetch_one(&mut *tx)
        .await?;
        if counts.1 < counts.0 {
            return Err(DbError::WriteRefused {
                entity: "mass functions of claim".to_string(),
                id: claim_id,
                action: "delete".to_string(),
            });
        }
        tx.commit().await?;
        Ok(u64::try_from(counts.1).unwrap_or(0))
    }

    /// Delete every mass function keyed to a single perspective.
    ///
    /// The retraction-repair primitive. Edge-factor BBAs are persisted with
    /// `perspective_id = edge_id` and their `masses` are **frozen at wire
    /// time** from the source claim's interval (see
    /// `epigraph_engine::edge_factor::auto_wire_ds_for_edge`), so re-running
    /// the combine pipeline over them after the source is retracted is a
    /// bit-for-bit no-op. Repair therefore requires *invalidation*, not
    /// recombination — and it must be a delete rather than an overwrite,
    /// because `auto_wire_edge_if_epistemic` short-circuits on
    /// [`Self::exists_for_perspective`], so a re-wire that leaves the stale
    /// row in place is a permanent no-op.
    ///
    /// [`Self::delete_for_claim`] is the wrong tool here: it would drop every
    /// *other* supporter's BBA along with the retracted one.
    ///
    /// Returns the number of rows deleted.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    ///
    /// Migration 115: DELETE is owner-scoped, and the BBA of an edge is
    /// routinely somebody else's row (the writer who wired the edge, or the
    /// target claim's group), so a non-privileged session goes through the
    /// audited cascade definer; see [`delete_edge_bbas`]. A refusal is an
    /// `Err` (CD02), never a silent `Ok(0)`, so the cascade records it instead
    /// of reading it as "this edge carried no BBA".
    #[instrument(skip(executor))]
    pub async fn delete_for_perspective<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        perspective_id: Uuid,
    ) -> Result<u64, DbError> {
        Ok(delete_edge_bbas(
            executor,
            &[perspective_id],
            EdgeBbaCascade::RetractionCascade,
        )
        .await?)
    }

    /// Mark a claim's cached DS scalars as **unbacked**: NULL out
    /// `belief`, `plausibility`, `pignistic_prob`, `mass_on_empty`,
    /// `mass_on_missing` and `classification`.
    ///
    /// Needed because the cached scalars on `claims` are a *stale cache*, not
    /// a derived view: `recompute_claim_belief_on_frame` short-circuits with
    /// `Ok(false)` and writes nothing when the claim has no BBAs left, so a
    /// claim whose last supporter was retracted would otherwise keep believing
    /// its pre-retraction number with no evidence behind it.
    ///
    /// NULL is the same state a claim carries before it ever acquires a BBA,
    /// which lets readers distinguish "unbacked" from "believed at 0.79" —
    /// a vacuous 0.5 could not be distinguished from a genuine maximally
    /// uncertain combine result.
    ///
    /// # Only clears a cache that exists
    /// The `WHERE` clause requires at least one derived column to be non-NULL,
    /// and the row count is returned so the caller can tell "cleared" from
    /// "there was nothing to clear". Without the guard this is **not** a no-op
    /// on a claim that never had a BBA: `claims.mass_on_empty` and
    /// `claims.mass_on_missing` are `DEFAULT 0.0` (migration
    /// `001_initial_schema.sql`) and `ClaimRepository::create` omits them, so
    /// an unconditional clear flips a real `0.0` to NULL and bumps
    /// `updated_at` on a claim the retraction never touched — visible through
    /// `GET /api/v1/claims/{id}/belief` as `mass_on_conflict: 0.0 → null`.
    /// `mark_duplicate` puts BOTH endpoints in
    /// [`crate::DedupRepair::stale_claims`] unconditionally, so every dedup of
    /// two BBA-free claims (the common case in a bulk
    /// `sweep_semantic_duplicates` run) would hit exactly that.
    ///
    /// Returns the number of rows cleared: 0 or 1.
    ///
    /// # A non-owner on a public claim (migration 114)
    ///
    /// These cache columns live on the CLAIM row, which a non-owner cannot
    /// write. When the session is not privileged, can read the claim, the claim
    /// is public and its owner is not writable
    /// ([`crate::repos::foreign_attach`]), the SAME statement writes through
    /// migration 114's audited `epigraph_foreign_*` definer instead: it touches
    /// only the DS cache (never `truth_value`, `labels` or `content`) and writes
    /// a `claims.foreign_aggregate_write` audit event. Every other session runs
    /// the UPDATE below exactly as before.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor))]
    pub async fn clear_claim_belief<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        claim_id: Uuid,
    ) -> Result<u64, DbError> {
        let sql = format!(
            r#"
            WITH acc AS (SELECT {foreign} AS foreign_public),
            own AS (
                UPDATE claims
                SET belief = NULL, plausibility = NULL, mass_on_empty = NULL,
                    pignistic_prob = NULL, mass_on_missing = NULL,
                    classification = NULL, updated_at = NOW()
                WHERE id = $1
                  AND NOT (SELECT foreign_public FROM acc)
                  AND (belief IS NOT NULL OR plausibility IS NOT NULL
                       OR pignistic_prob IS NOT NULL OR classification IS NOT NULL)
                RETURNING 1
            )
            SELECT CASE WHEN acc.foreign_public
                        THEN public.epigraph_foreign_belief_clear($1)::bigint
                        ELSE (SELECT count(*) FROM own)
                   END
              FROM acc
            "#,
            foreign = crate::repos::foreign_attach::foreign_public_claim("$1"),
        );
        let cleared: i64 = sqlx::query_scalar(&sql)
            .bind(claim_id)
            .fetch_one(executor)
            .await?;

        Ok(u64::try_from(cleared).unwrap_or(0))
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
    /// # A non-owner on a public claim (migration 114)
    ///
    /// These cache columns live on the CLAIM row, which a non-owner cannot
    /// write. When the session is not privileged, can read the claim, the claim
    /// is public and its owner is not writable
    /// ([`crate::repos::foreign_attach`]), the SAME statement writes through
    /// migration 114's audited `epigraph_foreign_*` definer instead: it touches
    /// only the DS cache (never `truth_value`, `labels` or `content`) and writes
    /// a `claims.foreign_aggregate_write` audit event. Every other session runs
    /// the UPDATE below exactly as before.
    ///
    /// Returns whether the claim's cache was written. `false` for a claim that
    /// does not exist (as before, silently), and for a non-owner whose frame is
    /// not the one the claim's cache carries: a non-owner refreshes the cache on
    /// THAT frame or seeds it when there is none, and never re-points it (the
    /// frame that carries a claim's belief is the owner's decision; migration
    /// 114, section 5). The caller's BBA is stored either way.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor))]
    pub async fn update_claim_belief<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        claim_id: Uuid,
        cached: CachedBelief,
    ) -> Result<bool, DbError> {
        // claims_{belief,plausibility,mass_empty}_bounds — see helper at
        // epigraph_ds::measures::clamp_claim_belief_measures.
        // Note: helper threads pignistic_prob between plausibility and mass_on_empty;
        // this function's parameter order differs, so arguments are threaded explicitly.
        let (belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing) =
            epigraph_ds::measures::clamp_claim_belief_measures(
                cached.belief,
                cached.plausibility,
                cached.pignistic_prob,
                cached.mass_on_empty,
                cached.mass_on_missing,
            );

        let sql = format!(
            r#"
            WITH acc AS (SELECT {foreign} AS foreign_public),
            own AS (
                UPDATE claims
                SET belief = $1, plausibility = $2, mass_on_empty = $3,
                    pignistic_prob = $4, mass_on_missing = $5, belief_frame_id = $7,
                    updated_at = NOW()
                WHERE id = $6
                  AND NOT (SELECT foreign_public FROM acc)
                RETURNING 1
            )
            SELECT CASE WHEN acc.foreign_public
                        THEN public.epigraph_foreign_belief_cache($6, $1, $2, $3, $4, $5, $7) > 0
                        ELSE (SELECT count(*) FROM own) > 0
                   END
              FROM acc
            "#,
            foreign = crate::repos::foreign_attach::foreign_public_claim("$6"),
        );
        let written = sqlx::query_scalar::<_, bool>(&sql)
            .bind(belief)
            .bind(plausibility)
            .bind(mass_on_empty)
            .bind(pignistic_prob)
            .bind(mass_on_missing)
            .bind(claim_id)
            .bind(cached.belief_frame_id)
            .fetch_one(executor)
            .await?;

        Ok(written)
    }

    /// Write the CDST classification label for a claim.
    ///
    /// A verdict on the claim's *combined* belief (`supported` |
    /// `contradicted` | `not_enough_info`), produced by
    /// `epigraph_engine::classifier::classify` inside
    /// `recompute_combined_belief`. Kept as a separate one-column UPDATE
    /// rather than folded into [`Self::update_claim_belief`] because that
    /// method has many callers and a param-ordering ratchet test; only the
    /// combine cascade computes a classification, so only it calls this.
    /// The extra UPDATE lands on the recompute (maintenance) path, not an
    /// online read path.
    ///
    /// `belief_frame_id` is the frame whose combination the verdict is about.
    /// The owner's statement ignores it (unchanged); a non-owner's verdict is
    /// written only when that frame is the one the claim's cache carries.
    ///
    /// # A non-owner on a public claim (migration 114)
    ///
    /// These cache columns live on the CLAIM row, which a non-owner cannot
    /// write. When the session is not privileged, can read the claim, the claim
    /// is public and its owner is not writable
    /// ([`crate::repos::foreign_attach`]), the SAME statement writes through
    /// migration 114's audited `epigraph_foreign_*` definer instead: it touches
    /// only the DS cache (never `truth_value`, `labels` or `content`) and writes
    /// a `claims.foreign_aggregate_write` audit event. Every other session runs
    /// the UPDATE below exactly as before.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor))]
    pub async fn update_claim_classification<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        claim_id: Uuid,
        classification: &str,
        belief_frame_id: Uuid,
    ) -> Result<(), DbError> {
        let sql = format!(
            r#"
            WITH acc AS (SELECT {foreign} AS foreign_public),
            own AS (
                UPDATE claims SET classification = $1, updated_at = NOW()
                WHERE id = $2 AND NOT (SELECT foreign_public FROM acc)
                RETURNING 1
            )
            SELECT CASE WHEN acc.foreign_public
                        THEN public.epigraph_foreign_claim_classification($2, $1, $3)
                   END
              FROM acc
            "#,
            foreign = crate::repos::foreign_attach::foreign_public_claim("$2"),
        );
        sqlx::query(&sql)
            .bind(classification)
            .bind(claim_id)
            .bind(belief_frame_id)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Count mass functions for a claim-frame pair
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count_for_claim_frame<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        frame_id: Uuid,
    ) -> Result<i64, DbError> {
        let sql = viewer.splice(
            &with_retracted_excluded(
                "SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2 \
                 /* {NOT_RETRACTED} */ /* {VISIBILITY:mass_functions} */",
                "",
            ),
            3,
        );
        let mut vq = sqlx::query_as(&sql).bind(claim_id).bind(frame_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let row: (i64,) = vq.fetch_one(executor).await?;

        Ok(row.0)
    }

    /// Count the mass functions attached to `claim_id` across ALL frames.
    ///
    /// The unframed counterpart to [`Self::count_for_claim_frame`], used by
    /// `GET /api/v1/claims/:id/belief` to report how many BBAs contribute to a
    /// claim's cached belief interval.
    ///
    /// The count is the reader's count, not the corpus count: a mass function
    /// the viewer cannot see does not contribute to the number it is told. A
    /// bare `COUNT(*)` here would be a cardinality oracle — it reveals how much
    /// evidence exists against a claim without disclosing any of it, which is
    /// exactly the kind of "returns more, not less" leak `Viewer::splice`
    /// exists to make impossible to write by accident.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count_for_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<i64, DbError> {
        let sql = viewer.splice(
            &with_retracted_excluded(
                "SELECT COUNT(*) FROM mass_functions WHERE claim_id = $1 \
                 /* {NOT_RETRACTED} */ /* {VISIBILITY:mass_functions} */",
                "",
            ),
            2,
        );
        let mut vq = sqlx::query_as(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let row: (i64,) = vq.fetch_one(executor).await?;

        Ok(row.0)
    }

    /// Get all mass functions for a frame (across all claims and agents).
    ///
    /// Used for frame-level combination and conflict computation.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_all_for_frame<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        frame_id: Uuid,
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let sql = viewer.splice(
            &with_retracted_excluded(
                r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, combination_method, source_strength, evidence_type, locality_tag, evidence_id, created_at
            FROM mass_functions
            WHERE frame_id = $1
              /* {NOT_RETRACTED} */
              /* {VISIBILITY:mass_functions} */
            ORDER BY claim_id, created_at ASC
            "#,
                "",
            ),
            2,
        );
        let mut vq = sqlx::query_as(&sql).bind(frame_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows: Vec<MassFunctionRow> = vq.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Batch-load mass functions for multiple claims.
    ///
    /// Returns all mass function rows for the given claim IDs,
    /// ordered by claim_id then created_at. The caller groups by claim_id.
    ///
    /// Cached combination rows are excluded (see
    /// [`with_cached_combination_excluded`]): every caller of this reader folds
    /// or reads its rows as INPUT evidence, and a cached result re-folded is
    /// that evidence counted twice (backlog b5cb3efb).
    #[instrument(skip(executor, claim_ids, viewer))]
    pub async fn get_for_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_ids: &[Uuid],
    ) -> Result<Vec<MassFunctionRow>, DbError> {
        let sql = viewer.splice(
            &with_cached_combination_excluded(
                r#"
            SELECT id, claim_id, frame_id, source_agent_id, perspective_id,
                   masses, conflict_k, combination_method,
                   source_strength, evidence_type, locality_tag, evidence_id, created_at
            FROM mass_functions
            WHERE claim_id = ANY($1)
              /* {NOT_CACHED_COMBINATION} */
              /* {VISIBILITY:mass_functions} */
            ORDER BY claim_id, created_at ASC
            "#,
                "",
            ),
            2,
        );
        let mut vq = sqlx::query_as(&sql).bind(claim_ids);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows: Vec<MassFunctionRow> = vq.fetch_all(executor).await?;

        Ok(rows)
    }

    /// List every distinct `frame_id` a claim carries BBAs on, paired with the
    /// frame's name and **ordered by frame name**.
    ///
    /// Name order is a stable LISTING order only. It does not say which frame
    /// owns the claim's cached `claims.{belief, plausibility, pignistic_prob,
    /// ...}` scalars: that is [`Self::cache_owner_frame_for_claim`].
    #[instrument(skip(executor, viewer))]
    pub async fn list_frames_for_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        let sql = viewer.splice(
            &with_retracted_excluded(
                r#"
            SELECT DISTINCT mf.frame_id, f.name
            FROM mass_functions mf
            JOIN frames f ON f.id = mf.frame_id
            WHERE mf.claim_id = $1
              /* {NOT_RETRACTED} */
              /* {VISIBILITY:mf} */ /* {VISIBILITY:f} */
            ORDER BY f.name
            "#,
                "mf.",
            ),
            2,
        );
        let mut vq = sqlx::query_as(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows: Vec<(Uuid, String)> = vq.fetch_all(executor).await?;

        Ok(rows)
    }

    /// The frame that owns a claim's cached `claims.{belief, plausibility,
    /// mass_on_empty, pignistic_prob, mass_on_missing, belief_frame_id}`
    /// scalars, or `None` (leave the cache alone) when the claim has no
    /// combine input the viewer can see.
    ///
    /// Only combine inputs count: cached combination rows are excluded exactly
    /// as [`Self::get_for_claim_frame`] excludes them, so the owner is always a
    /// frame the recompute can fold. **Ingest template rows
    /// ([`ingest_template_predicate`]) do not count either.** A claim whose
    /// only inputs are templates has no owner, so no recompute that resolves
    /// its owner here replaces its cache with the template's near-vacuous
    /// fold; and a frame that holds nothing but a template cannot own a claim
    /// that has real input elsewhere. (The fold of the owner frame itself is unchanged: a template
    /// that shares the owner frame with a real input is still folded there.)
    ///
    /// **A compound has no owner** ([`super::claim_role::IS_COMPOUND_SQL`]):
    /// its belief is a query over its leaves, so no recompute that resolves its
    /// owner here (the three bulk recomputers and the `routes::assess`
    /// refresh) refolds the BBAs that sit on it into its cache. Writers that
    /// fold a named frame directly are not covered. A procedural node (one
    /// whose every root is a workflow thesis authored by the registered
    /// `workflow-ingest` system agent, [`super::claim_role::IS_PROCEDURAL_SQL`])
    /// keeps the rules below.
    ///
    /// Among the frames holding the claim's remaining inputs:
    ///
    /// 1. the frame named `binary_truth`, when the claim has an input on it;
    /// 2. else the frame named `claim_validity`, when the claim has an input on it;
    /// 3. else the claim's recorded owner (`claims.belief_frame_id`), while that
    ///    frame still holds a non-template input;
    /// 4. else the first-writer frame: the frame holding the claim's earliest
    ///    input (`mass_functions.created_at`), ties broken by frame id.
    ///
    /// `frames.name` is UNIQUE, so the two canonical names identify at most one
    /// frame each (migration 114 treats the frame named `binary_truth` the same
    /// way). No other frame name plays a part.
    ///
    /// Once a claim's cache has an owner, a later input on another non-canonical
    /// frame does not move it (rule 3): `belief_frame_id` is written only by the
    /// claim's owner or by migration 114's definer, which keeps the recorded
    /// frame. Rule 3 also means the owner does not follow `created_at` once
    /// recorded; `created_at` is set by the database and is reset when an agent
    /// replaces its own BBA ([`Self::store_with_perspective`]'s upsert), so it
    /// decides only a claim with no recorded owner, or one whose recorded owner
    /// no longer holds an input. A canonical frame still outranks the recorded
    /// owner as soon as the claim has an input on it.
    ///
    /// Read-only: no frame is created.
    #[instrument(skip(executor, viewer))]
    pub async fn cache_owner_frame_for_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<Uuid>, DbError> {
        let sql = viewer.splice(
            &with_frozen_compound_excluded(&with_ingest_template_excluded(
                &with_cached_combination_excluded(
                    r#"
            SELECT mf.frame_id
            FROM mass_functions mf
            JOIN frames f ON f.id = mf.frame_id
            WHERE mf.claim_id = $1
              /* {NOT_CACHED_COMBINATION} */
              /* {NOT_INGEST_TEMPLATE} */
              /* {NOT_FROZEN_COMPOUND} */
              /* {VISIBILITY:mf} */ /* {VISIBILITY:f} */
            ORDER BY CASE
                       WHEN f.name = 'binary_truth' THEN 0
                       WHEN f.name = 'claim_validity' THEN 1
                       WHEN mf.frame_id = (
                           SELECT c.belief_frame_id
                           FROM claims c
                           WHERE c.id = $1
                             /* {VISIBILITY:c} */
                       ) THEN 2
                       ELSE 3
                     END,
                     mf.created_at,
                     mf.frame_id
            LIMIT 1
            "#,
                    "mf.",
                ),
                "mf.",
                "f.",
            )),
            2,
        );
        let mut vq = sqlx::query_scalar(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let owner: Option<Uuid> = vq.fetch_optional(executor).await?;

        Ok(owner)
    }

    /// List distinct `claim_id`s of **current** claims that have at least one
    /// BBA, ordered by `claim_id` for stable pagination. Used by bulk
    /// belief-recompute to enumerate the rebuild population when no explicit
    /// target set is given.
    ///
    /// The `JOIN claims … WHERE c.is_current` matters because supersede /
    /// mark_duplicate flip `is_current = false` but leave the claim's
    /// `mass_functions` rows in place; without the filter the bulk path would
    /// recompute beliefs on retired claims. This mirrors the sibling
    /// labels-target path (`list_by_labels(.., current_only = true, ..)`).
    /// `recompute_beliefs`' explicit `claim_ids` target bypasses this method,
    /// so a caller can still deliberately recompute a non-current claim by id.
    #[instrument(skip(executor, viewer))]
    pub async fn list_claim_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Uuid>, DbError> {
        debug_assert!(
            viewer.is_bypass(),
            "list_claim_ids is the belief-recompute enumerator; a Scoped viewer \
             here would leave every other tenant's cached beliefs stale forever"
        );
        // No splice: this query is EXEMPT, and `Viewer::splice` panics on a
        // marker-free literal by design.
        let rows: Vec<Uuid> = sqlx::query_scalar(
            r#"
            -- VISIBILITY-EXEMPT: belief-recompute enumerator. Runs under
            -- SystemReason::BeliefRecomputation on a maintenance connection; a
            -- per-tenant view of the work queue would leave every other tenant's
            -- cached beliefs permanently stale. The `_viewer` parameter exists
            -- so the exemption is visible at every call site, not only here.
            SELECT DISTINCT mf.claim_id
            FROM mass_functions mf
            JOIN claims c ON c.id = mf.claim_id
            WHERE c.is_current
            ORDER BY mf.claim_id
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(executor)
        .await?;

        Ok(rows)
    }
}

/// One legacy BBA with no `evidence_type`, and the stored provenance the
/// evidence-type backfill decides from (backlog bc06ec6f).
///
/// Every field is read from a stored column; nothing here is inferred. The
/// decision itself lives with the caller (`epigraph_cli::evidence_type_backfill`),
/// which holds the calibration this crate does not depend on.
#[derive(Debug, Clone, Default, FromRow)]
pub struct UntypedBbaProvenance {
    pub id: Uuid,
    pub combination_method: Option<String>,
    /// `mass_functions.source_agent_id`.
    pub source_agent_id: Option<Uuid>,
    /// `mass_functions.perspective_id`.
    pub perspective_id: Option<Uuid>,
    /// `frames.name` of the BBA's frame.
    pub frame_name: Option<String>,
    /// TRUE for a cached combination row, by [`cached_combination_predicate`].
    pub cached_combination: bool,
    /// TRUE for an UNLABELLED (`combination_method` NULL) row with no agent and
    /// no perspective that shares its (claim, frame) with another BBA: the
    /// shape of the single-input cache copy writers stored before b5cb3efb,
    /// which the predicate above cannot tell from a lone legacy input.
    pub unlabelled_slot_shared: bool,
    /// `evidence.evidence_type` of the linked evidence row (`evidence_id`).
    pub linked_evidence_type: Option<String>,
    /// `claims.properties->>'evidence_type'`.
    pub claim_evidence_type: Option<String>,
    /// `claims.properties->>'methodology'`.
    pub claim_methodology: Option<String>,
    /// `claims.properties->>'source_doi'`.
    pub claim_source_doi: Option<String>,
    /// `claims.properties->>'source_type'`.
    pub claim_source_type: Option<String>,
    /// `claims.labels` (empty when the claim row is missing).
    pub claim_labels: Vec<String>,
    /// `perspectives.name` when `perspective_id` names a perspective.
    pub perspective_name: Option<String>,
    /// The BBA's source agent's display name, else its claim's agent's.
    pub agent_name: Option<String>,
}

impl MassFunctionRepository {
    /// One keyset page of BBAs whose `evidence_type` is NULL or empty, in `id`
    /// order, strictly after `after` (from the start when `None`), at most
    /// `limit` rows, each with the provenance the backfill decides from.
    ///
    /// MAINTENANCE ONLY: it reads every tenant's rows and must run on the
    /// maintenance connection; on an application session RLS hides most of
    /// the corpus and the backfill would silently cover a fraction of it.
    ///
    /// The cursor is `m.id > COALESCE($1, nil uuid)`, never `$1 IS NULL OR
    /// m.id > $1`: the statement is prepared once and re-executed per page, and
    /// under a generic plan the OR form cannot be an index condition, so every
    /// page would re-walk the key from the start.
    ///
    /// # Errors
    /// `DbError` on a query failure.
    pub async fn untyped_provenance_page<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        after: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<UntypedBbaProvenance>, DbError> {
        let sql = format!(
            r#"
            SELECT m.id,
                   m.combination_method,
                   m.source_agent_id,
                   m.perspective_id,
                   f.name::text AS frame_name,
                   {cached} AS cached_combination,
                   (m.combination_method IS NULL
                    AND m.source_agent_id IS NULL AND m.perspective_id IS NULL
                    AND EXISTS (SELECT 1 FROM mass_functions s
                                 WHERE s.claim_id = m.claim_id AND s.frame_id = m.frame_id
                                   AND s.id <> m.id)) AS unlabelled_slot_shared,
                   e.evidence_type::text              AS linked_evidence_type,
                   c.properties->>'evidence_type'     AS claim_evidence_type,
                   c.properties->>'methodology'       AS claim_methodology,
                   c.properties->>'source_doi'        AS claim_source_doi,
                   c.properties->>'source_type'       AS claim_source_type,
                   COALESCE(c.labels, ARRAY[]::text[]) AS claim_labels,
                   p.name::text                       AS perspective_name,
                   COALESCE(sa.display_name, ca.display_name)::text AS agent_name
              FROM mass_functions m
              LEFT JOIN claims c        ON c.id = m.claim_id
              LEFT JOIN frames f        ON f.id = m.frame_id
              LEFT JOIN evidence e      ON e.id = m.evidence_id
              LEFT JOIN perspectives p  ON p.id = m.perspective_id
              LEFT JOIN agents sa       ON sa.id = m.source_agent_id
              LEFT JOIN agents ca       ON ca.id = c.agent_id
             WHERE (m.evidence_type IS NULL OR m.evidence_type = '')
               AND m.id > COALESCE($1::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
             ORDER BY m.id
             LIMIT $2
            "#,
            cached = cached_combination_predicate("m.")
        );
        let rows = sqlx::query_as::<_, UntypedBbaProvenance>(&sql)
            .bind(after)
            .bind(limit)
            .fetch_all(executor)
            .await?;
        Ok(rows)
    }

    /// Set `evidence_type` on each `ids[i]` to `types[i]`, ONLY where the row
    /// is still untyped (NULL or empty). Returns the number of rows written.
    ///
    /// The untyped guard makes the backfill idempotent and safe beside a live
    /// writer: a row a writer typed after the page was read is left as the
    /// writer stored it. No other column is touched.
    ///
    /// MAINTENANCE ONLY (see [`Self::untyped_provenance_page`]).
    ///
    /// # Errors
    /// `DbError` on a query failure, or if the two slices differ in length.
    pub async fn backfill_evidence_type_where_untyped<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        ids: &[Uuid],
        types: &[String],
    ) -> Result<u64, DbError> {
        if ids.len() != types.len() {
            return Err(DbError::InvalidData {
                reason: format!(
                    "backfill_evidence_type_where_untyped: {} ids but {} types",
                    ids.len(),
                    types.len()
                ),
            });
        }
        if ids.is_empty() {
            return Ok(0);
        }
        let done = sqlx::query(
            r#"
            UPDATE mass_functions m
               SET evidence_type = v.t
              FROM unnest($1::uuid[], $2::text[]) AS v(id, t)
             WHERE m.id = v.id
               AND (m.evidence_type IS NULL OR m.evidence_type = '')
            "#,
        )
        .bind(ids)
        .bind(types)
        .execute(executor)
        .await?;
        Ok(done.rows_affected())
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
            None, // evidence_type
            "unknown",
            None,
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
            None, // evidence_type
            "unknown",
            None,
        )
        .await
        .unwrap();

        let all = MassFunctionRepository::get_all_for_frame(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            frame_id,
        )
        .await
        .unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|r| r.claim_id == claim1_id));
        assert!(all.iter().any(|r| r.claim_id == claim2_id));
    }

    // Helper: insert a fresh system agent and return its id.
    #[cfg(test)]
    async fn insert_agent(pool: &PgPool, name: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test'])
             RETURNING id",
        )
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[cfg(test)]
    async fn insert_frame(pool: &PgPool, name: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO frames (name, hypotheses) VALUES ($1, '{\"supported\",\"contradicted\"}') RETURNING id",
        )
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[cfg(test)]
    async fn insert_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id) VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
        )
        .bind(content)
        .bind(agent_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    /// `list_frames_for_claim` must (a) return each frame ONCE even when the
    /// claim has multiple BBAs on it (DISTINCT), and (b) order by frame NAME,
    /// not by insertion order / frame id — the ordering the recompute cascade
    /// relies on for deterministic last-writer convergence.
    #[sqlx::test(migrations = "../../migrations")]
    async fn list_frames_for_claim_is_distinct_and_name_ordered(pool: sqlx::PgPool) {
        let agent_a = insert_agent(&pool, "frames-for-claim-a").await;
        let agent_b = insert_agent(&pool, "frames-for-claim-b").await;
        // Insert the alphabetically-LATER frame FIRST, so insertion order is
        // the reverse of name order — a name-blind query would fail the assert.
        let suffix = Uuid::new_v4();
        let frame_z = insert_frame(&pool, &format!("zzz-{suffix}")).await;
        let frame_a = insert_frame(&pool, &format!("aaa-{suffix}")).await;
        let claim_id = insert_claim(&pool, agent_a, &format!("ffc-{suffix}")).await;

        let masses = serde_json::json!({"0": 0.6, "0,1": 0.4});
        // Two BBAs (distinct agents) on frame_z → must still collapse to one frame entry.
        for ag in [agent_a, agent_b] {
            MassFunctionRepository::store(
                &pool,
                claim_id,
                frame_z,
                Some(ag),
                &masses,
                None,
                Some("test"),
                None, // evidence_type
                "unknown",
                None,
            )
            .await
            .unwrap();
        }
        MassFunctionRepository::store(
            &pool,
            claim_id,
            frame_a,
            Some(agent_a),
            &masses,
            None,
            Some("test"),
            None, // evidence_type
            "unknown",
            None,
        )
        .await
        .unwrap();

        let frames = MassFunctionRepository::list_frames_for_claim(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            claim_id,
        )
        .await
        .unwrap();
        assert_eq!(frames.len(), 2, "two distinct frames despite 3 BBAs");
        assert_eq!(frames[0].0, frame_a, "name-ordered: aaa frame first");
        assert_eq!(frames[1].0, frame_z, "name-ordered: zzz frame last");
    }

    /// `list_claim_ids` must return DISTINCT claim ids (a claim with multiple
    /// BBAs appears once), ordered ascending, and page correctly via limit/offset.
    #[sqlx::test(migrations = "../../migrations")]
    async fn list_claim_ids_is_distinct_and_paged(pool: sqlx::PgPool) {
        let agent_a = insert_agent(&pool, "lci-a").await;
        let agent_b = insert_agent(&pool, "lci-b").await;
        let suffix = Uuid::new_v4();
        let frame_id = insert_frame(&pool, &format!("lci-frame-{suffix}")).await;
        let c1 = insert_claim(&pool, agent_a, &format!("lci-1-{suffix}")).await;
        let c2 = insert_claim(&pool, agent_a, &format!("lci-2-{suffix}")).await;
        let c3 = insert_claim(&pool, agent_a, &format!("lci-3-{suffix}")).await;

        let masses = serde_json::json!({"0": 0.6, "0,1": 0.4});
        // c1 gets TWO BBAs (distinct agents) — must appear ONCE in the result.
        for ag in [agent_a, agent_b] {
            MassFunctionRepository::store(
                &pool,
                c1,
                frame_id,
                Some(ag),
                &masses,
                None,
                Some("test"),
                None, // evidence_type
                "unknown",
                None,
            )
            .await
            .unwrap();
        }
        for c in [c2, c3] {
            MassFunctionRepository::store(
                &pool,
                c,
                frame_id,
                Some(agent_a),
                &masses,
                None,
                Some("test"),
                None, // evidence_type
                "unknown",
                None,
            )
            .await
            .unwrap();
        }

        // Ephemeral sqlx::test DB → only our 3 distinct claims have BBAs.
        let all = MassFunctionRepository::list_claim_ids(
            &pool,
            &crate::visibility::Viewer::test_bypass(
                crate::visibility::SystemReason::BeliefRecomputation,
            ),
            100,
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            all.len(),
            3,
            "3 distinct claim ids despite c1 having 2 BBAs"
        );

        let mut expected = vec![c1, c2, c3];
        expected.sort();
        assert_eq!(all, expected, "ascending claim_id order");

        // Paging: page 1 (limit 2) + page 2 (offset 2) partition the set, disjoint.
        let page1 = MassFunctionRepository::list_claim_ids(
            &pool,
            &crate::visibility::Viewer::test_bypass(
                crate::visibility::SystemReason::BeliefRecomputation,
            ),
            2,
            0,
        )
        .await
        .unwrap();
        let page2 = MassFunctionRepository::list_claim_ids(
            &pool,
            &crate::visibility::Viewer::test_bypass(
                crate::visibility::SystemReason::BeliefRecomputation,
            ),
            2,
            2,
        )
        .await
        .unwrap();
        assert_eq!(page1, expected[..2].to_vec());
        assert_eq!(page2, vec![expected[2]]);
    }

    /// `list_claim_ids` (the bulk belief-recompute enumeration) must EXCLUDE
    /// non-current claims. supersede/mark_duplicate flip `is_current = false`
    /// but deliberately leave the claim's `mass_functions` rows in place, so
    /// without an is_current filter the bulk recompute path rebuilds beliefs
    /// on retired claims — wasted work, and it diverges from the sibling
    /// labels-target path which is already current-only.
    #[sqlx::test(migrations = "../../migrations")]
    async fn list_claim_ids_excludes_non_current_claims(pool: sqlx::PgPool) {
        let agent = insert_agent(&pool, "lci-cur-a").await;
        let suffix = Uuid::new_v4();
        let frame_id = insert_frame(&pool, &format!("lci-cur-frame-{suffix}")).await;
        let c_current = insert_claim(&pool, agent, &format!("lci-cur-1-{suffix}")).await;
        let c_retired = insert_claim(&pool, agent, &format!("lci-cur-2-{suffix}")).await;

        let masses = serde_json::json!({"0": 0.6, "0,1": 0.4});
        for c in [c_current, c_retired] {
            MassFunctionRepository::store(
                &pool,
                c,
                frame_id,
                Some(agent),
                &masses,
                None,
                Some("test"),
                None, // evidence_type
                "unknown",
                None,
            )
            .await
            .unwrap();
        }

        // Retire one claim the way supersede/mark_duplicate do — flip
        // is_current WITHOUT removing its BBAs.
        sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
            .bind(c_retired)
            .execute(&pool)
            .await
            .unwrap();

        let ids = MassFunctionRepository::list_claim_ids(
            &pool,
            &crate::visibility::Viewer::test_bypass(
                crate::visibility::SystemReason::BeliefRecomputation,
            ),
            100,
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            ids,
            vec![c_current],
            "only the current claim's id is enumerated"
        );
        assert!(
            !ids.contains(&c_retired),
            "retired (is_current=false) claim must be excluded from bulk recompute"
        );
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
            None,
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
            None,
        )
        .await
        .unwrap();

        let rows = MassFunctionRepository::get_for_claim_frame(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            claim_id,
            frame_id,
        )
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
            CachedBelief {
            belief: 0.7,
            plausibility: // belief
            drifted_plausibility,
            mass_on_empty: // plausibility (drift; expect clamp to 1.0)
            0.1,
            pignistic_prob: // mass_on_empty
            Some(0.6),
            mass_on_missing: // pignistic_prob
            0.05,
            belief_frame_id: None,
        },
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
            evidence_id: Some(Uuid::new_v4()),
            created_at: Utc::now(),
        };
    }

    /// Only a LABELLED agent-less, perspective-less row blocks the cache.
    /// An agent's row and a perspective's row live on other keys, and an
    /// unlabelled row in the slot is the pre-b5cb3efb single-BBA copy, which
    /// the writer overwrites.
    #[test]
    fn only_a_labelled_row_in_the_shared_slot_blocks_the_cached_combination() {
        let row =
            |agent: Option<Uuid>, perspective: Option<Uuid>, label: Option<&str>| MassFunctionRow {
                id: Uuid::new_v4(),
                claim_id: Uuid::nil(),
                frame_id: Uuid::nil(),
                source_agent_id: agent,
                perspective_id: perspective,
                masses: serde_json::json!({"0": 0.6, "0,1": 0.4}),
                conflict_k: None,
                combination_method: label.map(str::to_string),
                source_strength: None,
                evidence_type: None,
                locality_tag: "unknown".to_string(),
                evidence_id: None,
                created_at: Utc::now(),
            };
        let some = Some(Uuid::new_v4());
        let agent_input = row(some, None, Some("discount"));
        let perspective_input = row(None, some, Some("discount"));

        assert!(!cached_combination_slot_holds_input(&[]));
        assert!(!cached_combination_slot_holds_input(&[
            agent_input.clone(),
            perspective_input.clone()
        ]));
        assert!(!cached_combination_slot_holds_input(&[
            agent_input.clone(),
            row(None, None, None)
        ]));
        for label in ["discount", "auto_wire", "prior"] {
            assert!(
                cached_combination_slot_holds_input(&[
                    agent_input.clone(),
                    row(None, None, Some(label))
                ]),
                "an agent-less, perspective-less {label:?} input holds the slot"
            );
        }
    }

    /// The cached-row labels are exactly the `Debug` spelling the writers
    /// record (`format!("{:?}", report.method_used)`), for every variant.
    #[test]
    fn cached_combination_labels_match_the_writers_debug_spelling() {
        use epigraph_ds::CombinationMethod as M;
        for m in [
            M::Conjunctive,
            M::Dempster,
            M::YagerOpen,
            M::YagerClosed,
            M::DuboisPrade,
            M::Inagaki,
            M::TbmConjunctive,
        ] {
            let debug = format!("{m:?}");
            assert_eq!(combination_method_label(m), debug);
            assert!(
                CACHED_COMBINATION_LABELS.contains(&debug.as_str()),
                "{debug} missing from CACHED_COMBINATION_LABELS"
            );
        }
        assert!(CACHED_COMBINATION_LABELS.contains(&CACHED_COMBINATION_UNFOLDED));
    }

    /// Every combine-input reader drops the writers' cached combination row
    /// in each of its shapes, and keeps the rows that only look like one
    /// (backlog b5cb3efb):
    /// * an input labelled `"Dempster"` WITH its agent — `submit_ds_evidence`
    ///   stores exactly that (`format!("{method:?}")`, `Some(agent_id)`);
    /// * an agent-less row with no label — a legacy input shape the
    ///   predicate cannot classify, so it must not be silently dropped
    ///   (`NOT (NULL)` would drop it; the `COALESCE` is what keeps it);
    /// * agent-less, perspective-less INPUTS with a non-combination label —
    ///   `"discount"` is what `/assess` and an anonymous `/evidence` store, and
    ///   `"auto_wire"` / `"prior"` are other writers' labels. These pin the
    ///   label list: dropping every labelled agent-less row would pass the
    ///   cached cases;
    /// * an agent-less row WITH a perspective labelled `"Dempster"` — pins the
    ///   perspective conjunct.
    ///
    /// Each look-alike sits on its OWN claim: two agent-less, perspective-less
    /// rows on one pair would upsert into one another (NULLS NOT DISTINCT).
    #[sqlx::test(migrations = "../../migrations")]
    async fn combine_input_readers_exclude_only_cached_combination_rows(pool: sqlx::PgPool) {
        let viewer = crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]);
        let agent_a = insert_agent(&pool, "b5cb-input-a").await;
        let agent_b = insert_agent(&pool, "b5cb-input-b").await;
        let suffix = Uuid::new_v4();
        let frame = insert_frame(&pool, &format!("b5cb-binary-{suffix}")).await;
        let masses = serde_json::json!({"0": 0.6, "0,1": 0.4});

        // (cached label, is it a cached combination row?)
        let perspective: Uuid = sqlx::query_scalar(
            "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
        )
        .bind(format!("b5cb-perspective-{suffix}"))
        .bind(agent_a)
        .fetch_one(&pool)
        .await
        .expect("seed perspective");

        // (label of the agent-less row, its perspective, is it a cached
        // combination row?)
        let cases: Vec<(Option<String>, Option<Uuid>, bool)> = CACHED_COMBINATION_LABELS
            .iter()
            .map(|l| (Some((*l).to_string()), None, true))
            .chain([
                (Some("cautious+Dempster".to_string()), None, true),
                (Some("cautious+none".to_string()), None, true),
                (None, None, false),
                (Some("discount".to_string()), None, false),
                (Some("auto_wire".to_string()), None, false),
                (Some("prior".to_string()), None, false),
                (Some("Dempster".to_string()), Some(perspective), false),
            ])
            .collect();

        for (label, perspective_id, is_cached) in cases {
            let claim = insert_claim(
                &pool,
                agent_a,
                &format!("b5cb-{label:?}-{perspective_id:?}-{suffix}"),
            )
            .await;
            let input_a = MassFunctionRepository::store(
                &pool,
                claim,
                frame,
                Some(agent_a),
                &masses,
                None,
                Some("discount"),
                None, // evidence_type
                "unknown",
                None,
            )
            .await
            .unwrap();
            let input_dempster_with_agent = MassFunctionRepository::store(
                &pool,
                claim,
                frame,
                Some(agent_b),
                &masses,
                None,
                Some("Dempster"),
                None, // evidence_type
                "unknown",
                None,
            )
            .await
            .unwrap();
            let agentless = MassFunctionRepository::store_with_perspective(
                &pool,
                claim,
                frame,
                None,
                perspective_id,
                &masses,
                Some(0.1),
                label.as_deref(),
                None, // source_strength
                None, // evidence_type
                "unknown",
                None,
            )
            .await
            .unwrap();

            let mut want = vec![input_a, input_dempster_with_agent];
            if !is_cached {
                want.push(agentless);
            }
            want.sort();

            let by_frame =
                MassFunctionRepository::get_for_claim_frame(&pool, &viewer, claim, frame)
                    .await
                    .unwrap();
            let by_binary =
                MassFunctionRepository::get_for_claim_binary_frames(&pool, &viewer, claim)
                    .await
                    .unwrap();
            let by_claims = MassFunctionRepository::get_for_claims(&pool, &viewer, &[claim])
                .await
                .unwrap();
            for (reader, rows) in [
                ("get_for_claim_frame", by_frame),
                ("get_for_claim_binary_frames", by_binary),
                ("get_for_claims", by_claims),
            ] {
                let mut got: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
                got.sort();
                assert_eq!(
                    got, want,
                    "{reader}, agent-less row labelled {label:?}, perspective \
                     {perspective_id:?} (cached: {is_cached})"
                );
            }
        }
    }
}
