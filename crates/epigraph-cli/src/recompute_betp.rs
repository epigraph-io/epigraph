//! Backfill stale cached `claims.pignistic_prob` (and `belief`,
//! `plausibility`, `conflict_k`, `mass_on_missing`) on the cohort of claims
//! whose combined belief was last written under the superseded
//! raw-`source_strength` model, before issue #197's dynamic
//! `effective_source_strength` derivation (evidence_type + locality +
//! per-frame override + calibration) existed.
//!
//! Backlog claim f2521c53-86bb-4b3b-96b4-a5cc963f8015.
//!
//! Reuses the canonical recompute entry point
//! (`epigraph_engine::edge_factor::recompute_claim_belief_on_frame` /
//! `preview_claim_belief_on_frame`) rather than re-deriving discount+combine
//! logic — see `crates/epigraph-cli/src/bin/recompute_claim_belief.rs` for
//! the established per-claim, per-frame pattern this module mirrors.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Write as _;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::repos::claim_role::{claim_role_sql, ClaimRole};
use epigraph_db::repos::mass_function::ingest_template_predicate;
use epigraph_engine::atom_items::{
    atom_drift_rows, drift_atom_fold, drift_legacy_grouping_betp, drift_scope_fold,
    AtomFoldMode, AxiomMode, CompoundSourceEdges, EvidencedInterval,
};
use epigraph_engine::edge_factor::{
    AtomCacheOutcome, AtomCacheSettings, CacheWriteCause, LegacyFold, VacateOutcome,
};

use crate::belief_cache::{
    read_cache_columns, scoped_sidecar_path, write_scoped_record, write_wave_record, CacheColumns,
    ScopedColumns, ScopedWaveRecord, WaveRecord,
};

/// Cohort SQL: claims whose cached BetP is due for a refresh under the
/// current (dynamic reliability) combine pipeline.
///
/// Two disjoint populations, unioned:
///
/// (a) **Multi-BBA hub claims** — claims with more than one BBA on the same
///     2-hypothesis ("binary") frame. `frames.hypotheses` array-length
///     scoping matches `MassFunctionRepository::get_for_claim_binary_frames`
///     (the established "is this a binary frame" query in this codebase).
///     These need a fresh Dempster combination across sources because the
///     per-BBA reliability weight feeding the combine changed model
///     (issue #197 Phase 2/4) since the cached value was last written.
///
/// (b) **Single-BBA non-simple-shape claims** — claims with exactly one BBA
///     on a binary frame whose `masses` JSONB puts POSITIVE mass on a
///     focal-element key of `"1"` (mass on the non-supported hypothesis
///     alone) or `"~"` (open-world/complement mass on the empty set). Both
///     are focal-element shapes beyond the simple `{"0", "0,1"}` case a raw
///     single-source discount was originally calibrated against. A key
///     present with zero mass does not qualify (cohort v2 narrowing).
///
/// **Cohort v1 is a dry-run report only** (SPEC §10.7, §10.6 freeze F3): the
/// writing path is [`select_wave_cohort`]'s waves. Arms (a) and (b) skip an
/// evidenced atom with one simple BBA, whose cache can still be stale, and
/// admit claims the wave never writes.
///
/// `UNION` (not `UNION ALL`) so a claim that happens to satisfy both (a) and
/// (b) — a hub claim where one of its BBAs also has a "~" key — is not
/// double-counted or double-processed by the caller.
pub async fn select_cohort(pool: &PgPool) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT claim_id FROM (
            -- (a) multi-BBA hub claims: >1 BBA on the same binary frame.
            SELECT mf.claim_id
              FROM mass_functions mf
              JOIN frames f ON f.id = mf.frame_id
             WHERE array_length(f.hypotheses, 1) = 2
             GROUP BY mf.claim_id, mf.frame_id
            HAVING COUNT(*) > 1

            UNION

            -- (b) single-BBA claims on a binary frame whose stored masses
            -- contain a non-simple focal-element key: a lone "1" (mass on
            -- the non-supported hypothesis by itself) or "~" (open-world /
            -- complement mass on the empty set). The `?` operator is exact
            -- top-level-key containment, so `masses ? '~'` matches only the
            -- bare "~" key, not "~0" / "~0,1" / "~1".
            --
            -- Narrowed for cohort v2 (SPEC §10.7): the key must carry mass.
            -- A zero-mass "1" or "~" is the simple shape written with an
            -- explicit zero, so it no longer qualifies a claim by itself.
            -- `COALESCE` keeps a non-numeric value (no stored BBA has one)
            -- from failing the whole cohort: it reads as no mass.
            SELECT mf.claim_id
              FROM mass_functions mf
              JOIN frames f ON f.id = mf.frame_id
             WHERE array_length(f.hypotheses, 1) = 2
               AND (COALESCE(CASE WHEN jsonb_typeof(mf.masses->'1') = 'number'
                                  THEN (mf.masses->>'1')::float8 END, 0) > 0
                    OR COALESCE(CASE WHEN jsonb_typeof(mf.masses->'~') = 'number'
                                     THEN (mf.masses->>'~')::float8 END, 0) > 0)
             GROUP BY mf.claim_id, mf.frame_id
            HAVING COUNT(*) = 1
        ) cohort
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Discover every distinct `frame_id` a claim has BBAs on, ordered by the
/// frame's name. Name order is only a stable listing order for the dry-run
/// preview; which frame's value a real run caches is decided by
/// `MassFunctionRepository::cache_owner_frame_for_claim`, never by name.
async fn claim_frames(pool: &PgPool, claim_id: Uuid) -> Result<Vec<Uuid>, String> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT DISTINCT mf.frame_id, f.name \
           FROM mass_functions mf \
           JOIN frames f ON f.id = mf.frame_id \
          WHERE mf.claim_id = $1 \
          ORDER BY f.name",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("list frames for claim: {e}"))?;
    Ok(rows.into_iter().map(|(frame_id, _name)| frame_id).collect())
}

/// Dry-run half: preview the recomputed belief for every frame this claim
/// has BBAs on, without writing anything. Returns `(frame_id, preview)`
/// pairs in frame-name order. `run_claim` writes only the owner frame's
/// value; [`predict_cached_after`] returns that one.
///
/// # Errors
/// Propagates any error from the frame-discovery query or from
/// `epigraph_engine::edge_factor::preview_claim_belief_on_frame`.
pub async fn preview_claim(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
) -> Result<Vec<(Uuid, epigraph_engine::edge_factor::CombinedBeliefPreview)>, String> {
    let frames = claim_frames(pool, claim_id).await?;
    let mut out = Vec::with_capacity(frames.len());
    for frame_id in frames {
        // An operator one-shot, run on whatever DSN the operator supplies — in
        // practice a superuser, where a stamp is inert. The acquire is mechanical:
        // it moves the whole recompute onto ONE connection.
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;
        if let Some(preview) = epigraph_engine::edge_factor::preview_claim_belief_on_frame(
            &mut conn, viewer, claim_id, frame_id,
        )
        .await?
        {
            out.push((frame_id, preview));
        }
    }
    Ok(out)
}

/// Dry-run prediction: the `(owner frame, preview)` a real run (`run_claim`)
/// would leave in the claim's cache, or `None` when the claim has no input.
///
/// # Errors
/// Propagates any error from the owner lookup or the preview.
pub async fn predict_cached_after(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
) -> Result<Option<(Uuid, epigraph_engine::edge_factor::CombinedBeliefPreview)>, String> {
    // Same read-only owner lookup `run_claim`'s recompute uses, on one
    // connection, then the write-free preview of that frame alone.
    let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;
    let Some(owner) = epigraph_db::MassFunctionRepository::cache_owner_frame_for_claim(
        &mut *conn, viewer, claim_id,
    )
    .await
    .map_err(|e| format!("cache_owner_frame_for_claim: {e}"))?
    else {
        return Ok(None);
    };
    Ok(epigraph_engine::edge_factor::preview_claim_belief_on_frame(
        &mut conn, viewer, claim_id, owner,
    )
    .await?
    .map(|preview| (owner, preview)))
}

/// One claim through the single atom-cache writer
/// (`epigraph_engine::edge_factor::recompute_atom_cache`, SPEC §4.2) under
/// this process's `EPIGRAPH_ATOM_FOLD`: the AEF where the fold covers the
/// claim's role, else the owner-frame legacy fold this binary always wrote.
/// A compound is never written. Returns 1 when the cache was written, 0
/// otherwise.
///
/// Under the default `legacy` fold this is exactly the previous behaviour
/// (`recompute_claim_cached_belief`, which carries the PR-0 guard).
///
/// # Errors
/// Propagates any error from the engine's recompute-and-write call.
pub async fn run_claim(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
) -> Result<usize, String> {
    // An operator one-shot: the whole recompute rides ONE connection.
    let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;
    let outcome = epigraph_engine::edge_factor::recompute_atom_cache(
        &mut conn,
        viewer,
        claim_id,
        CacheWriteCause::Organic,
        LegacyFold::OwnerFrame,
    )
    .await?;
    Ok(usize::from(outcome_written(&outcome)))
}

/// Whether the writer reports a cache write.
#[must_use]
pub const fn outcome_written(outcome: &AtomCacheOutcome) -> bool {
    match outcome {
        AtomCacheOutcome::Legacy { written }
        | AtomCacheOutcome::Folded { written, .. }
        | AtomCacheOutcome::Vacated { written } => *written,
        AtomCacheOutcome::CompoundSkipped
        | AtomCacheOutcome::NotVisible
        | AtomCacheOutcome::KeptEmpty => false,
    }
}

/// BetP of the vacuous interval (Bel 0, Pl 1).
const VACUOUS_BETP: f64 = 0.5;

/// The CLI spelling of a fold mode (as `EPIGRAPH_ATOM_FOLD` takes it).
#[must_use]
pub const fn fold_str(fold: AtomFoldMode) -> &'static str {
    match fold {
        AtomFoldMode::Legacy => "legacy",
        AtomFoldMode::AefStandalone => "aef_standalone",
        AtomFoldMode::Aef => "aef",
    }
}

// ── cohort v2: waves over evidenced atoms (SPEC §10.3, §10.7) ──────────────

/// Which atoms a wave covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaveRole {
    /// Claims with no in-force `decomposes_to` in either direction (W0).
    Standalone,
    /// Decomposition leaves: a `decomposes_to` in-edge and none out (W1).
    Leaf,
}

impl WaveRole {
    /// Parse `standalone` / `leaf`.
    #[must_use]
    pub fn parse_value(raw: &str) -> Option<Self> {
        match raw.trim() {
            "standalone" => Some(Self::Standalone),
            "leaf" => Some(Self::Leaf),
            _ => None,
        }
    }

    /// The CLI spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Leaf => "leaf",
        }
    }

    /// The [`ClaimRole`] this wave covers.
    #[must_use]
    pub const fn claim_role(self) -> ClaimRole {
        match self {
            Self::Standalone => ClaimRole::Standalone,
            Self::Leaf => ClaimRole::Atom,
        }
    }

    /// Whether `fold` folds this role's caches with the AEF (SPEC §10.2):
    /// standalones under `aef_standalone` and `aef`, leaves under `aef` only.
    #[must_use]
    pub const fn folded_by(self, fold: AtomFoldMode) -> bool {
        match self {
            Self::Standalone => matches!(fold, AtomFoldMode::AefStandalone | AtomFoldMode::Aef),
            Self::Leaf => matches!(fold, AtomFoldMode::Aef),
        }
    }
}

/// How many claims one AEF-input probe reads at a time.
const COHORT_PROBE_CHUNK: usize = 500;

/// The wave cohort (SPEC §10.7): current claims of `role` (never a compound,
/// a procedural or a rule claim) whose AEF input is non-empty, as the single
/// atom-cache writer reads it under `compound_source_edges` (P1). A claim
/// whose only input is the ingest template, a cached combination or nothing
/// is not in it. Ordered by id.
///
/// # Errors
/// A database read.
pub async fn select_wave_cohort(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    role: WaveRole,
    compound_source_edges: CompoundSourceEdges,
) -> Result<Vec<Uuid>, String> {
    // Candidates: current claims of the role that carry at least one BBA (a
    // claim with none has no AEF input; the EXISTS keeps the role expression
    // off claims that cannot qualify). The role is CLAIM_ROLE_SQL, the one
    // spelling (`epigraph_db::repos::claim_role`).
    let sql = format!(
        "SELECT c.id FROM claims c \
          WHERE c.is_current \
            AND EXISTS (SELECT 1 FROM mass_functions mf WHERE mf.claim_id = c.id) \
            AND {role_sql} = $1 \
          ORDER BY c.id",
        role_sql = claim_role_sql("c"),
    );
    let candidates: Vec<Uuid> = sqlx::query_scalar(&sql)
        .bind(role.claim_role().as_sql())
        .fetch_all(pool)
        .await
        .map_err(|e| format!("wave cohort candidates: {e}"))?;

    let ctx = epigraph_engine::belief_query::FramedBeliefContext::global();
    let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;
    let mut cohort = Vec::new();
    for chunk in candidates.chunks(COHORT_PROBE_CHUNK) {
        let inputs = epigraph_engine::atom_items::atom_axiom_rows_under(
            &mut conn,
            viewer,
            chunk,
            AxiomMode::Display,
            &ctx,
            compound_source_edges,
        )
        .await?;
        cohort.extend(
            chunk
                .iter()
                .copied()
                .filter(|id| inputs.get(id).is_some_and(|rows| !rows.is_empty())),
        );
    }
    Ok(cohort)
}

// ── the disk gate (SPEC §10.4) ─────────────────────────────────────────────

/// The disk gate a writing run passes before EVERY batch (SPEC §10.4): the
/// free space on the data volume, less the batch's projected write volume,
/// must stay at or above the headroom, and an optional operator command
/// (backup and archive health, for example) must exit 0. A failure aborts the
/// run before that batch writes anything.
#[derive(Debug, Clone)]
pub struct DiskGate {
    /// A path on the volume to measure (the database's data volume).
    pub path: std::path::PathBuf,
    /// Headroom that must remain after the batch, in bytes.
    pub min_free_bytes: u64,
    /// Projected write volume per claim (WAL and archive), in bytes.
    pub projected_bytes_per_claim: u64,
    /// A shell command run before each batch; non-zero exit fails the gate.
    pub check_cmd: Option<String>,
}

impl DiskGate {
    /// Check the gate for a batch of `claims` claims.
    ///
    /// # Errors
    /// Why the gate failed: the free space could not be read, the headroom
    /// would be crossed, or the check command failed.
    pub fn check(&self, claims: usize) -> Result<(), String> {
        let free = free_bytes(&self.path)?;
        let projected = self
            .projected_bytes_per_claim
            .saturating_mul(u64::try_from(claims).unwrap_or(u64::MAX));
        let after = free.saturating_sub(projected);
        if after < self.min_free_bytes {
            return Err(format!(
                "disk check failed on {}: {free} bytes free, {projected} projected for this \
                 batch, leaves {after} < the {} byte headroom",
                self.path.display(),
                self.min_free_bytes
            ));
        }
        if let Some(cmd) = &self.check_cmd {
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .status()
                .map_err(|e| format!("disk check command {cmd:?} could not run: {e}"))?;
            if !status.success() {
                return Err(format!("disk check command {cmd:?} failed: {status}"));
            }
        }
        Ok(())
    }
}

/// Free bytes on the volume holding `path`, from POSIX `df -P -k`.
fn free_bytes(path: &std::path::Path) -> Result<u64, String> {
    let out = std::process::Command::new("df")
        .arg("-P")
        .arg("-k")
        .arg(path)
        .output()
        .map_err(|e| format!("disk check: df could not run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "disk check: df {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_df_available_kib(&String::from_utf8_lossy(&out.stdout))
        .map(|kib| kib.saturating_mul(1024))
        .ok_or_else(|| {
            format!(
                "disk check: cannot read the available space for {} from df",
                path.display()
            )
        })
}

/// The "Available" column (KiB) of `df -P -k` output's data line.
fn parse_df_available_kib(out: &str) -> Option<u64> {
    out.lines()
        .nth(1)
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|v| v.parse().ok())
}

// ── the wave file ──────────────────────────────────────────────────────────

/// Where a writing run records what it wrote (SPEC §10.8): the wave file
/// (claim caches, [`WaveRecord`]) and its scoped sidecar
/// ([`ScopedWaveRecord`]), both appended and flushed BEFORE the write they
/// record commits, so every committed write has a record.
pub struct WaveLog {
    wave: String,
    at: DateTime<Utc>,
    claims: std::sync::Mutex<std::fs::File>,
    scoped: std::sync::Mutex<std::fs::File>,
}

impl WaveLog {
    /// Open (append, create) `wave_file` and its sidecar for the wave named
    /// `wave` whose run started at `at` (the database clock, before the first
    /// write; see [`WaveRecord::at`]).
    ///
    /// # Errors
    /// Either file cannot be opened.
    pub fn open(wave_file: &std::path::Path, wave: &str, at: DateTime<Utc>) -> Result<Self, String> {
        let open = |p: &std::path::Path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .map_err(|e| format!("{}: {e}", p.display()))
        };
        Ok(Self {
            wave: wave.to_string(),
            at,
            claims: std::sync::Mutex::new(open(wave_file)?),
            scoped: std::sync::Mutex::new(open(&scoped_sidecar_path(wave_file))?),
        })
    }

    /// The run's `wave_at`.
    #[must_use]
    pub const fn at(&self) -> DateTime<Utc> {
        self.at
    }

    fn record(&self, wave: &str, claim_id: Uuid, before: CacheColumns, written: CacheColumns) -> Result<(), String> {
        let mut f = self.claims.lock().map_err(|_| "wave file lock poisoned".to_string())?;
        let mut line = Vec::new();
        write_wave_record(
            &mut line,
            &WaveRecord {
                claim_id,
                before,
                written,
                wave: wave.to_string(),
                at: self.at,
            },
        )
        .map_err(|e| format!("wave record: {e}"))?;
        f.write_all(&line)
            .and_then(|()| f.flush())
            .and_then(|()| f.sync_data())
            .map_err(|e| format!("wave file write: {e}"))
    }

    fn record_scoped(&self, rec: &ScopedWaveRecord) -> Result<(), String> {
        let mut f = self.scoped.lock().map_err(|_| "scoped file lock poisoned".to_string())?;
        let mut line = Vec::new();
        write_scoped_record(&mut line, rec).map_err(|e| format!("scoped record: {e}"))?;
        f.write_all(&line)
            .and_then(|()| f.flush())
            .and_then(|()| f.sync_data())
            .map_err(|e| format!("scoped file write: {e}"))
    }
}

/// What one wave write did.
#[derive(Debug, Clone, PartialEq)]
pub struct WaveClaimOutcome {
    /// The single atom-cache writer's outcome.
    pub outcome: AtomCacheOutcome,
    /// The claim's cache changed (and was recorded).
    pub changed: bool,
    /// Scoped rows rewritten (and recorded).
    pub scoped_rewritten: usize,
    /// Scoped rows left alone: no AEF row of their scope, or an override.
    pub scoped_kept: usize,
}

async fn lock_cache(
    tx: &mut sqlx::PgConnection,
    claim_id: Uuid,
) -> Result<Option<CacheColumns>, String> {
    let locked: Option<Uuid> = sqlx::query_scalar("SELECT id FROM claims WHERE id = $1 FOR UPDATE")
        .bind(claim_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("lock claim: {e}"))?;
    if locked.is_none() {
        return Ok(None);
    }
    Ok(read_cache_columns(&mut *tx, &[claim_id])
        .await
        .map_err(|e| format!("read cache: {e}"))?
        .remove(&claim_id))
}

/// One wave write (SPEC §10.7): in ONE transaction, lock the claim, read its
/// cache, run the single atom-cache writer under `settings`, read the cache
/// back, record `before` and `written` (only when it changed), resync the
/// atom's existing per-scope rows from the fold (when the AEF wrote), and
/// commit. Records are flushed before the commit.
///
/// # Errors
/// A database read or write, a fold, or a record write; the transaction is
/// rolled back.
pub async fn write_wave_claim(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    settings: AtomCacheSettings,
    log: &WaveLog,
) -> Result<WaveClaimOutcome, String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let Some(before) = lock_cache(&mut tx, claim_id).await? else {
        return Ok(WaveClaimOutcome {
            outcome: AtomCacheOutcome::NotVisible,
            changed: false,
            scoped_rewritten: 0,
            scoped_kept: 0,
        });
    };
    let outcome = epigraph_engine::edge_factor::recompute_atom_cache_with(
        &mut tx,
        viewer,
        claim_id,
        CacheWriteCause::Organic,
        LegacyFold::OwnerFrame,
        settings,
    )
    .await?;
    let after = read_cache_columns(&mut *tx, &[claim_id])
        .await
        .map_err(|e| format!("read cache: {e}"))?
        .remove(&claim_id)
        .ok_or_else(|| format!("claim {claim_id} vanished inside its own transaction"))?;
    let changed = after != before;
    if changed {
        log.record(&log.wave, claim_id, before, after)?;
    }
    let (scoped_rewritten, scoped_kept) = match &outcome {
        AtomCacheOutcome::Folded {
            interval,
            written: true,
        } => {
            resync_scoped_rows(
                &mut tx,
                viewer,
                claim_id,
                interval,
                settings.compound_source_edges,
                log,
            )
            .await?
        }
        _ => (0, 0),
    };
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(WaveClaimOutcome {
        outcome,
        changed,
        scoped_rewritten,
        scoped_kept,
    })
}

/// `strategy_used` of a scoped row a wave rewrote from the atom fold.
pub const SCOPED_RESYNC_STRATEGY: &str = "atom_fold";
/// `strategy_used` of a community row written from the community's own mass
/// override (`routes/belief.rs`): not a fold of the atom's rows, kept.
const SCOPED_OVERRIDE_STRATEGY: &str = "override";

type ScopedRow = (
    Uuid,
    Uuid,
    String,
    Option<Uuid>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<String>,
    Option<f64>,
);

/// Resync an atom's EXISTING `ds_combined_beliefs` rows from the atom fold
/// (SPEC §7.2), mirroring the selection `routes/belief.rs` folds per scope:
/// a `global` row takes the atom's fold (`interval`, what the cache got); a
/// `perspective` row the fold of the atom's AEF rows from that perspective;
/// a `community` row the fold of the rows from its member perspectives. A
/// scope with no AEF row, and a community override row, is left as it is.
/// No row is created. Returns `(rewritten, kept)`.
async fn resync_scoped_rows(
    tx: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    interval: &EvidencedInterval,
    compound_source_edges: CompoundSourceEdges,
    log: &WaveLog,
) -> Result<(usize, usize), String> {
    let rows: Vec<ScopedRow> = sqlx::query_as(
        "SELECT id, frame_id, scope_type, scope_id, belief, plausibility, mass_on_empty, \
                mass_on_missing, conflict_k, strategy_used, pignistic_prob \
           FROM ds_combined_beliefs WHERE claim_id = $1 ORDER BY id FOR UPDATE",
    )
    .bind(claim_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("scoped rows: {e}"))?;
    if rows.is_empty() {
        return Ok((0, 0));
    }
    let drift_rows = if rows.iter().any(|r| r.2 != "global") {
        epigraph_engine::atom_items::atom_drift_rows(
            &mut *tx,
            viewer,
            &[claim_id],
            compound_source_edges,
        )
        .await?
        .remove(&claim_id)
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    let (mut rewritten, mut kept) = (0, 0);
    for (id, frame_id, scope_type, scope_id, b, p, me, mm, k, strategy, betp) in rows {
        let before = ScopedColumns {
            belief: b,
            plausibility: p,
            mass_on_empty: me,
            mass_on_missing: mm,
            conflict_k: k,
            strategy_used: strategy.clone(),
            pignistic_prob: betp,
        };
        let fold = match (scope_type.as_str(), scope_id) {
            ("global", _) => Some(interval.clone()),
            ("perspective", Some(pid)) => drift_scope_fold(&drift_rows, &BTreeSet::from([pid]))?,
            ("community", Some(cid)) if strategy.as_deref() != Some(SCOPED_OVERRIDE_STRATEGY) => {
                let members: BTreeSet<Uuid> = sqlx::query_scalar::<_, Uuid>(
                    "SELECT perspective_id FROM community_members WHERE community_id = $1",
                )
                .bind(cid)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| format!("community members: {e}"))?
                .into_iter()
                .collect();
                drift_scope_fold(&drift_rows, &members)?
            }
            _ => None,
        };
        let Some(fold) = fold else {
            kept += 1;
            continue;
        };
        let written = ScopedColumns {
            belief: Some(fold.belief()),
            plausibility: Some(fold.plausibility()),
            mass_on_empty: Some(fold.mass_on_conflict()),
            mass_on_missing: Some(fold.mass_on_missing()),
            conflict_k: (fold.items() > 1).then_some(fold.mass_on_conflict()),
            strategy_used: Some(SCOPED_RESYNC_STRATEGY.to_string()),
            pignistic_prob: Some(fold.pignistic_prob()),
        };
        if written == before {
            continue;
        }
        log.record_scoped(&ScopedWaveRecord {
            row_id: id,
            claim_id,
            frame_id,
            scope_type,
            scope_id,
            before,
            written: written.clone(),
            wave: log.wave.clone(),
            at: log.at,
        })?;
        sqlx::query(
            "UPDATE ds_combined_beliefs SET belief = $2, plausibility = $3, mass_on_empty = $4, \
                    mass_on_missing = $5, conflict_k = $6, strategy_used = $7, \
                    pignistic_prob = $8, computed_at = now() \
              WHERE id = $1",
        )
        .bind(id)
        .bind(written.belief)
        .bind(written.plausibility)
        .bind(written.mass_on_empty)
        .bind(written.mass_on_missing)
        .bind(written.conflict_k)
        .bind(written.strategy_used)
        .bind(written.pignistic_prob)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("scoped resync write: {e}"))?;
        rewritten += 1;
    }
    Ok((rewritten, kept))
}

// ── the accepted-vacate path (SPEC §10.5) ──────────────────────────────────

/// An operator-accepted vacate list: the claim ids in file order (duplicates
/// dropped), the class rule(s) it was generated from, and the file's SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptList {
    pub ids: Vec<Uuid>,
    pub rules: Vec<String>,
    pub sha256: String,
}

/// Parse an accept list: JSON lines, each either `{"claim_id": "<uuid>", ...}`
/// (one accepted claim; other fields are carried by the file, not read) or
/// `{"rule": "<the accepted class rule>", ...}` (stored with the list). Blank
/// lines are skipped; anything else is an error naming its line.
///
/// # Errors
/// A malformed line.
pub fn parse_accept_list(bytes: &[u8]) -> Result<AcceptList, String> {
    use sha2::Digest as _;
    let text = std::str::from_utf8(bytes).map_err(|e| format!("accept list is not UTF-8: {e}"))?;
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    let mut rules = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("accept list line {}: {e}", i + 1))?;
        if let Some(id) = v.get("claim_id") {
            let id: Uuid = id
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("accept list line {}: claim_id is not a uuid", i + 1))?;
            if seen.insert(id) {
                ids.push(id);
            }
        } else if let Some(rule) = v.get("rule").and_then(serde_json::Value::as_str) {
            rules.push(rule.to_string());
        } else {
            return Err(format!(
                "accept list line {}: neither a claim_id nor a rule",
                i + 1
            ));
        }
    }
    Ok(AcceptList {
        ids,
        rules,
        sha256: hex::encode(sha2::Sha256::digest(bytes)),
    })
}

/// One accepted vacate (SPEC §10.5), in one transaction: lock the claim,
/// read its cache, `vacate_atom_cache` (which refuses a compound, a
/// procedural or rule claim and an atom with AEF input), read back, record
/// `before`/`written` when it changed, commit.
///
/// # Errors
/// A database read or write, or a record write.
pub async fn vacate_listed_claim(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    compound_source_edges: CompoundSourceEdges,
    log: &WaveLog,
    wave: &str,
) -> Result<VacateOutcome, String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let Some(before) = lock_cache(&mut tx, claim_id).await? else {
        return Ok(VacateOutcome::NotVisible);
    };
    let outcome = epigraph_engine::edge_factor::vacate_atom_cache(
        &mut tx,
        viewer,
        claim_id,
        compound_source_edges,
    )
    .await?;
    let after = read_cache_columns(&mut *tx, &[claim_id])
        .await
        .map_err(|e| format!("read cache: {e}"))?
        .remove(&claim_id)
        .ok_or_else(|| format!("claim {claim_id} vanished inside its own transaction"))?;
    if after != before {
        log.record(wave, claim_id, before, after)?;
    }
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(outcome)
}

