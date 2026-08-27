//! Repository for the obligation layer
//! (backlog 4b48ffb5, `migrations/073_obligations.sql`).
//!
//! Per CLAUDE.md every statement this feature issues lives here. The rule
//! table — which standards are decidable by counting and which are not — is a
//! pure function in [`epigraph_core::obligation`] and issues no SQL of its
//! own.
//!
//! # Why the verdict is stored AND recomputable
//!
//! A verdict computed at write time DECAYS. `ClaimRepository::supersede` and
//! `mark_duplicate` both flip `is_current = false`, so a contract that was
//! satisfied on Tuesday is breached on Friday when one of its anchors is
//! retired. Storing the anchor ids as `UUID[]` is what makes
//! [`ObligationRepository::recheck`] able to re-derive the numerator from the
//! live graph instead of trusting the stored number.
//!
//! # No foreign key on `anchors`
//!
//! Postgres cannot FK an array element. A vanished anchor is simply not
//! counted by `recheck`'s `WHERE id = ANY($1)`, which is the correct
//! arithmetic — a deleted anchor covers nothing — rather than a lost referent
//! or a constraint error.

use chrono::{DateTime, Utc};
use epigraph_core::obligation::{evaluate, CoverageContract, CoverageStandard};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

/// `obligations.anchor_kind` for a `claims` row. The only kind implemented.
pub const ANCHOR_KIND_CLAIM: &str = "claim";

/// One stored `obligations` row.
#[derive(Debug, Clone)]
pub struct ObligationRow {
    pub id: Uuid,
    pub agent_id: Option<Uuid>,
    /// One of `CoverageStandard::VOCABULARY`, enforced by
    /// `obligations_standard_vocab`.
    pub standard: String,
    pub unit: String,
    pub declared_total: i32,
    /// Distinct anchor ids. Order is not meaningful.
    pub anchors: Vec<Uuid>,
    pub anchor_kind: String,
    pub observed_total: i32,
    /// `satisfied` | `breach` | `indeterminate` | `not_applicable`.
    pub verdict: String,
    pub verdict_reason: Option<String>,
    /// What the contract has not specified about itself.
    pub missing_contract_fields: Vec<String>,
    pub source_tool: String,
    pub created_at: DateTime<Utc>,
    pub checked_at: DateTime<Utc>,
}

/// Everything one `obligations` INSERT needs.
///
/// `verdict` / `observed_total` / `verdict_reason` / `missing_contract_fields`
/// come from [`epigraph_core::obligation::evaluate`]; the repository does not
/// re-derive them on insert so the caller's response and the stored row can
/// never disagree about what was decided at write time.
#[derive(Debug, Clone)]
pub struct NewObligation {
    pub agent_id: Option<Uuid>,
    pub standard: CoverageStandard,
    pub unit: String,
    pub declared_total: i32,
    pub anchors: Vec<Uuid>,
    pub anchor_kind: String,
    pub observed_total: i32,
    pub verdict: String,
    pub verdict_reason: Option<String>,
    pub missing_contract_fields: Vec<String>,
    pub source_tool: String,
}

pub struct ObligationRepository;

impl ObligationRepository {
    /// Insert one obligation, returning its id.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the insert fails — including when
    /// `verdict` is outside `obligations_verdict_vocab`. Callers on a write
    /// path that has already persisted its anchors are expected to warn and
    /// continue rather than propagate: an obligation is a record OF a write,
    /// never a precondition for it.
    #[instrument(skip(pool, obligation), fields(source_tool = %obligation.source_tool))]
    pub async fn record(pool: &PgPool, obligation: NewObligation) -> Result<Uuid, DbError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO obligations
                (agent_id, standard, unit, declared_total, anchors, anchor_kind,
                 observed_total, verdict, verdict_reason, missing_contract_fields,
                 source_tool)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            "#,
            obligation.agent_id,
            obligation.standard.as_str(),
            obligation.unit,
            obligation.declared_total,
            &obligation.anchors[..],
            obligation.anchor_kind,
            obligation.observed_total,
            obligation.verdict,
            obligation.verdict_reason,
            &obligation.missing_contract_fields[..],
            obligation.source_tool,
        )
        .fetch_one(pool)
        .await?;

        Ok(row.id)
    }

    /// Read one obligation by id.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<ObligationRow>, DbError> {
        let row = sqlx::query_as!(
            ObligationRow,
            r#"
            SELECT id, agent_id, standard, unit, declared_total,
                   anchors, anchor_kind, observed_total, verdict, verdict_reason,
                   missing_contract_fields, source_tool, created_at, checked_at
            FROM obligations
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Re-count an obligation's live anchors, re-decide it, and persist the
    /// fresh verdict.
    ///
    /// This is the whole point of storing `anchors` rather than only a number:
    /// a satisfied contract becomes a breach once one of its anchors is
    /// superseded or marked duplicate (both flip `is_current = false`), and an
    /// anchor deleted outright is simply not matched by `id = ANY($1)` —
    /// dropping it is the correct arithmetic, not an error.
    ///
    /// Returns `Ok(None)` when no such obligation exists.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any statement fails.
    #[instrument(skip(pool))]
    pub async fn recheck(pool: &PgPool, id: Uuid) -> Result<Option<ObligationRow>, DbError> {
        let Some(existing) = Self::get(pool, id).await? else {
            return Ok(None);
        };

        // Only `claim` anchors are countable in this MVP. Any other kind keeps
        // the stored numerator rather than silently recounting against the
        // wrong table.
        if existing.anchor_kind != ANCHOR_KIND_CLAIM {
            return Ok(Some(existing));
        }

        let counted = sqlx::query!(
            r#"
            SELECT COUNT(DISTINCT id) AS "n!"
            FROM claims
            WHERE id = ANY($1) AND is_current = true
            "#,
            &existing.anchors[..],
        )
        .fetch_one(pool)
        .await?;

        // A row can only reach the table through `obligations_standard_vocab`,
        // so an unparseable standard means the SQL vocabulary drifted from
        // `CoverageStandard`. Surface that rather than guessing a standard on
        // the caller's behalf — a silent default would make a drifted row owe
        // whatever the default happens to owe.
        let standard: CoverageStandard =
            existing
                .standard
                .parse()
                .map_err(|e| DbError::InvalidData {
                    reason: format!("obligation {id} stores an unrecognised standard: {e}"),
                })?;

        let contract = CoverageContract {
            standard,
            unit: existing.unit.clone(),
            declared_total: u32::try_from(existing.declared_total).unwrap_or(u32::MAX),
        };
        let observed = u32::try_from(counted.n).unwrap_or(u32::MAX);
        let assessment = evaluate(&contract, observed);

        let row = sqlx::query_as!(
            ObligationRow,
            r#"
            UPDATE obligations
            SET observed_total          = $2,
                verdict                 = $3,
                verdict_reason          = $4,
                missing_contract_fields = $5,
                checked_at              = NOW()
            WHERE id = $1
            RETURNING id, agent_id, standard, unit, declared_total,
                      anchors, anchor_kind, observed_total, verdict, verdict_reason,
                      missing_contract_fields, source_tool, created_at, checked_at
            "#,
            id,
            i32::try_from(assessment.observed_total).unwrap_or(i32::MAX),
            assessment.verdict.as_str(),
            assessment.reason,
            &assessment.missing_contract_fields[..],
        )
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List obligations that are not closed — `breach` or `indeterminate` —
    /// most recently checked first. Served by `obligations_unmet_idx`.
    ///
    /// No MCP tool or HTTP route reads this yet; it exists for a future
    /// sweeper. Note before exposing it: this worktree predates the
    /// multi-user tenancy work, so `obligations` has no owner/group column and
    /// an unscoped listing would leak the SHAPE of another tenant's batch.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn list_unmet(
        pool: &PgPool,
        agent_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<ObligationRow>, DbError> {
        let rows = sqlx::query_as!(
            ObligationRow,
            r#"
            SELECT id, agent_id, standard, unit, declared_total,
                   anchors, anchor_kind, observed_total, verdict, verdict_reason,
                   missing_contract_fields, source_tool, created_at, checked_at
            FROM obligations
            WHERE verdict IN ('breach', 'indeterminate')
              AND ($1::uuid IS NULL OR agent_id = $1)
            ORDER BY checked_at DESC
            LIMIT $2
            "#,
            agent_id,
            limit.clamp(1, 500),
        )
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}
