//! The authorship countersign route: a person named on a document by
//! another principal's ingest (an `agent -authored-> paper` row marked
//! `pending_countersign`, the naming ingest's word) confirms or declines it.
//!
//! Every write goes through migration 208's
//! `epigraph_countersign_authorship` definer, called on the CALLER's stamped
//! transaction: it reads the caller from the session's principal, allows only
//! the named agent itself or that agent's LIVE operator (its operator link
//! while not retired, else its unrevoked client allowance), and audits each
//! act in `security_events`. The row's signed `properties` are never edited:
//!
//! * confirm adds the reserved label `epigraph:countersigned_by:<caller>`,
//!   which every reader of the pending mark
//!   ([`crate::agent_lookup::authorship_pending_sql`]) reads as NOT pending:
//!   the agent card counts the paper as authored, the claim block lists the
//!   person as a primary author where that ingest recorded them, and
//!   `query_paper` drops the flag;
//! * decline adds `epigraph:countersign_declined_by:<caller>` and retracts
//!   the row; the ingest dedup probe never lets a declined naming stop the
//!   person's own later ingest of the same fact.
//!
//! Not undone here: a pending naming never wrote the person's `asserts`
//! edges onto the naming ingest's claims, so a confirmation moves the card's
//! `authored_papers`, not its `asserted_claims`.

use uuid::Uuid;

use crate::errors::{DbError, RefusalKind};

/// What the named person decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountersignDecision {
    Confirm,
    Decline,
}

impl CountersignDecision {
    /// Parse `confirm` / `decline` (case-insensitive).
    ///
    /// # Errors
    /// `DbError::InvalidData` for anything else.
    pub fn parse(s: &str) -> Result<Self, DbError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "confirm" => Ok(Self::Confirm),
            "decline" => Ok(Self::Decline),
            other => Err(DbError::InvalidData {
                reason: format!("decision must be confirm or decline, got {other:?}"),
            }),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirm => "confirm",
            Self::Decline => "decline",
        }
    }
}

/// One authorship row the act changed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CountersignedRow {
    pub edge_id: Uuid,
    /// The principal whose ingest named the person (the row's marker).
    pub ingested_by: Option<Uuid>,
    /// `confirmed` or `declined`.
    pub outcome: String,
}

/// The countersign route's repository.
pub struct CountersignRepository;

impl CountersignRepository {
    /// Confirm or decline `agent`'s (default: the caller's) pending
    /// authorship of `paper`, every pending row or only `ingested_by`'s,
    /// on `conn`'s transaction, which must be stamped as the caller
    /// (`ScopedPool::begin_as`). An empty result means nothing was pending:
    /// nothing was written and nothing audited.
    ///
    /// # Errors
    /// `DbError::Refused` (authority) when the caller is not the named agent
    /// nor its live operator, or has no principal; otherwise as the query.
    pub async fn countersign_conn(
        conn: &mut sqlx::PgConnection,
        paper: Uuid,
        agent: Option<Uuid>,
        decision: CountersignDecision,
        ingested_by: Option<Uuid>,
    ) -> Result<Vec<CountersignedRow>, DbError> {
        let rows: Vec<(Uuid, Option<Uuid>, String)> = sqlx::query_as(
            "SELECT edge_id, ingested_by, outcome \
               FROM public.epigraph_countersign_authorship($1, $2, $3, $4)",
        )
        .bind(paper)
        .bind(agent)
        .bind(decision.as_str())
        .bind(ingested_by)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d)
                if d.message().starts_with("CSG01") || d.message().starts_with("CSG02") =>
            {
                DbError::Refused {
                    kind: RefusalKind::Authority,
                    message: d.message().to_string(),
                }
            }
            _ => DbError::from(e),
        })?;
        Ok(rows
            .into_iter()
            .map(|(edge_id, ingested_by, outcome)| CountersignedRow {
                edge_id,
                ingested_by,
                outcome,
            })
            .collect())
    }
}
