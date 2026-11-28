//! `EPIGRAPH_CONTRADICT_COMPOUND_GUARD` (backlog b4c2fc2f, 73317662): what a
//! `contradicts` or `refutes` edge aimed at an UNDECOMPOSED compound claim
//! does.
//!
//! A negative edge transmits the source's belief as disbelief in its WHOLE
//! target. When the target's text asserts several independent things and
//! nobody has split it into atoms, a contradiction that disputes one of them
//! lands on all of them: the target's other conjuncts lose belief for a
//! reason that is not about them (a partial contradiction). The remedy is to
//! decompose the target and contradict the atom actually disputed.
//!
//! The guard fires when all three hold:
//!
//! 1. the relationship, ASCII case-folded, is `contradicts` or `refutes`
//!    ([`is_contradiction`]);
//! 2. the target's text screens compound
//!    (`epigraph_core::atomicity::conjunct_screen(..).is_compound()`);
//! 3. the target has NO in-force `decomposes_to` children: it is not a
//!    compound by structure (migration 193's definer,
//!    `claim_role::is_compound_by_definer`, decided on the whole graph). A
//!    decomposed target already has atoms, and its own belief is derived
//!    from them, so it is left alone here.
//!
//! The writers that act on it are MCP `link_epistemic` and REST
//! `POST /api/v1/edges`:
//!
//! - [`ContradictCompoundGuard::Warn`] (the default): the edge is written as
//!   before and the response adds `partial_contradiction_risk`
//!   ([`PartialContradictionRisk`]: `{conjuncts, hint}`). Once the edge has
//!   committed the writer logs the caller under [`LOG_TARGET`]
//!   ([`PartialContradictionRisk::log_accepted`]): the writer, the caller's
//!   agent id and the mode, never the claim's content, so the callers to fix
//!   before a flip to `refuse` can be read from the journal.
//! - [`ContradictCompoundGuard::Refuse`]: nothing is written, and the caller
//!   gets [`REFUSAL_CODE`] (MCP `invalid_params`, REST `422`).
//!
//! The writers decide AFTER their own not-found checks, on the target text
//! the caller could read, so the guard answers nothing about a claim the
//! caller cannot see.

use serde::Serialize;
use uuid::Uuid;

use epigraph_db::repos::claim_role;
use epigraph_db::DbError;

use crate::belief_modes::ContradictCompoundGuard;

/// The `tracing` target every guarded contradiction is logged under.
pub const LOG_TARGET: &str = "epigraph::contradiction_guard";

/// The machine-readable code of a refusal (MCP `data.error`, REST `error`).
pub const REFUSAL_CODE: &str = "compound_contradiction_target";

/// The relationships the guard covers, in their canonical spelling.
pub const RELATIONSHIPS: &[&str] = &["contradicts", "refutes"];

/// The `hint` every [`PartialContradictionRisk`] carries.
pub const HINT: &str = "The target claim appears to assert several independent things and has \
     not been decomposed, so this negative edge disputes all of them at once. If it disputes \
     only one, decompose the target into atoms (link_hierarchical with decomposes_to) and \
     aim the contradiction at the atom it disputes.";

/// Whether `relationship` (any ASCII case) is one the guard covers.
#[must_use]
pub fn is_contradiction(relationship: &str) -> bool {
    RELATIONSHIPS
        .iter()
        .any(|r| relationship.eq_ignore_ascii_case(r))
}

/// What a warned (or refused) contradiction is told: how many independent
/// assertions the target's text appears to make, and what to do instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartialContradictionRisk {
    /// `conjunct_screen(content).conjunct_count` of the target.
    pub conjuncts: usize,
    /// [`HINT`].
    pub hint: &'static str,
}

impl PartialContradictionRisk {
    /// The message of a `refuse`-mode refusal.
    #[must_use]
    pub fn refusal(&self, target_id: Uuid) -> String {
        format!(
            "claim {target_id} appears to assert {} independent things and has not been \
             decomposed: a contradicts/refutes edge onto it is not accepted \
             (EPIGRAPH_CONTRADICT_COMPOUND_GUARD=refuse); nothing was written. Decompose the \
             target into atoms (link_hierarchical with decomposes_to) and aim the edge at the \
             atom it disputes.",
            self.conjuncts
        )
    }

    /// The machine-readable body of a refusal, shared by both transports:
    /// `{"error": "compound_contradiction_target", "claim_id", "conjuncts",
    /// "hint", "flag", "retryable": false}`.
    #[must_use]
    pub fn refusal_data(&self, target_id: Uuid) -> serde_json::Value {
        serde_json::json!({
            "error": REFUSAL_CODE,
            "claim_id": target_id,
            "conjuncts": self.conjuncts,
            "hint": self.hint,
            "flag": ContradictCompoundGuard::ENV,
            "retryable": false,
        })
    }

    /// Log a `warn`-mode edge that has COMMITTED, under [`LOG_TARGET`]: the
    /// writer, the caller's agent id and the mode. Never the claim's content
    /// (nor its id): the journal names who to fix, not what they wrote.
    pub fn log_accepted(&self, writer: &'static str, caller: Option<Uuid>) {
        let caller = caller.map(|c| c.to_string());
        tracing::warn!(
            target: LOG_TARGET,
            writer,
            caller = caller.as_deref().unwrap_or("anonymous"),
            conjuncts = self.conjuncts,
            guard = ContradictCompoundGuard::Warn.as_str(),
            "contradiction onto an undecomposed compound accepted; the caller should \
             decompose the target and contradict the atom it disputes"
        );
    }
}

/// What the guard decided for one edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContradictionDecision {
    /// Not a contradiction, an atomic target, or a decomposed one: the write
    /// is unchanged.
    Unaffected,
    /// `warn`: the edge goes ahead, and the caller is told.
    Warn(PartialContradictionRisk),
    /// `refuse`: nothing may be written.
    Refuse(PartialContradictionRisk),
}

/// The text-only half of the trigger: `Some` when `relationship` is a
/// contradiction and `target_content` screens compound. Pure.
#[must_use]
pub fn screen(relationship: &str, target_content: &str) -> Option<PartialContradictionRisk> {
    if !is_contradiction(relationship) {
        return None;
    }
    let screened = epigraph_core::atomicity::conjunct_screen(target_content);
    screened.is_compound().then_some(PartialContradictionRisk {
        conjuncts: screened.conjunct_count,
        hint: HINT,
    })
}

/// Decide a `relationship` edge by `caller` through `writer` onto
/// `target_id`, whose text (as the caller read it) is `target_content`,
/// under `mode`, before anything is written. A refusal is logged here under
/// [`LOG_TARGET`] (writer, caller, mode; never content); an accepted (`warn`)
/// edge is logged by the writer once it has committed
/// ([`PartialContradictionRisk::log_accepted`]).
///
/// The decomposition test is read only when the text screens compound, on
/// `conn` with definer rights (whatever its row security admits).
///
/// # Errors
/// [`DbError`] when the query fails.
pub async fn decide(
    conn: &mut sqlx::PgConnection,
    relationship: &str,
    target_id: Uuid,
    target_content: &str,
    mode: ContradictCompoundGuard,
    writer: &'static str,
    caller: Option<Uuid>,
) -> Result<ContradictionDecision, DbError> {
    let Some(risk) = screen(relationship, target_content) else {
        return Ok(ContradictionDecision::Unaffected);
    };
    if claim_role::is_compound_by_definer(&mut *conn, target_id).await? {
        return Ok(ContradictionDecision::Unaffected);
    }
    match mode {
        ContradictCompoundGuard::Warn => Ok(ContradictionDecision::Warn(risk)),
        ContradictCompoundGuard::Refuse => {
            let caller = caller.map(|c| c.to_string());
            tracing::info!(
                target: LOG_TARGET,
                writer,
                caller = caller.as_deref().unwrap_or("anonymous"),
                conjuncts = risk.conjuncts,
                guard = mode.as_str(),
                "contradiction onto an undecomposed compound refused"
            );
            Ok(ContradictionDecision::Refuse(risk))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPOUND: &str = "The catalyst raised the yield, but it shortened the column life.";
    const ATOM: &str = "The catalyst raised the yield.";

    #[test]
    fn only_contradicts_and_refutes_in_any_case_are_covered() {
        for rel in ["contradicts", "CONTRADICTS", "Refutes", "refutes"] {
            assert!(is_contradiction(rel), "{rel}");
            assert!(screen(rel, COMPOUND).is_some(), "{rel}");
        }
        for rel in [
            "supports",
            "corroborates",
            "qualifies",
            "cites",
            "contradict",
            "",
        ] {
            assert!(!is_contradiction(rel), "{rel}");
            assert!(screen(rel, COMPOUND).is_none(), "{rel}");
        }
    }

    #[test]
    fn an_atomic_target_text_is_not_screened() {
        assert!(screen("contradicts", ATOM).is_none());
        let risk = screen("refutes", COMPOUND).expect("compound text");
        assert_eq!(risk.conjuncts, 2);
        assert_eq!(risk.hint, HINT);
    }

    #[test]
    fn the_refusal_body_is_machine_keyed_and_names_the_flag() {
        let risk = screen("contradicts", COMPOUND).unwrap();
        let id = Uuid::from_u128(7);
        let data = risk.refusal_data(id);
        assert_eq!(data["error"], REFUSAL_CODE);
        assert_eq!(data["claim_id"], id.to_string());
        assert_eq!(data["conjuncts"], 2);
        assert_eq!(data["flag"], "EPIGRAPH_CONTRADICT_COMPOUND_GUARD");
        assert_eq!(data["retryable"], false);
        assert!(risk.refusal(id).contains("nothing was written"));
        let wire = serde_json::to_value(&risk).unwrap();
        assert_eq!(
            wire.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["conjuncts", "hint"]
        );
    }
}
