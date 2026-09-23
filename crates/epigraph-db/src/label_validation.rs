//! Write-time rejection of label values that still carry unexpanded shell syntax.
//!
//! # Evidence
//!
//! Claim `2a0125e2` carries the literal label `group:$EPICLAW_GROUP_ID` — a
//! shell variable that was interpolated into a label array by an agent script
//! and never expanded. Before this module no label-content validation existed
//! on any claim-label write path: the HTTP handler
//! `epigraph_api::routes::claims::update_labels` checked only that `add`/`remove`
//! were non-empty plus ownership, the MCP `submit_claim` / `update_labels` tools
//! passed `labels` through verbatim, and `epigraph_core::labels::Label::new`
//! (the only validating constructor in the workspace) is never called on a
//! claim-label write path.
//!
//! A literal-variable label is worse than a typo: it is a *silent* grouping
//! failure. Every claim that should have joined `group:<uuid>` instead joins a
//! group that can never exist, so the label reads as a membership signal while
//! conveying none.
//!
//! # Why not reuse `Label::validate`
//!
//! `epigraph_core::labels::Label::validate` permits only
//! `[A-Za-z][A-Za-z0-9_]*` — it rejects `:` and `/`, which essentially every
//! real EpiGraph label uses (`backlog`, `src:MEMORY.md`, `policy:active`,
//! `claude-memory`). Reusing it would reject the entire live label vocabulary,
//! so this module carries a deliberately *narrow* predicate instead.
//!
//! # The predicate
//!
//! A label is rejected iff it contains `$`. The motivating corruption is shell
//! parameter/command syntax (`$NAME`, `${NAME}`, `$(cmd)`), but the check is the
//! blanket character rather than that subset, because:
//!
//! * a truncated expansion (`group:$`) is the same bug and the subset misses it;
//! * `$` carries no meaning in any EpiGraph label. Measured, not assumed: no
//!   label literal in `crates/` contains `$`, and
//!   `SELECT DISTINCT l FROM claims, unnest(labels) l WHERE l LIKE '%$%'`
//!   returns zero rows on the repo test database.
//!
//! Deliberately NOT part of the predicate: a general label grammar. `:`, `/`
//! and `-` are load-bearing separators and must keep flowing through.
//!
//! # Applies to added labels only
//!
//! Callers must validate the **add** side and never the **remove** side.
//! Removal is the remediation path for the rows already carrying
//! `group:$EPICLAW_GROUP_ID`; rejecting a bad value in `remove` would make the
//! corruption permanently unfixable through the API.

use crate::errors::DbError;

/// The character whose presence in a label indicates an unexpanded expansion.
const SHELL_SIGIL: char = '$';

/// Reject any label in `labels` that contains unexpanded shell syntax.
///
/// Intended for the **added** labels of a write. See the module docs for why
/// the removed side must NOT be passed here.
///
/// # Errors
/// Returns [`DbError::InvalidData`] naming the offending label. Callers in
/// `epigraph-api` surface this as HTTP 400 `ValidationError` (see the
/// `From<DbError> for ApiError` mapping); handlers that match on `DbError`
/// explicitly must add an `InvalidData` arm or the rejection degrades to a 500.
pub fn reject_unexpanded_labels(labels: &[String]) -> Result<(), DbError> {
    for label in labels {
        if label.contains(SHELL_SIGIL) {
            return Err(DbError::InvalidData {
                reason: format!(
                    "label {label:?} contains an unexpanded shell variable ('{SHELL_SIGIL}'); \
                     interpolate it before writing, or quote the intended literal value"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact corruption from the backlog report must be refused.
    #[test]
    fn rejects_the_observed_unexpanded_group_label() {
        let err = reject_unexpanded_labels(&["group:$EPICLAW_GROUP_ID".to_string()])
            .expect_err("an unexpanded shell variable must not be accepted as a label");
        let DbError::InvalidData { reason } = err else {
            panic!("expected DbError::InvalidData, got {err:?}");
        };
        // The offending value must appear in the message: an operator reading a
        // 400 needs to know WHICH label of the array was refused.
        assert!(
            reason.contains("group:$EPICLAW_GROUP_ID"),
            "rejection must name the offending label, got: {reason}"
        );
    }

    /// Braced, command-substitution and truncated forms are the same bug.
    #[test]
    fn rejects_braced_command_and_truncated_expansions() {
        for bad in [
            "group:${EPICLAW_GROUP_ID}",
            "run:$(hostname)",
            "group:$",
            "$AGENT",
        ] {
            assert!(
                reject_unexpanded_labels(&[bad.to_string()]).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    /// The live label vocabulary must keep flowing through. These are real
    /// labels from the graph; `Label::validate` would reject every one that
    /// carries `:`, `/` or `-`, which is why it could not be reused.
    #[test]
    fn accepts_the_live_label_vocabulary() {
        let real = [
            "backlog",
            "resolved",
            "claude-memory",
            "src:MEMORY.md",
            "policy:active",
            "policy:challenge",
            "group:0f4d3c1e-2b8a-4c6d-9e31-7a5b2c8d4f60",
            "telemetry",
            "workflow",
            "hypothesis",
            "docs/conventions/backlog-retirement.md",
        ]
        .map(String::from);
        assert!(
            reject_unexpanded_labels(&real).is_ok(),
            "no real label may be refused by this predicate"
        );
    }

    /// One bad value anywhere in the array fails the whole write — labels are
    /// applied as a single array update, so partial acceptance is not a thing.
    #[test]
    fn one_bad_label_rejects_the_whole_array() {
        let labels = [
            "backlog".to_string(),
            "group:$EPICLAW_GROUP_ID".to_string(),
            "resolved".to_string(),
        ];
        assert!(reject_unexpanded_labels(&labels).is_err());
    }

    #[test]
    fn empty_add_list_is_accepted() {
        assert!(reject_unexpanded_labels(&[]).is_ok());
    }
}
