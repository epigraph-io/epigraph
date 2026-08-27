//! Write-time guard rejecting unexpanded shell syntax in claim labels.
//!
//! Scope is deliberately narrow: shell-variable syntax ONLY. Do NOT swap this
//! for `epigraph_core::Label::validate` — that grammar is `[A-Za-z][A-Za-z0-9_]*`
//! and would reject live labels such as `doi:10.1234/abc` and `near-duplicate`.

use crate::errors::DbError;

/// Return a human-readable description of the shell-expansion construct in
/// `label`, or `None` when the label is clean.
///
/// Byte scanning is correct for multi-byte UTF-8: `$`, `` ` ``, `{` and `(` are
/// ASCII and can never appear as a UTF-8 continuation byte.
#[must_use]
pub fn shell_expansion_offense(label: &str) -> Option<&'static str> {
    if label.contains('`') {
        return Some("backtick command substitution");
    }
    let bytes = label.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b != b'$' {
            continue;
        }
        match bytes.get(i + 1) {
            Some(b'{') => return Some("`${...}` parameter expansion"),
            Some(b'(') => return Some("`$(...)` command substitution"),
            Some(c) if c.is_ascii_alphanumeric() || *c == b'_' => {
                return Some("`$NAME` variable reference");
            }
            _ => {}
        }
    }
    None
}

/// Reject a batch of labels that are about to be ADDED to a claim.
///
/// Only ever call this on the `add` side of a label mutation. The `remove`
/// side must stay unvalidated so an already-stored bad label remains
/// removable through the normal API.
///
/// # Errors
/// Returns [`DbError::InvalidData`] naming the offending label and construct.
pub fn reject_shell_expansion(labels: &[String]) -> Result<(), DbError> {
    for label in labels {
        if let Some(what) = shell_expansion_offense(label) {
            return Err(DbError::InvalidData {
                reason: format!(
                    "label {label:?} contains {what}; the value looks like an unexpanded shell \
                     variable. Expand it in the caller before writing it to the claim."
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bare_dollar_variable() {
        assert_eq!(
            shell_expansion_offense("$CLAIM_ID"),
            Some("`$NAME` variable reference")
        );
        assert_eq!(
            shell_expansion_offense("$HOME"),
            Some("`$NAME` variable reference")
        );
        assert_eq!(
            shell_expansion_offense("$1"),
            Some("`$NAME` variable reference")
        );
    }

    #[test]
    fn rejects_braced_parameter_expansion() {
        assert_eq!(
            shell_expansion_offense("${SESSION}"),
            Some("`${...}` parameter expansion")
        );
        assert_eq!(
            shell_expansion_offense("${FOO:-bar}"),
            Some("`${...}` parameter expansion")
        );
    }

    #[test]
    fn rejects_command_substitution() {
        assert_eq!(
            shell_expansion_offense("$(date +%F)"),
            Some("`$(...)` command substitution")
        );
        assert_eq!(
            shell_expansion_offense("$(git rev-parse HEAD)"),
            Some("`$(...)` command substitution")
        );
    }

    #[test]
    fn rejects_backtick_substitution() {
        assert_eq!(
            shell_expansion_offense("run-`hostname`"),
            Some("backtick command substitution")
        );
    }

    /// The scan must not be anchored at index 0 — a variable buried mid-label
    /// is just as broken as one at the start.
    #[test]
    fn rejects_expansion_embedded_mid_label() {
        assert_eq!(
            shell_expansion_offense("prefix$FOO-suffix"),
            Some("`$NAME` variable reference")
        );
    }

    /// Regression guard against over-rejection: these shapes are all live in
    /// the production graph and must keep writing cleanly.
    #[test]
    fn accepts_live_label_shapes() {
        for label in [
            "backlog",
            "resolved",
            "telemetry",
            "near-duplicate",
            "doi:10.1234/abc.def",
            "norcal-rfp-2026-07-05",
            "paper:Smith_2020",
            "workflow_step",
            "alt-chosen",
        ] {
            assert_eq!(shell_expansion_offense(label), None, "rejected {label:?}");
        }
    }

    /// Pins the deliberate narrowness of the rule: a `$` that cannot start a
    /// variable name is not shell syntax and must pass.
    #[test]
    fn accepts_dollar_not_followed_by_a_name() {
        for label in ["US$", "cost$", "a$-b", "$"] {
            assert_eq!(shell_expansion_offense(label), None, "rejected {label:?}");
        }
    }

    #[test]
    fn reject_shell_expansion_names_the_offending_label() {
        let err = reject_shell_expansion(&["backlog".to_string(), "$CLAIM_ID".to_string()])
            .expect_err("shell syntax must be rejected");
        match err {
            DbError::InvalidData { reason } => {
                assert!(reason.contains("$CLAIM_ID"), "reason was: {reason}");
                assert!(
                    reason.contains("`$NAME` variable reference"),
                    "reason was: {reason}"
                );
            }
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }

    #[test]
    fn reject_shell_expansion_passes_empty_and_clean_slices() {
        assert!(reject_shell_expansion(&[]).is_ok());
        assert!(reject_shell_expansion(&[
            "backlog".to_string(),
            "near-duplicate".to_string(),
            "doi:10.1234/abc.def".to_string(),
        ])
        .is_ok());
    }

    /// Byte-level scanning must not misfire on UTF-8 continuation bytes.
    #[test]
    fn guard_is_utf8_safe() {
        assert_eq!(shell_expansion_offense("coût$"), None);
        assert_eq!(shell_expansion_offense("naïve-résumé"), None);
        assert_eq!(
            shell_expansion_offense("coût$VAR"),
            Some("`$NAME` variable reference")
        );
    }
}
