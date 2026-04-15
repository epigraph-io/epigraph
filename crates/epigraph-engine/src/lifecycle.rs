//! Agent lifecycle state machine validation

/// Check if a state transition is valid
pub fn is_valid_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("pending", "active")
            | ("active", "suspended")
            | ("active", "revoked")
            | ("active", "archived")
            | ("suspended", "active")
            | ("suspended", "revoked")
            | ("suspended", "archived")
    )
}

/// Check if a state is terminal (no transitions out)
pub fn is_terminal(state: &str) -> bool {
    matches!(state, "revoked" | "archived")
}

/// Get valid next states from current state
pub fn valid_next_states(current: &str) -> Vec<&'static str> {
    match current {
        "pending" => vec!["active"],
        "active" => vec!["suspended", "revoked", "archived"],
        "suspended" => vec!["active", "revoked", "archived"],
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(is_valid_transition("pending", "active"));
        assert!(is_valid_transition("active", "suspended"));
        assert!(is_valid_transition("active", "revoked"));
        assert!(is_valid_transition("suspended", "active"));
        assert!(is_valid_transition("suspended", "revoked"));
    }

    #[test]
    fn test_invalid_transitions() {
        assert!(!is_valid_transition("revoked", "active"));
        assert!(!is_valid_transition("archived", "active"));
        assert!(!is_valid_transition("pending", "revoked"));
    }

    #[test]
    fn test_terminal_states() {
        assert!(is_terminal("revoked"));
        assert!(is_terminal("archived"));
        assert!(!is_terminal("active"));
        assert!(!is_terminal("suspended"));
    }

    #[test]
    fn test_valid_next_states() {
        assert_eq!(valid_next_states("pending"), vec!["active"]);
        assert_eq!(
            valid_next_states("active"),
            vec!["suspended", "revoked", "archived"]
        );
        assert_eq!(valid_next_states("revoked"), Vec::<&str>::new());
    }
}
