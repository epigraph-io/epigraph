//! Canonical scope sets for the three first-class service roles.
//!
//! These are the single source of truth for:
//! - the `bootstrap_clients` CLI binary, which provisions
//!   `epigraph-admin`, `epigraph-ro`, and `epigraph-wo` on a fresh install;
//! - tests that assert role boundaries (admin ⊇ wo ⊇ ro);
//! - any future tooling that needs to mint or audit a service token.
//!
//! Roles:
//! - **admin**: superset of every scope, including admin-only scopes.
//! - **read-write** (`wo`): admin minus the admin-only scopes. Despite the
//!   `wo` name (held over from EpigraphV2), this role gets read+write — it
//!   just can't perform admin-gated operations like dedup or client mgmt.
//! - **read-only** (`ro`): every read scope, no writes, no admin.

/// Scopes that gate admin-only operations. These are EXCLUDED from `wo` and
/// `ro`; included in `admin`.
pub const ADMIN_ONLY_SCOPES: &[&str] = &["claims:admin", "clients:admin"];

/// Read scopes. These are included in all three roles.
pub const READ_SCOPES: &[&str] = &[
    "claims:read",
    "evidence:read",
    "edges:read",
    "agents:read",
    "groups:read",
    "audit:read",
    "tasks:read",
    "analysis:belief",
    "analysis:gaps",
    "analysis:hypothesis",
    "analysis:political",
    "analysis:propagation",
    "analysis:reasoning",
    "analysis:structural",
];

/// Write scopes. Included in `admin` and `wo`; excluded from `ro`.
pub const WRITE_SCOPES: &[&str] = &[
    "claims:write",
    "claims:delete",
    "evidence:write",
    "evidence:submit",
    "edges:write",
    "agents:write",
    "tasks:write",
    "ingest:write",
    "policy:challenge",
];

/// `epigraph-admin`: admin-superset.
pub fn admin_scopes() -> Vec<String> {
    READ_SCOPES
        .iter()
        .chain(WRITE_SCOPES.iter())
        .chain(ADMIN_ONLY_SCOPES.iter())
        .map(|s| (*s).to_string())
        .collect()
}

/// `epigraph-wo`: read+write, no admin.
pub fn read_write_scopes() -> Vec<String> {
    READ_SCOPES
        .iter()
        .chain(WRITE_SCOPES.iter())
        .map(|s| (*s).to_string())
        .collect()
}

/// `epigraph-ro`: read-only.
pub fn read_only_scopes() -> Vec<String> {
    READ_SCOPES.iter().map(|s| (*s).to_string()).collect()
}

/// Canonical client name → scope-set lookup. Used by `bootstrap_clients`.
pub const CANONICAL_CLIENT_NAMES: &[&str] = &["epigraph-admin", "epigraph-ro", "epigraph-wo"];

/// Resolve a canonical client name to its scope set. Returns `None` for
/// unknown names.
pub fn scopes_for(name: &str) -> Option<Vec<String>> {
    match name {
        "epigraph-admin" => Some(admin_scopes()),
        "epigraph-ro" => Some(read_only_scopes()),
        "epigraph-wo" => Some(read_write_scopes()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ro_subset_of_wo() {
        let ro: HashSet<String> = read_only_scopes().into_iter().collect();
        let wo: HashSet<String> = read_write_scopes().into_iter().collect();
        assert!(ro.is_subset(&wo), "ro must be subset of wo");
    }

    #[test]
    fn wo_subset_of_admin() {
        let wo: HashSet<String> = read_write_scopes().into_iter().collect();
        let admin: HashSet<String> = admin_scopes().into_iter().collect();
        assert!(wo.is_subset(&admin), "wo must be subset of admin");
    }

    #[test]
    fn wo_excludes_admin_only_scopes() {
        let wo: HashSet<String> = read_write_scopes().into_iter().collect();
        for s in ADMIN_ONLY_SCOPES {
            assert!(!wo.contains(*s), "wo must not include {s}");
        }
    }

    #[test]
    fn ro_excludes_writes() {
        let ro: HashSet<String> = read_only_scopes().into_iter().collect();
        for s in WRITE_SCOPES {
            assert!(!ro.contains(*s), "ro must not include write scope {s}");
        }
    }

    #[test]
    fn admin_includes_admin_only_scopes() {
        let admin: HashSet<String> = admin_scopes().into_iter().collect();
        for s in ADMIN_ONLY_SCOPES {
            assert!(admin.contains(*s), "admin must include {s}");
        }
    }

    #[test]
    fn scopes_for_resolves_canonical_names() {
        for name in CANONICAL_CLIENT_NAMES {
            assert!(scopes_for(name).is_some(), "{name} should resolve");
        }
        assert!(scopes_for("not-a-canonical-name").is_none());
    }
}
