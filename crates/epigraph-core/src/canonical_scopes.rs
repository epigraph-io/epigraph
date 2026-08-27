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
///
/// `entity-types:write` gates `POST /api/v1/admin/entity-types` (the registry
/// registration endpoint). It is deliberately ADMIN-ONLY, NOT a generic write
/// scope: the registry threat model treats downstream read-write token holders
/// as adversarial (that is the whole reason for the `is_core` hijack guard and
/// the table denylist). Granting it to every `epigraph-wo` token via
/// `WRITE_SCOPES` would defeat least privilege — any ordinary write client
/// could register a non-core type pointing at a (denylisted, but still) new
/// table. Keeping it here means only `epigraph-admin` auto-gets it among the
/// three canonical roles; a dedicated registrar can still be minted with
/// exactly `["entity-types:write"]` (narrow, and distinct from
/// `clients:admin`/`claims:admin`).
///
/// `groups:admin` gates member management on an existing group
/// (`POST /api/v1/groups/:id/members`, `DELETE .../members/:agent_id`). It is
/// admin-only among the three canonical roles, but note it is NOT sufficient on
/// its own: those routes ALSO require live `role='admin'` membership in the
/// target group (`middleware/group_authz.rs`). Scope AND membership, never OR.
///
/// `instance:admin` is deliberately listed here and granted by **no**
/// registration path: `/oauth/register` never hands it out (the DCR arm grants
/// [`PUBLIC_CLIENT_READ_SCOPES`], the agent arm grants nothing), and
/// `routes/agents.rs` grants [`AGENT_PROVISION_SCOPES`]. It reaches a token
/// only through `bootstrap_clients` minting `epigraph-admin`, or an operator
/// UPDATE. **Known third path:** `POST /api/v1/admin/clients/:id/approve`
/// (`routes/admin.rs`) writes `granted_scopes` verbatim with no validation
/// against `allowed_scopes`, so a `clients:admin` holder can grant it. That is
/// pre-existing and is not closed here.
pub const ADMIN_ONLY_SCOPES: &[&str] = &[
    "claims:admin",
    "clients:admin",
    "entity-types:write",
    "groups:admin",
    "instance:admin",
];

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
    "webhooks:write",
    // Gates POST /api/v1/groups. Any read-write principal may create a group;
    // it becomes that group's sole `role='admin'` member by construction
    // (`GroupRepository::create_with_admin`), which is why managing an EXISTING
    // group needs `groups:admin` plus membership rather than this scope.
    "groups:write",
];

/// The exact scope set a **public client** registered through
/// `POST /oauth/register` receives — both the RFC 7591 DCR path (claude.ai /
/// claude.com, bounded by the redirect-host allowlist in `oauth/register.rs`)
/// and the `client_type: "service"` `allowed_scopes` proposal.
///
/// This is a **strict subset** of [`READ_SCOPES`] and is deliberately NOT
/// `read_only_scopes()`: collapsing the two would hand `audit:read` and
/// `tasks:read` — the security-event log and the task queue — to every client
/// that can complete a dynamic registration. `public_client_read_scopes_are_a_read_subset`
/// pins the subset relation; nothing pins equality, and nothing should.
pub const PUBLIC_CLIENT_READ_SCOPES: &[&str] = &[
    "claims:read",
    "evidence:read",
    "edges:read",
    "agents:read",
    "groups:read",
    "analysis:belief",
    "analysis:propagation",
    "analysis:reasoning",
    "analysis:gaps",
    "analysis:structural",
    "analysis:hypothesis",
    "analysis:political",
];

/// The exact scope set granted to an OAuth client auto-provisioned alongside a
/// new agent by `POST /api/v1/agents` (`routes/agents.rs`). Harvester-level:
/// read+write on claims, edges and evidence, plus `agents:read`.
///
/// A **strict subset** of `READ_SCOPES ∪ WRITE_SCOPES`, and not any canonical
/// union — in particular it carries no `ingest:write`, no analysis scopes and
/// no `agents:write`, so an auto-provisioned agent cannot mint further agents.
/// It is also the set `/oauth/register`'s `client_type: "agent"` arm now
/// proposes as `allowed_scopes` while granting **none** of them: an admin must
/// approve before any become effective.
pub const AGENT_PROVISION_SCOPES: &[&str] = &[
    "claims:read",
    "claims:write",
    "edges:read",
    "edges:write",
    "evidence:read",
    "evidence:write",
    "agents:read",
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

    #[test]
    fn entity_types_write_is_admin_only() {
        // Least privilege: entity-types:write must be admin-only. A generic
        // read-write (`wo`) token must NOT auto-receive it — the registry
        // threat model treats downstream write clients as adversarial.
        let ro: HashSet<String> = read_only_scopes().into_iter().collect();
        let wo: HashSet<String> = read_write_scopes().into_iter().collect();
        let admin: HashSet<String> = admin_scopes().into_iter().collect();

        assert!(
            !ro.contains("entity-types:write"),
            "ro must NOT include entity-types:write"
        );
        assert!(
            !wo.contains("entity-types:write"),
            "wo must NOT include entity-types:write (least privilege)"
        );
        assert!(
            admin.contains("entity-types:write"),
            "admin must include entity-types:write"
        );
    }

    #[test]
    fn webhooks_write_scope_role_membership() {
        let ro: HashSet<String> = read_only_scopes().into_iter().collect();
        let wo: HashSet<String> = read_write_scopes().into_iter().collect();
        let admin: HashSet<String> = admin_scopes().into_iter().collect();

        assert!(
            !ro.contains("webhooks:write"),
            "ro must NOT include webhooks:write"
        );
        assert!(
            wo.contains("webhooks:write"),
            "wo must include webhooks:write"
        );
        assert!(
            admin.contains("webhooks:write"),
            "admin must include webhooks:write"
        );
    }

    #[test]
    fn groups_scopes_role_membership() {
        let ro: HashSet<String> = read_only_scopes().into_iter().collect();
        let wo: HashSet<String> = read_write_scopes().into_iter().collect();
        let admin: HashSet<String> = admin_scopes().into_iter().collect();

        // ro: read only.
        assert!(ro.contains("groups:read"), "ro must include groups:read");
        assert!(
            !ro.contains("groups:write"),
            "ro must NOT include groups:write"
        );
        assert!(
            !ro.contains("groups:admin"),
            "ro must NOT include groups:admin"
        );

        // wo: adds write, still no admin.
        assert!(wo.contains("groups:read"), "wo must include groups:read");
        assert!(wo.contains("groups:write"), "wo must include groups:write");
        assert!(
            !wo.contains("groups:admin"),
            "wo must NOT include groups:admin"
        );

        // admin: all three.
        for s in ["groups:read", "groups:write", "groups:admin"] {
            assert!(admin.contains(s), "admin must include {s}");
        }
    }

    #[test]
    fn instance_admin_is_in_no_grantable_set() {
        // `instance:admin` reaches a token only via bootstrap_clients or an
        // operator UPDATE. No registration or auto-provision path may propose
        // or grant it.
        assert!(
            !PUBLIC_CLIENT_READ_SCOPES.contains(&"instance:admin"),
            "a dynamically registered public client must never receive instance:admin"
        );
        assert!(
            !AGENT_PROVISION_SCOPES.contains(&"instance:admin"),
            "an auto-provisioned agent client must never receive instance:admin"
        );
        // And it is admin-only among the canonical roles.
        let wo: HashSet<String> = read_write_scopes().into_iter().collect();
        let admin: HashSet<String> = admin_scopes().into_iter().collect();
        assert!(!wo.contains("instance:admin"), "wo must NOT include it");
        assert!(admin.contains("instance:admin"), "admin must include it");
    }

    #[test]
    fn public_client_read_scopes_are_a_read_subset() {
        let read: HashSet<&str> = READ_SCOPES.iter().copied().collect();
        for s in PUBLIC_CLIENT_READ_SCOPES {
            assert!(
                read.contains(s),
                "PUBLIC_CLIENT_READ_SCOPES entry {s} is not a read scope"
            );
        }
        // STRICT subset: it must not equal READ_SCOPES. Equality would mean a
        // future refactor could replace it with `read_only_scopes()` and hand
        // audit:read + tasks:read to every DCR client.
        assert!(
            PUBLIC_CLIENT_READ_SCOPES.len() < READ_SCOPES.len(),
            "PUBLIC_CLIENT_READ_SCOPES must be a STRICT subset of READ_SCOPES"
        );
        for s in ["audit:read", "tasks:read"] {
            assert!(
                !PUBLIC_CLIENT_READ_SCOPES.contains(&s),
                "a dynamically registered public client must never receive {s}"
            );
        }
    }

    #[test]
    fn agent_provision_scopes_are_a_readwrite_subset() {
        let rw: HashSet<String> = read_write_scopes().into_iter().collect();
        for s in AGENT_PROVISION_SCOPES {
            assert!(
                rw.contains(*s),
                "AGENT_PROVISION_SCOPES entry {s} is not in READ_SCOPES ∪ WRITE_SCOPES"
            );
        }
        assert!(
            AGENT_PROVISION_SCOPES.len() < rw.len(),
            "AGENT_PROVISION_SCOPES must be a STRICT subset of read_write_scopes()"
        );
        // Least privilege: an auto-provisioned agent cannot mint further agents,
        // cannot bulk-ingest, and holds no admin scope.
        for s in [
            "agents:write",
            "ingest:write",
            "claims:admin",
            "groups:admin",
        ] {
            assert!(
                !AGENT_PROVISION_SCOPES.contains(&s),
                "AGENT_PROVISION_SCOPES must NOT include {s}"
            );
        }
    }
}
