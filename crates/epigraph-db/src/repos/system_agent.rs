//! The system-agent registry (migration 148): which agent IS a system role,
//! such as "the workflow-ingest system agent", recorded rather than derived.
//!
//! # Why a registry, and not the derived key
//!
//! Until migration 148 the workflow-ingest resolvers found their agent by the
//! Ed25519 key `did_key_for_author(None, "workflow-ingest-system")` derives,
//! whose secret is BLAKE3 of a public string, and created one on a miss. That
//! identity could never be rotated to a secret key: after an
//! `UPDATE agents SET public_key = <fresh>` the next ingest misses the lookup
//! and creates a SECOND agent holding the public-constant key (the UNIQUE key
//! no longer blocks it), and attribution silently splits between the two.
//!
//! So the role -> agent mapping now lives in `system_agents`, written only by a
//! maintenance session and immutable. [`SystemAgentRepository::lookup`] reads
//! it (with the arming state, in one statement) and the resolvers decide:
//! a registered row wins, always; no row on an ARMED database refuses; no row
//! on an unarmed database keeps the pre-148 key lookup so a fresh install and
//! every test database still work.
//!
//! # Connections
//!
//! Both reads run on whatever connection the caller holds, including one
//! stamped from the system agent's viewer as the application role:
//! `system_agents` has no row security and the application role may SELECT it
//! (migration 148 section 3), and `epigraph_operator_binding_armed()` is an
//! application-callable definer (migration 122). Nothing here writes; the one
//! write path is the maintenance CLI (`epigraph-operator
//! register-system-agent`).

use std::sync::OnceLock;

use uuid::Uuid;

use crate::errors::DbError;

/// A role in migration 148's `system_agents` vocabulary
/// (`system_agents_role_known`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemAgentRole {
    /// The one agent every workflow-ingest row (MCP `store_workflow` /
    /// `ingest_workflow` / `improve_workflow_hierarchy` / `add_step` /
    /// `delete_step`, REST `/api/v1/workflows/*`) and every REST policy
    /// challenge is authored as.
    WorkflowIngest,
}

impl SystemAgentRole {
    /// Every role, in the order the CLI lists them.
    pub const ALL: &'static [SystemAgentRole] = &[SystemAgentRole::WorkflowIngest];

    /// The `system_agents.role` value. Migration 148's CHECK holds exactly
    /// these, so a test that registers through this constant fails on any
    /// drift between the two vocabularies.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkflowIngest => "workflow-ingest",
        }
    }

    /// Parse a `system_agents.role` value.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|r| r.as_str() == s)
    }

    /// The public constant name the pre-148 resolver derived this role's key
    /// from. Kept for the unarmed, unregistered fallback and for the reserved
    /// author check; never an authority.
    #[must_use]
    pub const fn legacy_seed_name(self) -> &'static str {
        match self {
            Self::WorkflowIngest => "workflow-ingest-system",
        }
    }

    /// `did_key_for_author(None, legacy_seed_name())`: the key every database
    /// created before migration 148 holds for this role. Public, derivable by
    /// anyone from public code, so it is a name, never a credential.
    #[must_use]
    pub fn legacy_public_key(self) -> [u8; 32] {
        static WORKFLOW_INGEST: OnceLock<[u8; 32]> = OnceLock::new();
        match self {
            Self::WorkflowIngest => *WORKFLOW_INGEST.get_or_init(|| {
                epigraph_crypto::did_key::did_key_for_author(None, self.legacy_seed_name()).1
            }),
        }
    }
}

impl std::fmt::Display for SystemAgentRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// True when `key` is the legacy public-constant key of any system role.
///
/// The author-name paths call it with `did_key_for_author(orcid, name).1`, so
/// it compares KEYS, not strings: every case, whitespace or punctuation
/// variant that normalizes to the seed name (`"Workflow-Ingest-System."`)
/// derives the same key and is caught, and an author with a non-empty ORCID
/// derives from the ORCID and never collides. A document can therefore never
/// name a system identity as its author, before or after a key rotation.
#[must_use]
pub fn is_reserved_author_key(key: &[u8; 32]) -> bool {
    SystemAgentRole::ALL
        .iter()
        .any(|r| &r.legacy_public_key() == key)
}

/// What the registry says about a role, read together with the arming state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemAgentLookup {
    /// A registered agent. Callers use it and NEVER look a key up or create.
    Registered(Uuid),
    /// No registration, and the database is ARMED (migration 122): callers
    /// refuse before writing anything.
    UnregisteredArmed,
    /// No registration on an unarmed database: callers keep the pre-148
    /// behaviour (key lookup, create on a miss).
    UnregisteredUnarmed,
}

/// Reads of migration 148's `system_agents`.
pub struct SystemAgentRepository;

impl SystemAgentRepository {
    /// The registry row for `role` and the arming state, in ONE statement so
    /// both answers come from one snapshot.
    ///
    /// "Armed" is `epigraph_operator_binding_armed()`, deliberately NOT
    /// `..._enforced()`: the session valve relieves the operator binding only,
    /// and re-creating a public-constant identity is not a binding question,
    /// so the valve must not reopen the create path.
    ///
    /// A runtime query, not a `query!` macro, so it needs no offline-cache
    /// entry. On a database below migration 148 it fails (42P01): callers fail
    /// closed on that, never fall back.
    ///
    /// # Errors
    /// [`DbError`] when the read fails, including a missing table.
    pub async fn lookup(
        conn: &mut sqlx::PgConnection,
        role: SystemAgentRole,
    ) -> Result<SystemAgentLookup, DbError> {
        let (agent, armed): (Option<Uuid>, bool) = sqlx::query_as(
            "SELECT (SELECT s.agent_id FROM public.system_agents s WHERE s.role = $1), \
                    public.epigraph_operator_binding_armed()",
        )
        .bind(role.as_str())
        .fetch_one(&mut *conn)
        .await?;
        Ok(match (agent, armed) {
            (Some(id), _) => SystemAgentLookup::Registered(id),
            (None, true) => SystemAgentLookup::UnregisteredArmed,
            (None, false) => SystemAgentLookup::UnregisteredUnarmed,
        })
    }

    /// Every registered system agent id (one read of a table with one row per
    /// role). The author-name loops read it ONCE per document, so an author
    /// whose name resolves to a registered system agent is never adopted,
    /// whatever that agent's current key is.
    ///
    /// # Errors
    /// [`DbError`] when the read fails, including a missing table.
    pub async fn registered_agent_ids(conn: &mut sqlx::PgConnection) -> Result<Vec<Uuid>, DbError> {
        let ids: Vec<Uuid> = sqlx::query_scalar("SELECT s.agent_id FROM public.system_agents s")
            .fetch_all(&mut *conn)
            .await?;
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_key(name: &str) -> [u8; 32] {
        epigraph_crypto::did_key::did_key_for_author(None, name).1
    }

    /// The key match catches every spelling that normalizes to the seed
    /// (lowercase, trimmed, `.` stripped by `normalize_author_name`), and
    /// nothing else. A compare on the FULLY normalized string would be
    /// equivalent for ORCID-less authors; only a weaker compare (lowercase and
    /// trim) is a defect, and the trailing `.` case is what kills it.
    #[test]
    fn reserved_key_matches_name_variants_and_nothing_else() {
        for reserved in [
            "workflow-ingest-system",
            "  WORKFLOW-INGEST-SYSTEM ",
            "Workflow-Ingest-System.",
        ] {
            assert!(
                is_reserved_author_key(&name_key(reserved)),
                "{reserved:?} derives the workflow-ingest legacy key and must be reserved"
            );
        }
        for free in [
            "workflow ingest system",
            "document-ingest-cli",
            "org:workflow-ingest-system",
        ] {
            assert!(
                !is_reserved_author_key(&name_key(free)),
                "{free:?} does not derive the legacy key and must stay free"
            );
        }
        // An ORCID-bearing author derives from the ORCID, whatever its name.
        let (_, orcid_key) = epigraph_crypto::did_key::did_key_for_author(
            Some("0000-0002-1825-0097"),
            "workflow-ingest-system",
        );
        assert!(!is_reserved_author_key(&orcid_key));
    }

    /// The legacy key, pinned to a LITERAL computed from the tree before
    /// migration 148 existed (`did_key_for_author(None,
    /// "workflow-ingest-system").1`, independently re-derived as BLAKE3 of
    /// `author:workflow-ingest-system` used as an Ed25519 seed). Every database
    /// created before 148 holds exactly this key for the workflow-ingest agent,
    /// so any drift here (a normalization tweak, an ORCID-path derivation)
    /// would make the unarmed fallback mint a SECOND agent on first deploy,
    /// with no rotation at all. It is a public derivation, not a secret.
    #[test]
    fn legacy_public_key_is_pinned_to_the_pre_148_derivation() {
        const PRE_148: &str = "bf97389e58aabc8680d6a376a0fdc8ffccccb5bc20cb9c5dedd4a3b6fe37aa33";
        let pinned: [u8; 32] = hex::decode(PRE_148)
            .expect("hex literal")
            .try_into()
            .expect("32 bytes");
        assert_eq!(SystemAgentRole::WorkflowIngest.legacy_public_key(), pinned);
    }

    /// Documentation of intent (not coverage: it moves with the code).
    #[test]
    fn legacy_public_key_is_the_did_key_for_author_derivation() {
        assert_eq!(
            SystemAgentRole::WorkflowIngest.legacy_public_key(),
            name_key(SystemAgentRole::WorkflowIngest.legacy_seed_name())
        );
    }

    #[test]
    fn roles_round_trip_through_their_text() {
        for r in SystemAgentRole::ALL {
            assert_eq!(SystemAgentRole::parse(r.as_str()), Some(*r));
        }
        assert_eq!(SystemAgentRole::parse("workflow_ingest"), None);
    }
}
