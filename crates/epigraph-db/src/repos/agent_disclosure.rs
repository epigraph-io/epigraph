//! Who may see an agent's name and profile details: the ONE reader of
//! another agent's `display_name`, `orcid`, `ror_id` and `properties` for
//! output (spec `docs/superpowers/specs/2026-11-24-human-identity-visibility-design.md`,
//! sections 4-6).
//!
//! The decision is made in SQL by migration 286's
//! `public.epigraph_agent_disclosure(target) -> (named, details)`:
//!
//! * a target that is not a human principal is `named` to everyone, and its
//!   `details` follow the profile rule every surface used before (privileged,
//!   self, a `public` profile, or a live direct membership of a group the
//!   caller reads);
//! * a human principal is `named` only when the operator's rule admits the
//!   caller (self, privileged, opted in, a shared team or community, a public
//!   claim by an agent ever bound to it, or a claim the caller can read by one);
//!   its `details` are `named AND` the profile rule.
//!
//! An UNNAMED human must read exactly as a nameless OAuth service principal
//! does (operator ruling C7): its name is that principal's placeholder,
//! `oauth:<client row id>` of its own provisioning client (migration 299's
//! `epigraph_unnamed_agent_name`, called in the ELSE of every disclosure
//! decision), ORCID / ROR null, no human evidence, never a distinguishable
//! absence. The id is never withheld.
//!
//! # The audience is the SESSION
//!
//! `epigraph_agent_disclosure` reads the stamped session (`epigraph.principal_id`,
//! `epigraph.group_ids`, `epigraph_bypass()`, `epigraph_is_elevated()`), so
//! every function here must run on a connection stamped from the caller's
//! viewer (`ScopedPool::read_as` / `begin_as`, `AppState::read_as`). On an
//! unstamped application connection the audience is the anonymous outsider,
//! so an unstamped call hides more, never less. On a MAINTENANCE (or
//! superuser) session `epigraph_bypass()` holds and every human is named: a
//! surface that is built on such a session but served to a narrower
//! audience (the Atlas leaf builder) must call
//! [`AgentDisclosureRepository::names_for_audience`] instead, which passes
//! that audience to the explicit-audience core.
//!
//! These functions take no `&Viewer`: the decision does not read one, and a
//! viewer argument here would only invite a call on a connection stamped from
//! someone else.

use std::collections::HashMap;

use sqlx::PgConnection;
use uuid::Uuid;

use serde_json::Value as JsonValue;

use crate::errors::DbError;
use crate::repos::atlas_map::AtlasMap;
use crate::repos::edge::EdgeRow;

/// What the caller may see of one agent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Disclosure {
    /// The agent's `display_name` may be shown (and matched).
    pub named: bool,
    /// Its profile details (`orcid`, `ror_id`, `properties`, an LLM model on
    /// its profile) may be shown (and matched). Never true when `named` is
    /// false.
    pub details: bool,
    /// When NOT `named`: the name the agent is shown under instead, the
    /// `oauth:<client row id>` placeholder a nameless service principal
    /// carries (migration 299, operator ruling C7), or `None` for an agent
    /// with no OAuth client. Always `None` when `named`.
    pub unnamed_as: Option<String>,
}

/// The `CROSS JOIN LATERAL` that decides disclosure for the agent row aliased
/// `alias`, in the caller's statement, binding `d_{alias}.named` and
/// `d_{alias}.details`. 286's core always returns exactly one row, so the
/// lateral never drops the outer row.
#[must_use]
pub fn disclosure_lateral_sql(alias: &str) -> String {
    format!("CROSS JOIN LATERAL public.epigraph_agent_disclosure({alias}.id) d_{alias}")
}

/// Redact what `d` does not admit on a whole `Agent` row (the REST agent
/// routes serialize these): the name when not `named` becomes the placeholder
/// a nameless service principal shows (`d.unnamed_as`, operator ruling C7),
/// ORCID and ROR when not `details` become null. `labels` are not identity
/// and are not redacted: an unnamed human and a nameless service principal
/// carry the same provisioning label (`oauth-principal`, 288's mint).
pub fn redact_agent(agent: &mut epigraph_core::Agent, d: Disclosure) {
    if !d.named {
        agent.display_name = d.unnamed_as;
    }
    if !d.details {
        agent.orcid = None;
        agent.ror_id = None;
    }
}

/// The `authored` edge properties that spell the author's name: the
/// extraction's spelling ([`crate::repos::paper::AUTHORED_NAME_KEY`]) and the
/// retracted name-derived node it replaced
/// ([`crate::repos::paper::AUTHORED_REPLACES_KEY`], whose `display_name` is
/// the name). Both sit on an edge whose source is the agent's own id, and
/// agent-endpoint edges are world-readable (migration 120). They are withheld
/// from EVERY non-privileged reader, whoever the agent is (spec 7, rows E2 /
/// E3; review 2, leaks#2): withholding them only where the agent is an
/// unnamed human left `explicit_agent_id: true` with no `author_name`, a shape
/// no other agent's explicit edge has, so an edge read alone told "this id is
/// a hidden human". The ingest-time matcher (row A6) reads stored rows, not
/// this projection.
pub const AUTHORED_IDENTITY_KEYS: [&str; 2] = [
    crate::repos::paper::AUTHORED_NAME_KEY,
    crate::repos::paper::AUTHORED_REPLACES_KEY,
];

/// Does this edge carry an author's spelling of a name on an agent's
/// `authored` edge?
fn carries_author_identity(source_type: &str, relationship: &str, props: &JsonValue) -> bool {
    source_type == "agent"
        && relationship == "authored"
        && AUTHORED_IDENTITY_KEYS
            .iter()
            .any(|k| props.get(*k).is_some())
}

/// Disclosure reads. See the module doc: every call runs on a stamped
/// connection.
pub struct AgentDisclosureRepository;

impl AgentDisclosureRepository {
    /// `(named, details)` for each of `ids` that names an agent, decided on
    /// the session `conn` is stamped as. Unknown ids are absent. One
    /// statement for the whole set.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn disclosure(
        conn: &mut PgConnection,
        ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Disclosure>, DbError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, bool, bool, Option<String>)> = sqlx::query_as(
            "SELECT a.id, d.named, d.details, \
                    CASE WHEN d.named THEN NULL \
                         ELSE public.epigraph_unnamed_agent_name(a.id) END \
               FROM agents a \
              CROSS JOIN LATERAL public.epigraph_agent_disclosure(a.id) d \
              WHERE a.id = ANY($1::uuid[])",
        )
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, named, details, unnamed_as)| {
                (
                    id,
                    Disclosure {
                        named,
                        details,
                        unnamed_as,
                    },
                )
            })
            .collect())
    }

    /// The name each of `ids` that names an agent is shown under, decided on
    /// the session `conn` is stamped as: its `display_name` when `named`,
    /// else (an unnamed human) the `oauth:<client row id>` placeholder a
    /// nameless service principal carries (migration 299); `None` when it has
    /// neither. Unknown ids are absent.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn names(
        conn: &mut PgConnection,
        ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Option<String>>, DbError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
            "SELECT a.id, CASE WHEN d.named THEN a.display_name \
                               ELSE public.epigraph_unnamed_agent_name(a.id) END \
               FROM agents a \
              CROSS JOIN LATERAL public.epigraph_agent_disclosure(a.id) d \
              WHERE a.id = ANY($1::uuid[])",
        )
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Remove [`AUTHORED_IDENTITY_KEYS`] from every agent `authored` edge in
    /// `edges`, in place, unless the session is privileged (a maintenance
    /// session or a live elevated viewer: the same privileged term migration
    /// 286's session wrapper passes to the core). Not per agent: an explicit
    /// edge reads alike whether its agent is a named person, an unnamed one or
    /// a nameless service principal, so the edge is no marker (operator ruling
    /// C7; review 2, leaks#2). The edge itself, its endpoints, `position`,
    /// `role`, `explicit_agent_id` and `affiliations` (OPEN C8) are unchanged.
    /// One read of the session's privilege, only when some edge carries a key.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails.
    pub async fn redact_authored_edges(
        conn: &mut PgConnection,
        edges: &mut [EdgeRow],
    ) -> Result<(), DbError> {
        if !edges
            .iter()
            .any(|e| carries_author_identity(&e.source_type, &e.relationship, &e.properties))
        {
            return Ok(());
        }
        let privileged: bool =
            sqlx::query_scalar("SELECT public.epigraph_bypass() OR public.epigraph_is_elevated()")
                .fetch_one(&mut *conn)
                .await?;
        if privileged {
            return Ok(());
        }
        for e in edges.iter_mut() {
            if carries_author_identity(&e.source_type, &e.relationship, &e.properties) {
                if let Some(o) = e.properties.as_object_mut() {
                    for k in AUTHORED_IDENTITY_KEYS {
                        o.remove(k);
                    }
                }
            }
        }
        Ok(())
    }

    /// [`Self::names`] for a stored document served to `map`'s whole
    /// audience rather than to the session that builds it: the public map is
    /// read by the anonymous outsider, a team map by a member of that team
    /// (no principal, the team as its one group, never privileged). Calls
    /// 286's explicit-audience core, which only the maintenance role may
    /// EXECUTE: run it on the maintenance session the Atlas builder holds. A
    /// bypass session must never be the audience of a stored document; it
    /// would name every human in a public map.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the read fails (an application session is
    /// refused EXECUTE on the core).
    pub async fn names_for_audience(
        conn: &mut PgConnection,
        ids: &[Uuid],
        map: AtlasMap,
    ) -> Result<HashMap<Uuid, Option<String>>, DbError> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let groups: Vec<Uuid> = match map {
            AtlasMap::Public => Vec::new(),
            AtlasMap::Team(t) => vec![t],
        };
        let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
            "SELECT a.id, CASE WHEN d.named THEN a.display_name \
                               ELSE public.epigraph_unnamed_agent_name(a.id) END \
               FROM agents a \
              CROSS JOIN LATERAL public.epigraph_agent_disclosure_for( \
                         a.id, NULL::uuid, $2::uuid[], false) d \
              WHERE a.id = ANY($1::uuid[])",
        )
        .bind(ids)
        .bind(&groups)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_agents_authored_edge_with_a_name_key_is_a_candidate() {
        let named = serde_json::json!({"author_name": "A", "position": 0});
        let replaced = serde_json::json!({"replaces_author": "x"});
        let plain = serde_json::json!({"position": 0});
        assert!(carries_author_identity("agent", "authored", &named));
        assert!(carries_author_identity("agent", "authored", &replaced));
        assert!(!carries_author_identity("agent", "authored", &plain));
        assert!(!carries_author_identity("claim", "authored", &named));
        assert!(!carries_author_identity("agent", "asserts", &named));
        assert_eq!(AUTHORED_IDENTITY_KEYS, ["author_name", "replaces_author"]);
    }

    #[test]
    fn the_lateral_names_its_alias() {
        assert_eq!(
            disclosure_lateral_sql("a"),
            "CROSS JOIN LATERAL public.epigraph_agent_disclosure(a.id) d_a"
        );
    }

    #[test]
    fn redaction_nulls_exactly_what_is_not_admitted() {
        let mut agent = epigraph_core::Agent::new([7u8; 32], Some("Ada Example".into()));
        agent.orcid = Some("0000-0002-0000-0001".into());
        agent.ror_id = Some("01abcde23".into());
        agent.labels = vec!["oauth-principal".into()];
        let mut named_only = agent.clone();
        redact_agent(
            &mut named_only,
            Disclosure {
                named: true,
                details: false,
                unnamed_as: None,
            },
        );
        assert_eq!(named_only.display_name.as_deref(), Some("Ada Example"));
        assert_eq!(named_only.orcid, None);
        assert_eq!(named_only.ror_id, None);
        let mut hidden = agent.clone();
        redact_agent(
            &mut hidden,
            Disclosure {
                unnamed_as: Some("oauth:00000000-0000-0000-0000-000000000001".into()),
                ..Disclosure::default()
            },
        );
        assert_eq!(
            hidden.display_name.as_deref(),
            Some("oauth:00000000-0000-0000-0000-000000000001"),
            "an unnamed agent is shown under its placeholder (C7)"
        );
        assert_eq!((hidden.orcid, hidden.ror_id), (None, None));
        assert_eq!(hidden.labels, agent.labels, "labels are not identity");
        let mut no_client = agent.clone();
        redact_agent(&mut no_client, Disclosure::default());
        assert_eq!(no_client.display_name, None, "no client, no placeholder");
        let mut all = agent.clone();
        redact_agent(
            &mut all,
            Disclosure {
                named: true,
                details: true,
                unnamed_as: None,
            },
        );
        assert_eq!(all.orcid, agent.orcid);
    }
}
