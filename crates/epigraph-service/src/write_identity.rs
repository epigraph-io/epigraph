//! The agent a write authors its rows as and stamps its transaction from
//! (batch H-b, D1).
//!
//! The decision and its ratchet are documented where the MCP server's write
//! tools live (the MCP crate's `write_identity` module and
//! `tests/write_identity_ratchet.rs`). This module holds the TYPE, so that its
//! constructor can be private to the crate that resolves it:
//! [`WriteIdentity::from_resolved`] is `pub(crate)` HERE, and its only callers
//! are [`Ctx::write_identity`](crate::ctx::Ctx::write_identity) and
//! [`Ctx::admin_borrowed_server_identity`](crate::ctx::Ctx::admin_borrowed_server_identity).
//! A front end cannot build one from an agent id it names; the compiler
//! refuses it, where a `pub(crate)` constructor inside the front end's own
//! crate only a source scan could police.
//!
//! The type does not decide WHICH agent the resolvers answer, though. Over
//! HTTP it is the token's principal. With no `auth` (stdio and the operator
//! CLIs) it is the context's own agent, found by the identity key the context
//! was built with ([`Ctx::with_identity_public_key`](crate::ctx::Ctx::with_identity_public_key),
//! else the signer's key), and whoever builds a context chooses that key. So
//! the trust boundary for the no-`auth` arm is building the context, which only
//! the process's own start-up does: the MCP crate's
//! `tests/write_identity_ratchet.rs` refuses `Ctx::new(` and
//! `.write_identity(` in every crate other than the MCP and service crates.
//!
//! The refusals below are the resolver's, as [`ServiceError`]s; a front end
//! maps them onto its own error type.

use uuid::Uuid;

use crate::errors::ServiceError;

/// The agent a write authors its rows as and stamps its transaction from.
///
/// Constructed only by [`Ctx::write_identity`](crate::ctx::Ctx::write_identity)
/// and [`Ctx::admin_borrowed_server_identity`](crate::ctx::Ctx::admin_borrowed_server_identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteIdentity {
    agent_id: Uuid,
}

impl WriteIdentity {
    /// The author's `agents.id`.
    #[must_use]
    pub const fn agent_id(self) -> Uuid {
        self.agent_id
    }

    /// Crate-private: the only constructor. Its callers are the two resolvers
    /// on [`Ctx`](crate::ctx::Ctx).
    pub(crate) const fn from_resolved(agent_id: Uuid) -> Self {
        Self { agent_id }
    }
}

/// Whether `auth` is the context an unauthenticated listener injects: no token
/// was presented, so it names no client and no token id.
///
/// A context validated from a real token carries the token's `sub` as
/// `client_id` and a random `jti` (`epigraph_auth::JwtConfig::issue_access_token`),
/// so both being nil identifies the injected context. A token forged with
/// both ids nil would only be treated MORE strictly (as principal-less), never
/// less.
#[must_use]
pub fn is_principal_less(auth: &epigraph_auth::AuthContext) -> bool {
    auth.client_id.is_nil() && auth.jti.is_nil()
}

/// A token that carries no `agents.id` has no author, as it has no reader (the
/// MCP server's `request_viewer` refuses it the same way).
#[must_use]
pub fn no_agent_principal_refusal() -> ServiceError {
    ServiceError::Denied(
        "token carries no agent principal, so this write has no author (see plan D3). \
         Re-mint the token through /oauth/token, which attaches an agents.id to every \
         principal. Nothing was written."
            .to_string(),
    )
}

/// A principal-less caller (an unauthenticated listener's injected context,
/// [`is_principal_less`]) without a write scope has no author that belongs to a
/// human, so it writes nothing (batch HTTP-id). The per-tool scope gate refuses
/// the same calls first; this is a second layer for the AUTHOR-STAMPED writes
/// only, keyed on the resolver every author-stamped transaction goes through.
#[must_use]
pub fn principal_less_write_refusal() -> ServiceError {
    ServiceError::Denied(
        "this listener serves callers with no authenticated principal, and such a caller \
         cannot write: an HTTP write is authored by the calling human's agent, and no human \
         is named here. Call this tool through an authenticated (OAuth bearer) listener, \
         where the write is authored as your own agent. Nothing was written."
            .to_string(),
    )
}

/// An ELEVATED request asked to write (elevation plan §1.4: the elevated
/// viewer is read-only). The same `ELEVATED READ-ONLY` refusal
/// `ScopedPool::begin_as` gives, raised HERE because an author-stamped write
/// never meets `begin_as` with the request's viewer: its transaction is stamped
/// from a freshly resolved SCOPED viewer of the author
/// ([`crate::ctx::author_write_authority`]), and a detached ingest carries the
/// request's viewer only after `detach_scoped` has downgraded it, so neither
/// that refusal nor migration 126's restrictive policies (keyed on the
/// elevation settings that scoped stamp leaves empty) would ever see the
/// elevation.
///
/// # Errors
/// The refusal, as the repository error
/// [`DbError::ElevatedReadOnly`](epigraph_db::DbError::ElevatedReadOnly) a
/// front end classifies as a denial, when `viewer` is elevated.
pub fn refuse_elevated(viewer: &epigraph_db::visibility::Viewer) -> Result<(), ServiceError> {
    if viewer.is_elevated() {
        Err(ServiceError::Repository(
            epigraph_db::DbError::ElevatedReadOnly,
        ))
    } else {
        Ok(())
    }
}

/// The request's viewer and its token name different principals.
#[must_use]
pub fn diverging_principals(token: Uuid, viewer: Option<Uuid>) -> ServiceError {
    ServiceError::Internal(format!(
        "refusing a write whose read and write principals diverge: the token names agent \
         {token}, the request viewer names {viewer:?}. Nothing was written."
    ))
}
