//! The ONE answer to "as which agent does this MCP write author and stamp its
//! rows" (batch H-b, D1).
//!
//! # The decision
//!
//! Operator decision of 2026-09-25: an authenticated MCP write carries the
//! CALLER's authority. When a request has an `AuthContext` (the HTTPS listener)
//! every write tool authors its rows as the caller's agent (`auth.agent_id`) and
//! stamps its transaction from that agent's viewer. stdio keeps the server's own
//! agent, and an operated stdio agent keeps #503's operator rule (its rows land
//! in the operator's personal group through `default_decl_for_author`).
//!
//! Before this module every write tool took `server.agent_id()` — the shared
//! server signer — whatever the transport. Measured by the batch H-a review
//! (#505 F5) and by the #505 ⨝ #503 merge report, over authenticated MCP on a
//! clean schema (config A):
//!
//! * `submit_claim` by a caller wrote a claim authored and owned by the SERVER
//!   agent;
//! * `patch_claim` / `update_labels` on the caller's OWN claims were refused
//!   (`42501`), because the transaction was stamped with the server agent's
//!   writable set, which does not contain the caller's group;
//! * an OPERATOR bearer acting on its linked agent's claim passed
//!   `require_owner_or_admin` through #503's operator arm and was then refused
//!   `42501` with nothing written: the gate admitted one principal and the stamp
//!   named another.
//!
//! # Resolved from `auth`, checked against the request's viewer
//!
//! `EpiGraphMcpFull::write_identity(auth, viewer)` maps `Some(auth)` to
//! `auth.agent_id` and `None` to `server.agent_id()` — the same mapping
//! `tools::viewer::request_viewer` makes for READS, so on every production path
//! the write principal is the read principal. Over HTTP it also REFUSES a viewer
//! whose principal is not the token's: every `#[tool]` body in `server.rs`
//! resolves its viewer from the same `auth` it passes on, so a mismatch can only
//! mean a caller wired one principal's viewer to another's write, and that must
//! not resolve silently in either direction.
//!
//! Keyed on `auth` rather than on the viewer alone because the tool functions
//! are also driven directly — by the operator `ingest-document` CLI (a
//! maintenance `Bypass` viewer, no principal) and by the integration suite (the
//! nil-principal public viewer). Both are stdio-shaped callers with no token,
//! and `None` gives them exactly the pre-H-b author, the server's own agent.
//!
//! # The ratchet
//!
//! [`WriteIdentity`] has a private field and one constructor,
//! [`crate::server::EpiGraphMcpFull::write_identity`]. Every author-stamped
//! transaction ([`crate::claim_helper::begin_author_stamped_tx`]) takes one, so
//! the compiler enumerates every write site: a tool cannot stamp from an agent it
//! chose itself. `tests/write_identity_ratchet.rs` pins the other halves — that
//! no module under `src/tools/` resolves `server.agent_id()` directly, that no
//! module but this one and `server.rs` calls [`WriteIdentity::from_resolved`]
//! (it is `pub(crate)`, so the privacy alone did not stop a tool minting one;
//! batch H-b review), that every `#[tool]` body that calls a write-tool function
//! hands it the request's `auth` (and every write body forwards it at all, or is
//! listed with a reason), and that `signer_agent_id()` is only ever bound as a
//! signer.
//!
//! # What the SIGNER is, and why it does not move
//!
//! The server's Ed25519 key still signs every claim and evidence digest. The
//! signer is recorded separately from the author (`claims.signer_id`,
//! `evidence.signer_id`), and `verify_claim` checks the signature against the
//! signer's key, so a claim authored by a caller and signed by the server
//! verifies. See [`crate::server::EpiGraphMcpFull::signer_agent_id`].

use uuid::Uuid;

use crate::errors::McpError;

/// The agent an MCP write authors its rows as and stamps its transaction from.
///
/// Constructed only by [`crate::server::EpiGraphMcpFull::write_identity`]; see
/// the module doc.
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

    /// Crate-private: the only constructor outside tests is
    /// `EpiGraphMcpFull::write_identity`.
    pub(crate) const fn from_resolved(agent_id: Uuid) -> Self {
        Self { agent_id }
    }
}

/// A token that carries no `agents.id` has no author, as it has no reader
/// (`tools::viewer::request_viewer` refuses it the same way).
pub(crate) fn no_agent_principal_refusal() -> McpError {
    McpError::invalid_request(
        "token carries no agent principal, so this write has no author (see plan D3). \
         Re-mint the token through /oauth/token, which attaches an agents.id to every \
         principal. Nothing was written."
            .to_string(),
        None,
    )
}

/// The request's viewer and its token name different principals.
pub(crate) fn diverging_principals(token: Uuid, viewer: Option<Uuid>) -> McpError {
    McpError::internal_error(
        format!(
            "refusing a write whose read and write principals diverge: the token names agent \
             {token}, the request viewer names {viewer:?}. Nothing was written."
        ),
        None,
    )
}
