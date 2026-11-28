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
//! # The principal-less listener (batch HTTP-id)
//!
//! The `--allow-unauthenticated-http` listener injects a context naming the
//! listener's own signer (`auth::unauthenticated_context`). Measured at the
//! batch H-b tip (`scripts/e2e/probe-httpid.sh`, `unauth` arm), every write
//! there was authored by that signer and owned by its personal group: an
//! agent that belongs to no human. Since batch HTTP-id that context is
//! read-only by default, and [`crate::server::EpiGraphMcpFull::write_identity`]
//! refuses it without a write scope, so an HTTP write is authored only by an
//! authenticated caller's own agent. `--allow-unauthenticated-writes` restores
//! signer-authored writes for a trusted local socket; the listener gates keep
//! that signer unlinked, so it never carries a human's authority.
//!
//! # The ratchet
//!
//! [`WriteIdentity`] has a private field and one constructor,
//! [`crate::server::EpiGraphMcpFull::write_identity`] (since backlog 30133ca8
//! it delegates to `epigraph_service::Ctx::write_identity`, and the type and its
//! `from_resolved` constructor live in `epigraph_service::write_identity`, where
//! the constructor is private to that crate). Every author-stamped
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

pub use epigraph_service::write_identity::WriteIdentity;

use crate::errors::{from_service, McpError};

/// An ELEVATED request asked to write (elevation plan §1.4: the elevated
/// viewer is read-only): `epigraph_service::write_identity::refuse_elevated`,
/// answered as this server answers a repository refusal
/// ([`crate::errors::db_caller_error`]'s `INVALID_REQUEST`). The resolver
/// raises it before anything else; `server.rs`'s dispatch check
/// (`refuse_elevated_write`) raises it for a federated write too.
///
/// # Errors
/// The refusal, when `viewer` is elevated.
pub(crate) fn refuse_elevated(viewer: &epigraph_db::visibility::Viewer) -> Result<(), McpError> {
    epigraph_service::write_identity::refuse_elevated(viewer).map_err(from_service)
}
