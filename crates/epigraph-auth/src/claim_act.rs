//! Who may perform a claim-retiring ACT: `supersede` and `mark_duplicate`
//! (batch OA1, operator decision D1).
//!
//! D1 splits a retirement in two. The ACT (retire the claim, insert its
//! replacement or point it at its canonical) is the caller's own write, so it
//! needs the caller's own write authority over the claim and nothing more. The
//! CASCADE that follows (re-pointing and retracting other writers' edges,
//! moving their edge-keyed BBAs, re-deriving belief) is administrative and runs
//! on the maintenance connection, deferred to the replay timer (W10/W12). So
//! the act is gated at `claims:write` plus the authority rule below, not at
//! `claims:admin`: an owner may retire their own claim without holding an
//! administrative scope, and `claims:admin` remains the arm for any claim.
//!
//! This module holds the one decision both transports (HTTP
//! `POST /api/v1/claims/:id/supersede` and `/dedup`, MCP `supersede_claim` and
//! `mark_duplicate`) make, so the two cannot drift apart. It is pure: the
//! caller reads the claim's author and owning group THROUGH ITS OWN VIEWER
//! first, and answers a claim that viewer cannot read exactly like a missing
//! one, before asking this function anything. A refusal from here therefore
//! only ever concerns a claim the caller could already see, so it is no
//! existence oracle.
//!
//! The database still decides the write itself: every arm here admits a
//! caller to ASK, and the act then runs on a stamped transaction whose row
//! security refuses a row the stamp cannot write.

use crate::AuthContext;
use uuid::Uuid;

/// The rule name a refused claim act carries in its machine-readable body,
/// next to `"error": "not_owner"` (the edge write contract of migration 120
/// uses the same key with its own rules).
pub const NOT_CLAIM_WRITER_RULE: &str = "not_claim_writer";

/// The two facts the decision reads about the target claim, as the caller's
/// viewer returned them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimActTarget {
    /// `claims.agent_id`: the claim's author.
    pub author: Uuid,
    /// `claims.owner_group_id`: the group that owns the row.
    pub owner_group: Uuid,
}

/// Why a caller was admitted to a claim act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimActArm {
    /// The token holds `claims:admin`: any claim the caller can read.
    Admin,
    /// The caller's agent principal is the claim's author.
    Author,
    /// The caller holds `admin` or `writer` in the group that owns the claim.
    GroupWriter,
    /// The token's owner (or, with none, its client) is recorded as the
    /// claim's author: the rule both transports applied before OA1, kept so
    /// that no caller admitted then is refused now.
    TokenOwner,
}

impl ClaimActArm {
    /// A stable label for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "claims_admin",
            Self::Author => "author",
            Self::GroupWriter => "group_writer",
            Self::TokenOwner => "token_owner",
        }
    }
}

/// May this authenticated caller perform a claim act on `target`?
///
/// `viewer_principal` and `writable_groups` come from the caller's resolved
/// viewer (`Viewer::principal()` and `Viewer::writable_groups()`), never from
/// the token alone: group membership is live state, and a token's scopes say
/// nothing about it.
///
/// Returns the first arm that admits the caller, in the order
/// [`ClaimActArm::Admin`], [`ClaimActArm::Author`],
/// [`ClaimActArm::GroupWriter`], [`ClaimActArm::TokenOwner`], or `None` for a
/// refusal. A transport may add arms of its own after a `None` (MCP keeps its
/// operator-link arm), never before, and never an arm that widens a refusal
/// into an allow on anything the caller cannot read.
#[must_use]
pub fn claim_act_arm(
    auth: &AuthContext,
    viewer_principal: Option<Uuid>,
    writable_groups: &[Uuid],
    target: ClaimActTarget,
) -> Option<ClaimActArm> {
    if auth.has_scope("claims:admin") {
        return Some(ClaimActArm::Admin);
    }
    if viewer_principal == Some(target.author) {
        return Some(ClaimActArm::Author);
    }
    if writable_groups.contains(&target.owner_group) {
        return Some(ClaimActArm::GroupWriter);
    }
    if auth.owner_id.unwrap_or(auth.client_id) == target.author {
        return Some(ClaimActArm::TokenOwner);
    }
    None
}

/// The human-readable refusal for a claim act the caller may not perform.
#[must_use]
pub fn not_claim_writer_message(claim_id: Uuid, action: &str) -> String {
    format!(
        "cannot {action} claim {claim_id}: the caller is not its author, holds no admin or \
         writer membership in the group that owns it, and lacks claims:admin; nothing was \
         written"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientType;

    fn auth(client: Uuid, owner: Option<Uuid>, scopes: &[&str]) -> AuthContext {
        AuthContext {
            client_id: client,
            agent_id: None,
            owner_id: owner,
            client_type: ClientType::Human,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
        }
    }

    fn target() -> ClaimActTarget {
        ClaimActTarget {
            author: Uuid::new_v4(),
            owner_group: Uuid::new_v4(),
        }
    }

    #[test]
    fn a_bystander_with_claims_write_is_refused() {
        let t = target();
        let a = auth(Uuid::new_v4(), Some(Uuid::new_v4()), &["claims:write"]);
        // A writable group that is not the claim's, and a principal that is
        // not its author: every arm has something to look at and must say no.
        let refused = claim_act_arm(&a, Some(Uuid::new_v4()), &[Uuid::new_v4()], t);
        assert_eq!(refused, None);
    }

    #[test]
    fn the_author_is_admitted_without_claims_admin() {
        let t = target();
        let a = auth(Uuid::new_v4(), Some(Uuid::new_v4()), &["claims:write"]);
        assert_eq!(
            claim_act_arm(&a, Some(t.author), &[], t),
            Some(ClaimActArm::Author)
        );
    }

    #[test]
    fn a_writer_of_the_owning_group_is_admitted() {
        let t = target();
        let a = auth(Uuid::new_v4(), Some(Uuid::new_v4()), &["claims:write"]);
        assert_eq!(
            claim_act_arm(
                &a,
                Some(Uuid::new_v4()),
                &[Uuid::new_v4(), t.owner_group],
                t
            ),
            Some(ClaimActArm::GroupWriter)
        );
    }

    #[test]
    fn claims_admin_is_admitted_for_a_claim_it_neither_wrote_nor_writes() {
        let t = target();
        let a = auth(Uuid::new_v4(), Some(Uuid::new_v4()), &["claims:admin"]);
        assert_eq!(
            claim_act_arm(&a, Some(Uuid::new_v4()), &[], t),
            Some(ClaimActArm::Admin)
        );
    }

    #[test]
    fn the_pre_oa1_token_owner_rule_still_admits() {
        let t = target();
        let with_owner = auth(Uuid::new_v4(), Some(t.author), &["claims:write"]);
        assert_eq!(
            claim_act_arm(&with_owner, None, &[], t),
            Some(ClaimActArm::TokenOwner)
        );
        // No owner: the client id stands in, as it always did.
        let ownerless = auth(t.author, None, &["claims:write"]);
        assert_eq!(
            claim_act_arm(&ownerless, None, &[], t),
            Some(ClaimActArm::TokenOwner)
        );
    }

    #[test]
    fn the_refusal_names_the_claim_and_the_missing_authority() {
        let id = Uuid::new_v4();
        let m = not_claim_writer_message(id, "supersede");
        assert!(m.contains(&id.to_string()), "{m}");
        assert!(m.contains("claims:admin"), "{m}");
        assert!(m.contains("nothing was written"), "{m}");
    }
}
