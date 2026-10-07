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
//! # The rule is the caller's own write authority
//!
//! Without `claims:admin`, a caller is admitted only when its viewer can WRITE
//! the group that owns the claim (`admin` or `writer` membership, live). That
//! is exactly the `WITH CHECK` of `claims_tenancy` (migration 077:
//! `owner_group_id = ANY(epigraph_writable_groups())`), so the pre-check and
//! the database agree, and the refusal carries a name instead of a raw row
//! security error. Authorship alone admits nothing: an author whose membership
//! in the owning group was revoked, or downgraded to `reader`, no longer
//! writes that claim, and must not be able to retire or rewrite it. The
//! [`ClaimActArm::Author`] label only says which of the two write-capable
//! callers asked.
//!
//! Every non-admin act then runs on a transaction stamped with the CALLER's
//! viewer, the one the gate read ran on. Only [`ClaimActArm::Admin`] may act
//! on a claim the caller does not write (on MCP, on the server agent's stamp,
//! as before batch OA1, when `claims:admin` was the tool's scope).

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
    /// The caller writes the group that owns the claim AND is its author.
    Author,
    /// The caller writes the group that owns the claim (`admin` or `writer`)
    /// and did not author it.
    GroupWriter,
}

impl ClaimActArm {
    /// A stable label for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "claims_admin",
            Self::Author => "author",
            Self::GroupWriter => "group_writer",
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
/// [`ClaimActArm::Admin`] for a `claims:admin` token; otherwise `None` unless
/// `writable_groups` holds the claim's owning group, and then
/// [`ClaimActArm::Author`] or [`ClaimActArm::GroupWriter`]. A transport must
/// not add arms of its own: any admission here that is not `Admin` is one the
/// caller's own stamp can carry out, and the transport runs it on that stamp.
///
/// There is deliberately no arm comparing the token's `owner_id` or
/// `client_id` with the claim's author. Those are `oauth_clients.id` values
/// and `claims.agent_id` is an `agents.id`; equating the two is a type
/// confusion that a colliding id would turn into a silent grant.
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
    if !writable_groups.contains(&target.owner_group) {
        return None;
    }
    if viewer_principal == Some(target.author) {
        Some(ClaimActArm::Author)
    } else {
        Some(ClaimActArm::GroupWriter)
    }
}

/// The human-readable refusal for a claim act the caller may not perform.
#[must_use]
pub fn not_claim_writer_message(claim_id: Uuid, action: &str) -> String {
    format!(
        "cannot {action} claim {claim_id}: the caller holds no admin or writer membership in \
         the group that owns it (authorship alone is not write authority) and lacks \
         claims:admin; nothing was written"
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
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: crate::AdminScopePosture::Unarmed,
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
    fn the_author_who_writes_the_owning_group_is_admitted_without_claims_admin() {
        let t = target();
        let a = auth(Uuid::new_v4(), Some(Uuid::new_v4()), &["claims:write"]);
        assert_eq!(
            claim_act_arm(&a, Some(t.author), &[t.owner_group], t),
            Some(ClaimActArm::Author)
        );
    }

    /// Authorship is not write authority: an author whose membership in the
    /// owning group was revoked or downgraded (so the group is not in its
    /// writable set) is refused, exactly as a bystander is.
    #[test]
    fn an_author_who_does_not_write_the_owning_group_is_refused() {
        let t = target();
        let a = auth(Uuid::new_v4(), Some(Uuid::new_v4()), &["claims:write"]);
        assert_eq!(claim_act_arm(&a, Some(t.author), &[], t), None);
        assert_eq!(
            claim_act_arm(&a, Some(t.author), &[Uuid::new_v4()], t),
            None
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

    /// The token's `owner_id` / `client_id` (`oauth_clients.id` values) are
    /// never compared with the claim's author (an `agents.id`): a token whose
    /// owner or client id equals the author's id admits nothing on its own.
    #[test]
    fn a_token_owner_or_client_id_equal_to_the_author_admits_nothing() {
        let t = target();
        let with_owner = auth(Uuid::new_v4(), Some(t.author), &["claims:write"]);
        assert_eq!(claim_act_arm(&with_owner, None, &[], t), None);
        let ownerless = auth(t.author, None, &["claims:write"]);
        assert_eq!(claim_act_arm(&ownerless, None, &[], t), None);
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
