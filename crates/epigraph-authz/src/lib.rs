//! Fail-closed, resource-aware write authorization.
//!
//! This crate holds [`GroupPolicyGate`], the [`PolicyGate`] every `AppState`
//! constructor installs. It answers one question:
//!
//! > May this principal perform this **mutating** action on this resource?
//!
//! and it answers "no" unless a positive grant says otherwise.
//!
//! # Why this is a separate crate
//!
//! The gate has to run above the repo layer. Resolving a principal's roles
//! needs `epigraph_db::repos::GroupMembershipRepository`, so a gate that
//! resolved them itself would need `epigraph-authz → epigraph-db`; calling the
//! gate from inside `OwnershipRepository` would need `epigraph-db →
//! epigraph-authz`. One of those has to give, and it is the resolution: the
//! caller resolves a `Viewer` (`epigraph_db::visibility::Viewer`) once, per
//! request, and hands this crate the already-computed
//! [`Principal::writable_groups`].
//!
//! That leaves this crate with **no SQL, no pool and no `epigraph-db`
//! dependency**, which is what makes it nameable in `epigraph-api`'s
//! `--no-default-features` build.
//!
//! The call sites are therefore in `routes/` and `tools/`. Two of the four
//! PR-11 wires up are deleted by PR-14 (`routes/ownership.rs`, MCP
//! `assign_ownership` / `update_partition`); PR-16 re-uses this gate at the
//! `INSERT INTO claims` sites, where the resource DOES carry an
//! `owner_group_id` and the group arm below stops being vestigial. The crate
//! outlives its first call sites, which is the point of putting the durable
//! work here.
//!
//! # The two grants, and what "deny" covers
//!
//! [`GroupPolicyGate::check`] allows on exactly two grounds:
//!
//! * **`resource-owner`** — the resource records this principal as its owner.
//! * **`group-writer`** — the resource names an owning group and the principal
//!   holds `admin` or `writer` in it. `reader` does not appear in
//!   `Viewer::writable_groups()` (`Viewer::resolve` filters on
//!   `matches!(role.as_str(), "admin" | "writer")`), so a reader-role member is
//!   denied on their own group. That is PR-11's stated acceptance criterion and
//!   `tests/fail_closed.rs` proves it against a real membership row.
//!
//! Everything else denies, including — and this is the D1 case, not an
//! oversight — a resource that names **no** owner at all. Nothing is authorized
//! by absence, by omission, or by default-on-error. The error branch is not
//! even reachable from a call site: [`PolicyGate::authorize`] maps `Err(_)` to
//! a denial inside `epigraph-interfaces`.
//!
//! # What this gate does NOT do
//!
//! * It never sees a read. [`Action`] has no `Read` variant.
//! * It does not emit SQL, so it cannot enforce anything against a writer that
//!   bypasses the application (the `epigraph-jobs` direct-`INSERT` paths, the
//!   CLI bins with their own pools). That half is RLS `WITH CHECK`, PR-16/17.
//!   A write gate that covers only HTTP and MCP is a partial control, and
//!   saying so is part of not over-claiming it.
//! * It does not decide whether a principal who cannot *read* a claim may write
//!   against it. That is `progress.json`'s open obligation
//!   `D-PR16-per-id-claim-oracles-write-half`, owned by PR-16. This gate is
//!   given the resource's owners by the caller and never performs the read that
//!   would force the question.

use async_trait::async_trait;
use epigraph_interfaces::{Action, Decision, PolicyError, PolicyGate, Principal, ResourceRef};

/// Group-and-role aware write gate. Denies unless a positive grant applies.
///
/// Stateless: it is a decision function over `(principal, action, resource)`,
/// all three supplied by the caller. Cheap to construct, cheap to clone, and
/// trivially `Send + Sync`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GroupPolicyGate;

impl GroupPolicyGate {
    /// Create the gate.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Grant name recorded when the principal owns the resource.
pub const GRANT_RESOURCE_OWNER: &str = "resource-owner";
/// Grant name recorded when the principal holds `admin`/`writer` in the
/// resource's owning group.
pub const GRANT_GROUP_WRITER: &str = "group-writer";

#[async_trait]
impl PolicyGate for GroupPolicyGate {
    async fn check(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &ResourceRef,
    ) -> Result<Decision, PolicyError> {
        // 1. The principal is the recorded owner.
        if resource.owner_agent() == Some(principal.id()) {
            return Ok(Decision::allow(GRANT_RESOURCE_OWNER));
        }

        // 2. The principal holds a write role in the owning group.
        if let Some(group) = resource.owner_group() {
            if principal.may_write_group(group) {
                return Ok(Decision::allow(GRANT_GROUP_WRITER));
            }
            return Ok(Decision::deny(format!(
                "principal {} may not {action:?} {:?} {}: no write role \
                 (admin|writer) in owning group {group}",
                principal.id(),
                resource.kind(),
                resource.id()
            )));
        }

        // 3. Neither. An undeclared resource is not a public one.
        Ok(Decision::deny(format!(
            "principal {} may not {action:?} {:?} {}: the resource names no \
             owning group and no owning agent, and nothing is authorized by \
             absence",
            principal.id(),
            resource.kind(),
            resource.id()
        )))
    }

    fn is_active(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_interfaces::{ResourceKind, ResourceRef};
    use uuid::Uuid;

    fn claim(id: Uuid) -> ResourceRef {
        ResourceRef::new(ResourceKind::Claim, id)
    }

    #[tokio::test]
    async fn a_writer_may_write_their_own_group() {
        let group = Uuid::new_v4();
        let principal = Principal::new(Uuid::new_v4(), vec![group]);
        let decision = GroupPolicyGate::new()
            .authorize(
                &principal,
                &Action::Create,
                &claim(Uuid::new_v4()).owned_by_group(group),
            )
            .await;
        assert_eq!(decision, Decision::allow(GRANT_GROUP_WRITER));
    }

    #[tokio::test]
    async fn a_non_member_may_not_write_someone_elses_group() {
        let principal = Principal::new(Uuid::new_v4(), vec![Uuid::new_v4()]);
        let decision = GroupPolicyGate::new()
            .authorize(
                &principal,
                &Action::Update,
                &claim(Uuid::new_v4()).owned_by_group(Uuid::new_v4()),
            )
            .await;
        assert!(!decision.is_allowed(), "got {decision:?}");
        assert!(decision
            .denial_reason()
            .expect("reason")
            .contains("no write role"));
    }

    #[tokio::test]
    async fn an_owner_may_write_their_own_resource() {
        let me = Uuid::new_v4();
        let decision = GroupPolicyGate::new()
            .authorize(
                &Principal::without_groups(me),
                &Action::Declassify,
                &claim(Uuid::new_v4()).owned_by_agent(me),
            )
            .await;
        assert_eq!(decision, Decision::allow(GRANT_RESOURCE_OWNER));
    }

    #[tokio::test]
    async fn a_stranger_may_not_write_someone_elses_resource() {
        let decision = GroupPolicyGate::new()
            .authorize(
                &Principal::without_groups(Uuid::new_v4()),
                &Action::Declassify,
                &claim(Uuid::new_v4()).owned_by_agent(Uuid::new_v4()),
            )
            .await;
        assert!(!decision.is_allowed(), "got {decision:?}");
    }

    /// D1, at the gate: a resource that declares no owner is refused, not
    /// treated as unowned-therefore-public.
    #[tokio::test]
    async fn an_undeclared_resource_is_denied_not_defaulted() {
        let group = Uuid::new_v4();
        let principal = Principal::new(Uuid::new_v4(), vec![group]);
        let decision = GroupPolicyGate::new()
            .authorize(&principal, &Action::Create, &claim(Uuid::new_v4()))
            .await;
        assert!(!decision.is_allowed(), "got {decision:?}");
        assert!(decision
            .denial_reason()
            .expect("reason")
            .contains("nothing is authorized by absence"));
    }

    /// The group arm is checked against the principal's WRITABLE set, not its
    /// membership set. A `Principal` built from `Viewer::writable_groups()`
    /// therefore cannot smuggle a reader-role group in — the filtering already
    /// happened in `Viewer::resolve`, and this asserts the gate does not
    /// second-guess it by falling back to some broader set.
    #[tokio::test]
    async fn the_group_arm_reads_only_the_writable_set() {
        let readable_only = Uuid::new_v4();
        let principal = Principal::without_groups(Uuid::new_v4());
        let decision = GroupPolicyGate::new()
            .authorize(
                &principal,
                &Action::Create,
                &claim(Uuid::new_v4()).owned_by_group(readable_only),
            )
            .await;
        assert!(!decision.is_allowed(), "got {decision:?}");
    }

    #[test]
    fn the_gate_reports_itself_active() {
        assert!(GroupPolicyGate::new().is_active());
    }
}
