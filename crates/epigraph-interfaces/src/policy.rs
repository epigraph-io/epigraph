//! `PolicyGate` — the kernel's **write-side** authorization gate.
//!
//! # What this is, and what it deliberately is not
//!
//! Plan §0.6 splits authorization in two and gives each half a different
//! mechanism:
//!
//! * **Reads** are filtered by `epigraph_db::visibility::Viewer` — a spliced
//!   SQL predicate today, an RLS `USING` clause from PR-17. `PolicyGate` never
//!   sees a read. That is not a convention: [`Action`] has **no `Read`
//!   variant**, so a read-side check is not expressible. It used to have one,
//!   and removing it is the cheapest available enforcement of *"Reads are never
//!   gated by it"*.
//! * **Writes** are gated here, in Rust. RLS `WITH CHECK` cannot express role
//!   semantics — *a `reader`-role member of group G must not write to G* — and
//!   PR-16/PR-17 add the SQL half beside this one, not instead of it.
//!
//! # Fail-closed, by construction rather than by convention
//!
//! `epigraph_db::visibility`'s invariant is that a fail-open must be
//! *unconstructible*, not merely un-chosen. The same discipline is applied here:
//!
//! * [`Decision`] has **no `Default`**, no `From<bool>`, and no
//!   `unwrap_or(true)`-shaped helper. There is no way to spell "allow" by
//!   omission.
//! * [`PolicyGate::authorize`] is the call sites' entry point and is
//!   **infallible**: a [`PolicyError`] from an implementation is mapped to
//!   `Decision::Deny`, once, in this file. Call sites cannot get the
//!   `Err(_) => allow` mapping wrong because they never see the `Err`. This is
//!   the D1 defect (`access_control.rs`'s `None => ContentAccess::Full`) closed
//!   at the type level.
//! * [`ResourceRef`] carries `Option` owners and the kernel gate denies when
//!   both are absent. Nothing is authorized by absence.
//! * The kernel's *type-level floor* is [`DenyAllPolicyGate`], not an
//!   allow-all. Precision matters here: `DenyAllPolicyGate` has **zero
//!   production install sites** — all six `AppState` constructors and both
//!   `EpiGraphMcpFull` constructors install `epigraph_authz::GroupPolicyGate`,
//!   which is the *runtime* default a deployment actually gets. The floor is
//!   what a downstream crate assembling its own state and installing no gate
//!   would land on. The allow-all is `AllowAllPolicyGate` and it exists only
//!   under `#[cfg(any(test, feature = "insecure-allow-all"))]` — and that cfg
//!   guards a *name*, not a behaviour: nothing constructs it outside tests, so
//!   the control that closes the hazard is "no constructor site names an
//!   allow-all gate", pinned by
//!   `epigraph-db/tests/locked_decisions.rs::d1_the_kernel_write_gate_is_not_an_allow_all`
//!   and `state.rs::the_default_gate_is_installed_at_every_constructor`, not
//!   the feature flag on its own.
//!
//! # Note on naming
//!
//! This gate is distinct from `epigraph-policy`, which manages *epistemic*
//! claim challenges (dispute resolution). `PolicyGate` governs *access
//! control* — who may write what.

use async_trait::async_trait;
use uuid::Uuid;

use crate::InterfaceError;

/// Errors returned by [`PolicyGate`] implementations.
///
/// A call site never handles one of these: [`PolicyGate::authorize`] turns any
/// error into a denial. The variants exist so an implementation can say *why*
/// it could not decide, and so the reason reaches the log.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The principal's roles or the resource's owners could not be resolved.
    #[error("policy evaluation failed for principal {principal}: {reason}")]
    EvaluationFailed { principal: Uuid, reason: String },
    /// Any other provider-specific error.
    #[error("policy gate error: {0}")]
    Provider(#[from] InterfaceError),
}

/// A **mutating** action the caller wants to perform.
///
/// There is no `Read` variant, on purpose — see the module docs. `Declassify`
/// is separated from `Update` because changing a row's visibility or ownership
/// is the escalation the gate exists to stop, and a policy that wants to treat
/// it differently from an ordinary field update should not have to parse a
/// string to find out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create a new entity (claim, evidence, edge, …).
    Create,
    /// Update the content of an existing entity.
    Update,
    /// Delete an entity.
    Delete,
    /// Change an entity's visibility, partition or ownership.
    Declassify,
    /// Arbitrary named action for extensibility.
    Custom(String),
}

/// What kind of thing is being written.
///
/// Coarse on purpose: the gate authorizes on *owners*, not on schema. The
/// variant is carried so a denial reason and an audit line can name the
/// surface without the call site formatting a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceKind {
    /// A row in `claims`.
    Claim,
    /// A row in `edges`.
    Edge,
    /// A row in `evidence`.
    Evidence,
    /// A row in `ownership` — the legacy partition table.
    Ownership,
    /// A row in `groups` or `group_memberships`.
    Group,
    /// Anything else, named.
    Other(String),
}

/// The thing an [`Action`] is being performed on, plus who owns it.
///
/// The two owner fields are what makes the gate *resource-aware* rather than a
/// scope check. Both are `Option` and both default to `None`: a `ResourceRef`
/// built and never told who owns it is **unauthorizable**, which is the
/// intended behaviour, not a gap. See [`DenyAllPolicyGate`] and
/// `epigraph_authz::GroupPolicyGate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    kind: ResourceKind,
    id: Uuid,
    owner_group: Option<Uuid>,
    owner_agent: Option<Uuid>,
}

impl ResourceRef {
    /// A resource with no declared owner. Denied by every kernel gate until a
    /// caller attaches one with [`Self::owned_by_group`] or
    /// [`Self::owned_by_agent`].
    #[must_use]
    pub const fn new(kind: ResourceKind, id: Uuid) -> Self {
        Self {
            kind,
            id,
            owner_group: None,
            owner_agent: None,
        }
    }

    /// Record the group whose write roll-call governs this resource.
    #[must_use]
    pub fn owned_by_group(mut self, group_id: Uuid) -> Self {
        self.owner_group = Some(group_id);
        self
    }

    /// Record the agent recorded as this resource's owner.
    #[must_use]
    pub fn owned_by_agent(mut self, agent_id: Uuid) -> Self {
        self.owner_agent = Some(agent_id);
        self
    }

    /// What kind of thing this is.
    #[must_use]
    pub const fn kind(&self) -> &ResourceKind {
        &self.kind
    }

    /// The resource's primary key.
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// The owning group, when the caller could name one.
    #[must_use]
    pub const fn owner_group(&self) -> Option<Uuid> {
        self.owner_group
    }

    /// The owning agent, when the caller could name one.
    #[must_use]
    pub const fn owner_agent(&self) -> Option<Uuid> {
        self.owner_agent
    }
}

/// The write authority of one principal, for one request.
///
/// `writable_groups` is the caller's `Viewer::writable_groups()` — the subset
/// of the principal's live memberships whose role is `admin` or `writer`
/// (`epigraph_db::visibility::Viewer::resolve`, `group_memberships_role_check`
/// in migration 060). It is passed in rather than looked up so that this crate
/// and `epigraph-authz` contain **no SQL and no pool**, which is what lets
/// `epigraph-api` name the gate under `--no-default-features`, where
/// `epigraph-db` does not exist.
///
/// There is no `Default` and no zero-argument constructor: a principal with
/// unspecified authority is exactly the "authority materialised out of
/// nothing" that `epigraph_db::visibility`'s module doc forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    id: Uuid,
    writable_groups: Vec<Uuid>,
}

impl Principal {
    /// Build a principal from an `agents.id` and its write-capable group set.
    #[must_use]
    pub fn new(id: Uuid, mut writable_groups: Vec<Uuid>) -> Self {
        writable_groups.sort_unstable();
        writable_groups.dedup();
        Self {
            id,
            writable_groups,
        }
    }

    /// A principal with no write authority anywhere.
    ///
    /// Spelled out rather than reached by `new(id, vec![])` at a call site so
    /// that "this caller has no writable groups" is a visible decision.
    #[must_use]
    pub const fn without_groups(id: Uuid) -> Self {
        Self {
            id,
            writable_groups: Vec::new(),
        }
    }

    /// The principal's `agents.id`.
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// The groups this principal may write to, sorted and deduplicated.
    #[must_use]
    pub fn writable_groups(&self) -> &[Uuid] {
        &self.writable_groups
    }

    /// Whether this principal holds `admin` or `writer` in `group_id`.
    #[must_use]
    pub fn may_write_group(&self, group_id: Uuid) -> bool {
        self.writable_groups.binary_search(&group_id).is_ok()
    }
}

/// The verdict of a [`PolicyGate`].
///
/// Replaces the `bool` the pre-PR-11 trait returned. A `bool` has a `Default`
/// (`false`, which happens to be safe) and, more to the point, is silently
/// interchangeable with every other boolean in a handler; a `Decision` carries
/// the *reason*, which is what an audit line and a 403 body need.
///
/// Deliberately no `Default`, no `From<bool>`, no `Deref<Target = bool>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permitted. `grant` names the rule that permitted it.
    Allow {
        /// Static name of the rule that allowed the action, for the audit log.
        grant: &'static str,
    },
    /// Refused. `reason` is safe to log; it is not necessarily safe to return
    /// to the caller, since it can name owners the caller cannot read.
    Deny {
        /// Why the action was refused.
        reason: String,
    },
}

impl Decision {
    /// Allow, naming the rule that did so.
    #[must_use]
    pub const fn allow(grant: &'static str) -> Self {
        Self::Allow { grant }
    }

    /// Deny, with a loggable reason.
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
        }
    }

    /// Whether the action may proceed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// The denial reason, or `None` when allowed.
    #[must_use]
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::Allow { .. } => None,
            Self::Deny { reason } => Some(reason),
        }
    }
}

/// Pluggable write-side access control.
///
/// The kernel holds an `Arc<dyn PolicyGate>` in `AppState`. `AppState`'s
/// constructors install `epigraph_authz::GroupPolicyGate`; `with_policy_gate`
/// replaces it.
///
/// Implement [`Self::check`]; **call** [`Self::authorize`].
#[async_trait]
pub trait PolicyGate: Send + Sync + 'static {
    /// Decide whether `principal` may perform `action` on `resource`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when the implementation cannot reach a verdict.
    /// Callers do not see this — [`Self::authorize`] converts it to a denial.
    async fn check(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &ResourceRef,
    ) -> Result<Decision, PolicyError>;

    /// Return `true` if this gate enforces real policies.
    ///
    /// Used to skip policy-logging overhead when a trivial gate is installed.
    fn is_active(&self) -> bool;

    /// The call sites' entry point: an evaluation failure **is** a denial.
    ///
    /// This is the whole reason `check` is not called directly. A gate that
    /// cannot decide has not decided "yes"; mapping `Err(_)` to allow is the
    /// exact defect plan §0.2's D1 names (`access_control.rs`'s
    /// `None => ContentAccess::Full`, `.unwrap_or(None)`). Doing the mapping
    /// once, here, means no call site can do it differently.
    async fn authorize(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &ResourceRef,
    ) -> Decision {
        match self.check(principal, action, resource).await {
            Ok(decision) => decision,
            Err(err) => Decision::deny(format!("policy evaluation failed: {err}")),
        }
    }
}

/// The kernel's type-level floor: **deny everything**.
///
/// This is the inverse of the pre-PR-11 `NoOpPolicyGate`, which returned
/// `Ok(true)` for every `(agent, action, resource)` and was never called by
/// anything — a trait object held in an `AppState` field and consulted zero
/// times (`git grep -l policy_gate -- crates/` returned one file).
///
/// **Not the runtime default.** Every `AppState` constructor and every
/// `EpiGraphMcpFull` constructor installs `epigraph_authz::GroupPolicyGate`;
/// this type has no production install site at all. What it is, is the honest
/// answer for a deployment that assembles its own state and installs no policy:
/// a kernel that does not know who may write must not let anyone write. Saying
/// "the kernel default" without that qualifier conflates it with the gate a
/// running process actually holds, and PR-11's acceptance criterion ("a fresh
/// `AppState` denies by default") is satisfied by `GroupPolicyGate`'s
/// behaviour, not by this type's existence.
///
/// `is_active()` is **`true`**: this gate does enforce a policy. The old no-op
/// returned `false` so callers could skip policy logging; a `false` here would
/// invite a caller to skip the check itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllPolicyGate;

impl DenyAllPolicyGate {
    /// Create the deny-everything gate.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PolicyGate for DenyAllPolicyGate {
    async fn check(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &ResourceRef,
    ) -> Result<Decision, PolicyError> {
        Ok(Decision::deny(format!(
            "no policy is installed; the kernel default denies {action:?} by principal {} on {:?} {}",
            principal.id(),
            resource.kind(),
            resource.id()
        )))
    }

    fn is_active(&self) -> bool {
        true
    }
}

/// Allow every write. **Not compiled into a production binary.**
///
/// This is the pre-PR-11 `NoOpPolicyGate`, renamed to say what it does and
/// placed behind `#[cfg(any(test, feature = "insecure-allow-all"))]` as plan
/// §2.7 prescribes.
///
/// # The hazard this inherits, stated rather than hidden
///
/// `progress.json`'s `Q4_allow_all_identities` locks "fail closed; explicit
/// opt-in required", and `epigraph_db::visibility::Viewer::test_scoped` puts
/// `#[cfg(test)]` on the *definition* rather than behind a cargo feature, with
/// the stated reason that *"a feature can be switched on from a dependent
/// crate's build graph, and then this constructor is reachable in
/// production"*. The `feature` half of this cfg is exactly that hazard.
///
/// It is kept because the plan prescribes it and because `cfg(test)` alone does
/// not cross a crate boundary — an integration test in another crate cannot see
/// a `cfg(test)` item here. The mitigation is that **nothing in this workspace
/// enables the feature**: no `[features]` table forwards it and no
/// `dev-dependencies` entry requests it, so `cargo build --workspace` and
/// `cargo test --workspace` both compile this type out everywhere except
/// `epigraph-interfaces`' own unit tests.
/// `epigraph_db::tests::locked_decisions` pins that.
#[cfg(any(test, feature = "insecure-allow-all"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllPolicyGate;

#[cfg(any(test, feature = "insecure-allow-all"))]
impl AllowAllPolicyGate {
    /// Create the allow-everything gate.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(any(test, feature = "insecure-allow-all"))]
#[async_trait]
impl PolicyGate for AllowAllPolicyGate {
    async fn check(
        &self,
        _principal: &Principal,
        _action: &Action,
        _resource: &ResourceRef,
    ) -> Result<Decision, PolicyError> {
        Ok(Decision::allow("insecure-allow-all"))
    }

    fn is_active(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource() -> ResourceRef {
        ResourceRef::new(ResourceKind::Claim, Uuid::new_v4())
    }

    fn actions() -> Vec<Action> {
        vec![
            Action::Create,
            Action::Update,
            Action::Delete,
            Action::Declassify,
            Action::Custom("publish".into()),
        ]
    }

    /// The inverse of the pre-PR-11 `noop_always_allows`. The plan's
    /// *Acceptance* line calls for "the inverse of today's
    /// `default_gate_allows_all`"; that identifier exists nowhere in the tree,
    /// so this is the negative test written rather than inverted.
    #[tokio::test]
    async fn the_kernel_default_denies_every_action() {
        let gate = DenyAllPolicyGate::new();
        let principal = Principal::without_groups(Uuid::new_v4());
        for action in actions() {
            let decision = gate.authorize(&principal, &action, &resource()).await;
            assert!(
                !decision.is_allowed(),
                "kernel default must deny {action:?}, got {decision:?}"
            );
            assert!(decision.denial_reason().is_some());
        }
    }

    /// A gate that cannot decide has not decided "yes".
    #[tokio::test]
    async fn an_evaluation_error_is_a_denial() {
        struct Broken;

        #[async_trait]
        impl PolicyGate for Broken {
            async fn check(
                &self,
                principal: &Principal,
                _action: &Action,
                _resource: &ResourceRef,
            ) -> Result<Decision, PolicyError> {
                Err(PolicyError::EvaluationFailed {
                    principal: principal.id(),
                    reason: "membership lookup timed out".into(),
                })
            }
            fn is_active(&self) -> bool {
                true
            }
        }

        let decision = Broken
            .authorize(
                &Principal::without_groups(Uuid::new_v4()),
                &Action::Create,
                &resource(),
            )
            .await;
        assert!(!decision.is_allowed());
        assert!(decision
            .denial_reason()
            .expect("denial carries a reason")
            .contains("membership lookup timed out"));
    }

    #[test]
    fn the_kernel_default_reports_itself_active() {
        assert!(
            DenyAllPolicyGate::new().is_active(),
            "a gate that denies is enforcing a policy; reporting inactive would \
             invite a caller to skip the check"
        );
    }

    #[tokio::test]
    async fn the_insecure_gate_allows_everything_and_reports_inactive() {
        let gate = AllowAllPolicyGate::new();
        let principal = Principal::without_groups(Uuid::new_v4());
        for action in actions() {
            assert!(gate
                .authorize(&principal, &action, &resource())
                .await
                .is_allowed());
        }
        assert!(!gate.is_active());
    }

    #[test]
    fn a_resource_with_no_owner_names_no_owner() {
        let r = resource();
        assert_eq!(r.owner_group(), None);
        assert_eq!(r.owner_agent(), None);
    }

    #[test]
    fn principal_write_authority_is_sorted_deduplicated_and_queryable() {
        let g1 = Uuid::from_u128(1);
        let g2 = Uuid::from_u128(2);
        let p = Principal::new(Uuid::new_v4(), vec![g2, g1, g2]);
        assert_eq!(p.writable_groups(), &[g1, g2]);
        assert!(p.may_write_group(g1));
        assert!(!p.may_write_group(Uuid::from_u128(3)));
        assert!(Principal::without_groups(Uuid::new_v4())
            .writable_groups()
            .is_empty());
    }
}
