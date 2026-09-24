//! `TenancyDecl` — what a write path says about who owns the row it is about
//! to create.
//!
//! # Why this type exists
//!
//! Migration 074 (PR-16) drops the `DEFAULT` on every tier-A table's
//! `visibility` and `owner_group_id`. From that point a write that names
//! neither column, and has no parent the database can derive them from, raises
//! `23502`. `TenancyDecl` is the parameter that carries the declaration from
//! the caller — who knows the acting principal — down to the SQL, which does
//! not.
//!
//! # Why it lives in `epigraph-core` and not in `epigraph-db`
//!
//! `epigraph-db` is `optional = true` in `epigraph-api`, so under
//! `--no-default-features` its types cannot be named at all. Two of the thirteen
//! call sites this type serves are HTTP handlers
//! (`routes/hypothesis.rs::create_hypothesis`, `routes/policies.rs::create_challenge`),
//! and a handler signature that mentions an `epigraph-db` type needs a
//! `#[cfg(not(feature = "db"))]` twin or the no-db build breaks — a build the
//! workspace's `--all-targets` gate never exercises. Putting the declaration in
//! `epigraph-core`, which is a hard dependency of both, removes the problem
//! rather than working around it.
//!
//! # Why there is no `Default`
//!
//! Same reason [`crate::truth::TruthValue`] has no "unknown" constructor and
//! `Viewer` has no infallible one: a value you get without deciding anything is
//! a decision nobody made, and D1 is the rule that says the database must not
//! accept one. `TenancyDecl::Inherited` is *not* that default — see below.
//!
//! # The two shapes, and why `Inherited` is not a loophole
//!
//! * [`TenancyDecl::Declared`] names both columns. The database validates the
//!   pair and, if the row also binds a parent, checks that the declaration does
//!   not *widen* past it (declaring `'public'` on a successor to a group-private
//!   claim raises `42501`).
//!
//! * [`TenancyDecl::Inherited`] binds SQL `NULL` for both and says, explicitly:
//!   *this row has a determinate parent; read the tenancy off it.* That is the
//!   D1-compliant answer for `supersede` (binds `supersedes`), `evolve_step` and
//!   `add_step` (bind `step_lineage_id`), and every claim-derived row (binds
//!   `claim_id`). The plan prefers it to restating, because restating is what
//!   invites an accidental downgrade.
//!
//!   `Inherited` on a row with **no** parent does not silently become public. It
//!   raises `23502` for an application role, and takes the `epigraph_seed`
//!   escape hatch — `('public', <seed group>)`, greppable, revocable with one
//!   `REVOKE` — only for a test-harness role. That asymmetry is the whole
//!   design: the loophole is a role membership visible in `pg_auth_members`, not
//!   a value in a struct.
//!
//! See `docs/tenancy.md#declaring-visibility-on-write`.

use uuid::Uuid;

/// The `visibility` vocabulary. Mirrors the `<table>_visibility_check`
/// constraint added by migration 062.
///
/// `Public` means **any authenticated agent** (decision D3), not *anonymous*.
/// There is no anonymous read path, so there is no third variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// Readable by any authenticated principal.
    Public,
    /// Readable only by live members of `owner_group_id`.
    Group,
}

impl Visibility {
    /// The exact string stored in the column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Group => "group",
        }
    }

    /// Parse a stored value. Returns `None` for anything outside the
    /// vocabulary — including `NULL` read as an empty string, which is what a
    /// pre-074 row would look like if the column were ever made nullable.
    #[must_use]
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "public" => Some(Self::Public),
            "group" => Some(Self::Group),
            _ => None,
        }
    }
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The world group: the `owner_group_id` every pre-tenancy row carried under
/// migration 062's `DEFAULT`, and the sentinel for *owned by nobody*.
///
/// Seeded by migration 062, memberless by design, and forbidden from ever
/// pairing with `visibility = 'group'`. Spelled once, here, because the literal
/// also appears in six migrations and a second Rust copy would be a place for
/// the two to drift.
pub const WORLD_GROUP: Uuid = Uuid::from_bytes([0u8; 16]);

/// What a write path declares about the tenancy of the row it creates.
///
/// Construct with [`TenancyDecl::public`], [`TenancyDecl::group`] or
/// [`TenancyDecl::inherited`]. There is deliberately no `Default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenancyDecl {
    /// Both columns named by the caller.
    Declared {
        /// Who may read the row.
        visibility: Visibility,
        /// Who owns it. Must be a real `groups.id`; pairing `Group` with the
        /// world or seed group is refused by `<table>_group_needs_real_group`.
        owner_group_id: Uuid,
    },
    /// Neither column named: the row binds a parent and the database derives
    /// the tenancy from it. Raises `23502` if there is no parent.
    Inherited,
}

impl TenancyDecl {
    /// `visibility = 'public'`, owned by `owner_group_id`.
    ///
    /// A public row still has a real owner. `visibility` says who may read it;
    /// `owner_group_id` says who it belongs to, and is what a later
    /// privatization acts on.
    #[must_use]
    pub const fn public(owner_group_id: Uuid) -> Self {
        Self::Declared {
            visibility: Visibility::Public,
            owner_group_id,
        }
    }

    /// `visibility = 'group'`, readable only by live members of `owner_group_id`.
    #[must_use]
    pub const fn group(owner_group_id: Uuid) -> Self {
        Self::Declared {
            visibility: Visibility::Group,
            owner_group_id,
        }
    }

    /// Derive from the row's parent. Only legal where the statement also binds
    /// one of `supersedes`, `step_lineage_id`, `claim_id`, or an edge's
    /// endpoints.
    #[must_use]
    pub const fn inherited() -> Self {
        Self::Inherited
    }

    /// `('public', <the world group>)` — for an **ownerless, instance-wide
    /// registry row**, and for nothing else.
    ///
    /// # This is the one construction that can be misused, so read this first
    ///
    /// The world group is memberless by design (`locked_decisions.rs::d2_world_and_seed_remain_memberless`).
    /// Pairing it with `'group'` is a black hole and is refused outright by
    /// `<table>_group_needs_real_group`; pairing it with `'public'`, as here,
    /// means *readable by every authenticated agent and owned by nobody*. That
    /// is a true statement about a `frames` row and a false one about anything
    /// carrying user content.
    ///
    /// **It is not available for `claims`.** §8.2 acceptance query A4 asserts
    /// `count(*) FROM claims WHERE owner_group_id = <world>` is 0, so a claim
    /// constructed this way would fail acceptance. Migration 074 arm 4 stamps
    /// the SEED group rather than world for exactly that reason. Claims get
    /// [`Self::public`] over the author's personal group.
    ///
    /// # Where it IS correct
    ///
    /// The six tier-A tables with no parent and no author:
    /// `frames`, `contexts`, `perspectives` and `communities` are instance-wide
    /// registries — a frame is a shared hypothesis space, and giving it an
    /// owner group would make Dempster-Shafer mass functions unreadable across
    /// groups for no gain. `perspectives.owner_agent_id` is `Option<Uuid>` and
    /// is `None` on both synthetic-perspective paths, so there is no author to
    /// derive from even where the column exists.
    ///
    /// This construction preserves the value those rows already carried under
    /// migration 062's `DEFAULT`. What changes is that it is now *chosen at the
    /// call site and greppable* rather than supplied by `pg_attrdef` to a write
    /// that said nothing — which is the whole of D1. If a later PR gives one of
    /// these tables a real owner, `grep -rn instance_wide` enumerates every
    /// place that has to change.
    #[must_use]
    pub const fn instance_wide() -> Self {
        Self::Declared {
            visibility: Visibility::Public,
            owner_group_id: WORLD_GROUP,
        }
    }

    /// The value to bind to the `visibility` column: `None` is SQL `NULL`,
    /// which is what makes the database's inheritance arms reachable.
    #[must_use]
    pub const fn visibility_bind(&self) -> Option<&'static str> {
        match self {
            Self::Declared { visibility, .. } => Some(visibility.as_str()),
            Self::Inherited => None,
        }
    }

    /// The value to bind to the `owner_group_id` column.
    #[must_use]
    pub const fn owner_group_bind(&self) -> Option<Uuid> {
        match self {
            Self::Declared { owner_group_id, .. } => Some(*owner_group_id),
            Self::Inherited => None,
        }
    }

    /// True when the caller named both columns.
    #[must_use]
    pub const fn is_declared(&self) -> bool {
        matches!(self, Self::Declared { .. })
    }
}

/// The tenancy of a claim being merged, as read back inside `consolidate`'s
/// transaction.
pub type SourceTenancy = (Uuid, Visibility);

/// Why a consolidation cannot be given a tenancy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsolidateTenancyError {
    /// Two or more group-visible sources are owned by *different* groups.
    ///
    /// Refused rather than resolved: merging claims owned by two groups into
    /// one row discloses each group's content to the other, and neither
    /// authorized it. Not a regression — before migration 074 the merged row
    /// simply landed on the world default, which disclosed to everyone.
    CrossGroup {
        /// The two distinct owners, sorted, so the message is deterministic.
        groups: (Uuid, Uuid),
    },
}

/// `Display` NAMES NEITHER GROUP — deliberately.
///
/// This message reaches the caller as HTTP 409 (`DbError::Conflict` ->
/// `ApiError::Conflict`) and as JSON-RPC `invalid_params`. Rendering the two
/// owner UUIDs into it would make `consolidate` an **oracle over the private
/// ownership graph**: name two claim ids you cannot read, and the refusal hands
/// back the groups that own them. The structured
/// [`ConsolidateTenancyError::CrossGroup`] variant still carries the pair, so
/// the repo layer logs it at `warn!` for an operator with catalog access.
impl std::fmt::Display for ConsolidateTenancyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrossGroup { .. } => write!(
                f,
                "consolidate: the sources are owned by more than one group. Merging them \
                 into one row would disclose each group's claim to the other, and neither \
                 authorized it. Merge within a group, or make the sources public first."
            ),
        }
    }
}

impl std::error::Error for ConsolidateTenancyError {}

/// `consolidate`'s meet rule (plan §4.6), as a pure function so it can be
/// tested without a database.
///
/// ```text
/// merged.visibility     = 'group' if ANY source is 'group', else 'public'
/// merged.owner_group_id = the single distinct owner among 'group'-visible sources
///                         (sources spanning two or more DIFFERENT groups -> REFUSE)
///                         else `actor_group`, the acting agent's personal group
/// ```
///
/// Note what is deliberately NOT the rule: the owner is taken from the
/// **group-visible** sources only. A public source's `owner_group_id` is who
/// authored it, not who may read it, so letting a public source contribute an
/// owner would let an unrelated group inherit a merge it had no part in — and
/// would make the cross-group refusal fire on merges that disclose nothing.
///
/// # Errors
///
/// Returns [`ConsolidateTenancyError::CrossGroup`] when the group-visible
/// sources are owned by more than one group.
pub fn consolidate_tenancy(
    sources: &[SourceTenancy],
    actor_group: Uuid,
) -> Result<TenancyDecl, ConsolidateTenancyError> {
    Ok(match consolidate_owner(sources)? {
        Some(g) => TenancyDecl::group(g),
        None => TenancyDecl::public(actor_group),
    })
}

/// The owner half of [`consolidate_tenancy`], decided **without** the acting
/// agent's group.
///
/// `Ok(Some(g))` — the merge is group-visible and owned by `g`.
/// `Ok(None)`    — every source is public, so the owner is the actor's own
///                 group and the caller must resolve it.
/// `Err(..)`     — the sources span two or more groups; refuse.
///
/// Split out so a caller can take the **refusal decision before doing any
/// work**. `ClaimRepository::consolidate` needs it: resolving the actor's
/// personal group is a database round trip that can MINT a row, and a merge
/// that is going to be refused must not pay for it — nor leave a `groups`
/// insert behind in a transaction it then rolls back. Keeping this as the
/// single implementation, with `consolidate_tenancy` a thin wrapper, is what
/// stops the two answers from drifting.
///
/// # Errors
///
/// Returns [`ConsolidateTenancyError::CrossGroup`] when the group-visible
/// sources are owned by more than one group.
pub fn consolidate_owner(
    sources: &[SourceTenancy],
) -> Result<Option<Uuid>, ConsolidateTenancyError> {
    let mut owners: Vec<Uuid> = sources
        .iter()
        .filter(|(_, v)| *v == Visibility::Group)
        .map(|(g, _)| *g)
        .collect();
    owners.sort_unstable();
    owners.dedup();

    match owners.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(*only)),
        [a, b, ..] => Err(ConsolidateTenancyError::CrossGroup { groups: (*a, *b) }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    #[test]
    fn visibility_round_trips_and_rejects_everything_else() {
        for v in [Visibility::Public, Visibility::Group] {
            assert_eq!(Visibility::from_db_str(v.as_str()), Some(v));
        }
        // The three spellings a careless writer reaches for. `private` is the
        // one that matters: it reads as stricter and would be silently accepted
        // by a `from_db_str` that fell back to a default.
        for bad in ["private", "PUBLIC", "", "world", "anonymous"] {
            assert_eq!(
                Visibility::from_db_str(bad),
                None,
                "{bad:?} must not parse — an unrecognised visibility has to fail, not \
                 land on a value nobody chose"
            );
        }
    }

    #[test]
    fn instance_wide_is_public_over_world_and_never_group() {
        let d = TenancyDecl::instance_wide();
        assert_eq!(d.visibility_bind(), Some("public"));
        assert_eq!(d.owner_group_bind(), Some(WORLD_GROUP));
        // ('group', world) is the black hole migration 062's
        // <table>_group_needs_real_group CHECK forbids. No constructor may
        // produce it, so if this ever fails the constructor has been widened
        // into the one shape the schema rejects.
        assert!(!matches!(
            d,
            TenancyDecl::Declared {
                visibility: Visibility::Group,
                owner_group_id: WORLD_GROUP
            }
        ));
    }

    #[test]
    fn the_world_group_constant_matches_the_migrations_literal() {
        // Six migration files carry this uuid as a literal. A mismatch here
        // would not fail to compile and would not fail any type check — it
        // would silently create a SECOND ownerless group that no policy,
        // CHECK or acceptance query knows about.
        assert_eq!(
            WORLD_GROUP.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn inherited_binds_null_and_declared_binds_both() {
        assert_eq!(TenancyDecl::inherited().visibility_bind(), None);
        assert_eq!(TenancyDecl::inherited().owner_group_bind(), None);
        assert!(!TenancyDecl::inherited().is_declared());

        let d = TenancyDecl::group(g(7));
        assert_eq!(d.visibility_bind(), Some("group"));
        assert_eq!(d.owner_group_bind(), Some(g(7)));
        assert!(d.is_declared());

        // A public declaration still carries a real owner — that is the whole
        // point of the pair, and a bind that dropped it would recreate the
        // world-owned corpus §8.2 A4 exists to forbid.
        assert_eq!(TenancyDecl::public(g(3)).owner_group_bind(), Some(g(3)));
    }

    // ---- consolidate's meet rule (plan §4.6, §8.1) ----

    #[test]
    fn all_public_sources_merge_public_into_the_actors_own_group() {
        let out = consolidate_tenancy(
            &[(g(1), Visibility::Public), (g(2), Visibility::Public)],
            g(9),
        )
        .expect("all-public never refuses");
        assert_eq!(out, TenancyDecl::public(g(9)));
    }

    #[test]
    fn any_group_source_makes_the_merge_group_visible() {
        // The asymmetry that matters: mixing one private source with a public
        // one yields a PRIVATE merge. The other direction would be a
        // one-statement declassification of the private source's content.
        let out = consolidate_tenancy(
            &[(g(1), Visibility::Public), (g(5), Visibility::Group)],
            g(9),
        )
        .expect("single group owner");
        assert_eq!(out, TenancyDecl::group(g(5)));
    }

    #[test]
    fn a_public_source_does_not_contribute_an_owner() {
        // g(1) is public and "owned" by group 1; g(5) is the only group-visible
        // source. If public sources contributed owners this would refuse as
        // cross-group, blocking a merge that discloses nothing.
        let out = consolidate_tenancy(
            &[(g(1), Visibility::Public), (g(5), Visibility::Group)],
            g(9),
        );
        assert_eq!(out, Ok(TenancyDecl::group(g(5))));
    }

    #[test]
    fn same_group_sources_merge_into_that_group() {
        let out = consolidate_tenancy(
            &[(g(4), Visibility::Group), (g(4), Visibility::Group)],
            g(9),
        )
        .expect("one distinct owner");
        assert_eq!(out, TenancyDecl::group(g(4)));
    }

    #[test]
    fn two_different_group_owners_are_refused_not_resolved() {
        let err = consolidate_tenancy(
            &[(g(4), Visibility::Group), (g(6), Visibility::Group)],
            g(9),
        )
        .expect_err("cross-group must refuse");
        assert_eq!(
            err,
            ConsolidateTenancyError::CrossGroup {
                groups: (g(4), g(6))
            }
        );
        // The PAIR lives on the structured variant, asserted above. The
        // RENDERED message must name NEITHER group: it is returned to the
        // caller as a 409, and `consolidate` refuses cross-group merges without
        // requiring the caller to be able to read either source — so a message
        // carrying the owner UUIDs would be an oracle over the private
        // ownership graph. Operators get the pair from the repo's `warn!`.
        let msg = err.to_string();
        assert!(
            !msg.contains(&g(4).to_string()) && !msg.contains(&g(6).to_string()),
            "the rendered 409 must not disclose either owner group: {msg}"
        );
        assert!(msg.contains("owned by more than one group"));
    }

    #[test]
    fn the_refusal_is_order_independent() {
        // Sorted before comparison, so the same merge refused from either
        // direction reports the same pair — otherwise a retry would produce a
        // different error string for the same defect.
        let a = consolidate_tenancy(
            &[(g(6), Visibility::Group), (g(4), Visibility::Group)],
            g(9),
        );
        let b = consolidate_tenancy(
            &[(g(4), Visibility::Group), (g(6), Visibility::Group)],
            g(9),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn consolidate_owner_and_consolidate_tenancy_never_disagree() {
        // The wrapper is thin by construction, but "thin" is a property of the
        // current body and not of the contract. `ClaimRepository::consolidate`
        // takes the REFUSAL from `consolidate_owner` and the VALUE from a
        // reconstruction of it, so a divergence would refuse one merge and
        // silently mis-own another.
        let actor = g(9);
        for sources in [
            vec![],
            vec![(g(1), Visibility::Public)],
            vec![(g(1), Visibility::Public), (g(5), Visibility::Group)],
            vec![(g(5), Visibility::Group), (g(5), Visibility::Group)],
            vec![(g(4), Visibility::Group), (g(6), Visibility::Group)],
        ] {
            let via_owner = consolidate_owner(&sources).map(|o| match o {
                Some(gr) => TenancyDecl::group(gr),
                None => TenancyDecl::public(actor),
            });
            assert_eq!(
                via_owner,
                consolidate_tenancy(&sources, actor),
                "{sources:?}"
            );
        }
    }

    #[test]
    fn an_empty_source_set_falls_back_to_the_actor() {
        // Not reachable through `ClaimRepository::consolidate` (it enforces
        // 2..=N sources before this is called), but the rule must still be
        // total: a partial function here would be a panic on a path that only
        // exists because of a validation the caller could later relax.
        assert_eq!(
            consolidate_tenancy(&[], g(9)),
            Ok(TenancyDecl::public(g(9)))
        );
    }
}
