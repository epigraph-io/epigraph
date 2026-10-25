//! **Claim roles**, decided by `decomposes_to` structure, and the
//! viewer-spliced **leaf closure** a compound is derived over (atom-level
//! belief program; SPEC §2.1 roles, §2.2 spine, §8 T1/T4 tenancy).
//!
//! "Compound" is a role in the edge graph, not an attribute of the claim. The
//! role is decided in this order, over in-force edges
//! ([`super::edge::EDGE_IN_FORCE`]) and current claims:
//!
//! | role | predicate |
//! |---|---|
//! | [`ClaimRole::Procedural`] | the claim, or an ancestor at most [`ROLE_MAX_DEPTH`] `decomposes_to` hops above it, is a ROOT (no in-force `decomposes_to` in-edge from a current claim), reached over in-force edges from current parents, and stamped as a workflow tree (`properties.source_type = 'workflow'` on a root AUTHORED by the registered `workflow-ingest` system agent; the property alone is caller-set); and no root the walk reaches is unstamped. A git-history tree is not procedural while its marker is pending |
//! | [`ClaimRole::Rule`] | labelled `rule` AND an in-force `rule_conclusion` out-edge to a current claim |
//! | [`ClaimRole::Compound`] | an in-force `decomposes_to` out-edge to a current claim |
//! | [`ClaimRole::Atom`] | an in-force `decomposes_to` in-edge from a current claim, and none out |
//! | [`ClaimRole::Standalone`] | no in-force `decomposes_to` in either direction |
//!
//! # ONE spelling
//!
//! [`IS_COMPOUND_SQL`], [`IS_PROCEDURAL_SQL`] and [`CLAIM_ROLE_SQL`] are the
//! only SQL spellings of these predicates, with the same contract as
//! `claim.rs::EFFECTIVE_BELIEF_SCORE_SQL`: a reader that needs to know whether
//! a claim is a compound splices one of them through [`is_compound_sql`] /
//! [`is_procedural_sql`] / [`claim_role_sql`], never a copy. All three are
//! assembled from the same fragments, so `IS_COMPOUND(c)` holds exactly when
//! `CLAIM_ROLE(c) = 'compound'` and `IS_PROCEDURAL(c)` exactly when it is
//! `'procedural'`. [`roles_batch`] is their Rust twin and reads
//! [`CLAIM_ROLE_SQL`] itself.
//!
//! # Role is structure; the leaf closure is spliced
//!
//! * **Deciding a role carries no viewer splice.** A compound's fan-out is a
//!   structural fact, and a viewer that cannot see a decomposition must not
//!   be able to make a compound look like an atom (and so, for example, get
//!   its cache refolded for everyone). That holds as written on a connection
//!   that bypasses row security (the maintenance pool and session, where the
//!   bulk writers run). `edges` and `claims` are FORCE ROW LEVEL SECURITY, so
//!   on an application connection the server still filters these reads, and
//!   a session that can see none of a compound's in-force decomposition
//!   edges finds no compound. Closing that gap would take a definer-rights
//!   function (a migration), which this module deliberately does not add:
//!   the role predicate is code only.
//! * **The leaf closure is spliced** on both `edges` (`EDGE_VISIBILITY`) and
//!   `claims` (`VISIBILITY`), because a compound's derived value served to a
//!   viewer may use only the leaves that viewer can read (§8 T1). A leaf is
//!   a visible node with no visible outgoing `decomposes_to`, so for a
//!   viewer who sees none of a mid node's decomposition, that mid node is a
//!   leaf (see [`leaf_closure_batch`]).
//! * **Spine counts visible leaves.** Whether a compound is served a profile
//!   instead of a conjunction depends on how many leaves the viewer can see
//!   (§8 T4), so the spine flag never reveals a hidden leaf count.
//!
//! # The `$alias` placeholder
//!
//! The three templates read only `$alias.id` and `$alias.labels` of a
//! `claims` row the caller has in scope. Every alias they introduce starts
//! with `role_`, and [`render`] refuses a caller alias with that prefix, so
//! `$alias` can never be captured by an inner `edges` or `claims` row. The
//! templates bind no parameters.

use std::collections::HashMap;

use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// The placeholder [`IS_COMPOUND_SQL`], [`IS_PROCEDURAL_SQL`] and
/// [`CLAIM_ROLE_SQL`] carry for the caller's `claims` alias.
pub const ALIAS_PLACEHOLDER: &str = "$alias";

/// The prefix every alias inside the role templates carries. A caller alias
/// may not start with it.
const INTERNAL_ALIAS_PREFIX: &str = "role_";

/// How many `decomposes_to` hops a role or closure walk takes: up, to find a
/// procedural root, and down, to find leaves. Manual `link_hierarchical` can
/// create cycles, so every walk is capped.
pub const ROLE_MAX_DEPTH: i32 = 6;

/// A compound with MORE than this many visible flattened leaves is spine
/// (served a profile, never a conjunction), whatever its level.
pub const SPINE_LEAF_CAP: usize = 16;

/// [`ROLE_MAX_DEPTH`] as an SQL literal, so the templates stay `const`.
/// `role_max_depth_literal_matches_the_constant` pins the two together.
macro_rules! role_max_depth {
    () => {
        "6"
    };
}

/// An in-force `decomposes_to` OUT-edge from `$alias` to a current claim.
macro_rules! has_decomposition {
    () => {
        "EXISTS (SELECT 1 FROM edges role_out \
           JOIN claims role_child ON role_child.id = role_out.target_id \
          WHERE role_out.source_id = $alias.id \
            AND role_out.source_type = 'claim' \
            AND role_out.target_type = 'claim' \
            AND role_out.relationship = 'decomposes_to' \
            AND (role_out.valid_to IS NULL OR role_out.valid_to > now()) \
            AND COALESCE(role_child.is_current, true))"
    };
}

/// An in-force `decomposes_to` IN-edge to the claim id `$col` from a current
/// claim. Its negation is the ONE root test: a claim is the root of its tree
/// exactly when no current claim decomposes into it over an in-force edge.
macro_rules! decomposed_from {
    ($col:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM edges role_in \
               JOIN claims role_parent ON role_parent.id = role_in.source_id \
              WHERE role_in.target_id = ",
            $col,
            " AND role_in.source_type = 'claim' \
                AND role_in.target_type = 'claim' \
                AND role_in.relationship = 'decomposes_to' \
                AND (role_in.valid_to IS NULL OR role_in.valid_to > now()) \
                AND COALESCE(role_parent.is_current, true))"
        )
    };
}

/// An in-force `decomposes_to` IN-edge to `$alias` from a current claim.
macro_rules! is_decomposed_from {
    () => {
        decomposed_from!("$alias.id")
    };
}

/// The procedural root stamp, over the `claims` row aliased `$root`: a
/// workflow tree's root, i.e. a claim stamped `source_type: workflow` (the
/// workflow builder stamps its thesis) AND authored by the registered
/// `workflow-ingest` system agent (migration 148's `system_agents`).
///
/// `properties` is caller-set: `PATCH /api/v1/claims/:id` merges any keys, so
/// the property alone would let any author opt its own tree, and any claim it
/// can attach beneath that root, out of the atom program. The author is not
/// caller-set: the operator binding (migration 122) binds an application
/// session's author to its caller, and nothing but the workflow ingest path
/// authors as the system agent.
///
/// A git-history tree (`ingest_git`) is NOT procedural until its marker is
/// ruled (SPEC §2.1, "marker pending"): its `source` / `node` properties are
/// caller-set too, and no system role writes it. Never NULL, so its negation
/// is "unstamped" on a claim with no stamp.
macro_rules! procedural_root_stamp {
    ($root:literal) => {
        concat!(
            "COALESCE(",
            $root,
            ".properties->>'source_type' = 'workflow' AND ",
            $root,
            ".agent_id IN (SELECT role_sa.agent_id FROM system_agents role_sa \
                            WHERE role_sa.role = 'workflow-ingest'), false)"
        )
    };
}

/// `$alias`, or an ancestor at most [`ROLE_MAX_DEPTH`] in-force
/// `decomposes_to` hops above it, is a root carrying the procedural stamp, AND
/// no root the walk reaches is unstamped. The walk climbs only to CURRENT
/// parents, and "root" is the one root test (`decomposed_from!` negated), so a
/// superseded parent neither hides a stamped root below it nor lends its own
/// stamp to the claims under it. A cycle or a deeper tree finds no root, so
/// the claim is not procedural.
///
/// Every root above the claim must be stamped because decomposition is a
/// DAG and the stamp is a caller-set property: were one stamped root enough,
/// a single edge from a stamped claim onto a node of an ordinary tree would
/// make that node and its subtree procedural for every reader. What this
/// cannot tell apart is a stamped claim attached above an ordinary ROOT: that
/// root then has an in-edge, and the stamped claim is the only root left.
macro_rules! is_procedural {
    () => {
        concat!(
            "EXISTS (WITH RECURSIVE role_up(id, depth) AS ( \
                 SELECT $alias.id, 0 \
                 UNION \
                 SELECT role_ue.source_id, role_up.depth + 1 \
                   FROM role_up \
                   JOIN edges role_ue ON role_ue.target_id = role_up.id \
                   JOIN claims role_upc ON role_upc.id = role_ue.source_id \
                  WHERE role_ue.relationship = 'decomposes_to' \
                    AND role_ue.source_type = 'claim' \
                    AND role_ue.target_type = 'claim' \
                    AND (role_ue.valid_to IS NULL OR role_ue.valid_to > now()) \
                    AND COALESCE(role_upc.is_current, true) \
                    AND role_up.depth < ",
            role_max_depth!(),
            ") \
             SELECT 1 FROM role_up \
               JOIN claims role_root ON role_root.id = role_up.id \
              WHERE ",
            procedural_root_stamp!("role_root"),
            " AND NOT ",
            decomposed_from!("role_up.id"),
            " AND NOT EXISTS (SELECT 1 FROM role_up role_uo \
                                JOIN claims role_oroot ON role_oroot.id = role_uo.id \
                               WHERE NOT ",
            procedural_root_stamp!("role_oroot"),
            " AND NOT ",
            decomposed_from!("role_uo.id"),
            "))"
        )
    };
}

/// Labelled `rule` with an in-force `rule_conclusion` out-edge to a current
/// claim.
macro_rules! is_rule {
    () => {
        "($alias.labels @> ARRAY['rule']::text[] \
          AND EXISTS (SELECT 1 FROM edges role_rc \
                        JOIN claims role_concl ON role_concl.id = role_rc.target_id \
                       WHERE role_rc.source_id = $alias.id \
                         AND role_rc.source_type = 'claim' \
                         AND role_rc.target_type = 'claim' \
                         AND role_rc.relationship = 'rule_conclusion' \
                         AND (role_rc.valid_to IS NULL OR role_rc.valid_to > now()) \
                         AND COALESCE(role_concl.is_current, true)))"
    };
}

/// A boolean SQL expression over the `claims` row `$alias`: TRUE exactly when
/// [`CLAIM_ROLE_SQL`] is `'procedural'`. Never NULL. Render it with
/// [`is_procedural_sql`].
pub const IS_PROCEDURAL_SQL: &str = concat!("(", is_procedural!(), ")");

/// A boolean SQL expression over the `claims` row `$alias`: TRUE exactly when
/// [`CLAIM_ROLE_SQL`] is `'compound'` (an in-force `decomposes_to` out-edge to
/// a current claim, and neither procedural nor a rule). Never NULL. Render it
/// with [`is_compound_sql`].
pub const IS_COMPOUND_SQL: &str = concat!(
    "(",
    has_decomposition!(),
    " AND NOT ",
    is_procedural!(),
    " AND NOT ",
    is_rule!(),
    ")"
);

/// A text SQL expression over the `claims` row `$alias`: one of
/// `'procedural'`, `'rule'`, `'compound'`, `'atom'`, `'standalone'`, decided
/// in that order. Never NULL. Render it with [`claim_role_sql`].
pub const CLAIM_ROLE_SQL: &str = concat!(
    "(CASE WHEN ",
    is_procedural!(),
    " THEN 'procedural' WHEN ",
    is_rule!(),
    " THEN 'rule' WHEN ",
    has_decomposition!(),
    " THEN 'compound' WHEN ",
    is_decomposed_from!(),
    " THEN 'atom' ELSE 'standalone' END)"
);

/// Substitute `alias` for [`ALIAS_PLACEHOLDER`] in one of this module's
/// templates.
///
/// # Panics
///
/// When `template` carries no placeholder, when `alias` is not a plain SQL
/// identifier, or when it starts with the templates' internal `role_` prefix
/// (an inner row would capture it). All three are programming errors on a
/// literal the caller wrote.
#[must_use]
pub fn render(template: &str, alias: &str) -> String {
    assert!(
        template.contains(ALIAS_PLACEHOLDER),
        "claim-role template has no {ALIAS_PLACEHOLDER} placeholder:\n{template}"
    );
    assert!(
        !alias.is_empty()
            && alias
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !alias.starts_with(|ch: char| ch.is_ascii_digit()),
        "claim-role alias {alias:?} is not a plain SQL identifier"
    );
    assert!(
        !alias.starts_with(INTERNAL_ALIAS_PREFIX),
        "claim-role alias {alias:?} uses the templates' internal \
         {INTERNAL_ALIAS_PREFIX:?} prefix and would be captured by an inner row"
    );
    template.replace(ALIAS_PLACEHOLDER, alias)
}

/// [`IS_COMPOUND_SQL`] over the `claims` row `alias`.
#[must_use]
pub fn is_compound_sql(alias: &str) -> String {
    render(IS_COMPOUND_SQL, alias)
}

/// [`IS_PROCEDURAL_SQL`] over the `claims` row `alias`.
#[must_use]
pub fn is_procedural_sql(alias: &str) -> String {
    render(IS_PROCEDURAL_SQL, alias)
}

/// [`CLAIM_ROLE_SQL`] over the `claims` row `alias`.
#[must_use]
pub fn claim_role_sql(alias: &str) -> String {
    render(CLAIM_ROLE_SQL, alias)
}

/// A claim's role (SPEC §2.1). The Rust twin of [`CLAIM_ROLE_SQL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimRole {
    /// A decomposition target with no decomposition of its own: belief from
    /// its own evidence.
    Atom,
    /// No decomposition in either direction: a provisional atom.
    Standalone,
    /// Has a decomposition: its belief is a query over its leaves. `spine`
    /// when it is a thesis or section (`properties.level` 0 or 1) or has more
    /// than [`SPINE_LEAF_CAP`] leaves the viewer can see; a spine compound is
    /// served a profile, never a conjunction.
    Compound { spine: bool },
    /// A node of a workflow tree rooted at a claim the registered
    /// `workflow-ingest` system agent authored: out of scope, today's
    /// behaviour.
    Procedural,
    /// A rule claim (label `rule` and a `rule_conclusion` edge).
    Rule,
}

impl ClaimRole {
    /// The value [`CLAIM_ROLE_SQL`] gives for this role.
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::Atom => "atom",
            Self::Standalone => "standalone",
            Self::Compound { .. } => "compound",
            Self::Procedural => "procedural",
            Self::Rule => "rule",
        }
    }

    fn from_sql(role: &str, spine: bool) -> Option<Self> {
        Some(match role {
            "atom" => Self::Atom,
            "standalone" => Self::Standalone,
            "compound" => Self::Compound { spine },
            "procedural" => Self::Procedural,
            "rule" => Self::Rule,
            _ => return None,
        })
    }
}

/// The viewer-spliced leaf walk, as a pair of CTEs `role_walk(root, node,
/// depth)` and `role_leaf(root, node)`, seeded by `$seed`: a `SELECT` of
/// `(root, root, 0)` over the requested ids the viewer can read. Shared by
/// [`leaf_closure_batch`] and [`roles_batch`] so both count the same leaves;
/// each passes the spliced seed from its own body, where
/// `tests/visibility_lint.rs` reads its marker.
///
/// * Only in-force `decomposes_to` edges between claims, to current claims,
///   that the viewer can read (edge AND target claim).
/// * The walk terminates by the depth cap, not by a visited set: the
///   recursive `UNION` over `(root, node, depth)` drops a row only when the
///   same node is reached again at the SAME depth, so a cycle is re-expanded
///   at each greater depth until [`ROLE_MAX_DEPTH`]. That bounds the walk to
///   at most (nodes reached) x 7 rows per root; a per-path visited array
///   would instead grow with the number of paths through a DAG.
/// * A leaf is a node below the root with no out-edge the walk could take
///   (in force, to a current claim, edge AND child visible): the walk's step
///   condition, negated. A node at the depth cap that still has children is
///   not a leaf, and its subtree is not reached.
/// * `role_leaf` is `DISTINCT`: a leaf reached along several paths, or at
///   several depths, is listed once.
macro_rules! leaf_walk_ctes {
    ($seed:literal) => {
        concat!(
            "WITH RECURSIVE role_walk(root, node, depth) AS ( ",
            $seed,
            " UNION \
                 SELECT role_w.root, role_d.target_id, role_w.depth + 1 \
                   FROM role_walk role_w \
                   JOIN edges role_d ON role_d.source_id = role_w.node \
                   JOIN claims role_c ON role_c.id = role_d.target_id \
                  WHERE role_d.relationship = 'decomposes_to' \
                    AND role_d.source_type = 'claim' \
                    AND role_d.target_type = 'claim' \
                    AND (role_d.valid_to IS NULL OR role_d.valid_to > now()) \
                    AND COALESCE(role_c.is_current, true) \
                    AND role_w.depth < ",
            role_max_depth!(),
            " /* {EDGE_VISIBILITY:role_d} */ /* {VISIBILITY:role_c} */ \
             ), \
             role_leaf AS ( \
                 SELECT DISTINCT role_lw.root, role_lw.node \
                   FROM role_walk role_lw \
                  WHERE role_lw.depth > 0 \
                    AND NOT EXISTS ( \
                        SELECT 1 FROM edges role_x \
                          JOIN claims role_xc ON role_xc.id = role_x.target_id \
                         WHERE role_x.source_id = role_lw.node \
                           AND role_x.relationship = 'decomposes_to' \
                           AND role_x.source_type = 'claim' \
                           AND role_x.target_type = 'claim' \
                           AND (role_x.valid_to IS NULL OR role_x.valid_to > now()) \
                           AND COALESCE(role_xc.is_current, true) \
                           /* {EDGE_VISIBILITY:role_x} */ /* {VISIBILITY:role_xc} */) \
             ) "
        )
    };
}

/// The visible leaves of each requested claim (SPEC §2.1).
///
/// Every requested id the viewer can read gets an entry: the ids of the
/// claims strictly below it that the walk reaches and that have no further
/// visible decomposition, sorted and deduplicated. A claim with no visible
/// decomposition (an atom, a standalone, or a compound whose children are all
/// hidden from this viewer) gets an empty list. An id the viewer cannot read
/// is absent, the batch-read convention.
///
/// A mid node whose decomposition the viewer can see is never in its
/// parent's list: a compound is derived over its own flattened leaves, never
/// composed from its children's values, which would count a shared leaf
/// twice. A visible node whose WHOLE decomposition is hidden from the viewer
/// has no visible out-edge, so it IS listed as a leaf for that viewer (SPEC
/// §2.1), while its role ([`roles_batch`], unspliced) stays
/// [`ClaimRole::Compound`]; a consumer that folds leaves must not fold such a
/// node's own rows as if it were an atom.
///
/// A claim the viewer cannot read behind an edge it can read is simply
/// absent: the map carries no count of such claims, so a derivation that must
/// treat them as vacuous conjuncts (SPEC §8 T1) has to count them itself.
///
/// # Errors
/// Returns [`DbError::QueryFailed`] if the query fails.
#[instrument(skip(executor, viewer, ids), fields(n = ids.len()))]
pub async fn leaf_closure_batch<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    viewer: &Viewer,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<Uuid>>, DbError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = viewer.splice(
        concat!(
            leaf_walk_ctes!(
                "SELECT role_seed.id, role_seed.id, 0 \
                   FROM claims role_seed \
                  WHERE role_seed.id = ANY($1) /* {VISIBILITY:role_seed} */"
            ),
            "SELECT role_s.root, \
                    COALESCE(array_agg(role_l.node ORDER BY role_l.node) \
                             FILTER (WHERE role_l.node IS NOT NULL), \
                             ARRAY[]::uuid[]) AS leaves \
               FROM role_walk role_s \
               LEFT JOIN role_leaf role_l ON role_l.root = role_s.root \
              WHERE role_s.depth = 0 \
              GROUP BY role_s.root"
        ),
        2,
    );
    let mut q = sqlx::query_as::<_, (Uuid, Vec<Uuid>)>(&sql).bind(ids);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    Ok(q.fetch_all(executor).await?.into_iter().collect())
}

/// The role of each requested claim the viewer can read (SPEC §2.1); an id the
/// viewer cannot read is absent.
///
/// The role itself is [`CLAIM_ROLE_SQL`] and carries no splice (see the module
/// doc). For a compound, `spine` is decided over the viewer's visible leaves:
/// `properties.level` 0 or 1, or more than [`SPINE_LEAF_CAP`] visible
/// flattened leaves.
///
/// # Errors
/// Returns [`DbError::QueryFailed`] if the query fails, and
/// [`DbError::InvalidData`] if the role expression yields a value this enum
/// does not know (it cannot, while both are spelled here).
#[instrument(skip(executor, viewer, ids), fields(n = ids.len()))]
pub async fn roles_batch<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    viewer: &Viewer,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, ClaimRole>, DbError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    // The role is CLAIM_ROLE_SQL over the requested row (no splice: role is
    // structure); the spine count is over the viewer-spliced leaf walk.
    let sql = viewer.splice(
        &[
            concat!(
                leaf_walk_ctes!(
                    "SELECT role_seed.id, role_seed.id, 0 \
                       FROM claims role_seed \
                      WHERE role_seed.id = ANY($1) /* {VISIBILITY:role_seed} */"
                ),
                "SELECT c.id, "
            ),
            &claim_role_sql("c"),
            " AS role, \
             COALESCE((c.properties->>'level') IN ('0', '1'), false) AS spine_level, \
             (SELECT count(*) FROM role_leaf role_n WHERE role_n.root = c.id) AS visible_leaves \
             FROM claims c \
             WHERE c.id = ANY($1) /* {VISIBILITY:c} */",
        ]
        .concat(),
        2,
    );
    let mut q = sqlx::query_as::<_, (Uuid, String, bool, i64)>(&sql).bind(ids);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    let rows = q.fetch_all(executor).await?;
    let mut out = HashMap::with_capacity(rows.len());
    for (id, role, spine_level, visible_leaves) in rows {
        let over_cap = usize::try_from(visible_leaves).unwrap_or(usize::MAX) > SPINE_LEAF_CAP;
        let role = ClaimRole::from_sql(&role, spine_level || over_cap).ok_or_else(|| {
            DbError::InvalidData {
                reason: format!("claim {id} has unknown role {role:?}"),
            }
        })?;
        out.insert(id, role);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_max_depth_literal_matches_the_constant() {
        assert_eq!(role_max_depth!().parse::<i32>().unwrap(), ROLE_MAX_DEPTH);
    }

    /// `concat!` cannot interpolate [`super::super::edge::EDGE_IN_FORCE`], so
    /// the templates spell the in-force test by hand. Every spelling must be
    /// exactly `EDGE_IN_FORCE` over its own alias, and no other `valid_to`
    /// test may appear, so a change to the shared predicate turns this red
    /// instead of leaving role and closure reads on the old rule.
    #[test]
    fn every_in_force_spelling_is_edge_in_force_over_its_alias() {
        use super::super::edge::EDGE_IN_FORCE;
        let leaf_walk = leaf_walk_ctes!("SELECT 1, 1, 0");
        let mut aliases = std::collections::BTreeSet::new();
        for (name, t) in [
            ("IS_COMPOUND_SQL", IS_COMPOUND_SQL),
            ("IS_PROCEDURAL_SQL", IS_PROCEDURAL_SQL),
            ("CLAIM_ROLE_SQL", CLAIM_ROLE_SQL),
            ("leaf_walk_ctes", leaf_walk),
        ] {
            let needle = ".valid_to IS NULL";
            let mut checked = 0;
            for (at, _) in t.match_indices(needle) {
                let start = t[..at]
                    .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                    .map_or(0, |i| i + 1);
                let alias = &t[start..at];
                let expected = EDGE_IN_FORCE.replace("e.", &format!("{alias}."));
                assert!(
                    t[start.saturating_sub(1)..].starts_with(&expected),
                    "{name}: the in-force test over {alias:?} is not EDGE_IN_FORCE \
                     ({expected}) in:\n{t}"
                );
                aliases.insert(alias.to_string());
                checked += 1;
            }
            assert!(checked > 0, "{name} has no in-force test");
            assert_eq!(
                t.matches("valid_to").count(),
                2 * checked,
                "{name} tests valid_to outside an EDGE_IN_FORCE spelling:\n{t}"
            );
        }
        // Every edge alias the templates walk is covered.
        for alias in [
            "role_out", "role_in", "role_ue", "role_rc", "role_d", "role_x",
        ] {
            assert!(aliases.contains(alias), "no in-force test over {alias}");
        }
    }

    #[test]
    fn every_template_carries_the_placeholder_and_no_bind() {
        for t in [IS_COMPOUND_SQL, IS_PROCEDURAL_SQL, CLAIM_ROLE_SQL] {
            assert!(t.contains(ALIAS_PLACEHOLDER));
            let rendered = render(t, "c");
            assert!(
                !rendered.contains('$'),
                "a template binds nothing: {rendered}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "internal")]
    fn an_internal_alias_is_refused() {
        let _ = render(IS_COMPOUND_SQL, "role_out");
    }

    #[test]
    #[should_panic(expected = "not a plain SQL identifier")]
    fn a_non_identifier_alias_is_refused() {
        let _ = render(IS_COMPOUND_SQL, "c.id");
    }

    #[test]
    fn every_role_round_trips_through_its_sql_name() {
        for role in [
            ClaimRole::Atom,
            ClaimRole::Standalone,
            ClaimRole::Compound { spine: true },
            ClaimRole::Compound { spine: false },
            ClaimRole::Procedural,
            ClaimRole::Rule,
        ] {
            let spine = matches!(role, ClaimRole::Compound { spine: true });
            assert_eq!(ClaimRole::from_sql(role.as_sql(), spine), Some(role));
        }
        assert_eq!(ClaimRole::from_sql("leaf", false), None);
    }
}
