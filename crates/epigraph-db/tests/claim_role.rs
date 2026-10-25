//! Claim roles and the viewer-spliced leaf closure (atom-level belief
//! program, PR-2; SPEC §2.1 roles, §2.2 spine, §8 T1/T4 tenancy).
//!
//! A claim's role is decided by `decomposes_to` structure, in the order
//! procedural, rule, compound, atom (leaf), standalone. A compound's value is
//! later derived over its FLATTENED leaves, never over its children, so the
//! leaf closure is the input every derived reader will share; it must
//!
//! * flatten (a mid node is a compound, never a leaf of its parent, unless
//!   its whole decomposition is hidden from the viewer),
//! * terminate on a manual cycle and never list a leaf twice,
//! * stop at 6 hops,
//! * see only the edges AND the claims the viewer can read.
//!
//! The role itself is structure and is not spliced; whether a compound is
//! "spine" (served a profile instead of a conjunction) depends on how many
//! leaves the VIEWER can see, so it never discloses a hidden leaf count.
//!
//! Every expectation here is a set of fixture ids chosen by construction (the
//! shape of the tree), never a value computed by the code under test.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use epigraph_db::repos::claim_role::{self, ClaimRole};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;

// ── seeding ────────────────────────────────────────────────────────────────

struct Seed {
    agent: Uuid,
    world: Uuid,
}

async fn seed(pool: &PgPool) -> Seed {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'claim-role', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent");
    plant_workflow_ingest_agent(pool, agent).await;
    Seed {
        agent,
        world: fixture::world_group(pool).await,
    }
}

/// Register `agent` as the `workflow-ingest` system agent (migration 148), the
/// only author whose `source_type: workflow` root stamp makes a tree
/// procedural. Planted directly, with triggers off, so the registry's own
/// definer (which this test does not exercise) is not in the way. One plant
/// per test database: the role is the registry's primary key.
async fn plant_workflow_ingest_agent(pool: &PgPool, agent: Uuid) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    let planted = sqlx::query(
        "INSERT INTO public.system_agents (role, agent_id, registered_public_key, reason) \
         SELECT 'workflow-ingest', a.id, a.public_key, 'claim-role test plant' \
           FROM public.agents a WHERE a.id = $1",
    )
    .bind(agent)
    .execute(&mut *tx)
    .await
    .expect("plant the workflow-ingest system agent");
    assert_eq!(planted.rows_affected(), 1);
    tx.commit().await.expect("commit");
}

/// A second author, NOT the registered system agent, writing into the same
/// world group as `s`.
async fn stranger(pool: &PgPool, s: &Seed) -> Seed {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'claim-role stranger', 'ai', \
                 ARRAY['test']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed stranger");
    Seed {
        agent,
        world: s.world,
    }
}

/// A claim with explicit tenancy, `properties` and `labels`.
async fn claim_full(
    pool: &PgPool,
    s: &Seed,
    what: &str,
    properties: serde_json::Value,
    labels: &[&str],
    owner_group: Option<Uuid>,
    is_current: bool,
) -> Uuid {
    let content = format!("{what} {}", Uuid::new_v4());
    let (visibility, group) = match owner_group {
        Some(g) => ("group", g),
        None => ("public", s.world),
    };
    let labels: Vec<String> = labels.iter().map(|l| (*l).to_string()).collect();
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             properties, labels, visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(&content)
    .bind(s.agent)
    .bind(is_current)
    .bind(properties)
    .bind(&labels)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn claim(pool: &PgPool, s: &Seed, what: &str) -> Uuid {
    claim_full(pool, s, what, serde_json::json!({}), &[], None, true).await
}

async fn claim_with(pool: &PgPool, s: &Seed, what: &str, properties: serde_json::Value) -> Uuid {
    claim_full(pool, s, what, properties, &[], None, true).await
}

/// An edge `source -> target` of `relationship`, tenancy as the trigger
/// stamps it from the endpoints; `retired` puts it out of force.
async fn edge(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    relationship: &str,
    retired: bool,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from, valid_to) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, \
                 now() - interval '2 days', \
                 CASE WHEN $4 THEN now() - interval '1 day' END) \
         RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .bind(retired)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid) -> Uuid {
    edge(pool, parent, child, "decomposes_to", false).await
}

/// Force an edge's own tenancy columns (the trigger fires only on endpoint
/// changes, so this UPDATE sticks); see `viewer_fixture::seed_edge_owned_by`.
async fn force_edge_tenancy(pool: &PgPool, edge: Uuid, visibility: &str, group: Uuid) {
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

// ── reading ────────────────────────────────────────────────────────────────

/// Run a closure read with a hard timeout: a closure that fails to terminate
/// on a cycle must fail this test, not hang the suite.
async fn closure(pool: &PgPool, viewer: &Viewer, ids: &[Uuid]) -> HashMap<Uuid, Vec<Uuid>> {
    tokio::time::timeout(
        Duration::from_secs(30),
        claim_role::leaf_closure_batch(pool, viewer, ids),
    )
    .await
    .expect("leaf_closure_batch must terminate")
    .expect("leaf_closure_batch")
}

async fn roles(pool: &PgPool, viewer: &Viewer, ids: &[Uuid]) -> HashMap<Uuid, ClaimRole> {
    tokio::time::timeout(
        Duration::from_secs(30),
        claim_role::roles_batch(pool, viewer, ids),
    )
    .await
    .expect("roles_batch must terminate")
    .expect("roles_batch")
}

fn set(ids: &[Uuid]) -> BTreeSet<Uuid> {
    ids.iter().copied().collect()
}

/// `(IS_COMPOUND, IS_PROCEDURAL, CLAIM_ROLE)` evaluated by the SQL spellings
/// themselves over a `claims` row aliased `c`.
async fn sql_role(pool: &PgPool, id: Uuid) -> (bool, bool, String) {
    let sql = format!(
        "SELECT {} AS is_compound, {} AS is_procedural, {} AS role \
           FROM claims c WHERE c.id = $1",
        claim_role::is_compound_sql("c"),
        claim_role::is_procedural_sql("c"),
        claim_role::claim_role_sql("c"),
    );
    sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("evaluate the role SQL")
}

/// The ONE-spelling property: for every claim, the boolean SQL predicates
/// agree with the SQL role. (`roles_batch` is not a leg of this check: it
/// splices `CLAIM_ROLE_SQL` itself, so agreement would be a tautology. Each
/// test asserts `roles_batch` against roles chosen by the fixture's shape.)
async fn assert_one_spelling(pool: &PgPool, ids: &[Uuid]) {
    for id in ids {
        let (is_compound, is_procedural, role) = sql_role(pool, *id).await;
        assert_eq!(
            is_compound,
            role == "compound",
            "IS_COMPOUND_SQL and CLAIM_ROLE_SQL disagree on {id}: role {role}"
        );
        assert_eq!(
            is_procedural,
            role == "procedural",
            "IS_PROCEDURAL_SQL and CLAIM_ROLE_SQL disagree on {id}: role {role}"
        );
    }
}

// ── (1) a mid node is a compound; leaves are flattened ─────────────────────

/// `R -> M -> {L1, L2, S}` and `R -> S` (S shared by the root and the mid
/// node). R and M are compounds; R's leaf set is {L1, L2, S}: M is NOT one of
/// R's leaves, and S is listed once although it is reached by two paths.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mid_node_is_a_compound_and_its_leaves_are_its_flattened_leaves(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;
    let r = claim(&pool, &s, "root").await;
    let m = claim(&pool, &s, "mid").await;
    let l1 = claim(&pool, &s, "leaf 1").await;
    let l2 = claim(&pool, &s, "leaf 2").await;
    let shared = claim(&pool, &s, "shared leaf").await;
    let lone = claim(&pool, &s, "standalone").await;
    decomposes_to(&pool, r, m).await;
    decomposes_to(&pool, r, shared).await;
    decomposes_to(&pool, m, l1).await;
    decomposes_to(&pool, m, l2).await;
    decomposes_to(&pool, m, shared).await;

    let all = [r, m, l1, l2, shared, lone];
    let leaves = closure(&pool, &viewer, &all).await;
    assert_eq!(
        set(&leaves[&r]),
        set(&[l1, l2, shared]),
        "root's leaves are flattened"
    );
    assert_eq!(
        leaves[&r].len(),
        3,
        "the shared leaf is listed once: {:?}",
        leaves[&r]
    );
    assert!(
        !leaves[&r].contains(&m),
        "a mid node is never a leaf of its parent"
    );
    assert_eq!(
        set(&leaves[&m]),
        set(&[l1, l2, shared]),
        "mid node's own leaves"
    );
    for atom in [l1, l2, shared, lone] {
        assert_eq!(
            leaves[&atom],
            Vec::<Uuid>::new(),
            "nothing lies below {atom}"
        );
    }

    let got = roles(&pool, &viewer, &all).await;
    assert_eq!(got[&r], ClaimRole::Compound { spine: false });
    assert_eq!(
        got[&m],
        ClaimRole::Compound { spine: false },
        "a mid node is a compound"
    );
    for atom in [l1, l2, shared] {
        assert_eq!(
            got[&atom],
            ClaimRole::Atom,
            "a decomposition target with no children is an atom"
        );
    }
    assert_eq!(got[&lone], ClaimRole::Standalone);
    // Every listed leaf is an atom, whatever the depth it was reached at (at
    // full visibility; see
    // `a_node_whose_whole_decomposition_is_hidden_is_a_leaf_for_that_viewer`).
    for leaf in &leaves[&r] {
        assert_eq!(
            got[leaf],
            ClaimRole::Atom,
            "leaf {leaf} of the root is an atom"
        );
    }

    assert_one_spelling(&pool, &all).await;
}

/// The edges that make a claim a compound or an atom are in force and point
/// at current claims; anything else leaves the claim a standalone.
#[sqlx::test(migrations = "../../migrations")]
async fn only_in_force_edges_between_current_claims_assign_a_role(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;

    // parent -(retired)-> child: both standalones.
    let retired_parent = claim(&pool, &s, "parent over a retired edge").await;
    let retired_child = claim(&pool, &s, "child under a retired edge").await;
    edge(&pool, retired_parent, retired_child, "decomposes_to", true).await;

    // parent -> superseded child: the parent is no compound.
    let dangling_parent = claim(&pool, &s, "parent of a superseded claim").await;
    let superseded_child = claim_full(
        &pool,
        &s,
        "superseded child",
        serde_json::json!({}),
        &[],
        None,
        false,
    )
    .await;
    decomposes_to(&pool, dangling_parent, superseded_child).await;

    // superseded parent -> child: the child is no atom.
    let superseded_parent = claim_full(
        &pool,
        &s,
        "superseded parent",
        serde_json::json!({}),
        &[],
        None,
        false,
    )
    .await;
    let orphan = claim(&pool, &s, "child of a superseded parent").await;
    decomposes_to(&pool, superseded_parent, orphan).await;

    // An epistemic edge is no decomposition.
    let supporter = claim(&pool, &s, "supporter").await;
    let supported = claim(&pool, &s, "supported").await;
    edge(&pool, supporter, supported, "supports", false).await;

    let ids = [
        retired_parent,
        retired_child,
        dangling_parent,
        orphan,
        supporter,
        supported,
    ];
    let got = roles(&pool, &viewer, &ids).await;
    for id in ids {
        assert_eq!(got[&id], ClaimRole::Standalone, "{id} is a standalone");
    }
    let leaves = closure(&pool, &viewer, &[retired_parent, dangling_parent]).await;
    assert!(
        leaves[&retired_parent].is_empty(),
        "a retired edge is not walked"
    );
    assert!(
        leaves[&dangling_parent].is_empty(),
        "a superseded child is not a leaf"
    );

    assert_one_spelling(&pool, &ids).await;
}

// ── (2) a manual cycle terminates and yields no duplicates ─────────────────

/// `A -> B -> A` with `A -> L` and `B -> L`: the walk revisits A and B, and L
/// is reachable from A along two paths. Both closures are exactly [L].
#[sqlx::test(migrations = "../../migrations")]
async fn a_manual_cycle_terminates_and_yields_no_duplicates(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;
    let a = claim(&pool, &s, "cycle A").await;
    let b = claim(&pool, &s, "cycle B").await;
    let l = claim(&pool, &s, "leaf under the cycle").await;
    decomposes_to(&pool, a, b).await;
    decomposes_to(&pool, b, a).await;
    decomposes_to(&pool, a, l).await;
    decomposes_to(&pool, b, l).await;

    let leaves = closure(&pool, &viewer, &[a, b]).await;
    assert_eq!(leaves[&a], vec![l], "A's closure is exactly [L]");
    assert_eq!(leaves[&b], vec![l], "B's closure is exactly [L]");

    let got = roles(&pool, &viewer, &[a, b, l]).await;
    assert_eq!(got[&a], ClaimRole::Compound { spine: false });
    assert_eq!(got[&b], ClaimRole::Compound { spine: false });
    assert_eq!(got[&l], ClaimRole::Atom);
}

/// A rootless cycle has no root, stamped or not, so a workflow stamp INSIDE
/// one exempts nothing: `C -> D -> C` with C stamped `source_type: workflow`
/// and `D -> leaf` is an ordinary pair of compounds over an atom. (The
/// "every root is stamped" rule alone would pass a cycle, which reaches no
/// unstamped root; the stamped node must itself be a root.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_stamp_inside_a_rootless_cycle_exempts_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;
    let c = claim_with(
        &pool,
        &s,
        "workflow-stamped cycle node",
        serde_json::json!({"source_type": "workflow", "level": 0}),
    )
    .await;
    let d = claim(&pool, &s, "unstamped cycle node").await;
    let leaf = claim(&pool, &s, "leaf under the stamped cycle").await;
    decomposes_to(&pool, c, d).await;
    decomposes_to(&pool, d, c).await;
    decomposes_to(&pool, d, leaf).await;

    let ids = [c, d, leaf];
    let got = roles(&pool, &viewer, &ids).await;
    assert_eq!(got[&c], ClaimRole::Compound { spine: true }, "level 0");
    assert_eq!(got[&d], ClaimRole::Compound { spine: false });
    assert_eq!(got[&leaf], ClaimRole::Atom);
    assert_one_spelling(&pool, &ids).await;
}

/// The walk stops at 6 hops: in a chain `n0 -> n1 -> ... -> n6 -> leaf`, the
/// leaf is 7 hops below n0 and 6 below n1. n1 finds it; n0 finds nothing
/// (n6 still has a child, so it is not a leaf either).
#[sqlx::test(migrations = "../../migrations")]
async fn the_leaf_closure_reaches_six_hops_and_no_further(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;
    let mut chain = Vec::new();
    for i in 0..7 {
        chain.push(claim(&pool, &s, &format!("chain node {i}")).await);
    }
    let leaf = claim(&pool, &s, "chain leaf").await;
    for w in chain.windows(2) {
        decomposes_to(&pool, w[0], w[1]).await;
    }
    decomposes_to(&pool, chain[6], leaf).await;

    let leaves = closure(&pool, &viewer, &[chain[0], chain[1]]).await;
    assert_eq!(leaves[&chain[1]], vec![leaf], "6 hops below n1: reached");
    assert!(
        leaves[&chain[0]].is_empty(),
        "7 hops below n0: past the cap, so n0 has no leaf: {:?}",
        leaves[&chain[0]]
    );
}

// ── (3) tenancy: a private leaf under a public compound ────────────────────

/// A public compound K with three leaves, built so each splice is
/// load-bearing on its own:
///
/// * `private_leaf`: a group-private claim behind an edge FORCED public. Only
///   the claim splice can hide it.
/// * `hidden_edge_leaf`: a public claim behind an edge forced group-private.
///   Only the edge splice can hide it.
/// * `open_leaf`: public behind a public edge (calibration).
///
/// The anonymous viewer sees [open_leaf]; the owner group sees all three
/// (over-suppression check). The role of K is the same for both.
///
/// Absent from the closure is not absent from the conjunction: SPEC §8 T1
/// counts a claim the viewer cannot read behind an edge it can read as a
/// VACUOUS conjunct. The closure carries no such count; whatever derives a
/// value from it has to supply it (an open question on the PR).
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_leaf_is_absent_for_the_anonymous_viewer_and_present_for_its_group(pool: PgPool) {
    let s = seed(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "claim-role-owner").await;
    let anonymous = fixture::public_viewer(&pool).await;
    let owner = Viewer::resolve(&pool, member).await.expect("resolve owner");

    let k = claim(&pool, &s, "public compound").await;
    let private_leaf = claim_full(
        &pool,
        &s,
        "private leaf",
        serde_json::json!({}),
        &[],
        Some(group),
        true,
    )
    .await;
    let hidden_edge_leaf = claim(&pool, &s, "public leaf behind a private edge").await;
    let open_leaf = claim(&pool, &s, "public leaf").await;

    let e_private = decomposes_to(&pool, k, private_leaf).await;
    force_edge_tenancy(&pool, e_private, "public", s.world).await;
    let e_hidden = decomposes_to(&pool, k, hidden_edge_leaf).await;
    force_edge_tenancy(&pool, e_hidden, "group", group).await;
    decomposes_to(&pool, k, open_leaf).await;

    let anon = closure(&pool, &anonymous, &[k]).await;
    assert_eq!(
        anon[&k],
        vec![open_leaf],
        "the anonymous viewer sees neither the private leaf nor the leaf behind a private edge"
    );
    let own = closure(&pool, &owner, &[k]).await;
    assert_eq!(
        set(&own[&k]),
        set(&[private_leaf, hidden_edge_leaf, open_leaf]),
        "the owner group sees every leaf"
    );

    // Role is structure: the same for both viewers.
    assert_eq!(
        roles(&pool, &anonymous, &[k]).await[&k],
        ClaimRole::Compound { spine: false }
    );
    assert_eq!(
        roles(&pool, &owner, &[k]).await[&k],
        ClaimRole::Compound { spine: false }
    );

    // A claim the viewer cannot read is absent from both maps.
    assert!(!closure(&pool, &anonymous, &[private_leaf])
        .await
        .contains_key(&private_leaf));
    assert!(!roles(&pool, &anonymous, &[private_leaf])
        .await
        .contains_key(&private_leaf));
    assert_eq!(
        roles(&pool, &owner, &[private_leaf]).await[&private_leaf],
        ClaimRole::Atom
    );
}

/// The leaf test is spliced like the walk: a leaf is a visible node with no
/// VISIBLE outgoing `decomposes_to` (SPEC §2.1), so a visible mid node whose
/// whole decomposition is hidden from the viewer is a LEAF of its parent for
/// that viewer. Each splice of the leaf test is load-bearing on its own, one
/// level below the root:
///
/// * `K1 -> M1 -> private`: the M1 edge is forced public, so only the CLAIM
///   splice of the leaf test (on the child) makes M1 a leaf.
/// * `K2 -> M2 -> hidden_edge`: a public child behind an edge forced
///   group-private, so only the EDGE splice of the leaf test makes M2 a leaf.
///
/// The owner group sees the grandchild as the leaf in both arms. The role of
/// M1 and M2 stays `Compound` (it is not spliced), so for a partially
/// sighted viewer the closure can list a structural compound as a leaf; this
/// pins that as the behaviour, which the PR raises as an open question.
#[sqlx::test(migrations = "../../migrations")]
async fn a_node_whose_whole_decomposition_is_hidden_is_a_leaf_for_that_viewer(pool: PgPool) {
    let s = seed(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "claim-role-owner").await;
    let anonymous = fixture::public_viewer(&pool).await;
    let owner = Viewer::resolve(&pool, member).await.expect("resolve owner");

    // K1 -> M1 -(forced public)-> private claim
    let k1 = claim(&pool, &s, "public root, claim-hidden arm").await;
    let m1 = claim(&pool, &s, "public mid node over a private claim").await;
    let private = claim_full(
        &pool,
        &s,
        "private grandchild",
        serde_json::json!({}),
        &[],
        Some(group),
        true,
    )
    .await;
    decomposes_to(&pool, k1, m1).await;
    let e1 = decomposes_to(&pool, m1, private).await;
    force_edge_tenancy(&pool, e1, "public", s.world).await;

    // K2 -> M2 -(forced group-private)-> public claim
    let k2 = claim(&pool, &s, "public root, edge-hidden arm").await;
    let m2 = claim(&pool, &s, "public mid node behind a private edge").await;
    let hidden_edge = claim(&pool, &s, "public grandchild behind a private edge").await;
    decomposes_to(&pool, k2, m2).await;
    let e2 = decomposes_to(&pool, m2, hidden_edge).await;
    force_edge_tenancy(&pool, e2, "group", group).await;

    let anon = closure(&pool, &anonymous, &[k1, k2, m1, m2]).await;
    assert_eq!(
        anon[&k1],
        vec![m1],
        "a child the viewer cannot read leaves M1 with no visible decomposition"
    );
    assert_eq!(
        anon[&k2],
        vec![m2],
        "an edge the viewer cannot read leaves M2 with no visible decomposition"
    );
    assert!(anon[&m1].is_empty() && anon[&m2].is_empty());

    let own = closure(&pool, &owner, &[k1, k2]).await;
    assert_eq!(
        own[&k1],
        vec![private],
        "the owner group sees the real leaf"
    );
    assert_eq!(
        own[&k2],
        vec![hidden_edge],
        "the owner group sees the real leaf"
    );

    // The role is not spliced: M1 and M2 are compounds for both viewers,
    // while the anonymous viewer's closure lists them as leaves.
    for viewer in [&anonymous, &owner] {
        let got = roles(&pool, viewer, &[m1, m2]).await;
        assert_eq!(got[&m1], ClaimRole::Compound { spine: false });
        assert_eq!(got[&m2], ClaimRole::Compound { spine: false });
    }
}

/// The role SQL carries no viewer splice while the closure does: a public
/// compound whose ONLY child is private (edge and claim both group-owned, as
/// the trigger stamps them) reads as a compound with no visible leaves for
/// the anonymous viewer.
///
/// This pins the SQL, NOT the end-to-end "role is structure" property: the
/// test harness connects as a superuser, where row security does not apply.
/// On an application session it does, and the same read finds no compound;
/// `on_an_app_session_row_security_hides_a_wholly_private_decomposition`
/// pins that.
#[sqlx::test(migrations = "../../migrations")]
async fn the_role_sql_is_unspliced_while_the_closure_is_spliced(pool: PgPool) {
    let s = seed(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "claim-role-owner").await;
    let anonymous = fixture::public_viewer(&pool).await;
    let owner = Viewer::resolve(&pool, member).await.expect("resolve owner");

    let k = claim(&pool, &s, "public compound, private child").await;
    let child = claim_full(
        &pool,
        &s,
        "private only child",
        serde_json::json!({}),
        &[],
        Some(group),
        true,
    )
    .await;
    decomposes_to(&pool, k, child).await;

    assert_eq!(
        roles(&pool, &anonymous, &[k]).await[&k],
        ClaimRole::Compound { spine: false }
    );
    assert!(closure(&pool, &anonymous, &[k]).await[&k].is_empty());
    assert_eq!(closure(&pool, &owner, &[k]).await[&k], vec![child]);
}

/// `roles_batch` on an `epigraph_app` session stamped with the read set
/// `groups`: the regime the per-viewer API reads run in, where row security
/// filters `edges` and `claims` whatever the query splices. The viewer is
/// resolved on the superuser pool beforehand.
async fn app_session_roles(
    pool: &PgPool,
    viewer: &Viewer,
    groups: &[Uuid],
    ids: &[Uuid],
) -> HashMap<Uuid, ClaimRole> {
    let set = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let ids = ids.to_vec();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let got = {
            let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
            sqlx::query(
                "SELECT set_config('epigraph.group_ids', $1, true), \
                        set_config('epigraph.writable_group_ids', '', true), \
                        set_config('epigraph.principal_id', '', true)",
            )
            .bind(&set)
            .execute(&mut *tx)
            .await
            .expect("stamp the app session");
            let got = claim_role::roles_batch(&mut *tx, viewer, &ids)
                .await
                .expect("roles_batch on an app session");
            tx.rollback().await.expect("rollback");
            got
        };
        (conn, got)
    })
    .await
}

/// The documented limit of "role is structure" (module doc of `claim_role`):
/// on an application session, row security hides a compound's decomposition
/// from a viewer who can read none of it, so the role read finds no compound.
/// A public compound whose only child is private reads `Standalone` for the
/// anonymous app session, and `Compound` for an app session stamped with the
/// owner group. Closing this needs a definer-rights role read, which this
/// code-only module does not add; per-viewer API callers of `roles_batch`
/// inherit the gap.
///
/// CALIBRATION: in the same anonymous session a fully public compound still
/// reads `Compound` over an `Atom`, so `Standalone` is row security hiding
/// the private decomposition, not a session that can read nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn on_an_app_session_row_security_hides_a_wholly_private_decomposition(pool: PgPool) {
    let s = seed(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "claim-role-owner").await;
    let anonymous = fixture::public_viewer(&pool).await;
    let owner = Viewer::resolve(&pool, member).await.expect("resolve owner");

    let k = claim(&pool, &s, "public compound, private child").await;
    let child = claim_full(
        &pool,
        &s,
        "private only child",
        serde_json::json!({}),
        &[],
        Some(group),
        true,
    )
    .await;
    decomposes_to(&pool, k, child).await;
    let open = claim(&pool, &s, "public compound, public child").await;
    let open_child = claim(&pool, &s, "public child").await;
    decomposes_to(&pool, open, open_child).await;

    let anon = app_session_roles(&pool, &anonymous, &[], &[k, open, open_child]).await;
    assert_eq!(
        anon[&k],
        ClaimRole::Standalone,
        "row security hides the private decomposition from the anonymous app session"
    );
    assert_eq!(anon[&open], ClaimRole::Compound { spine: false });
    assert_eq!(anon[&open_child], ClaimRole::Atom);

    let own = app_session_roles(&pool, &owner, &[group], &[k, child]).await;
    assert_eq!(own[&k], ClaimRole::Compound { spine: false });
    assert_eq!(own[&child], ClaimRole::Atom);
}

// ── (4) a workflow-rooted tree is procedural ───────────────────────────────

/// The shapes the workflow writers produce: a thesis root stamped
/// `source_type: workflow` (level 0), a phase (level 1), a step written the
/// way `add_step` writes one (level 2, `kind: workflow_step`), and an
/// unstamped node under the step (an evolved step carries no stamp). Every
/// node is procedural, the leaf included. The same tree without the stamp on
/// its root is an ordinary compound tree; a workflow stamp on a NON-root
/// claim exempts nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_rooted_tree_is_procedural(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;

    let thesis = claim_with(
        &pool,
        &s,
        "workflow thesis",
        serde_json::json!({"level": 0, "source_type": "workflow", "kind": "workflow_thesis"}),
    )
    .await;
    let phase = claim_with(
        &pool,
        &s,
        "workflow phase",
        serde_json::json!({"level": 1, "source_type": "workflow", "kind": "workflow_phase"}),
    )
    .await;
    let step = claim_with(
        &pool,
        &s,
        "workflow step",
        serde_json::json!({"level": 2, "source_type": "workflow", "kind": "workflow_step"}),
    )
    .await;
    let unstamped = claim(&pool, &s, "unstamped node under a step").await;
    decomposes_to(&pool, thesis, phase).await;
    decomposes_to(&pool, phase, step).await;
    decomposes_to(&pool, step, unstamped).await;

    let tree = [thesis, phase, step, unstamped];
    let got = roles(&pool, &viewer, &tree).await;
    for id in tree {
        assert_eq!(
            got[&id],
            ClaimRole::Procedural,
            "{id} of a workflow tree is procedural"
        );
    }

    // Control: the same tree under an unstamped root.
    let root = claim_with(&pool, &s, "paper thesis", serde_json::json!({"level": 0})).await;
    let section = claim_with(&pool, &s, "paper section", serde_json::json!({"level": 1})).await;
    let atom = claim(&pool, &s, "paper atom").await;
    decomposes_to(&pool, root, section).await;
    decomposes_to(&pool, section, atom).await;

    // A workflow-stamped compound under an ordinary root is not a root.
    let stamped_mid = claim_with(
        &pool,
        &s,
        "workflow-stamped mid node",
        serde_json::json!({"source_type": "workflow"}),
    )
    .await;
    let stamped_leaf = claim(&pool, &s, "leaf under the stamped mid node").await;
    decomposes_to(&pool, root, stamped_mid).await;
    decomposes_to(&pool, stamped_mid, stamped_leaf).await;

    let control = [root, section, atom, stamped_mid, stamped_leaf];
    let got = roles(&pool, &viewer, &control).await;
    assert!(matches!(got[&root], ClaimRole::Compound { .. }));
    assert!(matches!(got[&section], ClaimRole::Compound { .. }));
    assert!(matches!(got[&stamped_mid], ClaimRole::Compound { .. }));
    assert_eq!(got[&atom], ClaimRole::Atom);
    assert_eq!(got[&stamped_leaf], ClaimRole::Atom);

    let mut all = tree.to_vec();
    all.extend(control);
    assert_one_spelling(&pool, &all).await;
}

/// A git-history tree as `ingest_git` writes it (a repository root stamped
/// `source: git-history`, `node: repo`; a PR node; a commit) is an ORDINARY
/// compound tree. Its procedural marker is still pending (SPEC §2.1, Q-F1),
/// and `source` / `node` are caller-set properties (`PATCH
/// /api/v1/claims/:id` merges them), so no git stamp exempts a tree, not even
/// one authored by the registered system agent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_git_history_stamp_exempts_nothing_while_its_marker_is_pending(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;

    let repo = claim_with(
        &pool,
        &s,
        "repository root",
        serde_json::json!({"source": "git-history", "node": "repo", "repo": "o/r"}),
    )
    .await;
    let pr = claim_with(
        &pool,
        &s,
        "pull request",
        serde_json::json!({"source": "git-history", "node": "pr", "pr_number": 1}),
    )
    .await;
    let commit = claim_with(
        &pool,
        &s,
        "commit",
        serde_json::json!({"source": "git-history", "commit_type": "fix"}),
    )
    .await;
    decomposes_to(&pool, repo, pr).await;
    decomposes_to(&pool, pr, commit).await;

    let ids = [repo, pr, commit];
    let got = roles(&pool, &viewer, &ids).await;
    assert_eq!(got[&repo], ClaimRole::Compound { spine: false });
    assert_eq!(got[&pr], ClaimRole::Compound { spine: false });
    assert_eq!(got[&commit], ClaimRole::Atom);

    assert_one_spelling(&pool, &ids).await;
}

/// The workflow stamp counts only on a root AUTHORED by the registered
/// `workflow-ingest` system agent. `source_type` is a caller-set property, so
/// any other author (a claim created with it, or an ordinary claim patched to
/// carry it later) would otherwise opt its own tree, and any claim it can
/// attach beneath that root, out of the atom program. The identical tree
/// authored by the system agent stays procedural (positive control).
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_stamp_by_any_other_author_exempts_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;
    let x = stranger(&pool, &s).await;

    // Created stamped by a stranger.
    let thesis = claim_with(
        &pool,
        &x,
        "stranger's workflow-stamped thesis",
        serde_json::json!({"level": 0, "source_type": "workflow"}),
    )
    .await;
    let phase = claim_with(
        &pool,
        &x,
        "stranger's workflow-stamped phase",
        serde_json::json!({"level": 1, "source_type": "workflow"}),
    )
    .await;
    let leaf = claim(&pool, &x, "leaf under the stranger's tree").await;
    decomposes_to(&pool, thesis, phase).await;
    decomposes_to(&pool, phase, leaf).await;

    // An ordinary root, stamped afterwards the way a properties merge would.
    let patched = claim(&pool, &x, "ordinary root, stamped later").await;
    let patched_leaf = claim(&pool, &x, "leaf under the patched root").await;
    decomposes_to(&pool, patched, patched_leaf).await;
    sqlx::query(
        "UPDATE claims SET properties = properties || '{\"source_type\": \"workflow\"}' \
          WHERE id = $1",
    )
    .bind(patched)
    .execute(&pool)
    .await
    .expect("stamp the root afterwards");

    // Positive control: the same shape authored by the system agent.
    let sys_thesis = claim_with(
        &pool,
        &s,
        "system workflow thesis",
        serde_json::json!({"level": 0, "source_type": "workflow"}),
    )
    .await;
    let sys_leaf = claim(&pool, &s, "leaf under the system thesis").await;
    decomposes_to(&pool, sys_thesis, sys_leaf).await;

    let ids = [
        thesis,
        phase,
        leaf,
        patched,
        patched_leaf,
        sys_thesis,
        sys_leaf,
    ];
    let got = roles(&pool, &viewer, &ids).await;
    assert_eq!(
        got[&thesis],
        ClaimRole::Compound { spine: true },
        "a stranger's stamped thesis is an ordinary (spine) compound"
    );
    assert_eq!(got[&phase], ClaimRole::Compound { spine: true });
    assert_eq!(
        got[&leaf],
        ClaimRole::Atom,
        "its leaf stays in the atom program"
    );
    assert_eq!(got[&patched], ClaimRole::Compound { spine: false });
    assert_eq!(got[&patched_leaf], ClaimRole::Atom);
    assert_eq!(got[&sys_thesis], ClaimRole::Procedural);
    assert_eq!(got[&sys_leaf], ClaimRole::Procedural);

    assert_one_spelling(&pool, &ids).await;
}

/// `ingest_git` stamps `source: git-history` on EVERY claim it writes, commits
/// included, but only its repository node (`node: repo`) roots a git tree. A
/// commit with no repository or PR above it is an ordinary root: when
/// `decompose_claims` decomposes it (it is offered as undecomposed), it is a
/// compound over atoms, and those atoms stay in the atom program.
#[sqlx::test(migrations = "../../migrations")]
async fn a_decomposed_lone_commit_is_a_compound_over_its_atoms(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;

    let commit = claim_with(
        &pool,
        &s,
        "lone commit",
        serde_json::json!({
            "source": "git-history",
            "commit_hash": "0000000000000000000000000000000000000000",
            "commit_type": "fix",
        }),
    )
    .await;
    let a1 = claim(&pool, &s, "commit atom 1").await;
    let a2 = claim(&pool, &s, "commit atom 2").await;
    decomposes_to(&pool, commit, a1).await;
    decomposes_to(&pool, commit, a2).await;

    let ids = [commit, a1, a2];
    let got = roles(&pool, &viewer, &ids).await;
    assert_eq!(
        got[&commit],
        ClaimRole::Compound { spine: false },
        "a commit is no git tree root"
    );
    assert_eq!(got[&a1], ClaimRole::Atom);
    assert_eq!(got[&a2], ClaimRole::Atom);

    assert_one_spelling(&pool, &ids).await;
}

/// Decomposition is a DAG, not a tree: a claim can sit under a stamped root
/// AND an ordinary one. It is procedural only when EVERY root above it is
/// stamped. Otherwise one edge from a stamped claim (whose stamp is a
/// caller-set property) onto a node of an ordinary tree would turn that node
/// and its subtree procedural for every reader and every bulk recompute,
/// which is the refold the unspliced role exists to prevent.
///
/// * `shared`: under a workflow thesis and under an ordinary root.
/// * `m`: a mid node of a paper (`paper -> section -> m -> atoms`) with a
///   foreign workflow-stamped root attached above it.
///
/// The stamped roots themselves stay procedural (calibration: the exemption
/// is narrowed, not removed).
#[sqlx::test(migrations = "../../migrations")]
async fn a_node_under_an_ordinary_root_is_not_procedural_whatever_else_is_above_it(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;

    // workflow thesis -> shared -> leaf, and ordinary root -> shared
    let thesis = claim_with(
        &pool,
        &s,
        "workflow thesis",
        serde_json::json!({"level": 0, "source_type": "workflow"}),
    )
    .await;
    let ordinary = claim(&pool, &s, "ordinary root").await;
    let shared = claim(&pool, &s, "node under both").await;
    let shared_leaf = claim(&pool, &s, "leaf of the shared node").await;
    decomposes_to(&pool, thesis, shared).await;
    decomposes_to(&pool, ordinary, shared).await;
    decomposes_to(&pool, shared, shared_leaf).await;

    // paper -> section -> m -> {a1, a2}, and a foreign stamped root -> m
    let paper = claim_with(&pool, &s, "paper thesis", serde_json::json!({"level": 0})).await;
    let section = claim_with(&pool, &s, "paper section", serde_json::json!({"level": 1})).await;
    let m = claim(&pool, &s, "paragraph").await;
    let a1 = claim(&pool, &s, "atom 1").await;
    let a2 = claim(&pool, &s, "atom 2").await;
    decomposes_to(&pool, paper, section).await;
    decomposes_to(&pool, section, m).await;
    decomposes_to(&pool, m, a1).await;
    decomposes_to(&pool, m, a2).await;
    let foreign = claim_with(
        &pool,
        &s,
        "foreign workflow root",
        serde_json::json!({"level": 0, "source_type": "workflow"}),
    )
    .await;
    decomposes_to(&pool, foreign, m).await;

    let ids = [
        thesis,
        ordinary,
        shared,
        shared_leaf,
        paper,
        section,
        m,
        a1,
        a2,
        foreign,
    ];
    let got = roles(&pool, &viewer, &ids).await;
    assert_eq!(
        got[&shared],
        ClaimRole::Compound { spine: false },
        "a node under an ordinary root is not procedural"
    );
    assert_eq!(got[&shared_leaf], ClaimRole::Atom);
    assert_eq!(
        got[&m],
        ClaimRole::Compound { spine: false },
        "a foreign stamped root attached above a paper's mid node exempts nothing"
    );
    assert_eq!(got[&a1], ClaimRole::Atom);
    assert_eq!(got[&a2], ClaimRole::Atom);
    assert!(matches!(got[&ordinary], ClaimRole::Compound { .. }));
    assert!(matches!(got[&paper], ClaimRole::Compound { .. }));
    assert!(matches!(got[&section], ClaimRole::Compound { .. }));
    // Calibration: each stamped root has no ordinary root above it.
    assert_eq!(got[&thesis], ClaimRole::Procedural);
    assert_eq!(got[&foreign], ClaimRole::Procedural);

    assert_one_spelling(&pool, &ids).await;
}

/// The procedural root search is over in-force edges between CURRENT claims,
/// like every other role predicate (SPEC §2.1). `ClaimRepository::supersede`
/// flips `is_current` and leaves the claim's edges in force, so a superseded
/// parent is a real state, and it counts for nothing in either direction:
///
/// * a superseded UNSTAMPED claim above a workflow thesis does not stop the
///   thesis from being the root, so the workflow tree stays procedural;
/// * a superseded workflow thesis lends no procedural root to the claims it
///   decomposed into: the current claim below it is the root of an ordinary
///   tree.
#[sqlx::test(migrations = "../../migrations")]
async fn a_superseded_parent_neither_hides_nor_lends_a_procedural_root(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;
    // superseded X -> thesis T (workflow) -> step -> leaf
    let x = claim_full(
        &pool,
        &s,
        "superseded unstamped parent",
        serde_json::json!({}),
        &[],
        None,
        false,
    )
    .await;
    let thesis = claim_with(
        &pool,
        &s,
        "workflow thesis under a superseded parent",
        serde_json::json!({"level": 0, "source_type": "workflow"}),
    )
    .await;
    let step = claim(&pool, &s, "workflow step").await;
    let step_leaf = claim(&pool, &s, "workflow leaf").await;
    decomposes_to(&pool, x, thesis).await;
    decomposes_to(&pool, thesis, step).await;
    decomposes_to(&pool, step, step_leaf).await;

    // superseded workflow thesis W -> C -> L
    let w = claim_full(
        &pool,
        &s,
        "superseded workflow thesis",
        serde_json::json!({"level": 0, "source_type": "workflow"}),
        &[],
        None,
        false,
    )
    .await;
    let c = claim(&pool, &s, "current claim below a superseded workflow").await;
    let l = claim(&pool, &s, "its leaf").await;
    decomposes_to(&pool, w, c).await;
    decomposes_to(&pool, c, l).await;

    let ids = [thesis, step, step_leaf, c, l];
    let got = roles(&pool, &viewer, &ids).await;
    for id in [thesis, step, step_leaf] {
        assert_eq!(
            got[&id],
            ClaimRole::Procedural,
            "{id}: a superseded parent above the workflow thesis must not hide its root"
        );
    }
    assert_eq!(
        got[&c],
        ClaimRole::Compound { spine: false },
        "a superseded workflow thesis lends no procedural root"
    );
    assert_eq!(got[&l], ClaimRole::Atom);

    assert_one_spelling(&pool, &ids).await;
}

// ── rules ──────────────────────────────────────────────────────────────────

/// A rule claim (label `rule` AND an in-force `rule_conclusion` out-edge) is
/// a rule even when it also has a decomposition, and then it is NOT a
/// compound. The label alone, or the edge alone, makes no rule.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rule_needs_its_label_and_its_conclusion_edge_and_outranks_compound(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;
    let conclusion = claim(&pool, &s, "conclusion").await;

    let rule = claim_full(
        &pool,
        &s,
        "rule",
        serde_json::json!({}),
        &["rule"],
        None,
        true,
    )
    .await;
    edge(&pool, rule, conclusion, "rule_conclusion", false).await;

    let decomposed_rule = claim_full(
        &pool,
        &s,
        "decomposed rule",
        serde_json::json!({}),
        &["rule"],
        None,
        true,
    )
    .await;
    edge(&pool, decomposed_rule, conclusion, "rule_conclusion", false).await;
    let part = claim(&pool, &s, "part of the decomposed rule").await;
    decomposes_to(&pool, decomposed_rule, part).await;

    let label_only = claim_full(
        &pool,
        &s,
        "label only",
        serde_json::json!({}),
        &["rule"],
        None,
        true,
    )
    .await;
    let edge_only = claim(&pool, &s, "edge only").await;
    edge(&pool, edge_only, conclusion, "rule_conclusion", false).await;
    let retired_rule = claim_full(
        &pool,
        &s,
        "retired conclusion",
        serde_json::json!({}),
        &["rule"],
        None,
        true,
    )
    .await;
    edge(&pool, retired_rule, conclusion, "rule_conclusion", true).await;

    let ids = [
        rule,
        decomposed_rule,
        label_only,
        edge_only,
        retired_rule,
        conclusion,
    ];
    let got = roles(&pool, &viewer, &ids).await;
    assert_eq!(got[&rule], ClaimRole::Rule);
    assert_eq!(
        got[&decomposed_rule],
        ClaimRole::Rule,
        "rule outranks compound"
    );
    assert_eq!(got[&label_only], ClaimRole::Standalone);
    assert_eq!(got[&edge_only], ClaimRole::Standalone);
    assert_eq!(got[&retired_rule], ClaimRole::Standalone);
    assert_eq!(
        got[&conclusion],
        ClaimRole::Standalone,
        "a conclusion is not decomposed"
    );

    assert_one_spelling(&pool, &ids).await;
}

// ── (5) spine = level 0/1, or more than 16 visible leaves ──────────────────

async fn compound_with_leaves(
    pool: &PgPool,
    s: &Seed,
    what: &str,
    properties: serde_json::Value,
    n: usize,
) -> Uuid {
    let k = claim_with(pool, s, what, properties).await;
    for i in 0..n {
        let leaf = claim(pool, s, &format!("{what} leaf {i}")).await;
        decomposes_to(pool, k, leaf).await;
    }
    k
}

#[sqlx::test(migrations = "../../migrations")]
async fn spine_is_level_zero_or_one_or_more_than_sixteen_flattened_leaves(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let s = seed(&pool).await;

    let thesis =
        compound_with_leaves(&pool, &s, "thesis", serde_json::json!({"level": 0}), 2).await;
    let section =
        compound_with_leaves(&pool, &s, "section", serde_json::json!({"level": "1"}), 2).await;
    let para16 = compound_with_leaves(
        &pool,
        &s,
        "paragraph 16",
        serde_json::json!({"level": 2}),
        16,
    )
    .await;
    let para17 = compound_with_leaves(
        &pool,
        &s,
        "paragraph 17",
        serde_json::json!({"level": 2}),
        17,
    )
    .await;
    let plain16 = compound_with_leaves(&pool, &s, "plain 16", serde_json::json!({}), 16).await;
    let plain17 = compound_with_leaves(&pool, &s, "plain 17", serde_json::json!({}), 17).await;
    // A level-0 claim with no children is no compound, so no spine.
    let lone_thesis = claim_with(&pool, &s, "lone thesis", serde_json::json!({"level": 0})).await;

    // Flattened and deduplicated: root -> M1 -> {x0..x8}, root -> M2 -> {x7..x15}.
    // 16 distinct leaves (x7, x8 shared); counting per path would give 18.
    let root = claim(&pool, &s, "two-mid root").await;
    let m1 = claim(&pool, &s, "mid 1").await;
    let m2 = claim(&pool, &s, "mid 2").await;
    decomposes_to(&pool, root, m1).await;
    decomposes_to(&pool, root, m2).await;
    let mut xs = Vec::new();
    for i in 0..16 {
        xs.push(claim(&pool, &s, &format!("x{i}")).await);
    }
    for x in &xs[0..9] {
        decomposes_to(&pool, m1, *x).await;
    }
    for x in &xs[7..16] {
        decomposes_to(&pool, m2, *x).await;
    }
    // ... and one more leaf under M2 makes 17 distinct.
    let root17 = claim(&pool, &s, "two-mid root, 17").await;
    let n1 = claim(&pool, &s, "mid 1'").await;
    let n2 = claim(&pool, &s, "mid 2'").await;
    decomposes_to(&pool, root17, n1).await;
    decomposes_to(&pool, root17, n2).await;
    for x in &xs[0..9] {
        decomposes_to(&pool, n1, *x).await;
    }
    for x in &xs[7..16] {
        decomposes_to(&pool, n2, *x).await;
    }
    let extra = claim(&pool, &s, "x16").await;
    decomposes_to(&pool, n2, extra).await;

    let ids = [
        thesis,
        section,
        para16,
        para17,
        plain16,
        plain17,
        lone_thesis,
        root,
        m1,
        root17,
    ];
    let got = roles(&pool, &viewer, &ids).await;
    assert_eq!(got[&thesis], ClaimRole::Compound { spine: true }, "level 0");
    assert_eq!(
        got[&section],
        ClaimRole::Compound { spine: true },
        "level \"1\""
    );
    assert_eq!(
        got[&para16],
        ClaimRole::Compound { spine: false },
        "16 leaves"
    );
    assert_eq!(
        got[&para17],
        ClaimRole::Compound { spine: true },
        "17 leaves"
    );
    assert_eq!(got[&plain16], ClaimRole::Compound { spine: false });
    assert_eq!(got[&plain17], ClaimRole::Compound { spine: true });
    assert_eq!(got[&lone_thesis], ClaimRole::Standalone);
    assert_eq!(
        got[&root],
        ClaimRole::Compound { spine: false },
        "16 distinct flattened leaves (two shared): not spine"
    );
    assert_eq!(got[&m1], ClaimRole::Compound { spine: false });
    assert_eq!(
        got[&root17],
        ClaimRole::Compound { spine: true },
        "17 distinct leaves"
    );
}

/// Spine counts the leaves the VIEWER can see: a compound with 15 public and
/// 2 private leaves is spine for the owner group (17) and not for the
/// anonymous viewer (15), so the role a viewer gets never reveals how many
/// leaves it cannot see.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_counts_only_the_leaves_the_viewer_can_see(pool: PgPool) {
    let s = seed(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "claim-role-owner").await;
    let anonymous = fixture::public_viewer(&pool).await;
    let owner = Viewer::resolve(&pool, member).await.expect("resolve owner");

    let k = compound_with_leaves(&pool, &s, "mixed", serde_json::json!({"level": 2}), 15).await;
    for i in 0..2 {
        let p = claim_full(
            &pool,
            &s,
            &format!("private leaf {i}"),
            serde_json::json!({}),
            &[],
            Some(group),
            true,
        )
        .await;
        decomposes_to(&pool, k, p).await;
    }

    assert_eq!(
        roles(&pool, &owner, &[k]).await[&k],
        ClaimRole::Compound { spine: true }
    );
    assert_eq!(
        roles(&pool, &anonymous, &[k]).await[&k],
        ClaimRole::Compound { spine: false }
    );
}
