//! The edge meet over ALL FOUR endpoint combinations, and who can read the
//! result.
//!
//! PR-13's named test deliverable. The plan lists it as
//! `tests/privatization_boundary.rs`; it did not exist in any form (a `find`
//! over the tree returned nothing matching `privatization*`), so this is a new
//! file rather than an extension of one.
//!
//! # What "all four endpoint combinations" means
//!
//! An edge's tenancy is the MEET of its two endpoints', and `edges` has exactly
//! four shapes of endpoint pair:
//!
//! | source | target | edge |
//! |---|---|---|
//! | public | public | `('public', world, co = NULL)` |
//! | public | group G | `('group', G, co = NULL)` |
//! | group G | group G | `('group', G, co = NULL)` |
//! | group G | group H | `('group', G, co = H)` ← migration 072 |
//!
//! Only the fourth needs a second column, and before migration 072 it was
//! inexpressible: arm (b) RAISEd on it at INSERT and arm (d) left the edge
//! stale at privatization time. `tenancy_triggers.rs` covers the trigger arms
//! themselves; this file covers the four shapes together plus the READ side —
//! which viewer sees which edge — because a stamp nobody filters on is
//! decorative.
//!
//! # Every case carries a POSITIVE control, deliberately
//!
//! `visibility.rs`'s module doc records why a third "matches nothing" `Viewer`
//! shape was rejected: *"it is invisible to a test strategy written as 'assert
//! a stranger CANNOT read', so an over-restricting viewer would pass every
//! adversarial test while producing silent, permanent empty result sets."*
//!
//! `edge_predicate_fragment` is exactly that risk shape — it is the first
//! predicate in the codebase that can return FEWER rows than
//! `owner_group_id` alone. A file of negative assertions would pass over a
//! fragment that matched nothing at all. So every case below asserts both
//! halves: the viewer who must NOT see the edge, and the viewer who MUST.
//!
//! # Group kinds
//!
//! The two owning groups here are `kind = 'team'`, not the `kind = 'personal'`
//! groups `viewer_fixture::seed_agent_with_group` mints. That is the honest
//! fixture for co-ownership: migration 070's own comment records that for
//! personal groups one principal can never be a live member of two, so a
//! "viewer in both G and H" is only a real principal when the groups are teams
//! or communities. Using personal groups here would have required a membership
//! row production never writes, and the positive control would then be proving
//! something about a state that cannot occur.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::{EdgeRepository, SemanticLinkRepository};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;

const WORLD: Uuid = Uuid::nil();

// ===========================================================================
// Local fixture: team groups, and principals in one or both of them
// ===========================================================================

/// A `kind = 'team'` group. `groups_public_key_shape` (060) requires exactly 32
/// bytes of `public_key` for a team and zero for anything else.
async fn seed_team_group(pool: &PgPool, label: &str, creator: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) \
         VALUES ($1, $2, $3, $4, 'team', $5)",
    )
    .bind(id)
    .bind(format!("{label}:{id}"))
    .bind(format!("did:epigraph:test:team:{label}:{id}"))
    .bind(&key)
    .bind(creator)
    .execute(pool)
    .await
    .expect("seed team group");
    id
}

/// A bare agent with no personal group, so its `Viewer` group set is exactly
/// the teams it is joined to below and nothing else.
async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    agent
}

async fn join(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// The corpus every test below shares: two team groups, one claim in each, and
/// three principals — in G only, in H only, in both.
struct Corpus {
    group_g: Uuid,
    group_h: Uuid,
    author: Uuid,
    /// A claim owned by `group_g`.
    claim_g: Uuid,
    /// A claim owned by `group_h`.
    claim_h: Uuid,
    /// Two public claims, for the meets that do not involve a group.
    public_a: Uuid,
    public_b: Uuid,
    in_g: Viewer,
    in_h: Viewer,
    in_both: Viewer,
    stranger: Viewer,
}

async fn corpus(pool: &PgPool) -> Corpus {
    let author = seed_agent(pool).await;
    let group_g = seed_team_group(pool, "G", author).await;
    let group_h = seed_team_group(pool, "H", author).await;

    let agent_g = seed_agent(pool).await;
    let agent_h = seed_agent(pool).await;
    let agent_both = seed_agent(pool).await;
    let agent_none = seed_agent(pool).await;
    join(pool, group_g, agent_g).await;
    join(pool, group_h, agent_h).await;
    join(pool, group_g, agent_both).await;
    join(pool, group_h, agent_both).await;

    let claim_g = fixture::seed_group_claim(pool, author, group_g, "G's claim").await;
    let claim_h = fixture::seed_group_claim(pool, author, group_h, "H's claim").await;
    let public_a = fixture::seed_public_claim(pool, author, "public A").await;
    let public_b = fixture::seed_public_claim(pool, author, "public B").await;

    let resolve =
        |a: Uuid| async move { Viewer::resolve(pool, a).await.expect("resolve a viewer") };
    let in_g = resolve(agent_g).await;
    let in_h = resolve(agent_h).await;
    let in_both = resolve(agent_both).await;
    let stranger = resolve(agent_none).await;

    // The fixture's own precondition. `Viewer::resolve` unions LIVE
    // memberships; if a membership row failed to land, every negative assertion
    // below would still pass and every positive one would fail for the wrong
    // reason.
    assert_eq!(
        in_both.group_bind().map(<[Uuid]>::len),
        Some(2),
        "the both-groups principal must resolve to two groups"
    );
    assert_eq!(in_g.group_bind().map(<[Uuid]>::len), Some(1));
    assert_eq!(in_h.group_bind().map(<[Uuid]>::len), Some(1));
    assert_eq!(stranger.group_bind().map(<[Uuid]>::len), Some(0));

    Corpus {
        group_g,
        group_h,
        author,
        claim_g,
        claim_h,
        public_a,
        public_b,
        in_g,
        in_h,
        in_both,
        stranger,
    }
}

/// Insert an edge with NO declared tenancy, so arm (b) derives the meet. This
/// is the path the plan's "edges need no call-site edits" property rests on.
async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    // Shaped so `SemanticLinkRepository::get_by_id` can hydrate it: a
    // lower-case relationship (`str_to_link_type` rejects `SUPPORTS`) and a
    // `created_by` in `properties` (`semantic_link_from_row` requires it).
    // Otherwise `visible()` would fail on hydration, before the visibility
    // predicate it exists to exercise ever ran — a red test for the wrong
    // reason is as bad as a green one.
    //
    // `owner_group_id` / `visibility` are left UNBOUND so arm (b) derives the
    // meet. That is the path the plan's "edges need no call-site edits"
    // property rests on, and binding them would test the writer instead of the
    // trigger.
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            properties) \
         VALUES ($1, 'claim', $2, 'claim', 'supports', \
                 jsonb_build_object('created_by', $3::text, 'strength', 0.7)) \
         RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(Uuid::new_v4().to_string())
    .fetch_one(pool)
    .await
    .expect("insert edge")
}

async fn edge_tenancy(pool: &PgPool, id: Uuid) -> (Uuid, String, Option<Uuid>) {
    sqlx::query_as(
        "SELECT owner_group_id, visibility::text, co_owner_group_id FROM edges WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read edge tenancy")
}

/// Can `viewer` see edge `id` through the repo layer?
///
/// Goes through `SemanticLinkRepository::get_by_id`, which is a real read path
/// carrying `/* {EDGE_VISIBILITY:edges} */` — not a hand-written predicate. A
/// test that assembled its own SQL would prove the FRAGMENT correct while
/// saying nothing about whether any caller uses it.
async fn visible(pool: &PgPool, viewer: &Viewer, id: Uuid) -> bool {
    SemanticLinkRepository::get_by_id(pool, viewer, id.into())
        .await
        .expect("get_by_id must not error")
        .is_some()
}

// ===========================================================================
// 1 — the four endpoint combinations
// ===========================================================================

/// **public × public → `('public', world, co = NULL)`, visible to everyone.**
#[sqlx::test(migrations = "../../migrations")]
async fn both_endpoints_public_meets_at_public_and_is_visible_to_a_stranger(pool: PgPool) {
    let c = corpus(&pool).await;
    let edge = seed_edge(&pool, c.public_a, c.public_b).await;

    assert_eq!(
        edge_tenancy(&pool, edge).await,
        (WORLD, "public".to_string(), None)
    );
    assert!(visible(&pool, &c.stranger, edge).await);
    assert!(visible(&pool, &c.in_both, edge).await);
}

/// **public × group G → `('group', G, co = NULL)`.**
///
/// The single-owner private case: G sees it, H does not, a stranger does not.
/// H's exclusion is what the plain `predicate_fragment` already gave; it is
/// asserted here so the four-way table is complete rather than assumed.
#[sqlx::test(migrations = "../../migrations")]
async fn one_public_endpoint_meets_at_the_other_endpoints_group(pool: PgPool) {
    let c = corpus(&pool).await;
    let edge = seed_edge(&pool, c.public_a, c.claim_g).await;

    assert_eq!(
        edge_tenancy(&pool, edge).await,
        (c.group_g, "group".to_string(), None)
    );
    assert!(visible(&pool, &c.in_g, edge).await, "G owns it");
    assert!(visible(&pool, &c.in_both, edge).await, "so does the union");
    assert!(!visible(&pool, &c.in_h, edge).await, "H does not own it");
    assert!(!visible(&pool, &c.stranger, edge).await);
}

/// **group G × group G → `('group', G, co = NULL)`.**
///
/// Same group on both ends is NOT co-ownership: `co_owner_group_id` must stay
/// NULL. `edges_co_owner_shape` requires `co_owner_group_id <> owner_group_id`,
/// so a stamp of `(G, G)` would be a 23514 raised from a trigger.
#[sqlx::test(migrations = "../../migrations")]
async fn both_endpoints_in_one_group_is_single_owned_not_co_owned(pool: PgPool) {
    let c = corpus(&pool).await;
    let other_g = fixture::seed_group_claim(&pool, c.author, c.group_g, "G's other claim").await;
    let edge = seed_edge(&pool, c.claim_g, other_g).await;

    assert_eq!(
        edge_tenancy(&pool, edge).await,
        (c.group_g, "group".to_string(), None),
        "one group on both ends is single ownership; a co-owner equal to the \
         owner would violate edges_co_owner_shape"
    );
    assert!(visible(&pool, &c.in_g, edge).await);
    assert!(!visible(&pool, &c.in_h, edge).await);
}

/// **group G × group H → `('group', G, co = H)` — PR-13's acceptance criterion,
/// both halves.**
///
/// *"An edge between a group-G claim and a group-H claim is stored as
/// `('group', G, co_owner = H)`; a viewer in G but not H cannot see it; a
/// viewer in both can."*
///
/// The INSERT here is the write that migration 070 arm (b) HARD-FAILED with
/// `23514: edge spans groups % and %`. That failure was not theoretical — 070's
/// comment records it becoming reachable the moment 071's transcription made
/// two claims genuinely `('group', G)` with different owners, at which point
/// every cross-owner `link_epistemic` / `link_hierarchical` / decomposition
/// write started failing. `.expect(...)` below is the closing of that window.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cross_group_edge_is_co_owned_and_needs_membership_in_both(pool: PgPool) {
    let c = corpus(&pool).await;

    // Would have raised 23514 before migration 072.
    let edge = seed_edge(&pool, c.claim_g, c.claim_h).await;

    assert_eq!(
        edge_tenancy(&pool, edge).await,
        (c.group_g, "group".to_string(), Some(c.group_h)),
        "the acceptance criterion: ('group', G, co_owner = H)"
    );

    // NEGATIVE — the half the co-ownership column exists for. Under the plain
    // single-owner predicate `in_g` WOULD see this row: it matches on
    // `owner_group_id = G`. The INTERSECTION is what stops it.
    assert!(
        !visible(&pool, &c.in_g, edge).await,
        "a viewer in G but not H must not see an edge whose far endpoint is H's \
         private claim — this is the assertion the co-ownership column exists to \
         make true, and it FAILS under the single-owner predicate"
    );
    assert!(
        !visible(&pool, &c.in_h, edge).await,
        "and symmetrically for H, which is not even the edge's owner_group_id"
    );
    assert!(!visible(&pool, &c.stranger, edge).await);

    // POSITIVE — without this the whole file would pass over a fragment that
    // matched nothing at all.
    assert!(
        visible(&pool, &c.in_both, edge).await,
        "a viewer in BOTH G and H must see it: the co-ownership predicate is an \
         intersection, not a blanket denial. If this fails the fragment is \
         over-restricting, which every negative assertion above would happily \
         permit"
    );
}

// ===========================================================================
// 2 — the privatization path (arm d), including the outage this must not cause
// ===========================================================================

/// **Privatizing two public endpoints into different groups in ONE statement
/// co-owns the edge instead of picking a side.**
///
/// The read-side half of
/// `tenancy_triggers.rs::arm_d_co_owns_a_cross_group_edge_rather_than_picking_a_side`.
/// Before migration 072 the edge was left stale at `('public', world)` — which
/// meant a public edge naming two now-private claims, readable by a stranger.
#[sqlx::test(migrations = "../../migrations")]
async fn privatizing_both_endpoints_into_different_groups_co_owns_the_edge(pool: PgPool) {
    let c = corpus(&pool).await;
    let edge = seed_edge(&pool, c.public_a, c.public_b).await;
    assert!(
        visible(&pool, &c.stranger, edge).await,
        "precondition: it starts public"
    );

    sqlx::query(
        "UPDATE claims SET owner_group_id = CASE WHEN id = $1 THEN $2 ELSE $3 END, \
                           visibility = 'group' \
          WHERE id IN ($1, $4)",
    )
    .bind(c.public_a)
    .bind(c.group_g)
    .bind(c.group_h)
    .bind(c.public_b)
    .execute(&pool)
    .await
    .expect("a cross-group privatization must not raise from arm (d)");

    assert_eq!(
        edge_tenancy(&pool, edge).await,
        (c.group_g, "group".to_string(), Some(c.group_h))
    );
    assert!(
        !visible(&pool, &c.stranger, edge).await,
        "privatizing both endpoints must take the edge with them"
    );
    assert!(!visible(&pool, &c.in_g, edge).await);
    assert!(visible(&pool, &c.in_both, edge).await);
}

/// **Declassifying one endpoint of a co-owned edge CLEARS the co-owner — and
/// does not take the database down.**
///
/// This is the assertion that pins migration 072's most load-bearing detail,
/// and it is the one a plausible-looking simplification breaks.
///
/// The co-owner CASE is
/// `WHEN s.v = 'group' AND t.v = 'group' AND s.g <> t.g THEN t.g ELSE NULL`.
/// Written as the shorter `WHEN s.g <> t.g THEN t.g` it looks equivalent — but
/// trace this test: the edge is `(owner = G, co = H)`, then G's endpoint is
/// declassified to public. The meet collapses to `(H, 'group')`, and the short
/// form leaves `t.g = H` in `co_owner_group_id`, producing
/// `(owner = H, co_owner = H)`. `edges_co_owner_shape` requires
/// `co_owner_group_id <> owner_group_id`, so that raises **23514 from a
/// statement-level `AFTER UPDATE` trigger on `claims`** — not a rejected edge,
/// a failed `UPDATE claims`. Every privatization touching such an edge would
/// fail, which is precisely the outage migration 070's arm (d) comment says
/// this arm must never cause. `NOT VALID` does not help: it skips the backfill
/// scan, not new writes.
///
/// The `.expect` below is therefore as load-bearing as the assertions.
#[sqlx::test(migrations = "../../migrations")]
async fn declassifying_one_endpoint_of_a_co_owned_edge_clears_the_co_owner(pool: PgPool) {
    let c = corpus(&pool).await;
    let edge = seed_edge(&pool, c.claim_g, c.claim_h).await;
    assert_eq!(
        edge_tenancy(&pool, edge).await,
        (c.group_g, "group".to_string(), Some(c.group_h)),
        "precondition: co-owned"
    );

    // PR-16: declassification now needs the admin GUC. Migration 074 adds
    // `claims_block_widening`, which refuses a group→public UPDATE unless
    // `epigraph.allow_declassify = 'yes'` — the GUC the admin declassification
    // surface sets. The GUC is SESSION-scoped, so it and the UPDATE must ride
    // the SAME connection; issuing the SET on the pool would land on an
    // arbitrary one and the UPDATE would be refused intermittently.
    //
    // This does NOT weaken what the test is about. The assertion below is about
    // arm (d)'s edge recomputation, and the thing it must not do is RAISE — a
    // 42501 from `claims_block_widening` is the guard doing its job on the
    // caller's statement, not arm (d) failing on the cascade. Taking the
    // documented admin path is what puts the test back on the path a
    // privatization job actually takes.
    {
        use sqlx::Executor;
        let mut conn = pool.acquire().await.expect("acquire");
        conn.execute("SET epigraph.allow_declassify = 'yes'")
            .await
            .expect("set the admin declassification GUC");
        sqlx::query("UPDATE claims SET owner_group_id = $1, visibility = 'public' WHERE id = $2")
            .bind(WORLD)
            .bind(c.claim_g)
            .execute(&mut *conn)
            .await
            .expect(
                "declassifying one endpoint of a CO-OWNED edge must not raise: an \
                 exception from arm (d) is a write outage on privatization, not a \
                 rejected row",
            );
    }

    assert_eq!(
        edge_tenancy(&pool, edge).await,
        (c.group_h, "group".to_string(), None),
        "the meet collapsed to H alone, so co_owner_group_id must be NULL"
    );
    assert!(
        visible(&pool, &c.in_h, edge).await,
        "H now owns the edge outright and must be able to read it"
    );
    assert!(
        !visible(&pool, &c.in_g, edge).await,
        "G's endpoint went public but H's did not; the edge is H's"
    );
    assert!(!visible(&pool, &c.stranger, edge).await);
}

/// **Declassifying BOTH endpoints does not widen a co-owned edge.**
///
/// Arm (d)'s no-widening guard, carried through 072 unchanged. Widening on
/// declassification is PR-16's business (migration 074, alongside
/// `claims_block_widening`); until then the fail-closed answer is that the edge
/// keeps its ownership.
#[sqlx::test(migrations = "../../migrations")]
async fn declassifying_both_endpoints_does_not_widen_a_co_owned_edge(pool: PgPool) {
    let c = corpus(&pool).await;
    let edge = seed_edge(&pool, c.claim_g, c.claim_h).await;

    // PR-16: same as the single-endpoint case above — migration 074's
    // `claims_block_widening` requires the admin GUC, and it is session-scoped
    // so it must share the UPDATE's connection.
    {
        use sqlx::Executor;
        let mut conn = pool.acquire().await.expect("acquire");
        conn.execute("SET epigraph.allow_declassify = 'yes'")
            .await
            .expect("set the admin declassification GUC");
        sqlx::query(
            "UPDATE claims SET owner_group_id = $1, visibility = 'public' WHERE id IN ($2, $3)",
        )
        .bind(WORLD)
        .bind(c.claim_g)
        .bind(c.claim_h)
        .execute(&mut *conn)
        .await
        .expect("declassifying both endpoints must not raise");
    }

    let (_, vis, _) = edge_tenancy(&pool, edge).await;
    assert_eq!(
        vis, "group",
        "arm (d) never widens; a group-private edge stays group-private even \
         when the meet of its endpoints would now be public"
    );
    assert!(!visible(&pool, &c.stranger, edge).await);
}

// ===========================================================================
// 3 — the fragment reaches more than one caller
// ===========================================================================

/// **A co-owned edge is filtered on the `EdgeRepository` macro path too.**
///
/// `SemanticLinkRepository::get_by_id` (used by `visible` above) is spliced;
/// the eleven `EdgeRepository` reads are `sqlx::query!` macro sites carrying
/// the STATIC transcription of the same fragment, because `sqlx::query!` needs
/// a compile-time literal of fixed arity and cannot be spliced. Two spellings
/// of one rule is two places to get it wrong, so both are exercised.
///
/// `count_for_entity` is chosen over a row-returning read on purpose: a COUNT
/// leaks by arithmetic rather than by content, and PR-08 recorded exactly that
/// class of finding (`F-aggregate-existence-oracles`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_macro_read_path_filters_a_co_owned_edge_the_same_way(pool: PgPool) {
    let c = corpus(&pool).await;
    let _edge = seed_edge(&pool, c.claim_g, c.claim_h).await;

    let count = |v: &'static str, viewer: Viewer| {
        let pool = pool.clone();
        async move {
            let n = EdgeRepository::count_for_entity(&pool, &viewer, c.claim_g, "claim")
                .await
                .unwrap_or_else(|e| panic!("count_for_entity as {v}: {e}"));
            n
        }
    };

    assert_eq!(
        count("in_g", c.in_g).await,
        0,
        "a viewer in G alone must not be able to COUNT an edge it cannot read — \
         a count is an existence oracle for the far endpoint"
    );
    assert_eq!(count("in_h", c.in_h).await, 0);
    assert_eq!(count("stranger", c.stranger).await, 0);
    assert_eq!(
        count("in_both", c.in_both).await,
        1,
        "and a viewer in both groups must still count it"
    );
}

/// **`get_by_source` / `get_by_target` agree with the count.**
///
/// Row-returning reads on the same macro path, asserted in both directions
/// because the edge's two endpoints are in DIFFERENT groups and a predicate
/// that accidentally keyed off the source alone would pass a source-only test.
#[sqlx::test(migrations = "../../migrations")]
async fn the_row_returning_macro_reads_agree_from_both_directions(pool: PgPool) {
    let c = corpus(&pool).await;
    seed_edge(&pool, c.claim_g, c.claim_h).await;

    for (label, viewer, expected) in [
        ("in_g", &c.in_g, 0usize),
        ("in_h", &c.in_h, 0),
        ("stranger", &c.stranger, 0),
        ("in_both", &c.in_both, 1),
    ] {
        let from_source = EdgeRepository::get_by_source(&pool, viewer, c.claim_g, "claim")
            .await
            .unwrap_or_else(|e| panic!("get_by_source as {label}: {e}"));
        let from_target = EdgeRepository::get_by_target(&pool, viewer, c.claim_h, "claim")
            .await
            .unwrap_or_else(|e| panic!("get_by_target as {label}: {e}"));
        assert_eq!(from_source.len(), expected, "get_by_source as {label}");
        assert_eq!(from_target.len(), expected, "get_by_target as {label}");
    }
}

// ===========================================================================
// 4 — the fragment does not over-restrict the common case
// ===========================================================================

/// **A single-owner edge is unaffected by the co-ownership conjunct.**
///
/// `co_owner_group_id IS NULL` is the overwhelming majority of rows, and the
/// disjunct that keeps them visible is the difference between "an intersection"
/// and "a second mandatory membership test". A fragment that required a
/// co-owner match unconditionally would hide EVERY private edge in the corpus
/// from its own owner — silently, and only in production, since a fixture that
/// never sets a co-owner would not notice.
#[sqlx::test(migrations = "../../migrations")]
async fn a_single_owner_edge_is_untouched_by_the_co_ownership_conjunct(pool: PgPool) {
    let c = corpus(&pool).await;
    let other_g = fixture::seed_group_claim(&pool, c.author, c.group_g, "G again").await;
    let private = seed_edge(&pool, c.claim_g, other_g).await;
    let public = seed_edge(&pool, c.public_a, c.public_b).await;

    assert!(
        visible(&pool, &c.in_g, private).await,
        "G reads its own edge"
    );
    assert!(visible(&pool, &c.in_both, private).await);
    assert!(!visible(&pool, &c.in_h, private).await);

    assert!(visible(&pool, &c.in_g, public).await);
    assert!(visible(&pool, &c.stranger, public).await);
}

/// **A `Bypass` viewer sees every shape.**
///
/// The maintenance path emits no predicate at all, so co-ownership must not
/// become a way for a background job to silently skip rows —
/// `reference_monitor` failures of that shape (an enumerator that quietly
/// enumerates nothing) are the reason `EXPECTED_EXEMPTIONS` exists in
/// `visibility_lint.rs`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bypass_viewer_sees_a_co_owned_edge(pool: PgPool) {
    let c = corpus(&pool).await;
    let edge = seed_edge(&pool, c.claim_g, c.claim_h).await;

    let (_scoped, bypass) = fixture::bypass(&pool).await;
    assert!(visible(&pool, &bypass, edge).await);
    assert_eq!(
        EdgeRepository::count_for_entity(&pool, &bypass, c.claim_g, "claim")
            .await
            .expect("count as bypass"),
        1
    );
}

// ===========================================================================
// 5 — the CHECK is enforced on new writes despite NOT VALID
// ===========================================================================

/// **`edges_co_owner_shape` rejects a malformed co-ownership stamp, and the
/// repo layer classifies it as a CHECK violation rather than a server fault.**
///
/// `NOT VALID` skips the backfill scan of existing rows; it does NOT stop
/// enforcement on new writes, and the difference matters because PR-16's 075/076
/// are what validate these constraints. A direct `UPDATE` is used rather than an
/// INSERT because arm (b) rewrites `NEW.co_owner_group_id` on every INSERT and
/// would repair the malformed value before the CHECK ever ran — the trigger is
/// not the control being tested here.
///
/// The classification half is PR-13's other deliverable. Migration 070 asked for
/// "ERRCODE 23514 ... so the API/MCP layer can map it to a 4xx instead of
/// surfacing a bare 500", and before this PR
/// `From<sqlx::Error> for DbError` had arms for 23505 and 23503 only, so 23514
/// fell through to `QueryFailed` → `ApiError::DatabaseError` → HTTP 500.
#[sqlx::test(migrations = "../../migrations")]
async fn a_malformed_co_owner_is_a_check_violation_not_a_query_failure(pool: PgPool) {
    let c = corpus(&pool).await;
    let edge = seed_edge(&pool, c.claim_g, c.claim_h).await;

    // owner = co_owner. Forbidden: it is not co-ownership, and under the read
    // fragment it would be an extra membership test against a group the row
    // already names.
    let err = sqlx::query("UPDATE edges SET co_owner_group_id = owner_group_id WHERE id = $1")
        .bind(edge)
        .execute(&pool)
        .await
        .expect_err("edges_co_owner_shape must reject co_owner = owner");

    let classified = epigraph_db::DbError::from(err);
    match &classified {
        epigraph_db::DbError::CheckViolation {
            constraint,
            message,
        } => {
            assert_eq!(
                constraint, "edges_co_owner_shape",
                "the constraint NAME is what tells a caller which rule it broke"
            );
            // And the driver's own message must survive classification. It is
            // the ONLY diagnostic for the 23514s that report no constraint
            // name — migration 071's memberless-group `RAISE ... USING ERRCODE
            // = '23514'` is one — and `epigraph-mcp` renders `DbError` through
            // `Display`, so losing it here blanks that surface entirely.
            assert!(
                !message.is_empty(),
                "the driver message must be captured at construction; a struct \
                 variant with no `#[source]` discards it permanently otherwise"
            );
            assert!(
                classified.to_string().contains(message.as_str()),
                "`Display` is what epigraph-mcp's internal_error renders: {classified}"
            );
        }
        other => panic!(
            "23514 must classify as DbError::CheckViolation, not {other:?} — \
             QueryFailed becomes HTTP 500, and this is a client error"
        ),
    }

    // And a co-owner on a PUBLIC edge is equally malformed: co-ownership is
    // meaningless without `visibility = 'group'`, and permitting it would make
    // the fragment's leading `visibility = 'public'` disjunct hand back a row
    // whose co-owner nobody checked.
    let public_edge = seed_edge(&pool, c.public_a, c.public_b).await;
    let err = sqlx::query("UPDATE edges SET co_owner_group_id = $1 WHERE id = $2")
        .bind(c.group_h)
        .bind(public_edge)
        .execute(&pool)
        .await
        .expect_err("a co-owner on a public edge must be rejected");
    assert!(
        matches!(
            epigraph_db::DbError::from(err),
            epigraph_db::DbError::CheckViolation { .. }
        ),
        "a co-owner without visibility = 'group' is a CHECK violation"
    );
}
