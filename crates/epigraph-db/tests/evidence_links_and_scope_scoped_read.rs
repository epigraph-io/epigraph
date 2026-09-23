//! The three repo reads that replaced `F-SHARD6-A1`'s inline route reads, each
//! driven under four viewer shapes.
//!
//! * `EdgeRepository::first_claim_linked_to_evidence`: `get_evidence`'s
//!   `claim_id`.
//! * `EdgeRepository::first_agent_linked_to_evidence`: `get_evidence`'s
//!   `agent_id`.
//! * `AnalysisRepository::has_scope_limited_evidence_for`:
//!   `hypothesis_status`'s `has_explicit_scope`.
//!
//! The route-level arms live in
//! `epigraph-api/tests/shard6_routes_scoped_read.rs`. This file covers what a
//! route cannot reach:
//!
//! * the claim-side marker on `has_scope_limited_evidence_for`, because
//!   `hypothesis_status` 404s on an unreadable claim before it asks;
//! * the bypass and anonymous (public-only) viewer shapes;
//! * that `first_claim_linked_to_evidence` filters BEFORE `LIMIT 1`, so a
//!   hidden earlier link does not mask a visible later one, and that its order
//!   is the earliest link first.
//!
//! Every statement runs on the `#[sqlx::test]` superuser pool, which bypasses
//! RLS. So everything asserted here is the in-query `$V` predicate
//! `Viewer::splice` writes, which is the control this change adds. Each seeded
//! row is shaped so that ONE marker alone can withhold it:
//!
//! * a PUBLIC endpoint behind an edge forced group-private, which only
//!   `{EDGE_VISIBILITY:e}` can withhold;
//! * a group-private claim behind an edge forced PUBLIC, which only
//!   `{VISIBILITY:c}` can withhold.
//!
//! Edge tenancy is forced with an UPDATE after the INSERT, for the reason
//! `viewer_fixture::seed_edge_owned_by` gives: migration 070's trigger rewrites
//! the tenancy columns on every INSERT and does not fire on an UPDATE of only
//! `visibility` / `owner_group_id`. An edge left to the trigger tracks its
//! endpoints, and an arm built that way can pass on the claim predicate alone
//! with the edge predicate deleted.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{AnalysisRepository, EdgeRepository};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

/// An edge with explicit endpoint types and FORCED tenancy. `created_at` is
/// set to `now() - age_hours` explicitly, so an ordering assertion does not
/// rest on two `now()` calls being distinct.
#[allow(clippy::too_many_arguments)]
async fn seed_typed_edge(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    target_type: &str,
    relationship: &str,
    visibility: &str,
    owner_group_id: Uuid,
    age_hours: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed typed edge");

    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL, \
                          created_at = now() - make_interval(hours => $4) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(visibility)
    .bind(owner_group_id)
    .bind(age_hours)
    .execute(pool)
    .await
    .expect("force typed edge tenancy");
    id
}

/// An `analyses` row with the given `properties`. `analyses` has no tenancy
/// columns, so none are declared.
async fn seed_analysis(pool: &PgPool, agent: Uuid, properties: serde_json::Value) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO analyses (analysis_type, method_description, agent_id, properties) \
         VALUES ('statistical', 'seeded by evidence_links_and_scope_scoped_read', $1, $2) \
         RETURNING id",
    )
    .bind(agent)
    .bind(properties)
    .fetch_one(pool)
    .await
    .expect("seed analysis")
}

/// The four viewer shapes every arm runs under.
struct Viewers {
    outsider_agent: Uuid,
    member_agent: Uuid,
    member_group: Uuid,
    outsider: Viewer,
    member: Viewer,
    public: Viewer,
    bypass: Viewer,
    // Held so the bypass viewer's pool stays open for the whole test.
    _scoped: epigraph_db::ScopedPool,
}

impl Viewers {
    async fn new(pool: &PgPool, label: &str) -> Self {
        let (outsider_agent, _outsider_group) =
            fixture::seed_agent_with_group(pool, &format!("{label}-outsider")).await;
        let (member_agent, member_group) =
            fixture::seed_agent_with_group(pool, &format!("{label}-member")).await;
        let (scoped, bypass) = fixture::bypass(pool).await;
        Self {
            outsider_agent,
            member_agent,
            member_group,
            outsider: Viewer::resolve(pool, outsider_agent)
                .await
                .expect("resolve outsider"),
            member: Viewer::resolve(pool, member_agent)
                .await
                .expect("resolve member"),
            public: fixture::public_viewer(pool).await,
            bypass,
            _scoped: scoped,
        }
    }

    /// `(name, viewer)` in a fixed order, so a failure names the shape.
    fn all(&self) -> [(&'static str, &Viewer); 4] {
        [
            ("outsider", &self.outsider),
            ("public", &self.public),
            ("member", &self.member),
            ("bypass", &self.bypass),
        ]
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_claim_linked_to_evidence_filters_the_link_and_the_claim(pool: PgPool) {
    let v = Viewers::new(&pool, "fcl").await;
    let world = fixture::world_group(&pool).await;

    let host = fixture::seed_public_claim(&pool, v.outsider_agent, "fcl: public host").await;
    let edge_hidden = fixture::seed_evidence(&pool, host, "figure").await;
    let claim_hidden = fixture::seed_evidence(&pool, host, "document").await;
    let ordered = fixture::seed_evidence(&pool, host, "observation").await;

    // A PUBLIC claim behind a link private to `member_group`.
    let public_linker =
        fixture::seed_public_claim(&pool, v.member_agent, "fcl: public linker").await;
    seed_typed_edge(
        &pool,
        public_linker,
        "claim",
        edge_hidden,
        "evidence",
        "derived_from",
        "group",
        v.member_group,
        0,
    )
    .await;

    // A claim private to `member_group` behind a PUBLIC link.
    let private_linker =
        fixture::seed_group_claim(&pool, v.member_agent, v.member_group, "fcl: private linker")
            .await;
    seed_typed_edge(
        &pool,
        private_linker,
        "claim",
        claim_hidden,
        "evidence",
        "derived_from",
        "public",
        world,
        0,
    )
    .await;

    // FILTER, THEN PICK. The EARLIER link (an hour old) is private on both
    // counts; the LATER one is public on both. A lookup that took the first
    // link and then checked it would return None to the outsider.
    seed_typed_edge(
        &pool,
        private_linker,
        "claim",
        ordered,
        "evidence",
        "derived_from",
        "group",
        v.member_group,
        1,
    )
    .await;
    let later_public =
        fixture::seed_public_claim(&pool, v.outsider_agent, "fcl: later public linker").await;
    seed_typed_edge(
        &pool,
        later_public,
        "claim",
        ordered,
        "evidence",
        "derived_from",
        "public",
        world,
        0,
    )
    .await;

    for (name, viewer) in v.all() {
        let entitled = matches!(name, "member" | "bypass");

        let got = EdgeRepository::first_claim_linked_to_evidence(&pool, viewer, edge_hidden)
            .await
            .expect("claim link lookup");
        assert_eq!(
            got,
            entitled.then_some(public_linker),
            "[{name}] {edge_hidden}'s only claim link is an edge private to the member's \
             group, from a PUBLIC claim. Only the edge predicate can withhold it"
        );

        let got = EdgeRepository::first_claim_linked_to_evidence(&pool, viewer, claim_hidden)
            .await
            .expect("claim link lookup");
        assert_eq!(
            got,
            entitled.then_some(private_linker),
            "[{name}] {claim_hidden}'s only claim link is a PUBLIC edge from a claim private \
             to the member's group. Only the claim predicate can withhold it"
        );

        let got = EdgeRepository::first_claim_linked_to_evidence(&pool, viewer, ordered)
            .await
            .expect("claim link lookup");
        let want = if entitled {
            private_linker
        } else {
            later_public
        };
        assert_eq!(
            got,
            Some(want),
            "[{name}] {ordered} has an earlier private link and a later public one. A \
             viewer entitled to both gets the EARLIEST; any other viewer gets the later \
             public link, not None, because the predicates run before LIMIT 1"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_agent_linked_to_evidence_filters_the_link(pool: PgPool) {
    let v = Viewers::new(&pool, "fal").await;
    let world = fixture::world_group(&pool).await;

    let host = fixture::seed_public_claim(&pool, v.outsider_agent, "fal: public host").await;
    let private_link = fixture::seed_evidence(&pool, host, "figure").await;
    let public_link = fixture::seed_evidence(&pool, host, "document").await;

    // Agents are world-readable (migration 077's `agents_identity USING
    // (true)`), so the LINK is the only private thing and the edge predicate
    // the only control.
    seed_typed_edge(
        &pool,
        v.member_agent,
        "agent",
        private_link,
        "evidence",
        "submitted",
        "group",
        v.member_group,
        0,
    )
    .await;
    seed_typed_edge(
        &pool,
        v.outsider_agent,
        "agent",
        public_link,
        "evidence",
        "submitted",
        "public",
        world,
        0,
    )
    .await;

    for (name, viewer) in v.all() {
        let entitled = matches!(name, "member" | "bypass");

        let got = EdgeRepository::first_agent_linked_to_evidence(&pool, viewer, private_link)
            .await
            .expect("agent link lookup");
        assert_eq!(
            got,
            entitled.then_some(v.member_agent),
            "[{name}] {private_link}'s only agent link is private to the member's group"
        );

        let got = EdgeRepository::first_agent_linked_to_evidence(&pool, viewer, public_link)
            .await
            .expect("agent link lookup");
        assert_eq!(
            got,
            Some(v.outsider_agent),
            "[{name}] over-suppression check: {public_link}'s agent link is public, so \
             every viewer must get it"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn has_scope_limited_evidence_for_filters_the_link_and_the_claim(pool: PgPool) {
    let v = Viewers::new(&pool, "hsl").await;
    let world = fixture::world_group(&pool).await;

    let scoped = serde_json::json!({ "scope_limitations": ["n < 30, single site"] });

    // A PUBLIC hypothesis whose only scope evidence is behind a link private to
    // `member_group`. Only the edge predicate can withhold it.
    let edge_hidden = fixture::seed_public_claim(&pool, v.outsider_agent, "hsl: edge hidden").await;
    let a1 = seed_analysis(&pool, v.member_agent, scoped.clone()).await;
    seed_typed_edge(
        &pool,
        a1,
        "analysis",
        edge_hidden,
        "claim",
        "provides_evidence",
        "group",
        v.member_group,
        0,
    )
    .await;

    // A hypothesis private to `member_group` whose scope evidence is behind a
    // PUBLIC link. Only the claim predicate can withhold it. The route never
    // reaches this case, because it 404s on the claim first.
    let claim_hidden =
        fixture::seed_group_claim(&pool, v.member_agent, v.member_group, "hsl: claim hidden").await;
    let a2 = seed_analysis(&pool, v.member_agent, scoped.clone()).await;
    seed_typed_edge(
        &pool,
        a2,
        "analysis",
        claim_hidden,
        "claim",
        "provides_evidence",
        "public",
        world,
        0,
    )
    .await;

    // Over-suppression: public on every count, so every viewer must see it.
    let all_public = fixture::seed_public_claim(&pool, v.outsider_agent, "hsl: public").await;
    let a3 = seed_analysis(&pool, v.outsider_agent, scoped.clone()).await;
    seed_typed_edge(
        &pool,
        a3,
        "analysis",
        all_public,
        "claim",
        "provides_evidence",
        "public",
        world,
        0,
    )
    .await;

    // The body's own filter, unchanged by this fix: an empty list and an
    // absent key are not scope limitations, even for the bypass viewer.
    let no_scope = fixture::seed_public_claim(&pool, v.outsider_agent, "hsl: no scope").await;
    for props in [
        serde_json::json!({ "scope_limitations": [] }),
        serde_json::json!({}),
    ] {
        let a = seed_analysis(&pool, v.outsider_agent, props).await;
        seed_typed_edge(
            &pool,
            a,
            "analysis",
            no_scope,
            "claim",
            "provides_evidence",
            "public",
            world,
            0,
        )
        .await;
    }

    for (name, viewer) in v.all() {
        let entitled = matches!(name, "member" | "bypass");

        let got = AnalysisRepository::has_scope_limited_evidence_for(&pool, viewer, edge_hidden)
            .await
            .expect("scope lookup");
        assert_eq!(
            got, entitled,
            "[{name}] {edge_hidden}'s only scope evidence is behind a link private to the \
             member's group"
        );

        let got = AnalysisRepository::has_scope_limited_evidence_for(&pool, viewer, claim_hidden)
            .await
            .expect("scope lookup");
        assert_eq!(
            got, entitled,
            "[{name}] {claim_hidden} is private to the member's group. A viewer who may not \
             read it must get false, not one bit about its evidence"
        );

        let got = AnalysisRepository::has_scope_limited_evidence_for(&pool, viewer, all_public)
            .await
            .expect("scope lookup");
        assert!(
            got,
            "[{name}] over-suppression check: {all_public} and its scope evidence are public"
        );

        let got = AnalysisRepository::has_scope_limited_evidence_for(&pool, viewer, no_scope)
            .await
            .expect("scope lookup");
        assert!(
            !got,
            "[{name}] {no_scope}'s analyses carry an empty or absent scope_limitations, \
             which the body does not count"
        );
    }
}
