//! `EvidenceRepository::linked_from_claim`, the read that closed `F-SEC14-A`,
//! driven under four viewer shapes.
//!
//! It backs `GET /api/v1/claims/:id/provenance`. It replaced two inline,
//! viewer-less `SELECT target_id FROM edges …` scans in that handler. The
//! route-level arms live in `epigraph-api/tests/shard6_routes_scoped_read.rs`.
//! This file covers what a route arm does not pin:
//!
//! * the bypass and anonymous (public-only) viewer shapes;
//! * the direction and type filters (claim is the SOURCE, evidence the TARGET),
//!   against edges seeded to fail each one;
//! * the order, which is the edge's `created_at`, then its id.
//!
//! Every statement runs on the `#[sqlx::test]` superuser pool, which bypasses
//! RLS. So everything asserted here is the in-query `$V` predicate that
//! `Viewer::splice` writes. Each hidden row is shaped so that ONE marker alone
//! can withhold it:
//!
//! * PUBLIC evidence behind an edge forced group-private, which only
//!   `{EDGE_VISIBILITY:ed}` can withhold;
//! * group-private evidence behind an edge forced PUBLIC, which only
//!   `{VISIBILITY:e}` can withhold.
//!
//! Edge tenancy is forced with an UPDATE after the INSERT, for the reason
//! `viewer_fixture::seed_edge_owned_by` gives: migration 070's trigger rewrites
//! the tenancy columns on every INSERT and does not fire on an UPDATE of only
//! `visibility` / `owner_group_id`.

mod viewer_fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::EvidenceRepository;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

/// An edge with explicit endpoint types and FORCED tenancy. `created_at` is
/// set to `now() - age_hours` explicitly, so the ordering assertion does not
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

#[sqlx::test(migrations = "../../migrations")]
async fn linked_from_claim_filters_the_edge_and_the_evidence(pool: PgPool) {
    let (outsider_agent, _outsider_group) =
        fixture::seed_agent_with_group(&pool, "lfc-outsider").await;
    let (member_agent, member_group) = fixture::seed_agent_with_group(&pool, "lfc-member").await;
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let outsider = Viewer::resolve(&pool, outsider_agent)
        .await
        .expect("resolve outsider");
    let member = Viewer::resolve(&pool, member_agent)
        .await
        .expect("resolve member");
    let public = fixture::public_viewer(&pool).await;
    let world = fixture::world_group(&pool).await;

    let subject = fixture::seed_public_claim(&pool, member_agent, "lfc: subject").await;

    // Readable by everyone: PUBLIC evidence behind a PUBLIC edge. The oldest.
    let public_host = fixture::seed_public_claim(&pool, member_agent, "lfc: public host").await;
    let visible = fixture::seed_evidence(&pool, public_host, "observation").await;
    seed_typed_edge(
        &pool,
        subject,
        "claim",
        visible,
        "evidence",
        "derived_from",
        "public",
        world,
        3,
    )
    .await;

    // PUBLIC evidence behind an edge private to `member_group`.
    let edge_hidden = fixture::seed_evidence(&pool, public_host, "document").await;
    seed_typed_edge(
        &pool,
        subject,
        "claim",
        edge_hidden,
        "evidence",
        "derived_from",
        "group",
        member_group,
        2,
    )
    .await;

    // Evidence private to `member_group` (inherited from its host claim)
    // behind a PUBLIC edge. The newest.
    let private_host =
        fixture::seed_group_claim(&pool, member_agent, member_group, "lfc: private host").await;
    let ev_hidden = fixture::seed_evidence(&pool, private_host, "figure").await;
    seed_typed_edge(
        &pool,
        subject,
        "claim",
        ev_hidden,
        "evidence",
        "derived_from",
        "public",
        world,
        1,
    )
    .await;

    // Noise, all PUBLIC, so only the direction and type filters can exclude it:
    // an evidence -> claim edge INTO the subject, a claim -> claim edge out of
    // it, and an evidence link from a different claim.
    let reverse = fixture::seed_evidence(&pool, public_host, "testimony").await;
    seed_typed_edge(
        &pool, reverse, "evidence", subject, "claim", "SUPPORTS", "public", world, 0,
    )
    .await;
    let other_claim = fixture::seed_public_claim(&pool, member_agent, "lfc: other claim").await;
    seed_typed_edge(
        &pool,
        subject,
        "claim",
        other_claim,
        "claim",
        "relates_to",
        "public",
        world,
        0,
    )
    .await;
    let elsewhere = fixture::seed_evidence(&pool, public_host, "reference").await;
    seed_typed_edge(
        &pool,
        other_claim,
        "claim",
        elsewhere,
        "evidence",
        "derived_from",
        "public",
        world,
        0,
    )
    .await;

    for (name, viewer) in [
        ("outsider", &outsider),
        ("public", &public),
        ("member", &member),
        ("bypass", &bypass),
    ] {
        let entitled = matches!(name, "member" | "bypass");
        let got: Vec<Uuid> = EvidenceRepository::linked_from_claim(&pool, viewer, subject)
            .await
            .expect("linked_from_claim")
            .into_iter()
            .map(|r| r.id)
            .collect();
        let want = if entitled {
            vec![visible, edge_hidden, ev_hidden]
        } else {
            vec![visible]
        };
        assert_eq!(
            got, want,
            "[{name}] the subject links to {visible} (public edge, public evidence), \
             {edge_hidden} (edge private to the member's group, public evidence: only \
             the edge predicate can withhold it) and {ev_hidden} (public edge, evidence \
             private to the member's group: only the evidence predicate can withhold \
             it), in that edge order. {reverse}, {other_claim} and {elsewhere} are \
             reached by edges in the wrong direction, of the wrong type or from another \
             claim, and must never appear"
        );
    }
}
