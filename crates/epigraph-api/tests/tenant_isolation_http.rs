//! PR-07 — tenant isolation for the HTTP read paths converted in this PR.
//!
//! # What this file proves, and what it deliberately does not
//!
//! Each test drives the **repo function that a converted handler now calls**,
//! with two viewers over the same corpus:
//!
//! * a `Scoped` viewer resolved for an agent that owns a group, and
//! * `fixture::public_viewer` — a `Scoped` viewer over the NIL principal with
//!   an empty group set, i.e. exactly the authority a stranger's token yields.
//!
//! A `visibility = 'group'` claim must be visible to the first and invisible to
//! the second. That is the property PR-07 exists to create, and it is asserted
//! at the layer where the predicate actually lives.
//!
//! **Why at the repo layer?** Because that is where the predicate lives, and a
//! stranger-cannot-read assertion is sharpest there. Every test below executes
//! its repo function, so `Viewer::splice`'s runtime assert — which panics if a
//! read accepts a `&Viewer` and its SQL carries no `{VISIBILITY:...}` marker —
//! fires for real. A marker deleted from any of these statements turns these
//! tests red rather than silently reopening the leak.
//!
//! # Correction: repo-level testing is NECESSARY BUT NOT SUFFICIENT
//!
//! An earlier version of this comment argued that an HTTP round trip adds
//! nothing, on the grounds that "the wiring is held by the compiler — a handler
//! cannot name `viewer` without taking the extractor". **That argument is
//! false, and PR-07 contains its counterexample.** `belief.rs::frame_claims_sorted`
//! took a `ViewerExtractor`, spent the viewer on an unrelated frame-existence
//! check, and then built its claim-content query with `format!` +
//! `sqlx::query_as` — no marker, no `splice`, no panic, and a green repo suite.
//! Naming `viewer` proves the extractor is present; it proves nothing about
//! whether the read filters on it.
//!
//! Three things were added rather than arguing the point:
//!
//! * The two `#[tokio::test]` cases at the bottom of *this* file — real HTTP
//!   round trips for `GET /api/v1/claims/by-belief` and
//!   `GET /api/v1/frames/:id/claims`, the two handlers that held a `Viewer` and
//!   did not filter on it. They are the regression guard a repo-level test
//!   could not be, for the reason given in the comment above them.
//! * `tests/viewer_route_table_lint.rs` — a source lint asserting that no
//!   `sqlx::query*` in `src/routes/` selects claim content, with a dated
//!   exemption list. That is what actually catches the `frame_claims_sorted`
//!   shape, because it checks *where the SQL lives* rather than which
//!   extractors a signature declares.
//! * `tests/pr07_acceptance_http.rs` — real `spawn_app` round trips for the two
//!   acceptance criteria that are statements about a response *body*
//!   (`/themes/:id/embeddings` returning no raw vectors; `/challenges` leaking
//!   no foreign `explanation`). Neither is visible from the repo layer at all.
//!
//! # Coverage boundary
//!
//! These cover the reads PR-07 converted. They do NOT cover the graph
//! cluster/run metadata (`graph_clusters`, `graph_neighborhoods`,
//! `cluster_edges`, `neighborhood_edges`), which carry no tenancy columns, or
//! the `edges` traversals inside the graph projections, which do and are the
//! module's recorded residual — see `epigraph_db::repos::graph_view`'s module
//! docs and the `F-edges-unfiltered` entry in `docs/tenancy/progress.json`
//! (assigned to PR-13).

use epigraph_db::visibility::Viewer;
use epigraph_db::{
    ClaimRepository, EvidenceRepository, GraphViewRepository, MassFunctionRepository,
};
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

/// Seed an agent with a personal group plus one `visibility = 'group'` claim
/// owned by it, and return `(owner_viewer, stranger_viewer, claim_id)`.
async fn private_corpus(pool: &PgPool, label: &str) -> (Viewer, Viewer, Uuid) {
    let (agent, group) = fixture::seed_agent_with_group(pool, label).await;
    let claim = fixture::seed_group_claim(pool, agent, group, "tenant-private content").await;

    let owner = Viewer::resolve(pool, agent)
        .await
        .expect("resolve owner viewer");
    let stranger = fixture::public_viewer(pool).await;

    (owner, stranger, claim)
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/claims/:id/history  →  ClaimRepository::version_history
// ─────────────────────────────────────────────────────────────────────────

/// The version walk must terminate at a link the viewer cannot see. A stranger
/// gets an empty chain — which `claim_history` renders as 404 — while the owner
/// gets the claim.
#[sqlx::test(migrations = "../../migrations")]
async fn version_history_hides_a_group_private_chain_from_a_stranger(pool: PgPool) {
    let (owner, stranger, claim) = private_corpus(&pool, "history").await;

    let seen = ClaimRepository::version_history(&pool, &owner, claim)
        .await
        .expect("owner version_history");
    assert_eq!(
        seen.len(),
        1,
        "the owner must see the claim it owns; got {seen:?}"
    );
    assert_eq!(seen[0].id, claim);
    assert_eq!(seen[0].content, "tenant-private content");

    let hidden = ClaimRepository::version_history(&pool, &stranger, claim)
        .await
        .expect("stranger version_history");
    assert!(
        hidden.is_empty(),
        "a stranger must not see a group-private claim's history; got {hidden:?}"
    );
}

/// A public claim stays readable by a stranger — the predicate must not narrow
/// the public corpus. Without this, a test suite passes just as well against a
/// read that returns nothing at all.
#[sqlx::test(migrations = "../../migrations")]
async fn version_history_still_returns_a_public_claim_to_a_stranger(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "history-pub").await;
    let claim = fixture::seed_public_claim(&pool, agent, "public content").await;
    let stranger = fixture::public_viewer(&pool).await;

    let seen = ClaimRepository::version_history(&pool, &stranger, claim)
        .await
        .expect("stranger version_history");
    assert_eq!(seen.len(), 1, "public claims stay readable; got {seen:?}");
    assert_eq!(seen[0].content, "public content");
}

/// A visible claim whose ANCESTOR is another tenant's must still be readable.
///
/// The backward walk stops at the first invisible link, so rooting the chain
/// at `supersedes IS NULL` would return nothing here and render 404 on a read
/// the caller is entitled to. Failing closed is not a licence to fail on
/// authorized reads: the chain is rooted at the deepest *visible* ancestor
/// instead, and the invisible revision is omitted rather than truncating the
/// result to empty.
#[sqlx::test(migrations = "../../migrations")]
async fn version_history_survives_an_invisible_ancestor(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "history-ancestor").await;
    let private_ancestor =
        fixture::seed_group_claim(&pool, agent, group, "other tenant's revision").await;
    let public_successor = fixture::seed_public_claim(&pool, agent, "public successor").await;

    sqlx::query("UPDATE claims SET supersedes = $1 WHERE id = $2")
        .bind(private_ancestor)
        .bind(public_successor)
        .execute(&pool)
        .await
        .expect("link supersession");

    let stranger = fixture::public_viewer(&pool).await;
    let seen = ClaimRepository::version_history(&pool, &stranger, public_successor)
        .await
        .expect("stranger version_history");

    assert_eq!(
        seen.len(),
        1,
        "the visible successor must still be returned; got {seen:?}"
    );
    assert_eq!(seen[0].id, public_successor);
    assert!(
        !seen.iter().any(|h| h.id == private_ancestor),
        "the group-private ancestor must not appear; got {seen:?}"
    );
    assert!(
        !seen.iter().any(|h| h.content == "other tenant's revision"),
        "the group-private ancestor's content must not appear; got {seen:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/query/rag  →  ClaimRepository::rag_hybrid_context
// ─────────────────────────────────────────────────────────────────────────

/// Semantic retrieval must not rank a group-private claim into a stranger's
/// results. This is the endpoint's whole risk profile: an attacker does not
/// need to know a claim id, only to submit a probe vector.
#[sqlx::test(migrations = "../../migrations")]
async fn rag_context_does_not_retrieve_a_group_private_claim_for_a_stranger(pool: PgPool) {
    let (owner, stranger, claim) = private_corpus(&pool, "rag").await;

    // Give the claim an embedding so it is a retrieval candidate at all.
    let vec_literal = pgvector_literal(1.0);
    sqlx::query("UPDATE claims SET embedding = $1::vector, truth_value = 0.9 WHERE id = $2")
        .bind(&vec_literal)
        .bind(claim)
        .execute(&pool)
        .await
        .expect("set embedding");

    let owner_hits =
        ClaimRepository::rag_hybrid_context(&pool, &owner, &vec_literal, 0.0, None, 10)
            .await
            .expect("owner rag_hybrid_context");
    assert!(
        owner_hits.iter().any(|h| h.claim_id == claim),
        "the owner must retrieve its own claim; got {owner_hits:?}"
    );

    let stranger_hits =
        ClaimRepository::rag_hybrid_context(&pool, &stranger, &vec_literal, 0.0, None, 10)
            .await
            .expect("stranger rag_hybrid_context");
    assert!(
        !stranger_hits.iter().any(|h| h.claim_id == claim),
        "a stranger must not retrieve a group-private claim; got {stranger_hits:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/search/evidence  →  EvidenceRepository::search_by_embedding
// ─────────────────────────────────────────────────────────────────────────

/// Evidence search is filtered on the evidence row AND its parent claim, so
/// evidence hanging off a group-private claim is invisible to a stranger even
/// when the evidence row itself is public.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_search_hides_evidence_of_a_group_private_claim(pool: PgPool) {
    let (owner, stranger, claim) = private_corpus(&pool, "evidence").await;

    let vec_literal = pgvector_literal(1.0);
    let evidence_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, claim_id, evidence_type, raw_content, content_hash, embedding) \
         VALUES ($1, $2, 'observation', 'private evidence body', $3, $4::vector)",
    )
    .bind(evidence_id)
    .bind(claim)
    .bind(vec![7u8; 32])
    .bind(&vec_literal)
    .execute(&pool)
    .await
    .expect("seed evidence");

    let owner_hits = EvidenceRepository::search_by_embedding(&pool, &owner, &vec_literal, 10)
        .await
        .expect("owner evidence search");
    assert!(
        owner_hits.iter().any(|h| h.id == evidence_id),
        "the owner must find evidence on its own claim; got {owner_hits:?}"
    );

    let stranger_hits = EvidenceRepository::search_by_embedding(&pool, &stranger, &vec_literal, 10)
        .await
        .expect("stranger evidence search");
    assert!(
        !stranger_hits.iter().any(|h| h.id == evidence_id),
        "a stranger must not find evidence of a group-private claim; got {stranger_hits:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/claims/:id/belief  →  MassFunctionRepository::count_for_claim
// ─────────────────────────────────────────────────────────────────────────

/// `ClaimRepository::get_belief_columns` already carried the predicate; this
/// pins that `claim_history`'s sibling read — the mass-function *count* — is
/// filtered too, so the endpoint cannot leak "how much evidence exists" for a
/// claim whose belief interval it correctly refuses to disclose.
#[sqlx::test(migrations = "../../migrations")]
async fn belief_reads_are_filtered_for_a_stranger(pool: PgPool) {
    let (owner, stranger, claim) = private_corpus(&pool, "belief").await;

    let owner_cols = ClaimRepository::get_belief_columns(
        &pool,
        &owner,
        epigraph_core::ClaimId::from_uuid(claim),
    )
    .await
    .expect("owner get_belief_columns");
    assert!(
        owner_cols.is_some(),
        "the owner must see its own claim's belief columns"
    );

    let stranger_cols = ClaimRepository::get_belief_columns(
        &pool,
        &stranger,
        epigraph_core::ClaimId::from_uuid(claim),
    )
    .await
    .expect("stranger get_belief_columns");
    assert!(
        stranger_cols.is_none(),
        "a stranger must get 404, not a belief interval"
    );

    // The count executes `count_for_claim`'s spliced SQL for real. With no
    // mass functions seeded both are 0; the assertion that matters here is
    // that the statement is valid and carries a marker (else `splice` panics).
    let count = MassFunctionRepository::count_for_claim(&pool, &stranger, claim)
        .await
        .expect("stranger count_for_claim");
    assert_eq!(count, 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Graph view projections  →  GraphViewRepository
// ─────────────────────────────────────────────────────────────────────────

/// `/graph/claims/:id/compound-neighborhood` fetches the centre's `content`
/// with nothing but the path id. Before PR-07 that was a content oracle for
/// any claim in the corpus.
#[sqlx::test(migrations = "../../migrations")]
async fn compound_center_content_is_hidden_from_a_stranger(pool: PgPool) {
    let (owner, stranger, claim) = private_corpus(&pool, "compound-center").await;

    let owner_seen = GraphViewRepository::compound_center_content(&pool, &owner, claim)
        .await
        .expect("owner compound_center_content");
    assert_eq!(owner_seen.as_deref(), Some("tenant-private content"));

    let stranger_seen = GraphViewRepository::compound_center_content(&pool, &stranger, claim)
        .await
        .expect("stranger compound_center_content");
    assert!(
        stranger_seen.is_none(),
        "a stranger must get 404 rather than the claim's content; got {stranger_seen:?}"
    );
}

/// Executes the remaining graph projections end to end so their spliced SQL is
/// parsed by Postgres and `Viewer::splice`'s marker assert runs.
///
/// These return empty without seeded cluster runs / neighborhoods / edges,
/// which is why this is a validity-and-marker test rather than an isolation
/// assertion; the isolation property for the rows they *do* return is the same
/// `{VISIBILITY:c}` predicate the tests above pin on `claims`.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_projections_execute_with_a_spliced_predicate(pool: PgPool) {
    let (_owner, stranger, _claim) = private_corpus(&pool, "graph-smoke").await;

    let nodes = GraphViewRepository::expand_cluster_nodes(
        &pool,
        &stranger,
        Uuid::new_v4(),
        Uuid::new_v4(),
        &["supports".to_string()],
        10,
    )
    .await
    .expect("expand_cluster_nodes must produce valid SQL");
    assert!(nodes.is_empty());

    let atomic = GraphViewRepository::neighborhood_atomic_nodes(&pool, &stranger, Uuid::new_v4())
        .await
        .expect("neighborhood_atomic_nodes must produce valid SQL");
    assert!(atomic.is_empty());

    // Both arms of this one's UNION ALL project claim content, so both must
    // splice; Postgres rejects the statement outright if either arm is
    // malformed, and `Viewer::splice` panics if either marker is missing.
    let compound =
        GraphViewRepository::neighborhood_compound_nodes(&pool, &stranger, Uuid::new_v4())
            .await
            .expect("neighborhood_compound_nodes must produce valid SQL");
    assert!(compound.is_empty());

    let neighbors = GraphViewRepository::compound_neighbors(&pool, &stranger, Uuid::new_v4(), 10)
        .await
        .expect("compound_neighbors must produce valid SQL");
    assert!(neighbors.is_empty());
}

/// A forked supersession chain must produce a **stable** order and a
/// **truthful** `superseded_by`.
///
/// Forks are reachable in normal operation, not exotic:
/// `ClaimRepository::mark_duplicate` sets `supersedes = <canonical>` on every
/// duplicate, so any canonical claim with two marked duplicates has two
/// children. Before this fix `version_history` ended `ORDER BY depth` — not a
/// total order — and `versioning.rs::claim_history` derived `superseded_by`
/// from row *position* ("the following row's id"). Two rows at the same depth
/// have no tiebreaker, so two identical `GET /claims/:id/history` requests
/// could return different version numbers and different `superseded_by` links
/// for the same claim, and at the fork point the positional link named an
/// arbitrary one of the two real children.
///
/// This asserts the invariant that fixes it: `superseded_by` is read from
/// `claims.supersedes`, so the fork's parent points at a claim that genuinely
/// supersedes it, and repeated calls agree.
#[sqlx::test(migrations = "../../migrations")]
async fn version_history_is_stable_and_truthful_across_a_fork(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "fork").await;
    let parent = fixture::seed_public_claim(&pool, agent, "fork parent").await;
    let child_a = fixture::seed_public_claim(&pool, agent, "fork child a").await;
    let child_b = fixture::seed_public_claim(&pool, agent, "fork child b").await;

    for child in [child_a, child_b] {
        sqlx::query("UPDATE claims SET supersedes = $1 WHERE id = $2")
            .bind(parent)
            .bind(child)
            .execute(&pool)
            .await
            .expect("point child at parent");
    }

    let stranger = fixture::public_viewer(&pool).await;
    let first = ClaimRepository::version_history(&pool, &stranger, parent)
        .await
        .expect("version_history over a fork");

    assert_eq!(
        first.len(),
        3,
        "the walk must return the parent and both branches; got {first:?}"
    );

    // Stability: the total order `(depth, id)` makes repeated calls identical.
    for _ in 0..3 {
        let again = ClaimRepository::version_history(&pool, &stranger, parent)
            .await
            .expect("repeat version_history");
        let a: Vec<Uuid> = first.iter().map(|h| h.id).collect();
        let b: Vec<Uuid> = again.iter().map(|h| h.id).collect();
        assert_eq!(
            a, b,
            "version_history order is not reproducible across calls"
        );
    }

    // Truthfulness: the parent's forward pointer must be one of its REAL
    // children, and each child must be a genuine leaf.
    let parent_row = first
        .iter()
        .find(|h| h.id == parent)
        .expect("parent is in the chain");
    let pointed = parent_row
        .superseded_by
        .expect("the parent IS superseded, so this must not be None");
    assert!(
        pointed == child_a || pointed == child_b,
        "superseded_by named {pointed}, which is neither real child \
         ({child_a} / {child_b}) — this is what positional inference got wrong"
    );

    for child in [child_a, child_b] {
        let row = first
            .iter()
            .find(|h| h.id == child)
            .expect("both children are in the chain");
        assert!(
            row.superseded_by.is_none(),
            "a leaf of the fork must have no successor; got {:?}",
            row.superseded_by
        );
    }
}

/// A REAL isolation assertion for the neighborhood projection, seeded with
/// actual rows.
///
/// The smoke test above passes identically whether the predicate filters
/// correctly, filters nothing, or filters everything — it asserts `is_empty()`
/// against freshly-generated UUIDs with no matching rows. That is worth keeping
/// (it proves the SQL parses in Postgres and that `splice`'s missing-marker
/// panic fires) but it is not an isolation test, and it was the only coverage
/// four of the six `GraphViewRepository` functions had.
///
/// This one seeds a neighborhood containing one public and one group-private
/// claim and asserts the stranger sees exactly the public one. It exercises
/// BOTH markers on that statement: `/* {VISIBILITY:c} */` on `claims` and
/// `/* {VISIBILITY:m} */` on `claim_neighborhood_membership` — the latter added
/// in PR-07 after review established that both membership tables are in
/// migration 062's `tier_a` array and so carry their own tenancy columns.
/// Without the membership marker a private *membership* row still discloses
/// that a claim belongs to this neighborhood.
#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_atomic_nodes_hides_a_group_private_member_from_a_stranger(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "nbhd-iso").await;
    let public_claim = fixture::seed_public_claim(&pool, agent, "nbhd public content").await;
    let private_claim =
        fixture::seed_group_claim(&pool, agent, group, "nbhd private content").await;

    let run_id = Uuid::new_v4();
    let neighborhood_id = Uuid::new_v4();
    let theme_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description) VALUES ($1, 'nbhd-iso', 'fixture')",
    )
    .bind(theme_id)
    .execute(&pool)
    .await
    .expect("seed theme");
    sqlx::query("INSERT INTO graph_cluster_runs (run_id, cluster_count) VALUES ($1, 1)")
        .bind(run_id)
        .execute(&pool)
        .await
        .expect("seed cluster run");
    sqlx::query(
        "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size) \
         VALUES ($1, $2, $3, 'nbhd-iso', 2)",
    )
    .bind(neighborhood_id)
    .bind(run_id)
    .bind(theme_id)
    .execute(&pool)
    .await
    .expect("seed neighborhood");

    // The public claim's membership row is public; the private claim's
    // membership row is group-private and owned by the same group, mirroring
    // what PR-12's backfill will produce.
    sqlx::query(
        "INSERT INTO claim_neighborhood_membership \
           (run_id, claim_id, neighborhood_id, owner_group_id, visibility) \
         VALUES ($1, $2, $3, '00000000-0000-0000-0000-000000000000'::uuid, 'public')",
    )
    .bind(run_id)
    .bind(public_claim)
    .bind(neighborhood_id)
    .execute(&pool)
    .await
    .expect("seed public membership");
    sqlx::query(
        "INSERT INTO claim_neighborhood_membership \
           (run_id, claim_id, neighborhood_id, owner_group_id, visibility) \
         VALUES ($1, $2, $3, $4, 'group')",
    )
    .bind(run_id)
    .bind(private_claim)
    .bind(neighborhood_id)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed private membership");

    let owner = Viewer::resolve(&pool, agent)
        .await
        .expect("resolve owner viewer");
    let stranger = fixture::public_viewer(&pool).await;

    let owner_nodes =
        GraphViewRepository::neighborhood_atomic_nodes(&pool, &owner, neighborhood_id)
            .await
            .expect("owner neighborhood_atomic_nodes");
    let owner_ids: Vec<Uuid> = owner_nodes.iter().map(|n| n.id).collect();
    assert!(
        owner_ids.contains(&public_claim) && owner_ids.contains(&private_claim),
        "the owner must see BOTH members; got {owner_ids:?}"
    );

    let stranger_nodes =
        GraphViewRepository::neighborhood_atomic_nodes(&pool, &stranger, neighborhood_id)
            .await
            .expect("stranger neighborhood_atomic_nodes");
    let stranger_ids: Vec<Uuid> = stranger_nodes.iter().map(|n| n.id).collect();
    assert_eq!(
        stranger_ids,
        vec![public_claim],
        "a stranger must see exactly the public member; got {stranger_ids:?}"
    );
    // The label IS claims.content, so this also asserts no content leaked.
    assert!(
        !stranger_nodes
            .iter()
            .any(|n| n.label.contains("nbhd private content")),
        "private claim content leaked through the neighborhood node label"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// HTTP round trips for the two handlers that held a Viewer and did not
// filter on it:
//   GET /api/v1/claims/by-belief   →  ClaimRepository::list_by_belief_bounds
//   GET /api/v1/frames/:id/claims  →  ClaimRepository::frame_claims_sorted
// ─────────────────────────────────────────────────────────────────────────
//
// # Why these two are HTTP-level when everything above is repo-level
//
// A repo-level test could NOT have caught the defect these guard. Before the
// conversion neither repo function existed: `frame_claims_sorted` was built in
// the handler with `format!` + `sqlx::query_as` (no marker, no `splice`), and
// `claims_by_belief` ran an inline corpus scan with no viewer at all. A test
// naming `ClaimRepository::frame_claims_sorted` would not have compiled against
// the broken tree, so it cannot be the regression guard for it.
//
// What survives a rewrite of where the SQL lives is the *response body*: a
// stranger's token must not receive another group's `content` from these two
// URLs. That is asserted here, through `spawn_app` → `create_router`, so the
// bearer middleware, the `ViewerExtractor` and the handler wiring are all in
// the path. Delete the `{VISIBILITY:c}` marker from either repo function, or
// re-inline the statement into the handler, and these go red.
//
// They use the ambient `DATABASE_URL` rather than `#[sqlx::test]`'s throwaway
// database, matching `versioning_belief_cascade_test.rs` and
// `pr07_acceptance_http.rs`: `spawn_app` builds its own pool from a URL, and
// every assertion below is keyed on freshly-minted claim ids, so a shared
// database cannot make them pass or fail spuriously.

mod common;

/// One frame holding three claims that separate the two visibility markers
/// both statements carry, plus a bearer token for the owning principal and for
/// an unrelated one.
///
/// Both `list_by_belief_bounds` and `frame_claims_sorted` splice **two**
/// predicates — `{VISIBILITY:c}` on `claims` and `{VISIBILITY:cf}` on
/// `claim_frames` — and a corpus with only one kind of private row leaves the
/// second marker inert: deleting it would change no assertion. So the frame
/// holds one member that only `{VISIBILITY:c}` can hide, one that only
/// `{VISIBILITY:cf}` can hide, and one public control.
struct BeliefHttpCorpus {
    /// `visibility = 'group'` claim, PUBLIC `claim_frames` row. Only the
    /// `claims` predicate withholds it.
    private_claim: Uuid,
    /// `visibility = 'public'` claim, `visibility = 'group'` `claim_frames`
    /// row. Only the `claim_frames` predicate withholds it — the content is
    /// world-readable, but *that this claim is in this frame* is not, and an
    /// unfiltered subquery turns the endpoint into a membership oracle for
    /// rows the caller cannot otherwise enumerate.
    frame_private_member: Uuid,
    /// Public claim, public membership. The non-vacuity control.
    public_claim: Uuid,
    frame: Uuid,
    owner_token: String,
    stranger_token: String,
}

/// Seed the corpus above.
///
/// The `UPDATE ... SET belief` is load-bearing, not cosmetic.
/// `list_by_belief_bounds` filters `c.belief >= $1 AND c.plausibility <= $2`,
/// and `frame_claims_sorted` orders on the same columns. `seed_group_claim`
/// leaves both NULL, so without this the OWNER's result set is empty too and
/// every "the stranger sees nothing" assertion below would pass vacuously
/// against a completely unfiltered query.
///
/// Every read below is scoped to the freshly-minted `frame`, which also bounds
/// the result set to these three rows on the shared, never-truncated test
/// database — otherwise each run would add two more `belief = 0.9` claims to an
/// unscoped corpus scan and the assertions would eventually page out.
async fn belief_http_corpus(pool: &PgPool, label: &str) -> BeliefHttpCorpus {
    let (owner_agent, group) = fixture::seed_agent_with_group(pool, label).await;
    let (stranger_agent, _stranger_group) =
        fixture::seed_agent_with_group(pool, &format!("{label}-stranger")).await;

    let private_claim = fixture::seed_group_claim(
        pool,
        owner_agent,
        group,
        &format!("{label} private content"),
    )
    .await;
    let frame_private_member = fixture::seed_public_claim(
        pool,
        owner_agent,
        &format!("{label} frame-private member content"),
    )
    .await;
    let public_claim =
        fixture::seed_public_claim(pool, owner_agent, &format!("{label} public content")).await;

    for claim in [private_claim, frame_private_member, public_claim] {
        sqlx::query("UPDATE claims SET belief = 0.9, plausibility = 0.95 WHERE id = $1")
            .bind(claim)
            .execute(pool)
            .await
            .expect("populate belief columns");
    }

    let frame = common::seed_frame_with_claim(pool, private_claim).await;
    for claim in [frame_private_member, public_claim] {
        sqlx::query("INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2)")
            .bind(claim)
            .bind(frame)
            .execute(pool)
            .await
            .expect("assign claim to the fixture frame");
    }

    // Migration 062 lists `claim_frames` in `tier_a`, so the row carries its
    // own tenancy columns and defaults to `public`. This is the shape PR-12's
    // backfill will produce for a membership that belongs to one group.
    sqlx::query(
        "UPDATE claim_frames SET visibility = 'group', owner_group_id = $1 \
         WHERE claim_id = $2 AND frame_id = $3",
    )
    .bind(group)
    .bind(frame_private_member)
    .bind(frame)
    .execute(pool)
    .await
    .expect("make the membership row group-private");

    BeliefHttpCorpus {
        private_claim,
        frame_private_member,
        public_claim,
        frame,
        owner_token: common::mint_token_with_agent(&["claims:read", "graph:read"], owner_agent),
        stranger_token: common::mint_token_with_agent(
            &["claims:read", "graph:read"],
            stranger_agent,
        ),
    }
}

/// GET `path` with `token` and return `(claim ids under id_key, raw body)`.
///
/// The body comes back too so the content assertions can be made on the text
/// rather than on a field name — a rename of `content` must not be able to turn
/// a leak into a pass.
async fn get_claim_ids(
    addr: std::net::SocketAddr,
    path: &str,
    token: &str,
    who: &str,
    id_key: &str,
) -> (Vec<Uuid>, String) {
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {path} as {who}: {e}"));
    let status = resp.status();
    let body = resp.text().await.expect("response body");
    assert!(
        status.is_success(),
        "GET {path} as {who} must succeed; got {status}: {body}"
    );
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("GET {path} as {who}: {e}: {body}"));
    let ids = rows
        .iter()
        .map(|row| {
            let raw = row
                .get(id_key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("row has no string `{id_key}`: {row}"));
            Uuid::parse_str(raw).expect("row id is a uuid")
        })
        .collect();
    (ids, body)
}

/// `GET /api/v1/claims/by-belief` is an unbounded, caller-paginated scan that
/// projects `claims.content`. A stranger's token must not receive another
/// group's claim from it.
#[tokio::test(flavor = "multi_thread")]
async fn claims_by_belief_http_hides_a_group_private_claim_from_a_stranger() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool");
    let corpus = belief_http_corpus(&pool, "by-belief-http").await;
    let (addr, shutdown) = common::spawn_app(&url).await;

    // `frame_id` is passed so the `claim_frames` arm of the statement actually
    // executes: without it `$3::uuid IS NULL` short-circuits the whole
    // subquery and `{VISIBILITY:cf}` is never evaluated. It also bounds the
    // result set to this frame's three members.
    let frame = corpus.frame;
    let path = format!(
        "/api/v1/claims/by-belief?min_belief=0.5&max_plausibility=1.0&frame_id={frame}&limit=1000"
    );

    // Non-vacuity: the owner really does get all three rows back, so an absent
    // row below is the filter working rather than the query matching nothing.
    let (owner_ids, _) = get_claim_ids(addr, &path, &corpus.owner_token, "owner", "id").await;
    for expected in [
        corpus.private_claim,
        corpus.frame_private_member,
        corpus.public_claim,
    ] {
        assert!(
            owner_ids.contains(&expected),
            "the owner must see {expected} — every member of its own frame; got {owner_ids:?}"
        );
    }

    let (stranger_ids, stranger_body) =
        get_claim_ids(addr, &path, &corpus.stranger_token, "stranger", "id").await;
    assert!(
        stranger_ids.contains(&corpus.public_claim),
        "the stranger's request must still return the public control claim — \
         otherwise this test cannot distinguish a working filter from a broken \
         endpoint; got {stranger_ids:?}"
    );
    assert!(
        !stranger_ids.contains(&corpus.private_claim),
        "a stranger must not receive another group's claim from \
         /api/v1/claims/by-belief ({{VISIBILITY:c}}); got {stranger_ids:?}"
    );
    assert!(
        !stranger_ids.contains(&corpus.frame_private_member),
        "a stranger must not learn that {} is a member of this frame through a \
         private claim_frames row ({{VISIBILITY:cf}}); got {stranger_ids:?}",
        corpus.frame_private_member
    );
    assert!(
        !stranger_body.contains("by-belief-http private content"),
        "another group's claim content leaked in the by-belief body: {stranger_body}"
    );

    let _ = shutdown.send(());
}

/// `GET /api/v1/frames/:id/claims` is the handler that held a `Viewer`, spent
/// it on the frame-existence check, and then built its content query with
/// `format!` — the fail-open `Viewer::splice`'s missing-marker panic could not
/// see because `splice` was never called.
///
/// The frame itself is `visibility = 'public'`, so the stranger passes the
/// existence check and receives a page. That is the sharp case: the endpoint
/// must return the frame's public members and withhold the private one, not
/// 404 the whole frame.
#[tokio::test(flavor = "multi_thread")]
async fn frame_claims_sorted_http_hides_a_group_private_claim_from_a_stranger() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool");
    let corpus = belief_http_corpus(&pool, "frame-claims-http").await;

    let (addr, shutdown) = common::spawn_app(&url).await;
    let frame = corpus.frame;
    let path = format!("/api/v1/frames/{frame}/claims?limit=1000");

    let (owner_ids, _) = get_claim_ids(addr, &path, &corpus.owner_token, "owner", "claim_id").await;
    for expected in [
        corpus.private_claim,
        corpus.frame_private_member,
        corpus.public_claim,
    ] {
        assert!(
            owner_ids.contains(&expected),
            "the owner must see {expected} — every member of its own frame; got {owner_ids:?}"
        );
    }

    let (stranger_ids, stranger_body) =
        get_claim_ids(addr, &path, &corpus.stranger_token, "stranger", "claim_id").await;
    assert!(
        stranger_ids.contains(&corpus.public_claim),
        "the stranger must still receive the frame's public member — otherwise \
         this test cannot distinguish a working filter from a 404ed frame; \
         got {stranger_ids:?}"
    );
    assert!(
        !stranger_ids.contains(&corpus.private_claim),
        "a stranger must not receive another group's claim from \
         /api/v1/frames/:id/claims ({{VISIBILITY:c}}); got {stranger_ids:?}"
    );
    assert!(
        !stranger_ids.contains(&corpus.frame_private_member),
        "a stranger must not learn that {} is a member of this frame through a \
         private claim_frames row ({{VISIBILITY:cf}}); got {stranger_ids:?}",
        corpus.frame_private_member
    );
    assert!(
        !stranger_body.contains("frame-claims-http private content"),
        "another group's claim content leaked in the frame-claims body: {stranger_body}"
    );

    let _ = shutdown.send(());
}

/// A 1536-dimension pgvector literal with every component set to `v`.
fn pgvector_literal(v: f32) -> String {
    let mut s = String::with_capacity(1536 * 4 + 2);
    s.push('[');
    for i in 0..1536 {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&v.to_string());
    }
    s.push(']');
    s
}

// ─────────────────────────────────────────────────────────────────────────
// PR-07 FOLLOW-UP — the sites the first pass fixed in one place and left
// standing in their siblings, plus the two handlers that held a Viewer and
// spent it on something other than the read that returned data.
// ─────────────────────────────────────────────────────────────────────────

/// `POST /api/v1/voids/detect`, `GET /api/v1/voids/density`,
/// `POST /api/v1/gaps/analysis` and `POST /api/v1/experiments/hypothesize` all
/// now route their probe-vector corpus scan through
/// `ClaimRepository::semantic_search_flat`.
///
/// This is the exfiltration primitive PR-07's own repo docs call "the single
/// highest-value" one in the API: an authenticated principal submits an
/// arbitrary vector and gets other tenants' claim text back, ranked by
/// relevance. The first pass closed it in `search.rs` and `rag.rs` and left
/// four siblings running a near-identical statement.
#[sqlx::test(migrations = "../../migrations")]
async fn semantic_search_flat_does_not_rank_a_group_private_claim_for_a_stranger(pool: PgPool) {
    let (owner, stranger, claim) = private_corpus(&pool, "flat-search").await;
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "flat-search-pub").await;
    let public = fixture::seed_public_claim(&pool, agent, "flat-search public content").await;

    let vec_literal = pgvector_literal(1.0);
    for id in [claim, public] {
        sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
            .bind(&vec_literal)
            .bind(id)
            .execute(&pool)
            .await
            .expect("set embedding");
    }

    let owner_hits = ClaimRepository::semantic_search_flat(
        &pool,
        &owner,
        &vec_literal,
        -1.0,
        None,
        None,
        None,
        None,
        100,
    )
    .await
    .expect("owner semantic_search_flat");
    assert!(
        owner_hits.iter().any(|h| h.claim_id == claim),
        "the owner must retrieve its own claim; got {} hits",
        owner_hits.len()
    );

    let stranger_hits = ClaimRepository::semantic_search_flat(
        &pool,
        &stranger,
        &vec_literal,
        -1.0,
        None,
        None,
        None,
        None,
        100,
    )
    .await
    .expect("stranger semantic_search_flat");
    assert!(
        stranger_hits.iter().any(|h| h.claim_id == public),
        "the stranger must still retrieve the public control claim — otherwise \
         this test cannot distinguish a working filter from an empty corpus"
    );
    assert!(
        !stranger_hits.iter().any(|h| h.claim_id == claim),
        "a stranger must not rank a group-private claim into its results"
    );
    assert!(
        !stranger_hits
            .iter()
            .any(|h| h.statement.contains("tenant-private content")),
        "another group's claim content came back in the statement field"
    );
}

/// `GET /api/v1/voids/density` returns `claim_count` — how much of the corpus
/// sits within a similarity radius of an arbitrary caller-supplied point.
///
/// A bare `COUNT(*)` there is a cardinality oracle in the sense
/// `MassFunctionRepository::count_for_claim`'s doc forbids: it reports how much
/// exists without disclosing any of it. The count must be the reader's count.
#[sqlx::test(migrations = "../../migrations")]
async fn embedding_density_stats_does_not_count_a_group_private_claim_for_a_stranger(pool: PgPool) {
    let (owner, stranger, claim) = private_corpus(&pool, "density").await;
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "density-pub").await;
    let public = fixture::seed_public_claim(&pool, agent, "density public content").await;

    let vec_literal = pgvector_literal(1.0);
    for id in [claim, public] {
        sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
            .bind(&vec_literal)
            .bind(id)
            .execute(&pool)
            .await
            .expect("set embedding");
    }

    let (owner_count, _) =
        ClaimRepository::embedding_density_stats(&pool, &owner, &vec_literal, 0.99)
            .await
            .expect("owner density");
    let (stranger_count, _) =
        ClaimRepository::embedding_density_stats(&pool, &stranger, &vec_literal, 0.99)
            .await
            .expect("stranger density");

    assert_eq!(
        owner_count, 2,
        "the owner sees both its private claim and the public one"
    );
    assert_eq!(
        stranger_count, 1,
        "the stranger's count must exclude the group-private claim — a count \
         that includes it is a cardinality oracle even though no text is returned"
    );
}

/// The clustering branch of `POST /api/v1/experiments/hypothesize` pulled raw
/// `embedding::real[]` vectors for the 200 nearest claims.
///
/// PR-07's own acceptance criteria treat an embedding as approximately
/// invertible to the content it encodes — that is why `/themes/:id/embeddings`
/// returns none — so this is a content read, not a metadata read.
#[sqlx::test(migrations = "../../migrations")]
async fn neighborhood_embeddings_does_not_return_a_group_private_vector(pool: PgPool) {
    let (owner, stranger, claim) = private_corpus(&pool, "nbhd-vec").await;
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "nbhd-vec-pub").await;
    let public = fixture::seed_public_claim(&pool, agent, "nbhd-vec public content").await;

    let vec_literal = pgvector_literal(1.0);
    for id in [claim, public] {
        sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
            .bind(&vec_literal)
            .bind(id)
            .execute(&pool)
            .await
            .expect("set embedding");
    }

    let owner_rows =
        ClaimRepository::neighborhood_embeddings(&pool, &owner, &vec_literal, -1.0, 200)
            .await
            .expect("owner neighborhood_embeddings");
    assert!(
        owner_rows
            .iter()
            .any(|r| r.id == claim && !r.embedding.is_empty()),
        "the owner must get its own claim's vector back"
    );

    let stranger_rows =
        ClaimRepository::neighborhood_embeddings(&pool, &stranger, &vec_literal, -1.0, 200)
            .await
            .expect("stranger neighborhood_embeddings");
    assert!(
        stranger_rows.iter().any(|r| r.id == public),
        "the stranger must still get the public control vector"
    );
    assert!(
        !stranger_rows.iter().any(|r| r.id == claim),
        "a stranger must not receive a group-private claim's raw embedding"
    );
}

/// `GET /api/v1/claims/:id/belief-at` replays evidence through a Bayesian
/// updater and returns `evidence_count` plus the replayed truth value.
///
/// The handler held a `Viewer`, spent it on `ClaimRepository::get_by_id`, and
/// then read the evidence it actually replays with an inline unfiltered
/// statement. Both markers are exercised here: `{VISIBILITY:e}` on `evidence`
/// and `{VISIBILITY:ed}` on the joined `edges` row. Two separate private rows
/// are seeded so deleting EITHER marker turns this red — a corpus with only one
/// kind of private row would leave the other marker inert.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_as_of_hides_private_evidence_and_private_edges_from_a_stranger(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "belief-at").await;
    // The CLAIM is public: a stranger passes the existence check and gets a
    // 200, which is the sharp case — the endpoint must withhold the evidence,
    // not 404 the whole claim.
    let claim = fixture::seed_public_claim(&pool, agent, "belief-at public claim").await;
    let owner = Viewer::resolve(&pool, agent).await.expect("owner viewer");
    let stranger = fixture::public_viewer(&pool).await;
    let as_of = chrono::Utc::now() + chrono::Duration::days(1);

    // Three evidence rows, one per case.
    let private_evidence = seed_belief_at_evidence(&pool, claim, "private-evidence").await;
    let private_edge_evidence = seed_belief_at_evidence(&pool, claim, "private-edge").await;
    let public_evidence = seed_belief_at_evidence(&pool, claim, "public-control").await;

    // `{VISIBILITY:e}` alone withholds this one.
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $1 WHERE id = $2")
        .bind(group)
        .bind(private_evidence)
        .execute(&pool)
        .await
        .expect("privatise evidence row");

    // `{VISIBILITY:ed}` alone withholds this one: the evidence itself is
    // world-readable, but the fact that it bears on this claim is not.
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $1 \
         WHERE source_id = $2 AND target_id = $3",
    )
    .bind(group)
    .bind(private_edge_evidence)
    .bind(claim)
    .execute(&pool)
    .await
    .expect("privatise edge row");

    let owner_rows = EvidenceRepository::provided_for_claim_as_of(&pool, &owner, claim, as_of)
        .await
        .expect("owner evidence as-of");
    let owner_ids: Vec<Uuid> = owner_rows.iter().map(|r| r.id).collect();
    for expected in [private_evidence, private_edge_evidence, public_evidence] {
        assert!(
            owner_ids.contains(&expected),
            "the owner must replay every evidence row on its own claim; got {owner_ids:?}"
        );
    }

    let stranger_rows =
        EvidenceRepository::provided_for_claim_as_of(&pool, &stranger, claim, as_of)
            .await
            .expect("stranger evidence as-of");
    let stranger_ids: Vec<Uuid> = stranger_rows.iter().map(|r| r.id).collect();
    assert!(
        stranger_ids.contains(&public_evidence),
        "the stranger must still replay the public control row — otherwise this \
         test cannot distinguish a working filter from a broken join; got {stranger_ids:?}"
    );
    assert!(
        !stranger_ids.contains(&private_evidence),
        "a stranger must not replay group-private evidence ({{VISIBILITY:e}}); \
         got {stranger_ids:?}"
    );
    assert!(
        !stranger_ids.contains(&private_edge_evidence),
        "a stranger must not learn that {private_edge_evidence} bears on this \
         claim through a group-private edge ({{VISIBILITY:ed}}); got {stranger_ids:?}"
    );
}

/// One evidence row plus the `provides_evidence` edge `belief_at_time` walks.
async fn seed_belief_at_evidence(pool: &PgPool, claim: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, claim_id, evidence_type, raw_content, content_hash, properties) \
         VALUES ($1, $2, 'observation', $3, $4, $5)",
    )
    .bind(id)
    .bind(claim)
    .bind(format!("{tag} body"))
    .bind(id.as_bytes().iter().copied().cycle().take(32).collect::<Vec<u8>>())
    .bind(serde_json::json!({ "confidence": 0.7, "supports": true }))
    .execute(pool)
    .await
    .expect("seed evidence");

    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
         VALUES ($1, $2, 'evidence', 'claim', 'provides_evidence')",
    )
    .bind(id)
    .bind(claim)
    .execute(pool)
    .await
    .expect("seed evidence edge");

    id
}

/// `load_subgraph` must never return an edge naming a node it withheld.
///
/// It used to fetch edges FIRST, over the caller's raw id set, and never
/// recompute the set from the ids that survived the node projections — so the
/// `edges` array enumerated claim ids the `nodes` array had withheld. That is
/// the id-enumeration oracle PR-07 closed in `graph_neighborhood.rs` and left
/// standing here behind a `subgraph_edges` doc comment asserting the caller
/// narrowed the set. No caller did.
///
/// `edges.visibility` defaults to `'public'` under migration 062, so the edge
/// predicate matches every row today and the edge-side filter alone does not
/// close this. The ordering is what closes it.
#[sqlx::test(migrations = "../../migrations")]
async fn load_subgraph_never_returns_an_edge_naming_a_withheld_node(pool: PgPool) {
    let (owner, stranger, private_claim) = private_corpus(&pool, "subgraph").await;
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "subgraph-pub").await;
    let public_claim = fixture::seed_public_claim(&pool, agent, "subgraph public content").await;

    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
         VALUES ($1, $2, 'claim', 'claim', 'supports')",
    )
    .bind(private_claim)
    .bind(public_claim)
    .execute(&pool)
    .await
    .expect("seed claim-to-claim edge");

    let node_ids = vec![private_claim, public_claim];

    // Non-vacuity: the owner sees both nodes AND the edge between them.
    let owner_resp =
        epigraph_api::routes::graph_query_utils::load_subgraph(&pool, &owner, node_ids.clone())
            .await
            .expect("owner load_subgraph");
    assert!(
        owner_resp.0.nodes.iter().any(|n| n.id == private_claim),
        "the owner must see its own claim as a node"
    );
    assert_eq!(
        owner_resp.0.edges.len(),
        1,
        "the owner must see the edge between the two claims"
    );

    let stranger_resp =
        epigraph_api::routes::graph_query_utils::load_subgraph(&pool, &stranger, node_ids)
            .await
            .expect("stranger load_subgraph");
    assert!(
        stranger_resp.0.nodes.iter().any(|n| n.id == public_claim),
        "the stranger must still see the public node — otherwise this test \
         cannot distinguish a working filter from an empty response"
    );
    assert!(
        !stranger_resp.0.nodes.iter().any(|n| n.id == private_claim),
        "a stranger must not receive a group-private claim as a node"
    );

    let returned_node_ids: Vec<Uuid> = stranger_resp.0.nodes.iter().map(|n| n.id).collect();
    for edge in &stranger_resp.0.edges {
        assert!(
            returned_node_ids.contains(&edge.source_id)
                && returned_node_ids.contains(&edge.target_id),
            "edge {} names {} -> {}, and at least one of those is absent from \
             `nodes` — an id-enumeration oracle; nodes were {returned_node_ids:?}",
            edge.id,
            edge.source_id,
            edge.target_id
        );
    }
}

/// `GET /api/v1/hypothesis/:id/status` destructured a `ViewerExtractor` and
/// then read `content, truth_value, belief, plausibility, labels, properties`
/// for an arbitrary claim id with a raw pool query. The viewer was spent only
/// on two scalar reads (`MassFunctionRepository::get_for_claim_frame`,
/// `ExperimentRepository::count_completed_with_analysis`).
///
/// That satisfied acceptance criterion #1 *syntactically* — the extractor is
/// present — while leaking, which is the exact `frame_claims_sorted` shape the
/// criterion's own lint says it exists to catch. `hypothesis.rs` contains zero
/// `check_content_access` calls, so the register's stated compensating control
/// did not exist here either.
///
/// This is HTTP-level rather than repo-level for the same reason as the two
/// guards above: the defect lived in the handler, not in a repo function, so a
/// test naming a repo function could not have caught it.
#[tokio::test(flavor = "multi_thread")]
async fn hypothesis_status_http_hides_a_group_private_claim_from_a_stranger() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool");

    let (owner_agent, group) = fixture::seed_agent_with_group(&pool, "hyp-status").await;
    let (stranger_agent, _sg) = fixture::seed_agent_with_group(&pool, "hyp-status-stranger").await;
    let private_claim = fixture::seed_group_claim(
        &pool,
        owner_agent,
        group,
        "hyp-status private hypothesis content",
    )
    .await;
    let public_claim =
        fixture::seed_public_claim(&pool, owner_agent, "hyp-status public hypothesis content")
            .await;

    let owner_token = common::mint_token_with_agent(&["claims:read", "graph:read"], owner_agent);
    let stranger_token =
        common::mint_token_with_agent(&["claims:read", "graph:read"], stranger_agent);
    let (addr, shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();

    let get = |id: Uuid, token: String| {
        let client = client.clone();
        async move {
            let resp = client
                .get(format!("http://{addr}/api/v1/hypothesis/{id}/status"))
                .bearer_auth(token)
                .send()
                .await
                .expect("hypothesis status request");
            let status = resp.status();
            let body = resp.text().await.expect("body");
            (status, body)
        }
    };

    // Non-vacuity: the owner really does get its own hypothesis back, content
    // and all — so a 404 below is the filter working, not a broken endpoint.
    let (owner_status, owner_body) = get(private_claim, owner_token.clone()).await;
    assert!(
        owner_status.is_success(),
        "the owner must be able to read its own hypothesis; got {owner_status}: {owner_body}"
    );
    assert!(
        owner_body.contains("hyp-status private hypothesis content"),
        "the owner's response must carry the content: {owner_body}"
    );

    // Non-vacuity, second half: the stranger CAN read a public hypothesis, so
    // the 404 below is about visibility rather than about the endpoint.
    let (public_status, public_body) = get(public_claim, stranger_token.clone()).await;
    assert!(
        public_status.is_success(),
        "a stranger must still read a public hypothesis; got {public_status}: {public_body}"
    );

    let (stranger_status, stranger_body) = get(private_claim, stranger_token).await;
    assert_eq!(
        stranger_status.as_u16(),
        404,
        "a stranger must not receive another group's hypothesis; got \
         {stranger_status}: {stranger_body}"
    );
    assert!(
        !stranger_body.contains("hyp-status private hypothesis content"),
        "another group's claim content leaked in the hypothesis-status body: {stranger_body}"
    );

    let _ = shutdown.send(());
}

// ── GET /api/v1/events — a real round trip, both halves of the merge ────────
//
// This endpoint is the one place in the crate where a viewer-filtered SQL read
// is merged with an UNFILTERED in-process source before the response is built.
// A repo-level test proves the SQL half and cannot see the merge at all: the
// ring buffer is a `OnceLock<Arc<EventStore>>` reached from inside the handler.
// So this case drives the HTTP route, seeds the same private claim into BOTH
// stores, and asserts the stranger receives neither copy.
//
// The db-build handlers that push into that buffer are `routes/edges.rs`
// (`edge.added`, `claim.superseded`), `routes/belief.rs` (`frame.created`) and
// `routes/community.rs` — so the unfiltered half was the live event stream of
// the db build, not a no-db legacy artefact.

/// `GET /api/v1/events?event_type=<ty>` with `token`; returns the raw body.
///
/// Scoped by `event_type` on purpose. This suite runs against the ambient
/// `DATABASE_URL`, whose `events` table is never truncated and already holds
/// thousands of rows; an unscoped read pages the freshly-seeded rows off the
/// end (the endpoint sorts `created_at` ASC) and the non-vacuity control
/// disappears, which is exactly how the first draft of this test failed.
async fn get_events_body(
    addr: std::net::SocketAddr,
    token: &str,
    who: &str,
    event_type: &str,
) -> String {
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/events?limit=1000&event_type={event_type}"
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET /api/v1/events as {who}: {e}"));
    let status = resp.status();
    let body = resp.text().await.expect("response body");
    assert!(
        status.is_success(),
        "GET /api/v1/events as {who} must succeed; got {status}: {body}"
    );
    body
}

#[tokio::test(flavor = "multi_thread")]
async fn list_events_http_hides_a_private_claim_from_both_the_table_and_the_ring_buffer() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool");

    let (owner_agent, group) = fixture::seed_agent_with_group(&pool, "events-http").await;
    let (stranger_agent, _) = fixture::seed_agent_with_group(&pool, "events-http-stranger").await;
    let private =
        fixture::seed_group_claim(&pool, owner_agent, group, "events-http private content").await;
    let public = fixture::seed_public_claim(&pool, owner_agent, "events-http public control").await;

    // Half 1: the persisted table. Deliberately a `conflict.resolved`-shaped
    // payload — no `claim_id` key anywhere — because a rule keyed on
    // `claim_id` alone passes this row straight through.
    let persisted_type = format!("events-http.persisted.{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO events (event_type, actor_id, payload, graph_version) \
         VALUES ($1, NULL, jsonb_build_object('claim_a_id', $2::text, \
                                              'claim_b_id', $3::text), \
                 nextval('events_graph_version_seq'))",
    )
    .bind(&persisted_type)
    .bind(private)
    .bind(public)
    .execute(&pool)
    .await
    .expect("seed persisted event");

    // Half 2: the in-process ring buffer, in the `edge.added` shape
    // `routes/edges.rs` actually pushes — under its own unique type so this
    // read is bounded too.
    let in_mem_type = format!("events-http.inmem.{}", Uuid::new_v4());
    epigraph_api::routes::events::global_event_store()
        .push(
            in_mem_type.clone(),
            None,
            serde_json::json!({
                "source_id": private.to_string(),
                "target_id": public.to_string(),
                "relationship": "supports",
            }),
        )
        .await;

    let owner_token = common::mint_token_with_agent(&["claims:read", "graph:read"], owner_agent);
    let stranger_token =
        common::mint_token_with_agent(&["claims:read", "graph:read"], stranger_agent);
    let (addr, shutdown) = common::spawn_app(&url).await;

    // Each half carries BOTH the private id and the public control id, so a
    // response that withholds the private one while still returning the event
    // is distinguishable from a response that returns nothing.
    for (half, ty) in [("persisted", &persisted_type), ("in-memory", &in_mem_type)] {
        let stranger_body = get_events_body(addr, &stranger_token, "stranger", ty).await;
        assert!(
            !stranger_body.contains(&private.to_string()),
            "the {half} half of GET /api/v1/events leaked the private claim's \
             id to a stranger. Body: {stranger_body}"
        );

        let owner_body = get_events_body(addr, &owner_token, "owner", ty).await;
        assert!(
            owner_body.contains(&private.to_string()) && owner_body.contains(&public.to_string()),
            "Class P for the {half} half: the owner must receive its own \
             event, with both ids. A filter that returns nothing to anybody \
             passes the stranger assertion and is a fail-closed regression. \
             Body: {owner_body}"
        );
    }

    // Non-vacuity of the fixture itself: the seeded events really are reachable
    // through this endpoint. Asserted against the OWNER, whose view of both
    // halves is unfiltered in practice.
    let owner_persisted = get_events_body(addr, &owner_token, "owner", &persisted_type).await;
    assert!(
        owner_persisted.contains(&persisted_type),
        "the persisted fixture event must be reachable at all: {owner_persisted}"
    );

    let _ = shutdown.send(());
}

// ── GET /api/v1/match_candidates — the one regression class reachable TODAY ─
//
// Every other behaviour change in PR-09 is inert until PR-12 writes the first
// `visibility = 'group'` row. This one is not: `match_candidates` rows over
// superseded claims exist on any live corpus, because nothing prunes the queue
// when `supersede_claim` / `mark_duplicate` flips `is_current`.
//
// The regression already shipped silently once INSIDE this PR. `list_candidates`
// replaced an inline `SELECT id, content FROM claims WHERE id = ANY($1)` (no
// `is_current` filter) with `ClaimRepository::contents_by_ids` (which has one),
// and every superseded pair would have rendered as the literal
// `"(claim not found)"` — for a claim that exists. The repo-layer test on
// `contents_by_ids_any_version` pins the FUNCTION's contract; only this case
// pins the CALL SITE. Swap the call back to `contents_by_ids` and this fails.

#[tokio::test(flavor = "multi_thread")]
async fn list_candidates_http_renders_the_excerpt_of_a_superseded_claim() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect test pool");

    let (agent, _group) = fixture::seed_agent_with_group(&pool, "candidates-http").await;

    // A distinctive marker so the assertion reads the CONTENT, not a field
    // name: a rename of `claim_a_excerpt` must not be able to turn a
    // regression into a pass.
    let marker = format!("supersededmarker{}", Uuid::new_v4().simple());
    let stale = fixture::seed_public_claim(&pool, agent, &marker).await;
    let live = fixture::seed_public_claim(
        &pool,
        agent,
        &format!("candidates-http live side {}", Uuid::new_v4()),
    )
    .await;

    // Retire one side of the pair AFTER the candidate would have been queued —
    // the ordinary lifecycle, not a contrived state.
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(stale)
        .execute(&pool)
        .await
        .expect("supersede one side of the pair");

    let (a, b) = if stale < live {
        (stale, live)
    } else {
        (live, stale)
    };
    sqlx::query(
        "INSERT INTO match_candidates (claim_a, claim_b, score, status, features) \
         VALUES ($1, $2, 0.91, 'pending', '{}'::jsonb)",
    )
    .bind(a)
    .bind(b)
    .execute(&pool)
    .await
    .expect("seed the candidate");

    let token = common::mint_token_with_agent(&["claims:read", "graph:read"], agent);
    let (addr, shutdown) = common::spawn_app(&url).await;

    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/match_candidates?status=pending&limit=1000"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("GET /api/v1/match_candidates");
    let status = resp.status();
    let body = resp.text().await.expect("response body");
    assert!(
        status.is_success(),
        "GET /api/v1/match_candidates must succeed; got {status}: {body}"
    );

    assert!(
        body.contains(&marker),
        "the superseded claim's verbatim excerpt must be rendered. This \
         endpoint's own doc promises \"verbatim content excerpts of both claims \
         in each pair\", and `match_candidates` rows routinely outlive the \
         claims they name. Body: {body}"
    );
    assert!(
        !body.contains("(claim not found)"),
        "rendering `(claim not found)` for a claim that EXISTS is actively \
         false text, not merely a missing excerpt. Body: {body}"
    );

    let _ = shutdown.send(());
}
