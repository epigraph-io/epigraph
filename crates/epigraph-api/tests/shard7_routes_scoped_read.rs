//! Conversion shard 7's converted handlers serve every statement of a request
//! on ONE viewer-stamped connection, and a read that has a viewer to spend
//! suppresses on it — in BOTH directions.
//!
//! # What this file is, in the series
//!
//! Conversion shard 7 against `D-PR17-read-guards-widen-under-rls`: 27 sites
//! across eight route files (`routes/workflows.rs` 10, `routes/entities.rs` 5,
//! `routes/claims.rs` 4, `routes/crud.rs` 4, and one each in
//! `routes/versioning.rs`, `routes/conventions.rs`, `routes/graph.rs` and
//! `routes/challenge.rs`). It copies the template PR-28 established in
//! `claims_query_scoped_read.rs` and shards 4-6 carried into
//! `belief_computation_scoped_read.rs`, `dense_routes_scoped_read.rs` and
//! `shard6_routes_scoped_read.rs` — direct `async fn` invocation, a CALIBRATION
//! arm on every assertion, and `viewer_fixture::downgraded_pool` for
//! `AppState.db_pool`.
//!
//! # THE AUTHORITY TRAP, AND WHAT THIS FILE DOES ABOUT IT
//!
//! `#[sqlx::test]` connects as `epigraph`, which is superuser, `BYPASSRLS` AND
//! the table owner, so **no RLS policy filters anything on the pool it hands
//! you**. And `AppState::with_scoped_pool` sets `db_pool = scoped.inner()`, so
//! on a `spawn_app` fixture the converted and the unconverted arms are the SAME
//! POOL and reverting a site to `&state.db_pool` changes not one observable row.
//!
//! That is why the pre-existing HTTP binaries over these endpoints —
//! `claims_by_labels.rs`, `entities_scope_test.rs`, `graph_routes_test.rs`,
//! `graph_themes_test.rs`, `workflow_find_hierarchical_resolve_test.rs`,
//! `workflow_deprecate_test.rs`, `workflow_cascade_supersedes_test.rs`,
//! `workflow_evolve_step_test.rs`, `pr07_acceptance_http.rs`,
//! `tenant_isolation_http.rs` and `read_path_authz_test.rs` — **are this
//! shard's COUNTERFACTUAL and not its instrument.** They stay green on a
//! planted tree by construction, which is precisely what makes them useful:
//! they show the control added here is load-bearing rather than redundant.
//! Per the acceptance, `crates/epigraph-db/tests/no_unscoped_pool.rs` does NOT
//! count among them — this batch edits its rows.
//!
//! [`split_state`] is the instrument. It gives `AppState.db_pool` its own pool
//! whose every connection is `SET SESSION AUTHORIZATION epigraph_app` in
//! `after_connect`, while `AppState.scoped` holds an ordinary `ScopedPool`. So
//! `db_pool != scoped.inner()`, the raw arm is FILTERED and unstamped, and
//! reverting a converted site is observable.
//!
//! # BOTH DIRECTIONS ARE ASSERTED, and the split matters
//!
//! Every arm below asserts an EXACT count and then names a row by id in each
//! direction. A file of lower bounds detects only the fail-CLOSED regression (a
//! site reverted to `&state.db_pool` loses the viewer's own private row) and is
//! blind to the fail-OPEN one (a `{VISIBILITY:…}` marker deleted from a repo
//! function, a predicate widened, a broader `Viewer` handed to `read_as`).
//!
//! Each arm therefore plants a STRANGER row — an object owned by a group the
//! viewer is not in — and asserts it ABSENT by id, with the stranger row
//! reachable through a parent the viewer CAN see, so that no other predicate
//! can be what withholds it:
//!
//! | arm | stranger row | parent it hangs from |
//! |---|---|---|
//! | [`list_claims_counts_the_viewers_own_group_private_claim`] | a claim | the corpus |
//! | [`list_by_labels_serves_the_viewers_own_group_private_claim`] | a claim carrying the same label | the label |
//! | [`list_workflows_serves_the_viewers_own_group_private_workflow`] | a `workflow`-labelled claim | the label |
//! | [`list_skills_serves_the_viewers_own_group_private_workflow`] | a `workflow`-labelled claim | the label |
//! | [`claim_history_walks_through_the_viewers_own_group_private_successor`] | a successor of the SAME public root | a PUBLIC claim |
//! | [`list_claim_evidence_serves_the_viewers_own_group_private_evidence`] | evidence on the same claim | a PUBLIC claim |
//! | [`list_challenges_serves_the_viewers_own_group_private_challenge`] | a challenge on the same claim | a PUBLIC claim |
//! | [`entity_neighborhood_serves_the_viewers_own_group_private_triple`] | a triple on the same entity | an UNTENANTED entity |
//! | [`query_triples_serves_the_viewers_own_group_private_triple`] | a triple on the same entity | an UNTENANTED entity |
//!
//! # Coverage, stated per SITE because the fraction is otherwise ambiguous
//!
//! THIRTEEN of the shard's twenty-seven converted `.db_pool` sites — the unit
//! the ratchet uses — are driven by an arm here. Note the unit before
//! re-deriving that number: `.db_pool` SITES, not handlers and not repo
//! functions. `graph.rs::expand` for instance holds ONE
//! `let pool: &PgPool = &state.db_pool;` alias and spends it on four
//! statements, so it is one site and not four.
//!
//! | route | sites driven | arm |
//! |---|--:|---|
//! | `claims.rs::list_claims` | 1 | [`list_claims_counts_the_viewers_own_group_private_claim`] |
//! | `claims.rs::get_claim` | 1 | [`get_claim_serves_the_viewers_own_group_private_claim`] |
//! | `claims.rs::list_by_labels` | 1 | [`list_by_labels_serves_the_viewers_own_group_private_claim`] |
//! | `claims.rs::list_claim_evidence` | 1 | [`list_claim_evidence_serves_the_viewers_own_group_private_evidence`] |
//! | `workflows.rs::list_workflows` | 1 | [`list_workflows_serves_the_viewers_own_group_private_workflow`] |
//! | `conventions.rs::list_skills` | 1 | [`list_skills_serves_the_viewers_own_group_private_workflow`] |
//! | `versioning.rs::claim_history` | 1 | [`claim_history_walks_through_the_viewers_own_group_private_successor`] |
//! | `challenge.rs::list_challenges` | 1 | [`list_challenges_serves_the_viewers_own_group_private_challenge`] |
//! | `entities.rs::entity_neighborhood` | 2 | [`entity_neighborhood_serves_the_viewers_own_group_private_triple`] |
//! | `entities.rs::query_triples` | 3 | [`query_triples_serves_the_viewers_own_group_private_triple`] |
//!
//! **THE UNCOVERED SET, NAMED BY SITE AND WITH THE REASON, rather than implied
//! by subtraction.** The other fourteen carry no behavioural arm here:
//!
//! * `workflows.rs::search_workflows` (6) — FIVE of its six statements sit
//!   behind `if let Some(embedder) = state.embedding_service()`, and neither
//!   `build_app_for_tests` nor a direct `AppState::with_scoped_pool` injects
//!   one, so an arm driving them through this file's fixture would exercise the
//!   text-fallback branch only and report coverage it does not have. One of the
//!   five is doubly gated on an `affinity_map` hit, i.e. on seeded
//!   `behavioral_executions`. Driving them needs
//!   `common::spawn_app_with_mock_embedding` or an injected provider — a
//!   separable piece of work from the conversion.
//! * `workflows.rs::find_workflow_hierarchical` (3) — one is behind the same
//!   embedder gate. Of the other two, `search_hierarchical_by_text` reads
//!   `workflows`, which carries no tenancy at migration head 92, so an arm over
//!   it would assert a cardinality no predicate can move; the third,
//!   `resolve_steps_to_heads_batched`, DOES narrow, and covering it needs a
//!   `workflows` root, an `executes` edge and a step claim carrying
//!   `properties->>'level' = 2`. `workflow_find_hierarchical_resolve_test.rs`
//!   drives that path end to end through `spawn_app`, so it is a counterfactual
//!   for it rather than coverage.
//! * `crud.rs` (4) — `get_boundary_claims`, `get_split_candidates`,
//!   `get_distant_claims` and `get_theme_embeddings` all read `claim_themes`
//!   joined to `claims`, and `claim_themes` carries no tenancy at migration
//!   head 92. Each needs a theme, a centroid vector and per-claim embeddings
//!   seeded before it returns a row at all, and what an arm would then prove is
//!   filtering over the CLAIMS in a theme. Recorded rather than glossed: this
//!   is the `F-SHARD4-A4` shape, which already owns the gap.
//! * `graph.rs::expand` (1) — needs `graph_cluster_runs`, `graph_clusters` and a
//!   node assignment seeded, none of which carries tenancy, before its ONE
//!   narrowing statement (`GraphViewRepository::expand_cluster_nodes`) returns
//!   anything. `graph_routes_test.rs` drives the endpoint through `spawn_app`
//!   and is its counterfactual.
//!
//! # What is still NOT proven here
//!
//! `ScopedPoolOptions` exposes no `after_connect`, so the SCOPED arm is still a
//! superuser, `BYPASSRLS` session. Everything the stranger arms observe is
//! therefore the IN-QUERY `$V` predicate that `Viewer::splice` writes into the
//! SQL text — which is the control the conversion actually threads, and is why
//! those arms work at all. What no arm here can observe is drift in migration
//! 077's POLICIES on the converted path: dropping a policy leaves every arm
//! green. That limitation is inherited from every file this one copies, is
//! already recorded on
//! `D-PR17-request-path-never-stamps-session-gucs::pr26_disposition`, and this
//! shard does not claim to have closed it.
//!
//! # The mutations these arms were adjudicated against
//!
//! Four, each applied and then restored by file copy with the restored file
//! `touch`ed and the whole-worktree `git diff` `cmp`ed against a pre-mutation
//! reference patch. Recorded so the next reader does not have to re-derive
//! which arm answers to which control:
//!
//! 1. **Fail-CLOSED, executor.** `routes/workflows.rs::list_workflows`'s
//!    `&mut *read` reverted to `&state.db_pool`, arity preserved.
//!    [`list_workflows_serves_the_viewers_own_group_private_workflow`] failed
//!    `1 != 2` on its own `assert_eq!`.
//! 2. **Fail-CLOSED, acquisition.** `routes/claims.rs::list_claims`'s
//!    `state.read_as(&viewer)` reverted to `state.db_pool.acquire()`, so every
//!    downstream `&mut read` kept compiling and the three statements ran
//!    unstamped. [`list_claims_counts_the_viewers_own_group_private_claim`]
//!    failed `1 != 2` on its own `assert_eq!`. This is the shape the
//!    transaction sites needed, because reverting THEIR call arguments alone
//!    would not compile and a compile failure proves nothing about behaviour.
//! 3. **Fail-OPEN, spliced dialect.** `Viewer::predicate_fragment`'s Scoped arm
//!    OR-ed away — `" AND (true OR {alias}.visibility = 'public' OR …) "` —
//!    KEEPING the marker, the alias and the bind, because deleting the marker
//!    cannot model drift (`Viewer::splice` asserts the marker is present and
//!    fails before any SQL runs). SEVEN arms failed `3 != 2`.
//! 4. **Fail-OPEN, macro dialect.** `Viewer::bypass_bind` forced to `true`,
//!    which neutralises the hand-written `($N::bool OR … )` predicate that
//!    `sqlx::query!` sites carry verbatim because the macro needs a
//!    compile-time literal and cannot be spliced. The remaining THREE arms —
//!    [`list_claim_evidence_serves_the_viewers_own_group_private_evidence`],
//!    [`entity_neighborhood_serves_the_viewers_own_group_private_triple`] and
//!    [`query_triples_serves_the_viewers_own_group_private_triple`] — failed
//!    `3 != 2`.
//!
//! **Mutations 3 and 4 partition the arms exactly, and the partition is the
//! point.** Neither alone reaches every arm, because this workspace writes its
//! viewer predicate in two dialects and only one of them goes through
//! `Viewer::splice`. A file that tested only the spliced dialect would have
//! reported three arms as adjudicated when nothing had been shown to move them.
//!
//! **The UNCONVERTED side is what these arms prove, and they prove it
//! directly.** Reverting a converted site to `&state.db_pool` puts the read on a
//! session the RLS policies filter with no `epigraph.group_ids` to admit the
//! viewer's own group — while the viewer's group is still bound into `$V` on
//! that same statement, so the in-query predicate would have returned the row.
//! Only a row-level policy can have removed it.

mod viewer_fixture;

use axum::extract::{Path, Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::challenge::list_challenges;
use epigraph_api::routes::claims::{
    get_claim, list_by_labels, list_claim_evidence, list_claims, ClaimsByLabelsQuery,
    GetClaimQuery, PaginationParams,
};
use epigraph_api::routes::conventions::{list_skills, ListSkillsQuery};
use epigraph_api::routes::entities::{entity_neighborhood, query_triples, QueryTriplesRequest};
use epigraph_api::routes::versioning::claim_history;
use epigraph_api::routes::workflows::{list_workflows, ListWorkflowsQuery};
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    downgraded_pool, scoped_pool, seed_agent_with_group, seed_evidence, seed_group_claim,
    seed_public_claim,
};

// ── The instrument ──

/// An `AppState` whose `scoped` pool is stamped-but-superuser and whose raw
/// `db_pool` is filtered-but-unstamped.
///
/// The asymmetry IS the instrument: a converted site reads through `scoped` and
/// works; the same site reverted to `&state.db_pool` reads through a session the
/// RLS policies filter, with no `epigraph.group_ids` to admit the viewer's own
/// group, and loses the rows.
///
/// This is the NINTH hand-copy of this body in `crates/epigraph-api/tests/`,
/// registered as `F-SHARD6-A2`. That entry is cited rather than re-filed, and
/// the duplication is not fixed here: promoting this helper is a change to the
/// shared fixture whose reach is itself the subject of an open entry, and
/// bundling that into a conversion shard would put two unrelated decisions in
/// one diff.
async fn split_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let scoped = scoped_pool(pool).await;

    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);

    assert!(
        state.scoped.is_some(),
        "CALIBRATION: AppState.scoped must be populated, or read_as refuses and \
         the handler cannot serve at all"
    );
    let raw_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&state.db_pool)
        .await
        .expect("current_user on the raw pool");
    assert_eq!(
        raw_user, "epigraph_app",
        "CALIBRATION: AppState.db_pool must be DOWNGRADED, or reverting a converted \
         site to it is invisible and the mutation proof is vacuous"
    );
    // Role IDENTITY is not role PRIVILEGE, and only the second is what makes
    // this instrument work. If `epigraph_app` were ever granted BYPASSRLS or
    // superuser, the raw arm would stop being filtered, every negative arm in
    // this file -- and in the eight predecessor files it copies this body from
    // -- would pass while proving nothing, and no assertion above would notice.
    let raw_is_privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("role privileges on the raw pool");
    assert!(
        !raw_is_privileged,
        "CALIBRATION: the raw pool's role must be subject to RLS -- neither superuser \
         nor BYPASSRLS. A privileged role here makes every negative arm in this file \
         vacuous while leaving them all green"
    );
    let scoped_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(state.scoped.as_ref().expect("scoped").inner())
        .await
        .expect("current_user on the scoped pool");
    assert_ne!(
        scoped_user, raw_user,
        "CALIBRATION: the scoped and raw arms must not be the same session — that \
         sameness is exactly what makes with_scoped_pool useless as a conversion fixture"
    );

    state
}

/// Resolved on the SUPERUSER pool. `Viewer::resolve` reads live memberships
/// through a `SECURITY DEFINER` helper, so the downgraded pool would resolve the
/// same viewer; the superuser pool is a convenience and no assertion here rests
/// on the difference.
async fn viewer_for(pool: &PgPool, agent: Uuid) -> epigraph_db::visibility::Viewer {
    epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("resolve")
}

// ── File-local seeders ──

/// Give a seeded claim a label set. `viewer_fixture`'s claim seeders write none,
/// and three arms below read through label predicates.
async fn set_labels(pool: &PgPool, claim: Uuid, labels: &[&str]) {
    let owned: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $2 WHERE id = $1")
        .bind(claim)
        .bind(&owned)
        .execute(pool)
        .await
        .expect("set labels");
}

/// Force a derived row's tenancy columns after insert.
///
/// NOT redundant with declaring them in the INSERT. `triples`, `challenges` and
/// `evidence` all carry migration 070's statement-level inheritance trigger,
/// which is `AFTER INSERT` and rewrites the tenancy columns from the PARENT
/// CLAIM on every insert. A stranger row hung from a PUBLIC parent — which is
/// the shape every arm here needs, so that no predicate other than the one
/// under test can be what withholds it — would therefore land `('public',
/// world)` and be visible to everyone, and the arm would report a false pass in
/// the widening direction. The UPDATE touches only `visibility` and
/// `owner_group_id`, which the insert trigger does not fire for.
async fn force_tenancy(pool: &PgPool, table: &str, id: Uuid, visibility: &str, group: Uuid) {
    // `table` is a test-local literal at every call site, never caller data.
    let sql = format!("UPDATE {table} SET visibility = $2, owner_group_id = $3 WHERE id = $1");
    sqlx::query(&sql)
        .bind(id)
        .bind(visibility)
        .bind(group)
        .execute(pool)
        .await
        .expect("force tenancy");

    let (v, g): (String, Uuid) = sqlx::query_as(&format!(
        "SELECT visibility::text, owner_group_id FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read back tenancy");
    assert_eq!(
        (v.as_str(), g),
        (visibility, group),
        "CALIBRATION: the {table} row did not keep the tenancy it was given. An arm \
         built on a row whose tenancy the trigger rewrote asserts nothing about the \
         predicate under test"
    );
}

/// A `challenges` row against `claim`.
async fn seed_challenge(pool: &PgPool, claim: Uuid, agent: Uuid, explanation: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation) \
         VALUES ($1, $2, 'evidence', $3) RETURNING id",
    )
    .bind(claim)
    .bind(agent)
    .bind(explanation)
    .fetch_one(pool)
    .await
    .expect("seed challenge")
}

/// An `entities` row. `entities` carries no tenancy at migration head 92, which
/// is exactly why it makes a good shared parent for the triple arms: the entity
/// is visible to everyone, so only the triple predicate can withhold a triple.
async fn seed_entity(pool: &PgPool, name: &str, type_top: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO entities (canonical_name, type_top, is_canonical) \
         VALUES ($1, $2, true) RETURNING id",
    )
    .bind(name)
    .bind(type_top)
    .fetch_one(pool)
    .await
    .expect("seed entity")
}

/// A `triples` row asserting `(subject) --predicate--> (object)`, attributed to
/// `claim`.
async fn seed_triple(
    pool: &PgPool,
    claim: Uuid,
    subject: Uuid,
    predicate: &str,
    object: Uuid,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO triples (claim_id, subject_id, predicate, object_id, confidence, extractor) \
         VALUES ($1, $2, $3, $4, 0.9, 'test') RETURNING id",
    )
    .bind(claim)
    .bind(subject)
    .bind(predicate)
    .bind(object)
    .fetch_one(pool)
    .await
    .expect("seed triple")
}

/// A claim that supersedes `parent`, forced to `(visibility, group)`.
async fn seed_successor(
    pool: &PgPool,
    agent: Uuid,
    parent: Uuid,
    group: Uuid,
    content: &str,
) -> Uuid {
    let id = seed_group_claim(pool, agent, group, content).await;
    sqlx::query("UPDATE claims SET supersedes = $2, is_current = false WHERE id = $1")
        .bind(id)
        .bind(parent)
        .execute(pool)
        .await
        .expect("link successor");
    id
}

// ── routes/claims.rs ──

/// `GET /claims` — the primary mutation target for this shard.
///
/// Three claims: one PUBLIC, one group-private to the viewer's own group, one
/// group-private to a STRANGER group. The viewer must see exactly two, and must
/// not see the stranger's.
///
/// Reverting either converted site in `list_claims` to `&state.db_pool` puts
/// both `list_conn` and `count_conn` on a filtered, unstamped session with no
/// `epigraph.group_ids`, the `claims_tenancy` policy drops the viewer's own
/// private claim, and `total` falls to 1 — failing on the `assert_eq!` below
/// rather than inside an `.expect(...)`.
#[sqlx::test(migrations = "../../migrations")]
async fn list_claims_counts_the_viewers_own_group_private_claim(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-list-viewer").await;
    let (stranger_agent, stranger_group) =
        seed_agent_with_group(&pool, "shard7-list-stranger").await;

    let public = seed_public_claim(&pool, viewer_agent, "shard7 list public").await;
    let mine = seed_group_claim(&pool, viewer_agent, viewer_group, "shard7 list mine").await;
    let theirs = seed_group_claim(
        &pool,
        stranger_agent,
        stranger_group,
        "shard7 list stranger",
    )
    .await;

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    let response = list_claims(
        ViewerExtractor(viewer),
        State(state),
        Query(PaginationParams {
            limit: 100,
            offset: 0,
            search: None,
            agent_id: None,
            group_id: None,
        }),
        None,
    )
    .await
    .expect("list_claims");

    let ids: Vec<Uuid> = response.0.items.iter().map(|c| c.id).collect();

    assert_eq!(
        response.0.total, 2,
        "the viewer owns one group-private claim and one public claim, and must be \
         counted exactly two: the stranger's claim is not theirs to see. Got ids {ids:?}"
    );
    assert!(
        ids.contains(&public) && ids.contains(&mine),
        "both the public claim and the viewer's own group-private claim must be \
         served. Got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "the STRANGER's group-private claim must be absent. Its presence is the \
         widening direction — a deleted or OR-ed-away {{VISIBILITY:c}} predicate — \
         which a lower-bound assertion cannot see. Got {ids:?}"
    );
}

/// `GET /claims/:id` — the transaction site.
///
/// The claim under test is group-private to the VIEWER's own group, so the read
/// is one the caller is entitled to and the conversion is what makes it
/// succeed. On the reverted tree `get_by_id_conn` finds nothing and the handler
/// answers `NotFound`; that is a returned `Err`, adjudicated by this arm's own
/// `assert!`, not a panic inside an `.expect(...)`.
#[sqlx::test(migrations = "../../migrations")]
async fn get_claim_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-get-viewer").await;
    let mine = seed_group_claim(&pool, viewer_agent, viewer_group, "shard7 get mine").await;
    set_labels(&pool, mine, &["shard7-get"]).await;

    let (stranger_agent, stranger_group) =
        seed_agent_with_group(&pool, "shard7-get-stranger").await;
    let theirs =
        seed_group_claim(&pool, stranger_agent, stranger_group, "shard7 get stranger").await;

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    // Two handler calls, two viewers: `ViewerExtractor` takes its viewer BY
    // VALUE and `epigraph_db::Viewer` is no longer `Clone`. Resolving the same
    // principal twice is what a second request would do anyway, and it keeps
    // the fixture free of any viewer-duplication helper.
    let viewer_again = viewer_for(&pool, viewer_agent).await;
    let served = get_claim(
        ViewerExtractor(viewer_again),
        State(state.clone()),
        Path(mine),
        Query(GetClaimQuery {
            agent_id: None,
            group_id: None,
        }),
        None,
    )
    .await;

    assert!(
        served.is_ok(),
        "the viewer's OWN group-private claim must be served. On a reverted tree the \
         `claims_tenancy` policy hides it from an unstamped session and the handler \
         404s instead"
    );
    let body = served.expect("checked Ok above").0;
    assert_eq!(
        body.id, mine,
        "the served row must be the claim that was asked for"
    );
    assert_eq!(
        body.labels,
        vec!["shard7-get".to_string()],
        "the inline label read runs on the SAME connection as the claim read, so a \
         label set that comes back empty means the two statements did not share a \
         tenancy stamp"
    );

    let withheld = get_claim(
        ViewerExtractor(viewer),
        State(state),
        Path(theirs),
        Query(GetClaimQuery {
            agent_id: None,
            group_id: None,
        }),
        None,
    )
    .await;
    assert!(
        withheld.is_err(),
        "a STRANGER's group-private claim must NOT be served. Serving it is the \
         widening direction, which the arm above cannot see"
    );
}

/// `GET /api/v1/claims/by-labels`.
#[sqlx::test(migrations = "../../migrations")]
async fn list_by_labels_serves_the_viewers_own_group_private_claim(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-labels-viewer").await;
    let (stranger_agent, stranger_group) =
        seed_agent_with_group(&pool, "shard7-labels-stranger").await;

    let public = seed_public_claim(&pool, viewer_agent, "shard7 labels public").await;
    let mine = seed_group_claim(&pool, viewer_agent, viewer_group, "shard7 labels mine").await;
    let theirs = seed_group_claim(
        &pool,
        stranger_agent,
        stranger_group,
        "shard7 labels stranger",
    )
    .await;
    for c in [public, mine, theirs] {
        set_labels(&pool, c, &["shard7-label"]).await;
    }

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    let rows = list_by_labels(
        ViewerExtractor(viewer),
        State(state),
        Query(ClaimsByLabelsQuery {
            labels: "shard7-label".to_string(),
            exclude_labels: None,
            current_only: None,
            min_truth: None,
            limit: Some(100),
            offset: None,
        }),
    )
    .await
    .expect("list_by_labels")
    .0;

    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids.len(),
        2,
        "three claims carry the label; the viewer may read exactly two of them. Got {ids:?}"
    );
    assert!(
        ids.contains(&public) && ids.contains(&mine),
        "the public claim and the viewer's own group-private claim must both be \
         served. Got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "the STRANGER's labelled claim must be absent — the widening direction. Got {ids:?}"
    );
}

/// `GET /api/v1/claims/:id/evidence`.
///
/// The parent claim is PUBLIC and shared by all three evidence rows, so the
/// claim predicate cannot be what withholds the stranger's evidence: only
/// `EvidenceRepository::get_by_claim`'s own `{VISIBILITY:…}` marker can.
#[sqlx::test(migrations = "../../migrations")]
async fn list_claim_evidence_serves_the_viewers_own_group_private_evidence(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-ev-viewer").await;
    let (_stranger_agent, stranger_group) =
        seed_agent_with_group(&pool, "shard7-ev-stranger").await;

    let parent = seed_public_claim(&pool, viewer_agent, "shard7 evidence parent").await;

    let public_ev = seed_evidence(&pool, parent, "document").await;
    let my_ev = seed_evidence(&pool, parent, "observation").await;
    let their_ev = seed_evidence(&pool, parent, "computation").await;
    force_tenancy(&pool, "evidence", my_ev, "group", viewer_group).await;
    force_tenancy(&pool, "evidence", their_ev, "group", stranger_group).await;

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    let rows = list_claim_evidence(ViewerExtractor(viewer), State(state), Path(parent))
        .await
        .expect("list_claim_evidence")
        .0;

    let ids: Vec<String> = rows.iter().map(|e| e.id.clone()).collect();
    assert_eq!(
        ids.len(),
        2,
        "three evidence rows hang from one PUBLIC claim; the viewer may read exactly \
         two. Got {ids:?}"
    );
    assert!(
        ids.contains(&public_ev.to_string()) && ids.contains(&my_ev.to_string()),
        "the public evidence and the viewer's own group-private evidence must both be \
         served. Got {ids:?}"
    );
    assert!(
        !ids.contains(&their_ev.to_string()),
        "the STRANGER's evidence must be absent even though its parent claim is public \
         — the widening direction. Got {ids:?}"
    );
}

// ── routes/versioning.rs ──

/// `GET /api/v1/claims/:id/history`.
///
/// A PUBLIC root with two successors: one group-private to the viewer, one to a
/// stranger. The chain is walked from the public root, so the root is never what
/// is withheld and the cardinality moves only on the successors.
#[sqlx::test(migrations = "../../migrations")]
async fn claim_history_walks_through_the_viewers_own_group_private_successor(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-hist-viewer").await;
    let (stranger_agent, stranger_group) =
        seed_agent_with_group(&pool, "shard7-hist-stranger").await;

    let root = seed_public_claim(&pool, viewer_agent, "shard7 history root").await;
    let mine = seed_successor(
        &pool,
        viewer_agent,
        root,
        viewer_group,
        "shard7 history mine",
    )
    .await;
    let theirs = seed_successor(
        &pool,
        stranger_agent,
        root,
        stranger_group,
        "shard7 history stranger",
    )
    .await;

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    let body = claim_history(ViewerExtractor(viewer), State(state), Path(root))
        .await
        .expect("claim_history")
        .0;

    let ids: Vec<Uuid> = body.versions.iter().map(|v| v.claim_id).collect();
    assert_eq!(
        ids.len(),
        2,
        "the chain is a public root plus two successors, one of which belongs to a \
         stranger: the viewer walks exactly two nodes. Got {ids:?}"
    );
    assert!(
        ids.contains(&root) && ids.contains(&mine),
        "the public root and the viewer's own group-private successor must both be \
         walked. Got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "the STRANGER's successor must be absent even though it hangs from the same \
         PUBLIC root — the widening direction. Got {ids:?}"
    );
}

// ── routes/workflows.rs and routes/conventions.rs ──

/// `GET /api/v1/workflows`.
///
/// Both this arm and [`list_skills_serves_the_viewers_own_group_private_workflow`]
/// bottom out in `WorkflowRepository::list`, which is the single signature this
/// shard widened to serve two converted sites in two different files. They are
/// kept as two arms rather than one because the handlers differ in what they
/// pass and in which file's register row they move.
#[sqlx::test(migrations = "../../migrations")]
async fn list_workflows_serves_the_viewers_own_group_private_workflow(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-wf-viewer").await;
    let (stranger_agent, stranger_group) = seed_agent_with_group(&pool, "shard7-wf-stranger").await;

    let public = seed_public_claim(&pool, viewer_agent, "shard7 workflow public").await;
    let mine = seed_group_claim(&pool, viewer_agent, viewer_group, "shard7 workflow mine").await;
    let theirs = seed_group_claim(
        &pool,
        stranger_agent,
        stranger_group,
        "shard7 workflow stranger",
    )
    .await;
    for c in [public, mine, theirs] {
        set_labels(&pool, c, &["workflow"]).await;
    }

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    let body = list_workflows(
        ViewerExtractor(viewer),
        State(state),
        Query(ListWorkflowsQuery {
            limit: Some(100),
            min_truth: Some(0.0),
        }),
    )
    .await
    .expect("list_workflows")
    .0;

    let ids: Vec<Uuid> = body["workflows"]
        .as_array()
        .expect("workflows array")
        .iter()
        .map(|w| {
            w["workflow_id"]
                .as_str()
                .expect("workflow_id")
                .parse()
                .expect("uuid")
        })
        .collect();

    assert_eq!(
        ids.len(),
        2,
        "three claims carry the `workflow` label; the viewer may read exactly two. \
         Got {ids:?}"
    );
    assert!(
        ids.contains(&public) && ids.contains(&mine),
        "the public workflow and the viewer's own group-private workflow must both be \
         served. Got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "the STRANGER's workflow must be absent — the widening direction. Got {ids:?}"
    );
}

/// `GET /api/v1/skills`.
#[sqlx::test(migrations = "../../migrations")]
async fn list_skills_serves_the_viewers_own_group_private_workflow(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-sk-viewer").await;
    let (stranger_agent, stranger_group) = seed_agent_with_group(&pool, "shard7-sk-stranger").await;

    let public = seed_public_claim(&pool, viewer_agent, "shard7 skill public").await;
    let mine = seed_group_claim(&pool, viewer_agent, viewer_group, "shard7 skill mine").await;
    let theirs = seed_group_claim(
        &pool,
        stranger_agent,
        stranger_group,
        "shard7 skill stranger",
    )
    .await;
    for c in [public, mine, theirs] {
        set_labels(&pool, c, &["workflow", "shard7-skill"]).await;
    }

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    let rows = list_skills(
        ViewerExtractor(viewer),
        State(state),
        Query(ListSkillsQuery {
            category: Some("shard7-skill".to_string()),
            min_truth: 0.0,
            limit: 100,
        }),
    )
    .await
    .expect("list_skills")
    .0;

    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids.len(),
        2,
        "three claims carry both labels; the viewer may read exactly two. Got {ids:?}"
    );
    assert!(
        ids.contains(&public) && ids.contains(&mine),
        "the public skill and the viewer's own group-private skill must both be \
         served. Got {ids:?}"
    );
    assert!(
        !ids.contains(&theirs),
        "the STRANGER's skill must be absent — the widening direction. This arm also \
         exercises the CATEGORY branch of `WorkflowRepository::list`, which is the \
         other of the two mutually exclusive arms the executor widening had to keep \
         compiling. Got {ids:?}"
    );
}

// ── routes/challenge.rs ──

/// `GET /api/v1/claims/:id/challenges`.
///
/// Three challenges against ONE public claim, so the claim predicate cannot be
/// what withholds the stranger's.
#[sqlx::test(migrations = "../../migrations")]
async fn list_challenges_serves_the_viewers_own_group_private_challenge(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-ch-viewer").await;
    let (stranger_agent, stranger_group) = seed_agent_with_group(&pool, "shard7-ch-stranger").await;

    let claim = seed_public_claim(&pool, viewer_agent, "shard7 challenge parent").await;

    let public_ch = seed_challenge(&pool, claim, viewer_agent, "shard7 challenge public").await;
    let my_ch = seed_challenge(&pool, claim, viewer_agent, "shard7 challenge mine").await;
    let their_ch = seed_challenge(&pool, claim, stranger_agent, "shard7 challenge stranger").await;
    force_tenancy(&pool, "challenges", my_ch, "group", viewer_group).await;
    force_tenancy(&pool, "challenges", their_ch, "group", stranger_group).await;

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    let body = list_challenges(ViewerExtractor(viewer), State(state), Path(claim))
        .await
        .expect("list_challenges")
        .0;

    let ids: Vec<Uuid> = body.challenges.iter().map(|c| c.id).collect();
    assert_eq!(
        ids.len(),
        2,
        "three challenges hang from one PUBLIC claim; the viewer may read exactly \
         two. Got {ids:?}"
    );
    assert!(
        ids.contains(&public_ch) && ids.contains(&my_ch),
        "the public challenge and the viewer's own group-private challenge must both \
         be served. Got {ids:?}"
    );
    assert!(
        !ids.contains(&their_ch),
        "the STRANGER's challenge must be absent even though its claim is public — the \
         widening direction. Got {ids:?}"
    );
}

// ── routes/entities.rs ──

/// `GET /api/v1/entities/:id/neighborhood`.
///
/// The subject entity is the shared parent and carries NO tenancy at migration
/// head 92, so nothing but `TripleRepository::entity_neighborhood`'s own marker
/// can withhold the stranger's triple. `EntityRepository::get` — the handler's
/// other converted site — is what resolves the subject at all, so a failure
/// there is a 404 rather than a short list.
#[sqlx::test(migrations = "../../migrations")]
async fn entity_neighborhood_serves_the_viewers_own_group_private_triple(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-nb-viewer").await;
    let (stranger_agent, stranger_group) = seed_agent_with_group(&pool, "shard7-nb-stranger").await;

    let subject = seed_entity(&pool, "shard7-neighborhood-subject", "Concept").await;
    let object = seed_entity(&pool, "shard7-neighborhood-object", "Concept").await;

    let public_claim = seed_public_claim(&pool, viewer_agent, "shard7 triple public").await;
    let my_claim = seed_group_claim(&pool, viewer_agent, viewer_group, "shard7 triple mine").await;
    let their_claim = seed_group_claim(
        &pool,
        stranger_agent,
        stranger_group,
        "shard7 triple stranger",
    )
    .await;

    let public_t = seed_triple(&pool, public_claim, subject, "relates_to", object).await;
    let my_t = seed_triple(&pool, my_claim, subject, "relates_to", object).await;
    let their_t = seed_triple(&pool, their_claim, subject, "relates_to", object).await;
    force_tenancy(&pool, "triples", public_t, "public", {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM groups WHERE kind = 'world' LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("world group")
    })
    .await;
    force_tenancy(&pool, "triples", my_t, "group", viewer_group).await;
    force_tenancy(&pool, "triples", their_t, "group", stranger_group).await;

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    let rows = entity_neighborhood(ViewerExtractor(viewer), State(state), Path(subject))
        .await
        .expect("entity_neighborhood")
        .0;

    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids.len(),
        2,
        "three triples hang from one UNTENANTED entity; the viewer may read exactly \
         two. Got {ids:?}"
    );
    assert!(
        ids.contains(&public_t) && ids.contains(&my_t),
        "the public triple and the viewer's own group-private triple must both be \
         served. Got {ids:?}"
    );
    assert!(
        !ids.contains(&their_t),
        "the STRANGER's triple must be absent even though the entity it hangs from is \
         visible to everyone — the widening direction. Got {ids:?}"
    );
}

/// `POST /api/v1/triples/query`.
///
/// This is the handler PR #460's tail-RLS classification filed as unconvertible
/// on a rule keyed to the HTTP verb. This arm is the evidence that the three
/// sites in it are reads and that converting them changes what the endpoint
/// returns in exactly the direction the conversion is for. Both name
/// resolutions AND the spliced `TripleRepository::query` run on the one stamped
/// connection the arm exercises.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_serves_the_viewers_own_group_private_triple(pool: PgPool) {
    let (viewer_agent, viewer_group) = seed_agent_with_group(&pool, "shard7-qt-viewer").await;
    let (stranger_agent, stranger_group) = seed_agent_with_group(&pool, "shard7-qt-stranger").await;

    let subject = seed_entity(&pool, "shard7-query-subject", "Concept").await;
    let object = seed_entity(&pool, "shard7-query-object", "Concept").await;

    let public_claim = seed_public_claim(&pool, viewer_agent, "shard7 qt public").await;
    let my_claim = seed_group_claim(&pool, viewer_agent, viewer_group, "shard7 qt mine").await;
    let their_claim =
        seed_group_claim(&pool, stranger_agent, stranger_group, "shard7 qt stranger").await;

    let public_t = seed_triple(&pool, public_claim, subject, "asserts", object).await;
    let my_t = seed_triple(&pool, my_claim, subject, "asserts", object).await;
    let their_t = seed_triple(&pool, their_claim, subject, "asserts", object).await;
    force_tenancy(&pool, "triples", public_t, "public", {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM groups WHERE kind = 'world' LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("world group")
    })
    .await;
    force_tenancy(&pool, "triples", my_t, "group", viewer_group).await;
    force_tenancy(&pool, "triples", their_t, "group", stranger_group).await;

    let viewer = viewer_for(&pool, viewer_agent).await;
    let state = split_state(&pool).await;

    let rows = query_triples(
        ViewerExtractor(viewer),
        State(state),
        axum::Json(QueryTriplesRequest {
            subject_name: Some("shard7-query-subject".to_string()),
            subject_type: Some("Concept".to_string()),
            predicate: Some("asserts".to_string()),
            object_name: Some("shard7-query-object".to_string()),
            object_type: Some("Concept".to_string()),
            min_confidence: None,
            limit: Some(100),
        }),
    )
    .await
    .expect("query_triples")
    .0;

    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids.len(),
        2,
        "both entity names resolved on the stamped connection and three triples match \
         the predicate; the viewer may read exactly two. A count of ZERO here means a \
         name resolution failed, which is a different defect from a suppression. Got \
         {ids:?}"
    );
    assert!(
        ids.contains(&public_t) && ids.contains(&my_t),
        "the public triple and the viewer's own group-private triple must both be \
         served. Got {ids:?}"
    );
    assert!(
        !ids.contains(&their_t),
        "the STRANGER's triple must be absent — the widening direction. Got {ids:?}"
    );
}
