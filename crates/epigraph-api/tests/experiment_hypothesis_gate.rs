#![cfg(feature = "db")]
//! Every experiment route gates on the HYPOTHESIS claim through the caller's
//! viewer (operator ruling R-51, follow-up of backlog 4815dcf7), the analyze
//! route requires `claims:write` (R-52), and so does every other experiment
//! write route and `POST /api/v1/methods` (R-52a), checked before anything is
//! read.
//!
//! An experiment, its results and their analyses carry no tenancy of their
//! own; what they belong to is the hypothesis they test. So:
//!
//! * a read (`GET /api/v1/experiments?hypothesis_id=`) needs the hypothesis
//!   readable; a hidden hypothesis is the same 404 as a missing one;
//! * a write (`new`, `start`, `results`, `measurements`, `analyze`) needs the
//!   hypothesis WRITABLE by the caller: hidden is that same 404, readable but
//!   not writable is `403 not_owner`;
//! * `measurements` names a result under `:eid`, and a result of another
//!   experiment is the same 404 as a missing result.
//!
//! The "readable, not writable" caller is a `reader` member of the
//! hypothesis's owning group: it reads the claim and holds no write role.
//! Every refusal asserts the EFFECT (no row, no status change) and every arm
//! carries a calibration call by the owner that must succeed, so a refusal
//! cannot come from a broken fixture.
//!
//! The test database connects as a superuser, which bypasses row security;
//! what these arms discriminate is the viewer's in-query predicate and the
//! writable-group check, which apply whatever the connection's role.
mod common;
mod viewer_fixture;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::SocketAddr;
use uuid::Uuid;

async fn shared_pool() -> (String, PgPool) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect");
    (url, pool)
}

/// The three callers every arm needs, around one group-private hypothesis.
struct World {
    pool: PgPool,
    addr: SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    /// Admin of the hypothesis's group: may read and write it.
    owner: Uuid,
    /// `reader` member of that group: may read it, may not write it.
    reader: Uuid,
    /// `writer` member of that group, NOT its admin and NOT the hypothesis's
    /// author: may write it, through the writable-group rule alone.
    writer: Uuid,
    /// A member of its own group only: may not read it.
    stranger: Uuid,
    /// The group that owns `hypothesis`.
    group: Uuid,
    hypothesis: Uuid,
}

/// Add `agent` to `group` with `role`.
async fn join(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("{role} membership: {e}"));
}

async fn world(label: &str) -> World {
    let (url, pool) = shared_pool().await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    let (owner, group) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-owner")).await;
    let (reader, _) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-reader")).await;
    let (writer, _) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-writer")).await;
    let (stranger, _) =
        viewer_fixture::seed_agent_with_group(&pool, &format!("{label}-stranger")).await;
    join(&pool, group, reader, "reader").await;
    join(&pool, group, writer, "writer").await;
    let hypothesis = viewer_fixture::seed_group_claim(
        &pool,
        owner,
        group,
        &format!("{label} hypothesis {}", Uuid::new_v4()),
    )
    .await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        owner,
        reader,
        writer,
        stranger,
        group,
        hypothesis,
    }
}

const RW: &[&str] = &["claims:read", "claims:write"];

/// POST `path` as `agent` with `scopes`; returns (status, JSON body or Null).
async fn post(
    addr: SocketAddr,
    agent: Uuid,
    scopes: &[&str],
    path: String,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let token = common::mint_token_with_agent(scopes, agent);
    let res = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .expect("request");
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(serde_json::Value::Null))
}

async fn get(addr: SocketAddr, agent: Uuid, path: String) -> (u16, serde_json::Value) {
    let token = common::mint_token_with_agent(&["claims:read"], agent);
    let res = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request");
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(serde_json::Value::Null))
}

/// A 404 body with the named id masked, so a refusal naming a real id can be
/// compared with one naming a random id.
fn masked(body: &serde_json::Value, id: Uuid) -> String {
    body.to_string().replace(&id.to_string(), "<id>")
}

/// The refusal is the writable-group 403, not a scope or auth refusal.
fn assert_not_owner(status: u16, body: &serde_json::Value, what: &str) {
    assert_eq!(
        status, 403,
        "{what}: a caller who can read but not write the hypothesis must be refused 403, \
         got {status} {body}"
    );
    assert_eq!(
        body["error"], "not_owner",
        "{what}: the 403 is the hypothesis write gate, not a scope check: {body}"
    );
}

/// An experiment on `hypothesis` in `status`, with one result; returns
/// `(experiment, result)`.
async fn seed_experiment(
    pool: &PgPool,
    hypothesis: Uuid,
    creator: Uuid,
    status: &str,
) -> (Uuid, Uuid) {
    let experiment: Uuid = sqlx::query_scalar(
        "INSERT INTO experiments (hypothesis_id, created_by, status) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(hypothesis)
    .bind(creator)
    .bind(status)
    .fetch_one(pool)
    .await
    .expect("seed experiment");
    let result: Uuid = sqlx::query_scalar(
        "INSERT INTO experiment_results (experiment_id, data_source, raw_measurements, measurement_count) \
         VALUES ($1, 'instrument', $2, 2) RETURNING id",
    )
    .bind(experiment)
    .bind(serde_json::json!([
        {"value": 1.2, "random_error": 0.05, "systematic_error": 0.02},
        {"value": 1.1, "random_error": 0.05, "systematic_error": 0.02}
    ]))
    .fetch_one(pool)
    .await
    .expect("seed result");
    (experiment, result)
}

async fn experiments_on(pool: &PgPool, hypothesis: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM experiments WHERE hypothesis_id = $1")
        .bind(hypothesis)
        .fetch_one(pool)
        .await
        .expect("count experiments")
}

async fn experiment_status(pool: &PgPool, experiment: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM experiments WHERE id = $1")
        .bind(experiment)
        .fetch_one(pool)
        .await
        .expect("experiment status")
}

async fn results_of(pool: &PgPool, experiment: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM experiment_results WHERE experiment_id = $1")
        .bind(experiment)
        .fetch_one(pool)
        .await
        .expect("count results")
}

async fn measurement_count(pool: &PgPool, result: Uuid) -> i32 {
    sqlx::query_scalar("SELECT measurement_count FROM experiment_results WHERE id = $1")
        .bind(result)
        .fetch_one(pool)
        .await
        .expect("measurement count")
}

// ── POST /api/v1/experiments/new ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn creating_an_experiment_needs_the_hypothesis_writable() {
    let w = world("r51-new").await;
    let create = |agent: Uuid, hypothesis: Uuid| {
        post(
            w.addr,
            agent,
            RW,
            "/api/v1/experiments/new".to_string(),
            serde_json::json!({ "hypothesis_id": hypothesis, "agent_id": agent }),
        )
    };

    // Hidden: the same 404 as a hypothesis that does not exist.
    let (status, body) = create(w.stranger, w.hypothesis).await;
    assert_eq!(
        status, 404,
        "hidden hypothesis must be 404, got {status} {body}"
    );
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) = create(w.stranger, missing).await;
    assert_eq!(
        missing_status, 404,
        "calibration: a missing hypothesis is 404"
    );
    assert_eq!(
        masked(&body, w.hypothesis),
        masked(&missing_body, missing),
        "a hidden hypothesis must be indistinguishable from a missing one"
    );

    // Readable, not writable.
    let (status, body) = create(w.reader, w.hypothesis).await;
    assert_not_owner(status, &body, "new");

    assert_eq!(
        experiments_on(&w.pool, w.hypothesis).await,
        0,
        "a refused create must record no experiment"
    );

    // CALIBRATION: the owner.
    let (status, body) = create(w.owner, w.hypothesis).await;
    assert_eq!(status, 200, "calibration: the owner creates: {body}");
    assert_eq!(experiments_on(&w.pool, w.hypothesis).await, 1);
}

// ── POST /api/v1/experiments/:id/start ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn starting_an_experiment_needs_its_hypothesis_writable() {
    let w = world("r51-start").await;
    let (experiment, _) = seed_experiment(&w.pool, w.hypothesis, w.owner, "designed").await;
    let start = |agent: Uuid, experiment: Uuid| {
        post(
            w.addr,
            agent,
            RW,
            format!("/api/v1/experiments/{experiment}/start"),
            serde_json::json!({}),
        )
    };

    let (status, body) = start(w.stranger, experiment).await;
    assert_eq!(
        status, 404,
        "hidden hypothesis must be 404, got {status} {body}"
    );
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) = start(w.stranger, missing).await;
    assert_eq!(
        missing_status, 404,
        "a missing experiment is 404, not a silent no-op: {missing_body}"
    );
    assert_eq!(
        masked(&body, experiment),
        masked(&missing_body, missing),
        "an experiment on a hidden hypothesis must be indistinguishable from a missing one"
    );

    let (status, body) = start(w.reader, experiment).await;
    assert_not_owner(status, &body, "start");

    assert_eq!(
        experiment_status(&w.pool, experiment).await,
        "designed",
        "a refused start must not change the experiment"
    );

    let (status, body) = start(w.owner, experiment).await;
    assert_eq!(status, 200, "calibration: the owner starts: {body}");
    assert_eq!(experiment_status(&w.pool, experiment).await, "running");
}

// ── POST /api/v1/experiments/:id/results ───────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn submitting_results_needs_the_hypothesis_writable() {
    let w = world("r51-results").await;
    let (experiment, _) = seed_experiment(&w.pool, w.hypothesis, w.owner, "running").await;
    let submit = |agent: Uuid, experiment: Uuid| {
        post(
            w.addr,
            agent,
            RW,
            format!("/api/v1/experiments/{experiment}/results"),
            serde_json::json!({
                "data_source": "instrument",
                "measurements": [{"value": 1.0, "random_error": 0.1}],
            }),
        )
    };

    let (status, body) = submit(w.stranger, experiment).await;
    assert_eq!(
        status, 404,
        "hidden hypothesis must be 404, got {status} {body}"
    );
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) = submit(w.stranger, missing).await;
    assert_eq!(
        missing_status, 404,
        "calibration: a missing experiment is 404"
    );
    assert_eq!(
        masked(&body, experiment),
        masked(&missing_body, missing),
        "an experiment on a hidden hypothesis must be indistinguishable from a missing one"
    );

    let (status, body) = submit(w.reader, experiment).await;
    assert_not_owner(status, &body, "results");

    assert_eq!(
        (
            results_of(&w.pool, experiment).await,
            experiment_status(&w.pool, experiment).await
        ),
        (1, "running".to_string()),
        "a refused submit must record no result and change no status"
    );

    let (status, body) = submit(w.owner, experiment).await;
    assert_eq!(status, 200, "calibration: the owner submits: {body}");
    assert_eq!(results_of(&w.pool, experiment).await, 2);
}

// ── POST /api/v1/experiments/:eid/results/:rid/measurements ────────────────

#[tokio::test(flavor = "multi_thread")]
async fn adding_measurements_needs_the_hypothesis_writable_and_the_result_under_eid() {
    let w = world("r51-measure").await;
    let (experiment, result) = seed_experiment(&w.pool, w.hypothesis, w.owner, "collecting").await;
    // A second experiment of the SAME owner on the same hypothesis: the
    // mismatch below is refused for the pairing alone, not for any hypothesis.
    let (other_experiment, other_result) =
        seed_experiment(&w.pool, w.hypothesis, w.owner, "collecting").await;
    let add = |agent: Uuid, experiment: Uuid, result: Uuid| {
        post(
            w.addr,
            agent,
            RW,
            format!("/api/v1/experiments/{experiment}/results/{result}/measurements"),
            serde_json::json!({ "measurements": [{"value": 1.0, "random_error": 0.1}] }),
        )
    };

    let (status, body) = add(w.stranger, experiment, result).await;
    assert_eq!(
        status, 404,
        "hidden hypothesis must be 404, got {status} {body}"
    );
    // Compared with a pair that does not exist at all, both ids random: a
    // comparison with (hidden experiment, random result) would take the same
    // branch as the hidden pair and show nothing.
    let (absent_experiment, absent_result) = (Uuid::new_v4(), Uuid::new_v4());
    let (absent_status, absent_body) = add(w.stranger, absent_experiment, absent_result).await;
    assert_eq!(
        absent_status, 404,
        "calibration: a pair that does not exist is 404"
    );
    assert_eq!(
        masked(&body, result),
        masked(&absent_body, absent_result),
        "a result on a hidden hypothesis must be indistinguishable from a pair that does not \
         exist"
    );
    assert!(
        !body.to_string().contains(&experiment.to_string())
            && !body.to_string().contains(&w.hypothesis.to_string()),
        "the refusal must name neither the hidden experiment nor its hypothesis: {body}"
    );
    let missing = Uuid::new_v4();

    let (status, body) = add(w.reader, experiment, result).await;
    assert_not_owner(status, &body, "measurements");

    // The owner, naming its other experiment's result under this experiment.
    let (status, body) = add(w.owner, experiment, other_result).await;
    assert_eq!(
        status, 404,
        "a result of another experiment must be 404, got {status} {body}"
    );
    let (_, owner_missing_body) = add(w.owner, experiment, missing).await;
    assert_eq!(
        masked(&body, other_result),
        masked(&owner_missing_body, missing),
        "a mismatched result must be indistinguishable from a missing one"
    );

    assert_eq!(
        (
            measurement_count(&w.pool, result).await,
            measurement_count(&w.pool, other_result).await
        ),
        (2, 2),
        "a refused add must append no measurement to either result"
    );

    let (status, body) = add(w.owner, experiment, result).await;
    assert_eq!(status, 200, "calibration: the owner adds: {body}");
    let (status, body) = add(w.owner, other_experiment, other_result).await;
    assert_eq!(status, 200, "calibration: the matching pair adds: {body}");
    assert_eq!(
        (
            measurement_count(&w.pool, result).await,
            measurement_count(&w.pool, other_result).await
        ),
        (3, 3)
    );
}

// ── POST /api/v1/experiments/:eid/results/:rid/analyze ─────────────────────

async fn analyze(
    w: &World,
    agent: Uuid,
    scopes: &[&str],
    experiment: Uuid,
    result: Uuid,
) -> (u16, serde_json::Value) {
    post(
        w.addr,
        agent,
        scopes,
        format!("/api/v1/experiments/{experiment}/results/{result}/analyze"),
        serde_json::json!({
            "agent_id": agent,
            "direction": "supports",
            "scope_limitations": [],
            "expected_value": 0.0,
        }),
    )
    .await
}

/// (error-derived BBAs and `provides_evidence` edges on the hypothesis, the
/// experiment's status).
async fn analyze_footprint(w: &World, experiment: Uuid) -> (i64, i64, String) {
    analyze_footprint_on(&w.pool, w.hypothesis, experiment).await
}

/// [`analyze_footprint`] for any `hypothesis`.
async fn analyze_footprint_on(
    pool: &PgPool,
    hypothesis: Uuid,
    experiment: Uuid,
) -> (i64, i64, String) {
    let bbas: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions \
         WHERE claim_id = $1 AND combination_method = 'error_derived'",
    )
    .bind(hypothesis)
    .fetch_one(pool)
    .await
    .expect("count BBAs");
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'provides_evidence'",
    )
    .bind(hypothesis)
    .fetch_one(pool)
    .await
    .expect("count edges");
    (bbas, edges, experiment_status(pool, experiment).await)
}

async fn ensure_hypothesis_frame(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO frames (name, hypotheses) VALUES ('hypothesis_assessment', \
         ARRAY['true','false']::text[]) ON CONFLICT (name) DO NOTHING",
    )
    .execute(pool)
    .await
    .expect("seed hypothesis_assessment frame");
}

/// R-51: analyze files evidence ON the hypothesis, so reading it is not
/// enough. A reader of the hypothesis's group is refused 403 and nothing lands.
#[tokio::test(flavor = "multi_thread")]
async fn analyzing_needs_the_hypothesis_writable_not_only_readable() {
    let w = world("r51-analyze").await;
    ensure_hypothesis_frame(&w.pool).await;
    let (experiment, result) = seed_experiment(&w.pool, w.hypothesis, w.owner, "collecting").await;

    let before = analyze_footprint(&w, experiment).await;
    let (status, body) = analyze(&w, w.reader, RW, experiment, result).await;
    assert_not_owner(status, &body, "analyze");
    assert_eq!(
        analyze_footprint(&w, experiment).await,
        before,
        "a refused analyze must write no BBA, no edge and no status change"
    );

    let (status, body) = analyze(&w, w.owner, RW, experiment, result).await;
    assert_eq!(status, 200, "calibration: the owner analyzes: {body}");
    let (bbas, edges, exp_status) = analyze_footprint(&w, experiment).await;
    assert!(
        bbas == before.0 + 1 && edges == before.1 + 1 && exp_status == "complete",
        "calibration: the owner's analyze lands (bbas {bbas}, edges {edges}, status {exp_status})"
    );
}

/// R-51: a stranger naming a real, correctly paired experiment and result
/// whose hypothesis it cannot read gets the same 404 as for a result that
/// does not exist. Answering with a `hypothesis` 404 instead told it the pair
/// exists and handed it the private hypothesis's id.
#[tokio::test(flavor = "multi_thread")]
async fn analyzing_onto_a_hidden_hypothesis_is_the_missing_result_404() {
    let w = world("r51-analyze-hidden").await;
    ensure_hypothesis_frame(&w.pool).await;
    let (experiment, result) = seed_experiment(&w.pool, w.hypothesis, w.owner, "collecting").await;

    let before = analyze_footprint(&w, experiment).await;
    let (status, body) = analyze(&w, w.stranger, RW, experiment, result).await;
    assert_eq!(
        status, 404,
        "hidden hypothesis must be 404, got {status} {body}"
    );
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) = analyze(&w, w.stranger, RW, experiment, missing).await;
    assert_eq!(missing_status, 404, "calibration: a missing result is 404");
    assert_eq!(
        masked(&body, result),
        masked(&missing_body, missing),
        "a result on a hidden hypothesis must be indistinguishable from a missing one"
    );
    assert!(
        !body.to_string().contains(&w.hypothesis.to_string()),
        "the refusal must not name the hidden hypothesis: {body}"
    );
    assert_eq!(
        analyze_footprint(&w, experiment).await,
        before,
        "a refused analyze must write no BBA, no edge and no status change"
    );

    let (status, body) = analyze(&w, w.owner, RW, experiment, result).await;
    assert_eq!(status, 200, "calibration: the owner analyzes: {body}");
}

/// R-52: analyze writes evidence, so it takes the scope every other evidence
/// writer takes. The owner of the hypothesis with a read-only token is refused
/// 403 naming `claims:write`, and nothing lands.
#[tokio::test(flavor = "multi_thread")]
async fn analyzing_requires_the_claims_write_scope() {
    let w = world("r52-analyze").await;
    ensure_hypothesis_frame(&w.pool).await;
    let (experiment, result) = seed_experiment(&w.pool, w.hypothesis, w.owner, "collecting").await;

    let before = analyze_footprint(&w, experiment).await;
    let (status, body) = analyze(&w, w.owner, &["claims:read"], experiment, result).await;
    assert_eq!(
        status, 403,
        "analyze without claims:write must be 403, got {status} {body}"
    );
    assert!(
        body.to_string().contains("claims:write"),
        "the refusal names the missing scope: {body}"
    );
    assert_eq!(
        analyze_footprint(&w, experiment).await,
        before,
        "a refused analyze must write no BBA, no edge and no status change"
    );

    let (status, body) = analyze(&w, w.owner, RW, experiment, result).await;
    assert_eq!(
        status, 200,
        "calibration: the same owner with claims:write: {body}"
    );
}

// ── Who may write: the writable-group rule, and nothing else ──────────────
//
// Every other arm's admitted caller (`owner`) is the hypothesis's author AND
// its group's admin AND in its writable set at once, so on their own those
// arms would also pass an admin-only gate or an author-only gate. These two
// arms tell the three apart: R-51's "writable by the caller" is the owning
// group in the caller's writable set (`admin` OR `writer` role), with no
// author arm and no admin requirement.

/// A `writer` member of the owning group, who is neither its admin nor the
/// hypothesis's author, may create an experiment and analyze a result, and the
/// effect lands. An admin-only or author-only gate would refuse it.
#[tokio::test(flavor = "multi_thread")]
async fn a_writer_member_who_did_not_author_the_hypothesis_may_write_it() {
    let w = world("r51-writer").await;
    ensure_hypothesis_frame(&w.pool).await;

    // new
    let (status, body) = post(
        w.addr,
        w.writer,
        RW,
        "/api/v1/experiments/new".to_string(),
        serde_json::json!({ "hypothesis_id": w.hypothesis, "agent_id": w.writer }),
    )
    .await;
    assert_eq!(
        status, 200,
        "a writer member of the owning group creates an experiment: {body}"
    );
    assert_eq!(
        experiments_on(&w.pool, w.hypothesis).await,
        1,
        "the writer's create records the experiment"
    );

    // analyze, on an experiment and result of its own so nothing else touches
    // them.
    let (experiment, result) = seed_experiment(&w.pool, w.hypothesis, w.writer, "collecting").await;
    let before = analyze_footprint(&w, experiment).await;
    let (status, body) = analyze(&w, w.writer, RW, experiment, result).await;
    assert_eq!(
        status, 200,
        "a writer member of the owning group analyzes a result: {body}"
    );
    let (bbas, edges, exp_status) = analyze_footprint(&w, experiment).await;
    assert!(
        bbas == before.0 + 1 && edges == before.1 + 1 && exp_status == "complete",
        "the writer's analyze lands one BBA and one provides_evidence edge and completes the \
         experiment (bbas {bbas}, edges {edges}, status {exp_status})"
    );
}

/// Authoring a hypothesis is not write access to it. An agent who wrote the
/// claim but holds only a `reader` membership in its owning group is refused
/// `403 not_owner` on create and on analyze, and nothing is written. An
/// author-or-writable gate would admit it.
#[tokio::test(flavor = "multi_thread")]
async fn the_author_of_a_hypothesis_it_only_reads_may_not_write_it() {
    let w = world("r51-author-reader").await;
    ensure_hypothesis_frame(&w.pool).await;
    // Authored by the `reader` member, owned by the group it only reads.
    let hypothesis = viewer_fixture::seed_group_claim(
        &w.pool,
        w.reader,
        w.group,
        &format!("r51 hypothesis authored by a reader {}", Uuid::new_v4()),
    )
    .await;
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(hypothesis)
        .fetch_one(&w.pool)
        .await
        .expect("hypothesis author");
    assert_eq!(
        author, w.reader,
        "CALIBRATION: the refused caller is the author"
    );
    let create = |agent: Uuid| {
        post(
            w.addr,
            agent,
            RW,
            "/api/v1/experiments/new".to_string(),
            serde_json::json!({ "hypothesis_id": hypothesis, "agent_id": agent }),
        )
    };

    let (status, body) = create(w.reader).await;
    assert_not_owner(status, &body, "new, by the author with a reader membership");
    assert_eq!(
        experiments_on(&w.pool, hypothesis).await,
        0,
        "the author's refused create records no experiment"
    );

    let (experiment, result) = seed_experiment(&w.pool, hypothesis, w.owner, "collecting").await;
    let before = analyze_footprint_on(&w.pool, hypothesis, experiment).await;
    let (status, body) = analyze(&w, w.reader, RW, experiment, result).await;
    assert_not_owner(
        status,
        &body,
        "analyze, by the author with a reader membership",
    );
    assert_eq!(
        analyze_footprint_on(&w.pool, hypothesis, experiment).await,
        before,
        "the author's refused analyze writes no BBA, no edge and no status change"
    );

    // CALIBRATION: the same hypothesis is writable by a member who may write
    // its group, so the refusals above are about the caller.
    let (status, body) = create(w.owner).await;
    assert_eq!(status, 200, "calibration: the group admin creates: {body}");
    let (status, body) = analyze(&w, w.owner, RW, experiment, result).await;
    assert_eq!(status, 200, "calibration: the group admin analyzes: {body}");
}

// ── A public hypothesis: readable by everyone, writable by no ordinary agent ─

/// A PUBLIC hypothesis (owned by the memberless world group, the shape of the
/// legacy corpus) is the second way a caller can read a hypothesis it may not
/// write. R-51's consequence for it: any agent lists its experiments, but
/// none outside the owning group's writable set may create an experiment on
/// it or analyze a result onto it. That includes its author. The refusal is
/// `403 not_owner`, not a 404 and not a 200, and nothing is written.
#[tokio::test(flavor = "multi_thread")]
async fn a_public_hypothesis_is_listed_by_anyone_and_written_by_no_ordinary_agent() {
    let w = world("r51-public").await;
    ensure_hypothesis_frame(&w.pool).await;
    let hypothesis = viewer_fixture::seed_public_claim(
        &w.pool,
        w.owner,
        &format!("r51 public hypothesis {}", Uuid::new_v4()),
    )
    .await;
    let (experiment, result) = seed_experiment(&w.pool, hypothesis, w.owner, "collecting").await;

    // CALIBRATION: the hypothesis is readable by the stranger, so a refusal
    // below is the write gate and not a hidden-hypothesis 404.
    let (status, body) = get(
        w.addr,
        w.stranger,
        format!("/api/v1/experiments?hypothesis_id={hypothesis}"),
    )
    .await;
    assert_eq!(
        status, 200,
        "anyone lists the experiments of a public hypothesis: {body}"
    );
    let ids: Vec<String> = body["experiments"]
        .as_array()
        .expect("experiments array")
        .iter()
        .map(|e| e["id"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(ids, vec![experiment.to_string()], "{body}");

    // The stranger, and the claim's own author: neither may write it.
    for (agent, who) in [(w.stranger, "a stranger"), (w.owner, "its author")] {
        let (status, body) = post(
            w.addr,
            agent,
            RW,
            "/api/v1/experiments/new".to_string(),
            serde_json::json!({ "hypothesis_id": hypothesis, "agent_id": agent }),
        )
        .await;
        assert_not_owner(
            status,
            &body,
            &format!("new on a public hypothesis, by {who}"),
        );

        let before = analyze_footprint_on(&w.pool, hypothesis, experiment).await;
        let (status, body) = analyze(&w, agent, RW, experiment, result).await;
        assert_not_owner(
            status,
            &body,
            &format!("analyze onto a public hypothesis, by {who}"),
        );
        assert_eq!(
            analyze_footprint_on(&w.pool, hypothesis, experiment).await,
            before,
            "a refused analyze by {who} writes no BBA, no edge and no status change"
        );
    }
    assert_eq!(
        experiments_on(&w.pool, hypothesis).await,
        1,
        "the refused creates record no experiment beside the seeded one"
    );
}

// ── GET /api/v1/experiments?hypothesis_id= ─────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn listing_experiments_needs_the_hypothesis_readable() {
    let w = world("r51-list").await;
    let (experiment, _) = seed_experiment(&w.pool, w.hypothesis, w.owner, "designed").await;
    let list = |agent: Uuid, hypothesis: Uuid| {
        get(
            w.addr,
            agent,
            format!("/api/v1/experiments?hypothesis_id={hypothesis}"),
        )
    };

    let (status, body) = list(w.stranger, w.hypothesis).await;
    assert_eq!(
        status, 404,
        "listing the experiments of a hidden hypothesis must be 404, got {status} {body}"
    );
    assert!(
        !body.to_string().contains(&experiment.to_string()),
        "the refusal must not name the experiment: {body}"
    );
    let missing = Uuid::new_v4();
    let (missing_status, missing_body) = list(w.stranger, missing).await;
    assert_eq!(missing_status, 404, "a missing hypothesis is 404");
    assert_eq!(
        masked(&body, w.hypothesis),
        masked(&missing_body, missing),
        "a hidden hypothesis must be indistinguishable from a missing one"
    );

    // A read needs the hypothesis readable only: the reader lists it.
    for agent in [w.reader, w.owner] {
        let (status, body) = list(agent, w.hypothesis).await;
        assert_eq!(
            status, 200,
            "calibration: a reader of the hypothesis lists: {body}"
        );
        let ids: Vec<String> = body["experiments"]
            .as_array()
            .expect("experiments array")
            .iter()
            .map(|e| e["id"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(ids, vec![experiment.to_string()], "calibration: {body}");
    }
}

// ── R-52a: every experiment write route requires `claims:write` ───────────
//
// Each arm sends a `claims:read` token for three callers whose refusal would
// differ if the hypothesis gate ran first: the owner (the gate admits it), a
// `reader` member (the gate answers `403 not_owner`) and a stranger (the gate
// answers 404). All three must get the same scope refusal, so the scope is
// checked before the hypothesis is read and a read-only token learns nothing
// about it. The footprint is unchanged after the refusals, and the same owner
// with `claims:write` then writes.

const READ_ONLY: &[&str] = &["claims:read"];

/// The refusal is the scope check: `403 Forbidden` naming `claims:write`, not
/// the hypothesis gate's `not_owner` and not its 404.
fn assert_scope_refusal(status: u16, body: &serde_json::Value, what: &str) {
    assert_eq!(
        status, 403,
        "{what}: a token without claims:write must be refused 403, got {status} {body}"
    );
    assert_eq!(
        body["error"], "Forbidden",
        "{what}: the 403 is the scope check, not the hypothesis write gate: {body}"
    );
    assert!(
        body.to_string().contains("claims:write"),
        "{what}: the refusal names the missing scope: {body}"
    );
}

/// Send `call` for the owner, the reader and the stranger with a read-only
/// token; each must be the scope refusal, with one body for all three.
async fn assert_read_only_refused<F, Fut>(w: &World, what: &str, call: F)
where
    F: Fn(Uuid) -> Fut,
    Fut: std::future::Future<Output = (u16, serde_json::Value)>,
{
    let mut bodies = Vec::new();
    for (agent, who) in [
        (w.owner, "the owner"),
        (w.reader, "a reader member"),
        (w.stranger, "a stranger"),
    ] {
        let (status, body) = call(agent).await;
        assert_scope_refusal(status, &body, &format!("{what}, by {who}"));
        bodies.push(body);
    }
    assert!(
        bodies.windows(2).all(|p| p[0] == p[1]),
        "{what}: the scope refusal must not depend on the caller's access to the hypothesis: \
         {bodies:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn creating_an_experiment_requires_the_claims_write_scope() {
    let w = world("r52a-new").await;
    let create = |agent: Uuid, scopes: &'static [&'static str]| {
        post(
            w.addr,
            agent,
            scopes,
            "/api/v1/experiments/new".to_string(),
            serde_json::json!({ "hypothesis_id": w.hypothesis, "agent_id": agent }),
        )
    };

    assert_read_only_refused(&w, "new", |agent| create(agent, READ_ONLY)).await;
    assert_eq!(
        experiments_on(&w.pool, w.hypothesis).await,
        0,
        "a refused create must record no experiment"
    );

    let (status, body) = create(w.owner, RW).await;
    assert_eq!(
        status, 200,
        "calibration: the same owner with claims:write: {body}"
    );
    assert_eq!(experiments_on(&w.pool, w.hypothesis).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn starting_an_experiment_requires_the_claims_write_scope() {
    let w = world("r52a-start").await;
    let (experiment, _) = seed_experiment(&w.pool, w.hypothesis, w.owner, "designed").await;
    let start = |agent: Uuid, scopes: &'static [&'static str]| {
        post(
            w.addr,
            agent,
            scopes,
            format!("/api/v1/experiments/{experiment}/start"),
            serde_json::json!({}),
        )
    };

    assert_read_only_refused(&w, "start", |agent| start(agent, READ_ONLY)).await;
    assert_eq!(
        experiment_status(&w.pool, experiment).await,
        "designed",
        "a refused start must not change the experiment"
    );

    let (status, body) = start(w.owner, RW).await;
    assert_eq!(
        status, 200,
        "calibration: the same owner with claims:write: {body}"
    );
    assert_eq!(experiment_status(&w.pool, experiment).await, "running");
}

#[tokio::test(flavor = "multi_thread")]
async fn submitting_results_requires_the_claims_write_scope() {
    let w = world("r52a-results").await;
    let (experiment, _) = seed_experiment(&w.pool, w.hypothesis, w.owner, "running").await;
    let submit = |agent: Uuid, scopes: &'static [&'static str]| {
        post(
            w.addr,
            agent,
            scopes,
            format!("/api/v1/experiments/{experiment}/results"),
            serde_json::json!({
                "data_source": "instrument",
                "measurements": [{"value": 1.0, "random_error": 0.1}],
            }),
        )
    };

    assert_read_only_refused(&w, "results", |agent| submit(agent, READ_ONLY)).await;
    assert_eq!(
        (
            results_of(&w.pool, experiment).await,
            experiment_status(&w.pool, experiment).await
        ),
        (1, "running".to_string()),
        "a refused submit must record no result and change no status"
    );

    let (status, body) = submit(w.owner, RW).await;
    assert_eq!(
        status, 200,
        "calibration: the same owner with claims:write: {body}"
    );
    assert_eq!(results_of(&w.pool, experiment).await, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn adding_measurements_requires_the_claims_write_scope() {
    let w = world("r52a-measure").await;
    let (experiment, result) = seed_experiment(&w.pool, w.hypothesis, w.owner, "collecting").await;
    let add = |agent: Uuid, scopes: &'static [&'static str]| {
        post(
            w.addr,
            agent,
            scopes,
            format!("/api/v1/experiments/{experiment}/results/{result}/measurements"),
            serde_json::json!({ "measurements": [{"value": 1.0, "random_error": 0.1}] }),
        )
    };

    assert_read_only_refused(&w, "measurements", |agent| add(agent, READ_ONLY)).await;
    assert_eq!(
        measurement_count(&w.pool, result).await,
        2,
        "a refused add must append no measurement"
    );

    let (status, body) = add(w.owner, RW).await;
    assert_eq!(
        status, 200,
        "calibration: the same owner with claims:write: {body}"
    );
    assert_eq!(measurement_count(&w.pool, result).await, 3);
}

// ── POST /api/v1/methods ──────────────────────────────────────────────────

/// (method rows with `canonical_name`, capability links on them).
async fn method_footprint(pool: &PgPool, canonical_name: &str) -> (i64, i64) {
    let methods: i64 = sqlx::query_scalar("SELECT count(*) FROM methods WHERE canonical_name = $1")
        .bind(canonical_name)
        .fetch_one(pool)
        .await
        .expect("count methods");
    let links: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM method_capabilities mc JOIN methods m ON m.id = mc.method_id \
         WHERE m.canonical_name = $1",
    )
    .bind(canonical_name)
    .fetch_one(pool)
    .await
    .expect("count capability links");
    (methods, links)
}

/// R-52a: adding a method writes the shared method catalog (a method row and
/// its capability links), so it takes `claims:write` like the experiment
/// writes. A read-only token is refused and nothing is written; the same agent
/// with `claims:write` adds the method and its capability.
#[tokio::test(flavor = "multi_thread")]
async fn adding_a_method_requires_the_claims_write_scope() {
    let w = world("r52a-method").await;
    let tag = Uuid::new_v4().simple().to_string();
    let name = format!("r52a method {tag}");
    let canonical = name.to_lowercase().replace(' ', "_");
    let add = |scopes: &'static [&'static str]| {
        post(
            w.addr,
            w.owner,
            scopes,
            "/api/v1/methods".to_string(),
            serde_json::json!({
                "name": name,
                "technique_type": "characterization",
                "capabilities": [format!("r52a-capability-{tag}")],
            }),
        )
    };

    let (status, body) = add(READ_ONLY).await;
    assert_scope_refusal(status, &body, "add_method");
    assert_eq!(
        method_footprint(&w.pool, &canonical).await,
        (0, 0),
        "a refused add_method must write no method and no capability link"
    );

    let (status, body) = add(RW).await;
    assert_eq!(
        status, 200,
        "calibration: the same agent with claims:write: {body}"
    );
    assert_eq!(
        method_footprint(&w.pool, &canonical).await,
        (1, 1),
        "calibration: the method and its capability link land"
    );
}
