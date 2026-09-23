//! End-to-end tests for the `link_alternative` MCP tool.
//!
//! Drives `do_link_alternative` directly against a `sqlx::test` pool, the same
//! way `link_hierarchical_smoke.rs` drives its tool. Until this file the tool
//! had no caller outside its own module, and neither did its one writer,
//! `EdgeRepository::create_symmetric_if_absent_returning`.
//!
//! The two `ON CONFLICT` tests are the point of the file. The writer's
//! `INSERT … WHERE NOT EXISTS … ON CONFLICT DO NOTHING` has an exit that a
//! sequential second call never reaches, because the guard sees the first row.
//! It is reached when the guard cannot see the conflicting row: either the row
//! commits while the INSERT is in flight (VISIBLE once committed), or the row
//! is hidden from the writer by row-level security (INVISIBLE). The
//! repository-level versions of both are in `epigraph-db`'s
//! `edge_repo_tests.rs` and `rls_enforcement.rs`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::link_alternative::do_link_alternative;
use epigraph_mcp::types::LinkAlternativeParams;
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

/// Local mirror of the Serialize-only `LinkAlternativeResponse`.
#[derive(serde::Deserialize)]
struct LinkAlternativeResponse {
    edge_id: String,
    created: bool,
}

fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

fn params(a: Uuid, b: Uuid) -> LinkAlternativeParams {
    LinkAlternativeParams {
        claim_a: a.to_string(),
        claim_b: b.to_string(),
        target_claim_id: None,
        rationale: None,
    }
}

fn parse_response(result: &rmcp::model::CallToolResult) -> LinkAlternativeResponse {
    let text = result
        .content
        .first()
        .expect("at least one content block")
        .as_text()
        .expect("text content")
        .text
        .clone();
    serde_json::from_str(&text).expect("LinkAlternativeResponse JSON")
}

/// Every `alternative_of` row for the unordered pair, retracted or not, read on
/// the pool the caller passes (the superuser test pool sees everything).
async fn pair_count(pool: &PgPool, a: Uuid, b: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges \
         WHERE ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)) \
           AND relationship = 'alternative_of'",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("count alternative_of edges for the pair")
}

/// Two public claims by one seeded agent.
async fn two_public_claims(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let (agent, _group) = fixture::seed_agent_with_group(pool, label).await;
    let a = fixture::seed_public_claim(pool, agent, &format!("{label} rival a")).await;
    let b = fixture::seed_public_claim(pool, agent, &format!("{label} rival b")).await;
    (a, b)
}

#[sqlx::test(migrations = "../../migrations")]
async fn links_a_pair_once_and_a_reversed_call_returns_the_same_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    let (a, b) = two_public_claims(&pool, "alt-happy").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "alt-happy-target").await;
    let target = fixture::seed_public_claim(&pool, agent, "the shared target").await;

    let first = do_link_alternative(
        &server,
        &viewer,
        LinkAlternativeParams {
            claim_a: a.to_string(),
            claim_b: b.to_string(),
            target_claim_id: Some(target.to_string()),
            rationale: Some("rival explanations".to_string()),
        },
    )
    .await
    .expect("the first link succeeds");
    let first = parse_response(&first);
    assert!(first.created, "the first call must report created=true");

    let (source, dest, props): (Uuid, Uuid, serde_json::Value) = sqlx::query_as(
        "SELECT source_id, target_id, properties FROM edges \
         WHERE id = $1::uuid AND relationship = 'alternative_of' \
           AND source_type = 'claim' AND target_type = 'claim'",
    )
    .bind(&first.edge_id)
    .fetch_one(&pool)
    .await
    .expect("the returned edge_id names an alternative_of claim-claim row");
    assert_eq!((source, dest), (a, b), "the row keeps the caller's order");
    assert_eq!(
        props,
        serde_json::json!({
            "target_claim_id": target.to_string(),
            "rationale": "rival explanations",
        }),
        "target_claim_id and rationale are folded into the edge properties"
    );

    // Reversed order is the same unordered pair: dedup hit through the guard.
    let second = do_link_alternative(&server, &viewer, params(b, a))
        .await
        .expect("the reversed call succeeds");
    let second = parse_response(&second);
    assert!(
        !second.created,
        "a reversed call must report created=false: alternative_of is symmetric"
    );
    assert_eq!(
        second.edge_id, first.edge_id,
        "a reversed call must return the existing edge's id"
    );
    assert_eq!(
        pair_count(&pool, a, b).await,
        1,
        "exactly one edge for the pair"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_self_loop_is_refused_before_any_write(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    let (a, _) = two_public_claims(&pool, "alt-loop").await;

    let err = do_link_alternative(&server, &viewer, params(a, a))
        .await
        .expect_err("a claim cannot be its own alternative");
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(
        err.message.to_lowercase().contains("self-loop"),
        "the error must name the self-loop; got: {}",
        err.message
    );
    assert_eq!(pair_count(&pool, a, a).await, 0, "no edge written");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_endpoint_is_named_by_side(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    let (real, _) = two_public_claims(&pool, "alt-missing").await;
    let bogus = Uuid::new_v4();

    let err = do_link_alternative(&server, &viewer, params(bogus, real))
        .await
        .expect_err("a missing claim_a must be refused");
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(
        err.message.contains("claim_a") && err.message.contains(&bogus.to_string()),
        "the error must name claim_a and its UUID; got: {}",
        err.message
    );

    let err = do_link_alternative(&server, &viewer, params(real, bogus))
        .await
        .expect_err("a missing claim_b must be refused");
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(
        err.message.contains("claim_b") && err.message.contains(&bogus.to_string()),
        "the error must name claim_b and its UUID; got: {}",
        err.message
    );
    assert_eq!(pair_count(&pool, real, bogus).await, 0, "no edge written");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_target_claim_id_is_refused_before_any_write(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    let (a, b) = two_public_claims(&pool, "alt-target").await;
    let bogus = Uuid::new_v4();

    let err = do_link_alternative(
        &server,
        &viewer,
        LinkAlternativeParams {
            target_claim_id: Some(bogus.to_string()),
            ..params(a, b)
        },
    )
    .await
    .expect_err("an unknown target_claim_id must be refused");
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert!(
        err.message.contains("target_claim_id") && err.message.contains(&bogus.to_string()),
        "the error must name target_claim_id and its UUID; got: {}",
        err.message
    );
    assert_eq!(
        pair_count(&pool, a, b).await,
        0,
        "a refused call must not persist the edge with a dangling target"
    );
}

/// Wait until some backend is blocked by `blocker_pid`, polling on a connection
/// of its own. Panics after ~10s.
async fn wait_until_blocked_by(pool: &PgPool, blocker_pid: i32) {
    use sqlx::Connection;
    let mut probe = sqlx::PgConnection::connect_with(&pool.connect_options())
        .await
        .expect("probe connection");
    for _ in 0..200 {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
        )
        .bind(blocker_pid)
        .fetch_one(&mut probe)
        .await
        .expect("read pg_blocking_pids");
        if blocked > 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!(
        "no backend blocked on pid {blocker_pid} within 10s: the tool's INSERT never \
         reached the unique index, so this test cannot claim to exercise ON CONFLICT"
    );
}

/// `ON CONFLICT`, VISIBLE conflicting row: a concurrent link of the same pair
/// commits while the tool's INSERT is in flight.
///
/// Deterministic, not a race. A second connection inserts the reverse-direction
/// row and holds its transaction open. The tool's guard cannot see an
/// uncommitted row, so its INSERT blocks on
/// `edges_alternative_of_symmetric_uniq`; the test waits for
/// `pg_blocking_pids` to show that, then commits. `DO NOTHING` absorbs the
/// conflict and the dedup probe reads the committed row.
///
/// Without `ON CONFLICT DO NOTHING` the tool answers with an internal error
/// (a unique violation). The tool must instead report the committed edge with
/// `created = false`, which is what a reversed sequential call reports.
#[sqlx::test(migrations = "../../migrations")]
async fn a_concurrent_duplicate_resolves_to_the_committed_edge(pool: PgPool) {
    use sqlx::Connection;
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    let (a, b) = two_public_claims(&pool, "alt-race").await;

    let mut holder = sqlx::PgConnection::connect_with(&pool.connect_options())
        .await
        .expect("holder connection");
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut holder)
        .await
        .unwrap();
    let mut tx = holder.begin().await.expect("holder BEGIN");
    let held: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, \
                            relationship, properties) \
         VALUES ($1, 'claim', $2, 'claim', 'alternative_of', '{}'::jsonb) \
         RETURNING id",
    )
    .bind(b)
    .bind(a)
    .fetch_one(&mut *tx)
    .await
    .expect("holder inserts the reverse-direction row");

    let call = tokio::spawn(async move {
        do_link_alternative(&server, &viewer, params(a, b))
            .await
            .map(|r| parse_response(&r))
    });

    wait_until_blocked_by(&pool, holder_pid).await;
    tx.commit().await.expect("holder COMMIT");

    let resp = call.await.expect("tool task").unwrap_or_else(|e| {
        panic!(
            "a concurrent duplicate must resolve to an answer, not an error; got {:?}: {}",
            e.code, e.message
        )
    });
    assert!(
        !resp.created,
        "the tool must report created=false when another writer linked the pair first"
    );
    assert_eq!(
        resp.edge_id,
        held.to_string(),
        "the tool must return the committed edge's id"
    );
    assert_eq!(
        pair_count(&pool, a, b).await,
        1,
        "exactly one edge for the pair"
    );
}

/// `ON CONFLICT`, INVISIBLE conflicting row: the pair's `alternative_of` edge
/// exists but row-level security hides it from the tool's connection.
///
/// The state is planted as in `rls_enforcement.rs`: the edge is written between
/// two group claims, so the tenancy trigger stamps it `('group', G)`, and both
/// endpoints are then declassified. 072 arm (d)'s no-widening rule leaves the
/// edge group-owned, so an `epigraph_app` session sees both claims and not the
/// edge.
///
/// What the tool must do: refuse, and write nothing. Today that refusal is
/// `internal_error` (the writer's dedup probe finds no row it may read). It
/// must NOT report success, and its message must NOT carry the hidden edge's
/// id, which would hand a session an identifier for a row it cannot read.
///
/// At this surface the writer's `ON CONFLICT` clause is not observable: without
/// it the unique violation also maps to `internal_error`. That is the "one
/// error traded for another" the writer's doc records. The repository-level
/// test in `rls_enforcement.rs` is the one that tells the two apart. Dropping
/// the unique index IS observable here: the call then succeeds and a second
/// row lands.
#[sqlx::test(migrations = "../../migrations")]
async fn an_invisible_conflicting_edge_is_refused_without_a_duplicate_or_its_id(pool: PgPool) {
    use epigraph_db::EdgeRepository;
    use sqlx::Executor;

    let (agent, group) = fixture::seed_agent_with_group(&pool, "alt-hidden").await;
    let c1 = fixture::seed_group_claim(&pool, agent, group, "alt hidden one").await;
    let c2 = fixture::seed_group_claim(&pool, agent, group, "alt hidden two").await;
    let (hidden, created) = EdgeRepository::create_symmetric_if_absent_returning(
        &pool,
        c1,
        c2,
        "alternative_of",
        serde_json::json!({}),
    )
    .await
    .expect("seed the alternative_of edge");
    assert!(created, "the seed link must insert");

    let mut admin = pool.acquire().await.expect("admin connection");
    admin
        .execute("SET epigraph.allow_declassify = 'yes'")
        .await
        .expect("arm the declassification GUC");
    sqlx::query(
        "UPDATE claims SET visibility = 'public', \
         owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid \
         WHERE id = ANY($1)",
    )
    .bind(&[c1, c2][..])
    .execute(&mut *admin)
    .await
    .expect("declassify both endpoints");
    admin
        .execute("SET epigraph.allow_declassify = 'no'")
        .await
        .expect("disarm the declassification GUC");
    drop(admin);

    let edge_vis: String = sqlx::query_scalar("SELECT visibility FROM edges WHERE id = $1")
        .bind(hidden)
        .fetch_one(&pool)
        .await
        .expect("read the edge back");
    assert_eq!(
        edge_vis, "group",
        "PREMISE: the edge must stay group-owned after its endpoints go public"
    );

    // Resolve on the superuser pool, downgrade second (see `downgraded_pool`).
    let viewer = fixture::public_viewer(&pool).await;
    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;

    let claims_seen: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = ANY($1)")
        .bind(&[c1, c2][..])
        .fetch_one(&app_pool)
        .await
        .expect("count claims under the app role");
    assert_eq!(
        claims_seen, 2,
        "PREMISE: both endpoints must be visible to the app role, or the tool \
         refuses at its claim lookup and this test measures that instead"
    );
    assert_eq!(
        pair_count(&app_pool, c1, c2).await,
        0,
        "PREMISE: the edge must be INVISIBLE to the app role"
    );

    let app_server = make_server(app_pool.clone());
    let err = do_link_alternative(&app_server, &viewer, params(c2, c1))
        .await
        .map(|r| parse_response(&r).edge_id)
        .expect_err(
            "an invisible conflicting edge must be refused: created=true would mean a \
             duplicate landed, created=false would return an id the caller cannot read",
        );
    assert_eq!(
        err.code,
        ErrorCode::INTERNAL_ERROR,
        "pinned: the refusal is an internal error today; got: {}",
        err.message
    );
    assert!(
        !err.message.contains(&hidden.to_string()),
        "the refusal must not carry the hidden edge's id; got: {}",
        err.message
    );
    assert_eq!(
        pair_count(&pool, c1, c2).await,
        1,
        "exactly one alternative_of row on the owner connection: no duplicate landed"
    );

    // Calibration: the same app-role server links a pair it can see.
    let (c3, c4) = two_public_claims(&pool, "alt-hidden-visible").await;
    let ok = do_link_alternative(&app_server, &viewer, params(c3, c4))
        .await
        .expect("the app role must still link a pair it can see");
    assert!(
        parse_response(&ok).created,
        "the calibration link must insert"
    );
}

/// `delete_edge` then `link_alternative` restores the pair with a NEW live edge.
///
/// `delete_edge` retracts (`valid_to = now()`), and the row stays. Before the
/// writer's guard and probe were limited to in-force rows, the relink answered
/// `created = false` with the RETRACTED edge's id and wrote nothing. The pair
/// could not be linked again by any tool.
#[sqlx::test(migrations = "../../migrations")]
async fn relinking_after_delete_edge_writes_a_new_live_edge(pool: PgPool) {
    use epigraph_mcp::tools::edge_mutation::do_delete_edge;
    use epigraph_mcp::types::DeleteEdgeParams;

    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone());
    let (a, b) = two_public_claims(&pool, "alt-relink").await;

    let first = parse_response(
        &do_link_alternative(&server, &viewer, params(a, b))
            .await
            .expect("first link"),
    );
    assert!(first.created);
    do_delete_edge(
        &server,
        DeleteEdgeParams {
            edge_id: first.edge_id.clone(),
        },
    )
    .await
    .expect("delete_edge retracts the link");

    let relinked = parse_response(
        &do_link_alternative(&server, &viewer, params(b, a))
            .await
            .expect("relink after delete_edge"),
    );
    assert!(
        relinked.created && relinked.edge_id != first.edge_id,
        "a relink after delete_edge must write a NEW live edge; got edge_id={} created={} \
         where the deleted edge is {}",
        relinked.edge_id,
        relinked.created,
        first.edge_id
    );

    let again = parse_response(
        &do_link_alternative(&server, &viewer, params(a, b))
            .await
            .expect("dedup against the relinked edge"),
    );
    assert_eq!(
        (again.edge_id.as_str(), again.created),
        (relinked.edge_id.as_str(), false),
        "the dedup hit must name the LIVE edge, not the retracted one"
    );
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges \
         WHERE ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)) \
           AND relationship = 'alternative_of' AND valid_to IS NULL",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live, 1, "exactly one live alternative_of edge");
    assert_eq!(
        pair_count(&pool, a, b).await,
        2,
        "the retracted edge is kept for audit"
    );
}
