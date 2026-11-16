//! `store_workflow` matches a reworded goal to the existing hierarchical
//! workflow instead of minting a new generation-0 lineage (backlog 5e54282f).
//!
//! `store_workflow` derives the lineage from `slugify(goal)`, so it was
//! idempotent only on the EXACT goal text: "Deploy the Rust binary to the
//! Windows server" and "Deploy Rust binary to Windows server" became two
//! unrelated lineages, and the variant history `improve_workflow_hierarchy`
//! builds was split between them.
//!
//! # How the paraphrase is made similar in a test process
//!
//! `McpEmbedder::with_generator` replaces the provider. The generator here
//! ([`goal_vector`]) derives the vector from the goal's lower-cased words with
//! a few stop words removed and the rest sorted, so two wordings of one goal
//! embed to the SAME vector (cosine 1.0, the geometry a real embedder gives a
//! close paraphrase), and an unrelated goal to a pseudo-random one (cosine
//! near 0). The similarity itself is computed by pgvector over the stored
//! `workflows.goal_embedding`, through the real `store_workflow`.
//!
//! # Verified to fail
//!
//! On the code before this change the paraphrase arm minted a second
//! generation-0 row (two rows, `matched_existing` absent from the response).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::types::StoreWorkflowParams;
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;
const STOP_WORDS: [&str; 6] = ["the", "a", "an", "to", "on", "of"];

/// A deterministic vector for `text` that depends only on its set of
/// non-stop words (see the module docs). FNV-1a over the sorted words seeds an
/// xorshift64 stream; each component is the stream's top 16 bits, centred.
fn goal_vector(text: &str) -> Vec<f32> {
    let lower = text.to_lowercase();
    let mut words: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty() && !STOP_WORDS.contains(w))
        .collect();
    words.sort_unstable();
    words.dedup();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in words.join(" ").bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    let mut out = Vec::with_capacity(DIM);
    for _ in 0..DIM {
        h ^= h << 13;
        h ^= h >> 7;
        h ^= h << 17;
        let top = u16::try_from(h >> 48).expect("the top 16 bits fit a u16");
        out.push(f32::from(top) - 32_768.0);
    }
    out
}

async fn server_with_goal_embedder(
    pool: &PgPool,
) -> (EpiGraphMcpFull, epigraph_db::visibility::Viewer) {
    let scoped = fixture::scoped_pool(pool).await;
    let embedder = McpEmbedder::new(pool.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|text: &str| Ok(goal_vector(text))));
    let server = EpiGraphMcpFull::new(
        pool.clone(),
        AgentSigner::from_bytes(&[0x5Eu8; 32]).expect("signer"),
        embedder,
        false,
    )
    .with_scoped_pool(scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("viewer");
    (server, viewer)
}

fn params(goal: &str, force_new: Option<bool>) -> StoreWorkflowParams {
    StoreWorkflowParams {
        goal: goal.to_string(),
        steps: vec![format!("step for {goal}")],
        prerequisites: None,
        expected_outcome: None,
        confidence: None,
        tags: None,
        tenancy: None,
        force_new,
    }
}

async fn store(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    goal: &str,
    force_new: Option<bool>,
) -> serde_json::Value {
    let r = epigraph_mcp::tools::workflows::store_workflow(
        server,
        viewer,
        params(goal, force_new),
        None,
    )
    .await
    .expect("store_workflow");
    assert_ne!(r.is_error, Some(true), "{r:?}");
    first_text(&r)
}

async fn row_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows")
        .fetch_one(pool)
        .await
        .expect("count workflows")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reworded_goal_matches_the_existing_lineage_unless_forced(pool: PgPool) {
    let (server, viewer) = server_with_goal_embedder(&pool).await;
    let tag = Uuid::new_v4().simple().to_string();
    let original_goal = format!("Deploy the Rust binary to the Windows server {tag}");
    let reworded_goal = format!("Deploy Rust binary to Windows server {tag}");
    let base = row_count(&pool).await;

    let original = store(&server, &viewer, &original_goal, None).await;
    assert_eq!(original["matched_existing"], serde_json::json!(false));
    assert_eq!(row_count(&pool).await, base + 1);

    // The paraphrase stores nothing and names the existing workflow.
    let reworded = store(&server, &viewer, &reworded_goal, None).await;
    assert_eq!(
        reworded["matched_existing"],
        serde_json::json!(true),
        "{reworded}"
    );
    assert_eq!(
        reworded["workflow_id"], original["workflow_id"],
        "{reworded}"
    );
    assert_eq!(reworded["canonical_name"], original["canonical_name"]);
    assert_eq!(reworded["claims_ingested"], serde_json::json!(0));
    assert!(
        reworded["similarity"].as_f64().unwrap_or(0.0) >= 0.9,
        "{reworded}"
    );
    let hint = reworded["hint"].as_str().unwrap_or_default();
    assert!(
        hint.contains("improve_workflow_hierarchy")
            && hint.contains(original["canonical_name"].as_str().unwrap()),
        "{hint}"
    );
    assert_eq!(
        row_count(&pool).await,
        base + 1,
        "no second lineage was minted"
    );

    // The exact goal again is the ingest's own no-op, not a match.
    let again = store(&server, &viewer, &original_goal, None).await;
    assert_eq!(
        again["matched_existing"],
        serde_json::json!(false),
        "{again}"
    );
    assert_eq!(
        again["already_ingested"],
        serde_json::json!(true),
        "{again}"
    );
    assert_eq!(row_count(&pool).await, base + 1);

    // force_new mints the paraphrase as its own lineage.
    let forced = store(&server, &viewer, &reworded_goal, Some(true)).await;
    assert_eq!(
        forced["matched_existing"],
        serde_json::json!(false),
        "{forced}"
    );
    assert_ne!(forced["workflow_id"], original["workflow_id"]);
    assert_eq!(row_count(&pool).await, base + 2);

    // An unrelated goal is a new lineage without force_new.
    let unrelated = store(
        &server,
        &viewer,
        &format!("Rotate the TLS certificates on the proxy {tag}"),
        None,
    )
    .await;
    assert_eq!(
        unrelated["matched_existing"],
        serde_json::json!(false),
        "{unrelated}"
    );
    assert_eq!(row_count(&pool).await, base + 3);
}

/// The exact goal of a row with NO goal embedding (rows stored before
/// store_workflow embedded goals, and `embed: false` ingests) is still the
/// ingest's own no-op: it must not be "matched" to another lineage whose goal
/// vector happens to be identical. Deciding "this canonical_name exists"
/// through the embedding search alone got this wrong.
#[sqlx::test(migrations = "../../migrations")]
async fn an_exact_goal_whose_row_has_no_goal_embedding_is_not_matched_elsewhere(pool: PgPool) {
    let (server, viewer) = server_with_goal_embedder(&pool).await;
    let tag = Uuid::new_v4().simple().to_string();
    let goal_a = format!("Back up the Postgres cluster to object storage {tag}");
    let goal_b = format!("Back up Postgres cluster to object storage {tag}");

    let a = store(&server, &viewer, &goal_a, None).await;
    sqlx::query("UPDATE workflows SET goal_embedding = NULL WHERE id = $1::uuid")
        .bind(a["workflow_id"].as_str().expect("workflow_id"))
        .execute(&pool)
        .await
        .expect("null the goal embedding");
    let b = store(&server, &viewer, &goal_b, Some(true)).await;
    assert_ne!(b["workflow_id"], a["workflow_id"], "{b}");

    let again = store(&server, &viewer, &goal_a, None).await;
    assert_eq!(
        again["matched_existing"],
        serde_json::json!(false),
        "the exact goal must not be matched to the other lineage: {again}"
    );
    assert_eq!(
        again["already_ingested"],
        serde_json::json!(true),
        "{again}"
    );
    assert_eq!(again["workflow_id"], a["workflow_id"], "{again}");
}

/// A `workflows` row seeded on the harness superuser with its goal embedded
/// by [`goal_vector`], tenancy as given.
async fn seeded_workflow(pool: &PgPool, goal: &str, visibility: &str, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    seeded_generation(
        pool,
        id,
        &format!("seeded-{id}"),
        0,
        None,
        goal,
        visibility,
        owner,
    )
    .await;
    id
}

/// One generation `generation` of lineage `canonical_name`, seeded on the
/// harness superuser like [`seeded_workflow`].
#[allow(clippy::too_many_arguments)]
async fn seeded_generation(
    pool: &PgPool,
    id: Uuid,
    canonical_name: &str,
    generation: i32,
    parent_id: Option<Uuid>,
    goal: &str,
    visibility: &str,
    owner: Uuid,
) {
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, parent_id, goal, visibility, \
                                owner_group_id, goal_embedding) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::vector)",
    )
    .bind(id)
    .bind(canonical_name)
    .bind(generation)
    .bind(parent_id)
    .bind(goal)
    .bind(visibility)
    .bind(owner)
    .bind(epigraph_mcp::embed::format_pgvector(&goal_vector(goal)))
    .execute(pool)
    .await
    .expect("seed workflows row");
}

async fn tenancy_of(pool: &PgPool, workflow_id: &serde_json::Value) -> (String, Uuid) {
    sqlx::query_as("SELECT visibility::text, owner_group_id FROM workflows WHERE id = $1::uuid")
        .bind(workflow_id.as_str().expect("workflow_id"))
        .fetch_one(pool)
        .await
        .expect("read the stored row's tenancy")
}

/// On the application role, matching reads as the CALLER and stays inside
/// the tenancy the store would use. The stranger here declares nothing, so a
/// new lineage of its is private to its own default group:
///
/// * a paraphrase of a group-private plan it does not read mints a new
///   lineage, and the response never carries the private goal;
/// * a paraphrase of ANOTHER group's PUBLIC plan, which it does read, is not
///   matched either: matching it would route this caller's outcome reports
///   (goal text, deviation reasons, outcome_details) onto a public plan. The
///   new lineage lands private to the stranger's own group;
/// * a paraphrase of a plan in its own default tenancy IS matched (the
///   positive control: the matching runs at all here).
#[sqlx::test(migrations = "../../migrations")]
async fn matching_never_discloses_a_plan_the_caller_cannot_read(pool: PgPool) {
    let (_, group) = fixture::seed_agent_with_group(&pool, "swm-owner").await;
    let tag = Uuid::new_v4().simple().to_string();
    let private_goal = format!("Rotate the private signing keys of the vault {tag}");
    let public_goal = format!("Publish the weekly release notes to the wiki {tag}");
    let own_goal = format!("Compact the audit log archive on the replica {tag}");
    let private = seeded_workflow(&pool, &private_goal, "group", group).await;
    let public = seeded_workflow(&pool, &public_goal, "public", group).await;

    let url = fixture::database_url_for(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let embedder = McpEmbedder::new(scoped.inner().clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|text: &str| Ok(goal_vector(text))));
    let server = EpiGraphMcpFull::new(
        scoped.inner().clone(),
        AgentSigner::from_bytes(&[0x5Fu8; 32]).expect("signer"),
        embedder,
        false,
    )
    .with_scoped_pool(scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let stranger = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("stranger viewer");
    let own_group = default_owner_group(&pool, agent).await;
    let own = seeded_workflow(&pool, &own_goal, "group", own_group).await;

    let r = epigraph_mcp::tools::workflows::store_workflow(
        &server,
        &stranger,
        params(&format!("Rotate private signing keys of vault {tag}"), None),
        None,
    )
    .await
    .expect("store_workflow");
    let text = first_text(&r).to_string();
    let json = first_text(&r);
    assert_eq!(json["matched_existing"], serde_json::json!(false), "{json}");
    assert_ne!(json["workflow_id"], serde_json::json!(private.to_string()));
    assert!(
        !text.contains(&private_goal),
        "the private plan's goal left the database: {text}"
    );

    let r = epigraph_mcp::tools::workflows::store_workflow(
        &server,
        &stranger,
        params(&format!("Publish weekly release notes to wiki {tag}"), None),
        None,
    )
    .await
    .expect("store_workflow");
    let json = first_text(&r);
    assert_eq!(
        json["matched_existing"],
        serde_json::json!(false),
        "a private-by-default store was redirected onto another group's public plan: {json}"
    );
    assert_ne!(json["workflow_id"], serde_json::json!(public.to_string()));
    assert_eq!(
        tenancy_of(&pool, &json["workflow_id"]).await,
        ("group".to_string(), own_group),
        "the new lineage keeps the store's own private tenancy"
    );

    let r = epigraph_mcp::tools::workflows::store_workflow(
        &server,
        &stranger,
        params(&format!("Compact audit log archive on replica {tag}"), None),
        None,
    )
    .await
    .expect("store_workflow");
    let json = first_text(&r);
    assert_eq!(json["matched_existing"], serde_json::json!(true), "{json}");
    assert_eq!(json["workflow_id"], serde_json::json!(own.to_string()));
}

/// A keyed TEAM group (kind 'team' carries a 32-byte key) with `member` as a
/// writer, seeded on the harness superuser. Keyed, because a keyless team
/// group (`did:epigraph:group:`) counts only an agent with a human operator
/// as a live member (migration 164).
async fn seed_team(pool: &PgPool, member: Uuid, label: &str) -> Uuid {
    let team = Uuid::new_v4();
    let key: Vec<u8> = team.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(team)
    .bind(format!("{label} {team}"))
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed a team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(team)
    .bind(member)
    .execute(pool)
    .await
    .expect("seed a writer membership");
    team
}

/// A caller in TWO groups that declares a store into group B is not matched
/// to a reworded plan of group A, though it reads (and writes) both: the
/// match would put this B-meant plan's runs on A's plan. Declaring A matches
/// it (the positive control).
#[sqlx::test(migrations = "../../migrations")]
async fn a_declared_group_is_not_matched_to_another_groups_plan(pool: PgPool) {
    let (server, _) = server_with_goal_embedder(&pool).await;
    let agent = server.server_agent_id().await.expect("server agent");
    let team_a = seed_team(&pool, agent, "swm team a").await;
    let team_b = seed_team(&pool, agent, "swm team b").await;
    let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
        .await
        .expect("viewer in both teams");
    let tag = Uuid::new_v4().simple().to_string();
    let goal = format!("Reindex the vector store after the model upgrade {tag}");
    let plan_a = seeded_workflow(&pool, &goal, "group", team_a).await;

    let declared = |group: Uuid| {
        let mut p = params(
            &format!("Reindex vector store after model upgrade {tag}"),
            None,
        );
        p.tenancy = Some(
            serde_json::from_value(serde_json::json!({
                "visibility": "group",
                "owner_group_id": group,
            }))
            .expect("tenancy"),
        );
        p
    };

    let r =
        epigraph_mcp::tools::workflows::store_workflow(&server, &viewer, declared(team_b), None)
            .await
            .expect("store_workflow into B");
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let json = first_text(&r);
    assert_eq!(
        json["matched_existing"],
        serde_json::json!(false),
        "a store declared into B was redirected onto A's plan: {json}"
    );
    assert_ne!(json["workflow_id"], serde_json::json!(plan_a.to_string()));
    assert_eq!(
        tenancy_of(&pool, &json["workflow_id"]).await,
        ("group".to_string(), team_b)
    );

    let mut into_a = declared(team_a);
    into_a.goal = format!("Reindex the vector store after model upgrade {tag}");
    let r = epigraph_mcp::tools::workflows::store_workflow(&server, &viewer, into_a, None)
        .await
        .expect("store_workflow into A");
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let json = first_text(&r);
    assert_eq!(json["matched_existing"], serde_json::json!(true), "{json}");
    assert_eq!(json["workflow_id"], serde_json::json!(plan_a.to_string()));
    let hint = json["hint"].as_str().unwrap_or_default();
    assert!(
        hint.contains(&team_a.to_string()) && hint.contains("'group'"),
        "the hint names the matched plan's tenancy: {hint}"
    );
}

/// A match names the HEAD of the matched lineage, not the superseded
/// generation whose goal embedding happened to be the hit: outcome reports
/// on the returned id must land on the plan agents now follow.
#[sqlx::test(migrations = "../../migrations")]
async fn a_match_names_the_lineage_head_not_a_superseded_generation(pool: PgPool) {
    let (server, viewer) = server_with_goal_embedder(&pool).await;
    let agent = server.server_agent_id().await.expect("server agent");
    let own_group = default_owner_group(&pool, agent).await;
    let tag = Uuid::new_v4().simple().to_string();
    let canonical = format!("seeded-lineage-{tag}");
    let gen0 = Uuid::new_v4();
    let gen1 = Uuid::new_v4();
    let goal0 = format!("Archive the stale build caches on the runners {tag}");
    // The head's goal was reworded enough that it is NOT itself a hit.
    let goal1 = format!("Prune runner disk space weekly with a retention policy {tag}");
    seeded_generation(&pool, gen0, &canonical, 0, None, &goal0, "group", own_group).await;
    seeded_generation(
        &pool,
        gen1,
        &canonical,
        1,
        Some(gen0),
        &goal1,
        "group",
        own_group,
    )
    .await;

    let json = store(
        &server,
        &viewer,
        &format!("Archive stale build caches on runners {tag}"),
        None,
    )
    .await;
    assert_eq!(json["matched_existing"], serde_json::json!(true), "{json}");
    assert_eq!(
        json["workflow_id"],
        serde_json::json!(gen1.to_string()),
        "the match must name the lineage head (generation 1): {json}"
    );
    assert_eq!(json["generation"], serde_json::json!(1), "{json}");
    assert_eq!(json["canonical_name"], serde_json::json!(canonical));
}
