//! The novelty gate CORROBORATES instead of suppressing (backlog 4f4c6175),
//! inserts the caller's own flagged claim when it may not attach (backlog
//! 5578f693), and never moves a public claim's cached belief from a narrower
//! scope (backlog fef24216), measured on the APPLICATION ROLE.
//!
//! # How the gate is made to fire
//!
//! `McpEmbedder::with_generator` replaces the provider, so nothing leaves the
//! process. [`bag_of_words_vector`] embeds the SET of lower-cased words of a
//! text, so a reordering of the same words (the paraphrases below) embeds to
//! the same vector, at cosine distance 0, which is inside every band, while
//! unrelated texts land near distance 1. The distance is computed by pgvector
//! and the decision runs through the real `submit_claim` / `memorize` paths.
//!
//! # Why the application role
//!
//! The server is built from ONE `ScopedPool` logged in as `epigraph_app` (as
//! `main.rs` builds it), so every write below meets row security and migration
//! 114's writer-owned attach exactly as in production. The superuser `pool`
//! only seeds fixtures and reads rows back for the assertions.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::types::{MemorizeParams, SubmitClaimParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;

/// A deterministic vector for the SET of lower-cased alphanumeric words of
/// `text` (see the module docs).
fn bag_of_words_vector(text: &str) -> Vec<f32> {
    let lowered = text.to_lowercase();
    let mut words: Vec<&str> = lowered
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
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

/// A server built ONLY from an application-role `ScopedPool` (the plain pool
/// is its `inner()`, as in `main.rs`), whose embedder answers with
/// [`bag_of_words_vector`].
async fn app_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = scoped.inner().clone();
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&plain)
        .await
        .expect("current_user");
    assert_eq!(
        role, "epigraph_app",
        "PREMISE: the server's plain pool must be the application role"
    );
    let embedder = McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|text: &str| {
            Ok(bag_of_words_vector(text))
        }));
    let signer = AgentSigner::from_bytes(&[0x4cu8; 32]).expect("signer");
    let server = EpiGraphMcpFull::new(plain, signer, embedder, false).with_scoped_pool(scoped);
    server.server_agent_id().await.expect("server agent");
    server
}

/// The canonical binary frame, get-or-create, on the superuser pool.
async fn binary_truth(pool: &PgPool) {
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM frames WHERE name = 'binary_truth'")
            .fetch_optional(pool)
            .await
            .expect("read binary_truth");
    if existing.is_none() {
        epigraph_db::FrameRepository::create(
            pool,
            "binary_truth",
            Some("canonical binary frame"),
            &["TRUE".to_string(), "FALSE".to_string()],
        )
        .await
        .expect("binary_truth");
    }
}

/// An HTTP caller token naming `agent`.
fn token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("viewer")
}

/// A keyed TEAM group with no members.
async fn team(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, $2, 'did:epigraph:test-team:' || $1::text, $3, 'team')",
    )
    .bind(id)
    .bind(label)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

fn submit(
    content: &str,
    evidence: &str,
    visibility: &str,
    group: Option<Uuid>,
    labels: &[&str],
) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.to_string(),
        methodology: "direct_observation".to_string(),
        evidence_data: evidence.to_string(),
        evidence_type: "empirical".to_string(),
        confidence: 0.8,
        source_url: None,
        reasoning: None,
        labels: labels.iter().map(ToString::to_string).collect(),
        novelty_threshold: None,
        visibility: Some(visibility.to_string()),
        group_id: group.map(|g| g.to_string()),
        dataset: None,
    }
}

/// `agent` submits through MCP; the response body.
async fn submit_as(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    agent: Uuid,
    params: SubmitClaimParams,
) -> serde_json::Value {
    let what = params.content.clone();
    tools::claims::submit_claim(
        server,
        &viewer(pool, agent).await,
        params,
        Some(&token(agent)),
    )
    .await
    .map(|r| first_text(&r))
    .unwrap_or_else(|e| panic!("submit {what:?}: {e:?}"))
}

/// What a claim's row and its derived rows look like, for before/after
/// comparisons. The cached belief is read as TEXT, so "unchanged" means
/// byte-identical.
#[derive(Debug, PartialEq)]
struct ClaimState {
    truth_value: String,
    labels: Vec<String>,
    belief: Option<String>,
    plausibility: Option<String>,
    pignistic_prob: Option<String>,
    evidence_rows: i64,
    bba_rows: i64,
}

async fn claim_state(pool: &PgPool, claim: Uuid) -> ClaimState {
    let (truth_value, labels, belief, plausibility, pignistic_prob): (
        String,
        Vec<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT truth_value::text, labels, belief::text, plausibility::text, \
                pignistic_prob::text \
           FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("claim row");
    let evidence_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("evidence count");
    let bba_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("bba count");
    ClaimState {
        truth_value,
        labels,
        belief,
        plausibility,
        pignistic_prob,
        evidence_rows,
        bba_rows,
    }
}

async fn claims_with_content(
    pool: &PgPool,
    content: &str,
) -> Vec<(Uuid, Uuid, String, Vec<String>)> {
    sqlx::query_as(
        "SELECT id, owner_group_id, visibility::text, labels FROM claims WHERE content_hash = $1",
    )
    .bind(ContentHasher::hash(content.as_bytes()).as_slice())
    .fetch_all(pool)
    .await
    .expect("claims by content")
}

/// `(id, owner_group_id, visibility, writer_owned)` of the evidence rows on
/// `claim` whose body is `evidence_data`.
async fn evidence_with_body(
    pool: &PgPool,
    claim: Uuid,
    evidence_data: &str,
) -> Vec<(Uuid, Uuid, String, bool)> {
    sqlx::query_as(
        "SELECT id, owner_group_id, visibility::text, writer_owned FROM evidence \
          WHERE claim_id = $1 AND content_hash = $2",
    )
    .bind(claim)
    .bind(ContentHasher::hash(evidence_data.as_bytes()).as_slice())
    .fetch_all(pool)
    .await
    .expect("evidence by body")
}

/// Public evidence rows anywhere whose body is `evidence_data`.
async fn public_evidence_with_body(pool: &PgPool, evidence_data: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM evidence WHERE content_hash = $1 AND visibility = 'public'",
    )
    .bind(ContentHasher::hash(evidence_data.as_bytes()).as_slice())
    .fetch_one(pool)
    .await
    .expect("public evidence by body")
}

/// `(id, evidence_id)` of the BBAs on `claim` whose source agent is `agent`.
async fn bbas_by(pool: &PgPool, claim: Uuid, agent: Uuid) -> Vec<(Uuid, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT id, evidence_id FROM mass_functions WHERE claim_id = $1 AND source_agent_id = $2",
    )
    .bind(claim)
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("bbas by agent")
}

/// The `properties` of every AUTHORED edge `agent -> claim`.
async fn authored_edges(pool: &PgPool, agent: Uuid, claim: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT properties FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'AUTHORED'",
    )
    .bind(agent)
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("authored edges")
}

/// Agent A owns a PUBLIC claim; agent B submits a paraphrase of it, also
/// public. No claims row is written for B; B's evidence lands on A's claim as
/// a writer-owned row of B's group, its BBA is sourced from B, an AUTHORED
/// edge B -> A's claim records the corroboration, and A's truth_value and
/// labels are untouched. The response says the call was deduplicated by the
/// gate and names the evidence row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_paraphrase_corroborates_the_public_claim_it_duplicates(pool: PgPool) {
    binary_truth(&pool).await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "corro-a").await;
    let (b, b_home) = fixture::seed_agent_with_group(&pool, "corro-b").await;
    let server = app_server(&pool).await;

    let original = "The aquifer recharges fastest during the spring snowmelt";
    let a_body = submit_as(
        &pool,
        &server,
        a,
        submit(
            original,
            "well logs 2019-2024",
            "public",
            None,
            &["hydrology"],
        ),
    )
    .await;
    let a_claim = parse_uuid_field(&a_body, "claim_id");
    assert_eq!(
        a_body["embedded"], true,
        "fixture: A's claim is embedded: {a_body}"
    );
    let before = claim_state(&pool, a_claim).await;

    let paraphrase = "During the spring snowmelt the aquifer recharges fastest";
    let b_evidence = "independent piezometer readings, spring 2025";
    let b_body = submit_as(
        &pool,
        &server,
        b,
        submit(paraphrase, b_evidence, "public", None, &["b-run-tag"]),
    )
    .await;

    assert_eq!(b_body["claim_id"], a_claim.to_string(), "{b_body}");
    assert_eq!(b_body["deduplicated"]["by"], "novelty_gate", "{b_body}");
    assert!(
        claims_with_content(&pool, paraphrase).await.is_empty(),
        "no claims row is written for the paraphrase"
    );

    let evidence = evidence_with_body(&pool, a_claim, b_evidence).await;
    assert_eq!(
        evidence.len(),
        1,
        "exactly one evidence row from B on A's claim: {evidence:?}"
    );
    let (evidence_id, owner, visibility, writer_owned) = evidence[0].clone();
    assert_eq!(
        (owner, visibility.as_str(), writer_owned),
        (b_home, "public", true),
        "B's evidence is owned by B's group, public, writer-owned (migration 114)"
    );
    assert_eq!(
        b_body["corroboration"]["evidence_id"],
        evidence_id.to_string(),
        "{b_body}"
    );
    assert_eq!(
        b_body["corroboration"]["claim_id"],
        a_claim.to_string(),
        "{b_body}"
    );

    let bbas = bbas_by(&pool, a_claim, b).await;
    assert_eq!(
        bbas.iter().map(|(_, e)| *e).collect::<Vec<_>>(),
        vec![Some(evidence_id)],
        "one BBA sourced from B, keyed on B's evidence"
    );

    let edges = authored_edges(&pool, b, a_claim).await;
    assert_eq!(
        edges.len(),
        1,
        "one AUTHORED edge B -> A's claim: {edges:?}"
    );
    assert_eq!(edges[0]["corroboration"], true, "{edges:?}");
    assert_eq!(edges[0]["was_created"], false, "{edges:?}");

    let after = claim_state(&pool, a_claim).await;
    assert_eq!(
        after.truth_value, before.truth_value,
        "A's truth_value is A's"
    );
    assert_eq!(
        after.labels, before.labels,
        "A's labels are A's: B's label is discarded"
    );
    assert_eq!(after.evidence_rows, before.evidence_rows + 1);
    assert_eq!(after.bba_rows, before.bba_rows + 1);
    let discarded = b_body["deduplicated"]["inputs_discarded"].to_string();
    assert!(discarded.contains("labels"), "{b_body}");
    let applied = b_body["deduplicated"]["inputs_applied"].to_string();
    assert!(applied.contains("evidence_data"), "{b_body}");
}

/// The same through `memorize`: B memorizes a public paraphrase of A's public
/// claim and its memory corroborates A's claim instead of vanishing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_memorized_paraphrase_corroborates_the_public_claim_it_duplicates(pool: PgPool) {
    binary_truth(&pool).await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "corro-mem-a").await;
    let (b, b_home) = fixture::seed_agent_with_group(&pool, "corro-mem-b").await;
    let server = app_server(&pool).await;

    let original = "Lichen cover on the north slope doubled after the burn";
    let a_claim = parse_uuid_field(
        &submit_as(
            &pool,
            &server,
            a,
            submit(original, "transect survey", "public", None, &[]),
        )
        .await,
        "claim_id",
    );
    let before = claim_state(&pool, a_claim).await;

    let paraphrase = "After the burn lichen cover on the north slope doubled";
    let out = tools::memory::memorize(
        &server,
        &viewer(&pool, b).await,
        MemorizeParams {
            content: paraphrase.to_string(),
            confidence: Some(0.7),
            tags: Some(vec!["b-memory".to_string()]),
            novelty_threshold: None,
            visibility: Some("public".to_string()),
            group_id: None,
        },
        Some(&token(b)),
    )
    .await
    .expect("memorize");
    let body = first_text(&out);

    assert_eq!(body["claim_id"], a_claim.to_string(), "{body}");
    assert_eq!(body["deduplicated"]["by"], "novelty_gate", "{body}");
    assert!(claims_with_content(&pool, paraphrase).await.is_empty());
    let evidence_id = parse_uuid_field(&body["corroboration"], "evidence_id");
    let (owner, visibility, writer_owned): (Uuid, String, bool) = sqlx::query_as(
        "SELECT owner_group_id, visibility::text, writer_owned FROM evidence \
          WHERE id = $1 AND claim_id = $2",
    )
    .bind(evidence_id)
    .bind(a_claim)
    .fetch_one(&pool)
    .await
    .expect("B's evidence on A's claim");
    assert_eq!(
        (owner, visibility.as_str(), writer_owned),
        (b_home, "public", true)
    );
    assert_eq!(
        bbas_by(&pool, a_claim, b)
            .await
            .iter()
            .map(|(_, e)| *e)
            .collect::<Vec<_>>(),
        vec![Some(evidence_id)]
    );
    let edges = authored_edges(&pool, b, a_claim).await;
    assert_eq!(edges.len(), 1, "{edges:?}");
    assert_eq!(edges[0]["corroboration"], true, "{edges:?}");

    let after = claim_state(&pool, a_claim).await;
    assert_eq!(after.truth_value, before.truth_value);
    assert_eq!(after.labels, before.labels, "B's tags are not A's labels");
}

/// A's claim sits in a team where B is only a READER. B can read it (so the
/// gate finds it) but may not write it, so B's paraphrase is inserted as B's
/// OWN claim, labelled `near-duplicate`, and nothing of B lands on A's claim.
/// The response names the refusal and the nearest claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_gets_its_own_flagged_claim_and_writes_nothing_on_the_team_claim(pool: PgPool) {
    binary_truth(&pool).await;
    let t = team(&pool, "corro-team").await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "corro-writer").await;
    let (b, b_home) = fixture::seed_agent_with_group(&pool, "corro-reader").await;
    add_member(&pool, t, a, "writer").await;
    add_member(&pool, t, b, "reader").await;
    let server = app_server(&pool).await;

    let original = "The pilot reactor reached steady state within forty minutes";
    let a_claim = parse_uuid_field(
        &submit_as(
            &pool,
            &server,
            a,
            submit(original, "run sheet 12", "team", Some(t), &[]),
        )
        .await,
        "claim_id",
    );
    let before = claim_state(&pool, a_claim).await;

    let paraphrase = "Within forty minutes the pilot reactor reached steady state";
    let b_evidence = "reader's own run sheet";
    let body = submit_as(
        &pool,
        &server,
        b,
        submit(paraphrase, b_evidence, "private", None, &[]),
    )
    .await;

    assert_ne!(body["claim_id"], a_claim.to_string(), "{body}");
    assert!(
        body.get("deduplicated").is_none(),
        "an insert, not a dedup: {body}"
    );
    assert_eq!(
        body["corroboration"]["refused"], "claim not writable by caller",
        "{body}"
    );
    assert_eq!(
        body["corroboration"]["nearest_claim_id"],
        a_claim.to_string(),
        "{body}"
    );
    let own = claims_with_content(&pool, paraphrase).await;
    assert_eq!(own.len(), 1, "B's own claim: {own:?}");
    let (own_id, own_owner, own_visibility, own_labels) = own[0].clone();
    assert_eq!(body["claim_id"], own_id.to_string());
    assert_eq!((own_owner, own_visibility.as_str()), (b_home, "group"));
    assert!(
        own_labels.iter().any(|l| l == "near-duplicate"),
        "{own_labels:?}"
    );

    assert_eq!(
        claim_state(&pool, a_claim).await,
        before,
        "nothing of B's on A's claim"
    );
    assert!(evidence_with_body(&pool, a_claim, b_evidence)
        .await
        .is_empty());
    assert!(bbas_by(&pool, a_claim, b).await.is_empty());
    assert!(authored_edges(&pool, b, a_claim).await.is_empty());
}

/// B writes PRIVATELY a paraphrase of A's PUBLIC claim (backlog fef24216). B
/// could attach to the public claim, but its evidence and BBA would then be
/// public and folded into the public cache, carrying a group-private source to
/// every reader. So B's evidence stays in B's scope (its own flagged claim),
/// A's public cached belief is byte-identical, and B's evidence body is on no
/// public row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_paraphrase_never_moves_the_public_claims_cached_belief(pool: PgPool) {
    binary_truth(&pool).await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "corro-pub-a").await;
    let (b, b_home) = fixture::seed_agent_with_group(&pool, "corro-priv-b").await;
    let server = app_server(&pool).await;

    let original = "Soil nitrate peaks two weeks after the first irrigation";
    let a_claim = parse_uuid_field(
        &submit_as(
            &pool,
            &server,
            a,
            submit(original, "field cores", "public", None, &[]),
        )
        .await,
        "claim_id",
    );
    let before = claim_state(&pool, a_claim).await;
    assert!(
        before.pignistic_prob.is_some(),
        "fixture: A's public claim carries a cached belief: {before:?}"
    );

    let paraphrase = "Two weeks after the first irrigation soil nitrate peaks";
    let b_evidence = "unpublished group-private lab notebook, page 4";
    let body = submit_as(
        &pool,
        &server,
        b,
        submit(paraphrase, b_evidence, "private", None, &[]),
    )
    .await;

    assert_eq!(
        claim_state(&pool, a_claim).await,
        before,
        "A's public cached belief (belief, plausibility, pignistic_prob) and rows are \
         byte-identical"
    );
    assert!(bbas_by(&pool, a_claim, b).await.is_empty());
    assert!(authored_edges(&pool, b, a_claim).await.is_empty());
    assert_eq!(
        public_evidence_with_body(&pool, b_evidence).await,
        0,
        "B's private evidence body is on no public row"
    );
    assert_eq!(
        body["corroboration"]["nearest_claim_id"],
        a_claim.to_string(),
        "{body}"
    );
    assert!(
        body["corroboration"]["refused"].is_string(),
        "the response names why B did not corroborate: {body}"
    );

    // B's evidence and BBA exist, in B's scope.
    let own = claims_with_content(&pool, paraphrase).await;
    assert_eq!(own.len(), 1, "{own:?}");
    let (own_id, own_owner, own_visibility, own_labels) = own[0].clone();
    assert_eq!((own_owner, own_visibility.as_str()), (b_home, "group"));
    assert!(own_labels.iter().any(|l| l == "near-duplicate"));
    let own_evidence = evidence_with_body(&pool, own_id, b_evidence).await;
    assert_eq!(own_evidence.len(), 1, "{own_evidence:?}");
    assert_eq!(
        (own_evidence[0].1, own_evidence[0].2.as_str()),
        (b_home, "group")
    );
    assert_eq!(bbas_by(&pool, own_id, b).await.len(), 1);
}

/// B, a writer of team T, holds a TEAM claim and then submits a PUBLIC
/// paraphrase of it. The paraphrase is not attached to the team claim (it
/// would vanish from every public reader), so B's public claim is inserted,
/// and it carries NO `near-duplicate` label: that label is on a public row,
/// and would tell every public reader that some claim they cannot read lies
/// within the novelty threshold of this one. The refusal is still named to B.
#[sqlx::test(migrations = "../../migrations")]
async fn a_public_paraphrase_of_a_team_claim_is_not_labelled_near_duplicate(pool: PgPool) {
    binary_truth(&pool).await;
    let t = team(&pool, "corro-narrow-team").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "corro-narrow-b").await;
    add_member(&pool, t, b, "writer").await;
    let server = app_server(&pool).await;

    let original = "The team's prototype seal held at nine bar for an hour";
    let team_claim = parse_uuid_field(
        &submit_as(
            &pool,
            &server,
            b,
            submit(original, "bench log 7", "team", Some(t), &[]),
        )
        .await,
        "claim_id",
    );
    let before = claim_state(&pool, team_claim).await;

    let paraphrase = "For an hour the team's prototype seal held at nine bar";
    let body = submit_as(
        &pool,
        &server,
        b,
        submit(paraphrase, "public bench summary", "public", None, &[]),
    )
    .await;

    assert_ne!(body["claim_id"], team_claim.to_string(), "{body}");
    assert_eq!(
        body["corroboration"]["refused"], "claim visibility differs from this write's",
        "{body}"
    );
    let own = claims_with_content(&pool, paraphrase).await;
    assert_eq!(own.len(), 1, "B's own public claim: {own:?}");
    let (_, _, own_visibility, own_labels) = own[0].clone();
    assert_eq!(own_visibility, "public");
    assert!(
        !own_labels.iter().any(|l| l == "near-duplicate"),
        "a public claim must not disclose a team claim's proximity: {own_labels:?}"
    );
    assert_eq!(
        claim_state(&pool, team_claim).await,
        before,
        "nothing written on the team claim"
    );
}

/// A's public claim is a PROMOTED hypothesis, and the `research_validity`
/// frame its evidence is filed on does not exist, so no evidence can be
/// attached to it by anyone. B's public paraphrase is not failed on that fact
/// about a claim B never named: B's own claim is inserted, labelled
/// `near-duplicate` (the match is public), the response names the refusal, and
/// nothing of B lands on A's claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_paraphrase_of_a_claim_that_cannot_take_evidence_is_inserted_not_failed(pool: PgPool) {
    binary_truth(&pool).await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "corro-promoted-a").await;
    let (b, _) = fixture::seed_agent_with_group(&pool, "corro-promoted-b").await;
    let server = app_server(&pool).await;

    let original = "Raising the anneal temperature halves the defect density";
    let a_claim = parse_uuid_field(
        &submit_as(
            &pool,
            &server,
            a,
            submit(original, "wafer batch 3", "public", None, &[]),
        )
        .await,
        "claim_id",
    );
    sqlx::query(
        "UPDATE claims SET properties = coalesce(properties, '{}'::jsonb) \
                || '{\"hypothesis_status\": \"promoted\"}'::jsonb \
          WHERE id = $1",
    )
    .bind(a_claim)
    .execute(&pool)
    .await
    .expect("promote A's claim");
    let research_validity: i64 =
        sqlx::query_scalar("SELECT count(*) FROM frames WHERE name = 'research_validity'")
            .fetch_one(&pool)
            .await
            .expect("frames");
    assert_eq!(
        research_validity, 0,
        "PREMISE: no research_validity frame, so A's claim can take no evidence"
    );
    let before = claim_state(&pool, a_claim).await;

    let paraphrase = "The defect density halves raising the anneal temperature";
    let b_evidence = "independent wafer batch 9";
    let body = submit_as(
        &pool,
        &server,
        b,
        submit(paraphrase, b_evidence, "public", None, &[]),
    )
    .await;

    assert_ne!(body["claim_id"], a_claim.to_string(), "{body}");
    assert_eq!(
        body["corroboration"]["refused"],
        "claim cannot take this evidence: its evidence frame is missing or not binary",
        "{body}"
    );
    assert_eq!(
        body["corroboration"]["nearest_claim_id"],
        a_claim.to_string(),
        "{body}"
    );
    let own = claims_with_content(&pool, paraphrase).await;
    assert_eq!(own.len(), 1, "B's own claim: {own:?}");
    assert!(own[0].3.iter().any(|l| l == "near-duplicate"), "{own:?}");
    assert_eq!(claim_state(&pool, a_claim).await, before);
    assert!(evidence_with_body(&pool, a_claim, b_evidence)
        .await
        .is_empty());
    assert!(authored_edges(&pool, b, a_claim).await.is_empty());
}
