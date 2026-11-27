//! A non-public document ingest derives its claim ids from its owning group
//! (backlog 8f56a641), measured on the APPLICATION ROLE.
//!
//! Before it, a document's ids were a function of its text and title alone:
//! compound nodes `uuid_v5(COMPOUND, hash(text) || "{title}\u{1f}{path}")`,
//! atoms `uuid_v5(ATOM, hash(text))`, and atoms were resolved by a
//! content-hash lookup across every scope. So when tenant B privately ingested
//! a document tenant A had already privately ingested, every one of B's nodes
//! resolved to A's row (B could write no claim of its own, and its paper would
//! assert A's private claims). MEASURED on the old walk, application role:
//! B's ingest failed outright ("internal error"), so A's private ingest both
//! blocked B's and told B that some other scope held the document.
//!
//! * Two tenants' private ingests of the same titled document each get their
//!   own readable claims; B's response and B's paper never reach A's rows; A's
//!   claims are unchanged.
//! * A tenant re-ingesting a document it ingested under GLOBAL ids (before
//!   ids were scope-derived) writes no new claim: the walk re-uses the ids its
//!   paper recorded.
//!
//! Both server pools are `epigraph_app` (row security enforced); the harness
//! superuser seeds agents, seeds the pre-change state, and reads rows back.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_core::{TenancyDecl, TruthValue, VisibilityChoice};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use epigraph_mcp::types::{GetClaimParams, VerifyClaimParams};
use rmcp::model::{CallToolResult, ContentBlock};
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x47; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(plain.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(vec![0.01_f32; 1536])));
    EpiGraphMcpFull::new(plain, signer, embedder, /* read_only */ false).with_scoped_pool(scoped)
}

fn caller_token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Agent,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

/// One document, byte for byte, for every tenant: same title, same key, same
/// text. No authors: author agents are shared identity rows, not the question.
fn extraction(doi: &str) -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {"title": "Shared Title Paper", "doi": doi, "source_type": "Paper", "authors": []},
        "thesis": "Scoped ingest thesis",
        "thesis_derivation": "TopDown",
        "sections": [{"title": "Results", "paragraphs": [{
            "text": "Scoped ingest paragraph.",
            "atoms": ["Scoped ingest atom one.", "Scoped ingest atom two."],
            "generality": [1, 2], "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction")
}

fn json_of(result: &CallToolResult) -> serde_json::Value {
    match result.content.first().expect("content") {
        ContentBlock::Text(t) => serde_json::from_str(&t.text).expect("json"),
        other => panic!("expected text, got {other:?}"),
    }
}

async fn ingest(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    agent: Uuid,
    doi: &str,
    choice: VisibilityChoice,
) -> serde_json::Value {
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    let out = json_of(
        &do_ingest_document(
            server,
            &viewer,
            &extraction(doi),
            Some(&caller_token(agent)),
            choice,
        )
        .await
        .map_err(|e| e.message.to_string())
        .expect("ingest"),
    );
    // The ingest's tracked background work (its claims' embeddings) settles
    // before anything is compared, so a later snapshot sees only what the
    // NEXT ingest changed.
    assert!(
        server
            .background_tasks()
            .wait_idle(std::time::Duration::from_secs(60))
            .await,
        "the ingest's background work did not finish"
    );
    out
}

/// Every column of every claim `agent` authored, as one text row each,
/// ordered by id.
async fn claims_of(pool: &PgPool, agent: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT concat_ws(' | ', id::text, content, encode(content_hash, 'hex'), \
                visibility::text, owner_group_id::text, properties::text, labels::text, \
                truth_value::text, updated_at::text) \
           FROM claims WHERE agent_id = $1 ORDER BY id",
    )
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("claims")
}

async fn claim_ids_of(pool: &PgPool, agent: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT id FROM claims WHERE agent_id = $1 ORDER BY id")
        .bind(agent)
        .fetch_all(pool)
        .await
        .expect("claim ids")
}

async fn reads(server: &EpiGraphMcpFull, viewer: &Viewer, claim: Uuid) -> bool {
    tools::claims::get_claim(
        server,
        viewer,
        GetClaimParams {
            claim_id: claim.to_string(),
            frame_id: None,
            perspective_id: None,
        },
    )
    .await
    .is_ok()
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_tenants_private_ingests_of_one_document_are_two_sets_of_claims(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (a, group_a) = fixture::seed_agent_with_group(&pool, "scoped-a").await;
    let (b, group_b) = fixture::seed_agent_with_group(&pool, "scoped-b").await;
    let doi = "10.9999/scoped-ids-shared";

    let ra = ingest(&pool, &server, a, doi, VisibilityChoice::Private).await;
    let a_rows = claims_of(&pool, a).await;
    let a_ids = claim_ids_of(&pool, a).await;
    // thesis, section, paragraph, two atoms
    assert_eq!(a_ids.len(), 5, "A's ingest wrote its claims: {ra}");
    let a_paper = ra["paper_id"].as_str().expect("A's paper").to_string();

    let rb = ingest(&pool, &server, b, doi, VisibilityChoice::Private).await;

    // B's response says B wrote its own claims, and names none of A's rows.
    assert_eq!(
        rb["claims_skipped_dedup"], 0,
        "B's private ingest must not resolve to any existing row: {rb}"
    );
    assert_eq!(
        rb["already_ingested"], false,
        "B must not learn that another tenant ingested the document: {rb}"
    );
    assert_eq!(rb["claims_ingested"], 5, "{rb}");
    let rb_text = rb.to_string();
    for id in &a_ids {
        assert!(
            !rb_text.contains(&id.to_string()),
            "B's response names A's claim {id}: {rb}"
        );
    }
    assert!(
        !rb_text.contains(&a_paper),
        "B's response names A's paper: {rb}"
    );

    // B has its own claims, owned by its group and readable by it.
    let b_ids = claim_ids_of(&pool, b).await;
    assert_eq!(b_ids.len(), 5, "B wrote its own claims");
    for id in &b_ids {
        assert!(!a_ids.contains(id), "B's claim {id} is one of A's ids");
    }
    let owners: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT owner_group_id FROM claims WHERE agent_id = $1")
            .bind(b)
            .fetch_all(&pool)
            .await
            .expect("owners");
    assert_eq!(owners, vec![group_b]);
    let vb = Viewer::resolve(&pool, b).await.expect("viewer b");
    let va = Viewer::resolve(&pool, a).await.expect("viewer a");
    for id in &b_ids {
        assert!(
            reads(&server, &vb, *id).await,
            "B cannot read its claim {id}"
        );
    }
    for id in &a_ids {
        assert!(
            reads(&server, &va, *id).await,
            "A cannot read its claim {id}"
        );
        assert!(
            !reads(&server, &vb, *id).await,
            "control: B reads A's private claim {id}, the fixture is broken"
        );
    }

    // A scoped atom's stored digest folds in its group, and verify_claim says
    // so (not applicable) instead of calling it tampered.
    let b_atoms: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM claims WHERE agent_id = $1 AND properties->>'level' = '3' \
           AND properties->>'id_scope' = 'owner_group'",
    )
    .bind(b)
    .fetch_all(&pool)
    .await
    .expect("b atoms");
    assert_eq!(b_atoms.len(), 2, "B's atoms carry the scope marker");
    for id in &b_atoms {
        let v = json_of(
            &tools::claims::verify_claim(
                &server,
                &vb,
                VerifyClaimParams {
                    claim_id: id.to_string(),
                },
            )
            .await
            .expect("verify_claim"),
        );
        assert_eq!(v["hash_check"], "not_applicable", "{v}");
    }

    // B's paper asserts only B's claims.
    let b_paper: Uuid = rb["paper_id"].as_str().expect("B's paper").parse().unwrap();
    let onto_a: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = ANY($2)",
    )
    .bind(b_paper)
    .bind(&a_ids)
    .fetch_one(&pool)
    .await
    .expect("edges");
    assert_eq!(onto_a, 0, "B's paper has an edge onto A's claims");

    // A's claims are exactly as A left them.
    assert_eq!(
        claims_of(&pool, a).await,
        a_rows,
        "B's ingest changed A's claims"
    );
    let a_owner: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT owner_group_id FROM claims WHERE agent_id = $1")
            .bind(a)
            .fetch_all(&pool)
            .await
            .expect("owners");
    assert_eq!(a_owner, vec![group_a]);
}

/// The pre-change state of a private ingest: the GLOBAL plan's claims, owned
/// by the tenant's group, asserted by its in-scope paper through ingest-written
/// edges, as the walk wrote them before ids were scope-derived.
async fn seed_pre_change_ingest(pool: &PgPool, agent: Uuid, group: Uuid, doi: &str) -> Vec<Uuid> {
    let decl = TenancyDecl::group(group);
    let mut conn = pool.acquire().await.expect("conn");
    let paper = epigraph_db::PaperRepository::get_or_create_stored(
        &mut conn,
        doi,
        Some("Shared Title Paper"),
        None,
        decl,
        None,
    )
    .await
    .expect("paper");
    let plan = epigraph_ingest::document::build_ingest_plan(&extraction(doi));
    let mut ids = Vec::new();
    for c in &plan.claims {
        epigraph_db::ClaimRepository::create_with_id_if_absent_conn(
            &mut conn,
            c.id,
            &c.content,
            &c.content_hash,
            agent,
            TruthValue::clamped(0.5),
            &[],
            decl,
        )
        .await
        .expect("claim");
        epigraph_db::create_ingest_written_edge_if_absent_conn(
            &mut conn,
            None,
            "ingest_document",
            agent,
            paper.id,
            "paper",
            c.id,
            "claim",
            "asserts",
            Some(c.properties.clone()),
        )
        .await
        .expect("asserts edge");
        ids.push(c.id);
    }
    ids
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reingest_of_a_document_ingested_under_global_ids_writes_no_new_claim(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (a, group_a) = fixture::seed_agent_with_group(&pool, "scoped-legacy").await;
    let doi = "10.9999/scoped-ids-legacy";
    let mut global = seed_pre_change_ingest(&pool, a, group_a, doi).await;
    global.sort();
    global.dedup();
    assert_eq!(
        claim_ids_of(&pool, a).await,
        global,
        "fixture: the pre-change claims"
    );

    let r = ingest(&pool, &server, a, doi, VisibilityChoice::Private).await;

    assert_eq!(
        claim_ids_of(&pool, a).await,
        global,
        "the re-ingest wrote claims beside the ones its paper recorded: {r}"
    );
    let scoped: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE agent_id = $1 AND properties ? 'id_scope'",
    )
    .bind(a)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(scoped, 0, "no scope-derived duplicate: {r}");
    assert_eq!(r["claims_ingested"], 0, "{r}");
    assert_eq!(r["already_ingested"], true, "{r}");
}
