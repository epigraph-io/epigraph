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
//!   paper recorded, and, for an ingest from before migration 246 whose paper
//!   row that migration made public, the group's own non-public rows under
//!   the document's global ids (full walk and spine walk).
//!   A pre-246 atom that converged onto an existing public row is re-used
//!   from what the document's public paper row recorded.
//! * Those reads never reach outside the ingest's own non-public scope: not
//!   a team the author belongs to, not the author's own public rows, and not
//!   a public ingest's rows unless the group's own earlier ingest recorded
//!   them.
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
use epigraph_mcp::tools::ingestion::{do_ingest_document, do_ingest_document_spine};
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
/// The text names the key, so two keys in one test are two documents.
fn extraction(doi: &str) -> DocumentExtraction {
    serde_json::from_value(serde_json::json!({
        "source": {"title": "Shared Title Paper", "doi": doi, "source_type": "Paper", "authors": []},
        "thesis": format!("Scoped ingest thesis ({doi})"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": format!("Results ({doi})"), "paragraphs": [{
            "text": format!("Scoped ingest paragraph ({doi})."),
            "atoms": [format!("Scoped ingest atom one ({doi})."), format!("Scoped ingest atom two ({doi}).")],
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

    // A scoped atom's stored digest folds in its group, and verify_claim
    // re-derives it from the row's owner: an unchanged row matches.
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
        assert_eq!(v["hash_check"], "match", "{v}");
    }
    // A body changed under the row (direct table access) no longer matches.
    sqlx::query("UPDATE claims SET content = content || ' (altered)' WHERE id = $1")
        .bind(b_atoms[0])
        .execute(&pool)
        .await
        .expect("tamper");
    let v = json_of(
        &tools::claims::verify_claim(
            &server,
            &vb,
            VerifyClaimParams {
                claim_id: b_atoms[0].to_string(),
            },
        )
        .await
        .expect("verify_claim"),
    );
    assert_ne!(v["hash_check"], "match", "a changed body verified: {v}");

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
    seed_global_ingest(pool, agent, group, doi, TenancyDecl::group(group)).await
}

/// The state a group's ingest from before migration 246 is in now: its
/// claims under the GLOBAL plan's ids, owned by `group`, asserted by a paper
/// row 246's backfill made PUBLIC (owned by the all-zero world group). The
/// group has no in-scope paper row of its own.
async fn seed_pre_246_ingest(pool: &PgPool, agent: Uuid, group: Uuid, doi: &str) -> Vec<Uuid> {
    seed_global_ingest(pool, agent, group, doi, TenancyDecl::public(Uuid::nil())).await
}

async fn seed_global_ingest(
    pool: &PgPool,
    agent: Uuid,
    group: Uuid,
    doi: &str,
    paper_decl: TenancyDecl,
) -> Vec<Uuid> {
    let decl = TenancyDecl::group(group);
    let mut conn = pool.acquire().await.expect("conn");
    let paper = epigraph_db::PaperRepository::get_or_create_stored(
        &mut conn,
        doi,
        Some("Shared Title Paper"),
        None,
        paper_decl,
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

async fn scoped_count(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE agent_id = $1 AND properties ? 'id_scope'",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("count")
}

/// The pre-246 shape: the group's claims are asserted only through a paper
/// row 246 made public, so the group's own paper row is new and records
/// nothing. MEASURED before the own-group read: 5 claims before, 10 after
/// (`claims_ingested 5`); the global-id walk converged (`claims_skipped_dedup
/// 5`, `already_ingested true`).
#[sqlx::test(migrations = "../../migrations")]
async fn a_reingest_of_a_pre_246_ingest_whose_paper_is_public_writes_no_new_claim(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (a, group_a) = fixture::seed_agent_with_group(&pool, "scoped-pre246").await;
    let doi = "10.9999/scoped-ids-pre246";
    let mut global = seed_pre_246_ingest(&pool, a, group_a, doi).await;
    global.sort();
    global.dedup();
    assert_eq!(claim_ids_of(&pool, a).await, global, "fixture");

    let r = ingest(&pool, &server, a, doi, VisibilityChoice::Private).await;

    assert_eq!(
        claim_ids_of(&pool, a).await,
        global,
        "the re-ingest wrote claims beside the group's own pre-246 rows: {r}"
    );
    assert_eq!(scoped_count(&pool, a).await, 0, "{r}");
    assert_eq!(r["claims_ingested"], 0, "{r}");
    assert_eq!(r["claims_skipped_dedup"], 5, "{r}");
    assert_eq!(r["already_ingested"], true, "{r}");
}

async fn claim_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(pool)
        .await
        .expect("count")
}

/// A pre-246 ingest whose atom converged onto an existing PUBLIC row (another
/// author's, same text): that atom is recorded only on the paper row 246 made
/// public. The re-ingest re-uses it from there, as the global-id walk did, and
/// writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_pre_246_ingest_keeps_the_public_atom_it_converged_onto(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (a, group_a) = fixture::seed_agent_with_group(&pool, "scoped-pre246-pub").await;
    let (p, group_p) = fixture::seed_agent_with_group(&pool, "scoped-pre246-pub-other").await;
    let doi = "10.9999/scoped-ids-pre246-public-atom";
    let plan = epigraph_ingest::document::build_ingest_plan(&extraction(doi));
    let atom = plan.claims.iter().find(|c| c.level == 3).expect("atom");
    {
        let mut conn = pool.acquire().await.expect("conn");
        let created = epigraph_db::ClaimRepository::create_with_id_if_absent_conn(
            &mut conn,
            atom.id,
            &atom.content,
            &atom.content_hash,
            p,
            TruthValue::clamped(0.5),
            &[],
            TenancyDecl::public(group_p),
        )
        .await
        .expect("public atom");
        assert!(created, "fixture: the public atom");
    }
    seed_pre_246_ingest(&pool, a, group_a, doi).await;
    assert_eq!(
        claim_ids_of(&pool, a).await.len(),
        4,
        "fixture: four own rows"
    );
    let before = claim_count(&pool).await;

    let r = ingest(&pool, &server, a, doi, VisibilityChoice::Private).await;

    assert_eq!(
        claim_count(&pool).await,
        before,
        "the re-ingest wrote a claim beside the rows its document recorded: {r}"
    );
    assert_eq!(r["claims_ingested"], 0, "{r}");
    assert_eq!(r["claims_skipped_dedup"], 5, "{r}");
}

/// The public row's records are read only when the group's own earlier ingest
/// wrote through it: a group's first private ingest of a document that was
/// only ever ingested publicly writes the group's own claims.
#[sqlx::test(migrations = "../../migrations")]
async fn a_first_private_ingest_of_a_public_document_writes_its_own_claims(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (a, group_a) = fixture::seed_agent_with_group(&pool, "scoped-after-public").await;
    let (p, _) = fixture::seed_agent_with_group(&pool, "scoped-after-public-pub").await;
    let doi = "10.9999/scoped-ids-after-public";
    let rp = ingest(&pool, &server, p, doi, VisibilityChoice::Public).await;
    assert_eq!(rp["claims_ingested"], 5, "{rp}");

    let r = ingest(&pool, &server, a, doi, VisibilityChoice::Private).await;

    assert_eq!(
        r["claims_ingested"], 5,
        "the private ingest folded into the public ingest's rows: {r}"
    );
    assert_eq!(scoped_count(&pool, a).await, 5, "{r}");
    let owners: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT owner_group_id FROM claims WHERE agent_id = $1")
            .bind(a)
            .fetch_all(&pool)
            .await
            .expect("owners");
    assert_eq!(owners, vec![group_a]);
}

/// The public row's records are filtered in the SQL, not by row security:
/// on a connection that bypasses it (the harness superuser, as the operator
/// CLI's maintenance pool does), another group's non-public row the public
/// paper asserts is still never returned.
#[sqlx::test(migrations = "../../migrations")]
async fn the_public_twin_read_never_returns_another_groups_non_public_row(pool: PgPool) {
    let (a, group_a) = fixture::seed_agent_with_group(&pool, "scoped-twin-a").await;
    let (h, group_h) = fixture::seed_agent_with_group(&pool, "scoped-twin-h").await;
    let doi = "10.9999/scoped-ids-twin-filter";
    let plan = epigraph_ingest::document::build_ingest_plan(&extraction(doi));
    let atom = plan.claims.iter().find(|c| c.level == 3).expect("atom");
    let mut conn = pool.acquire().await.expect("conn");
    // H's non-public row holds the atom; the rest are A's.
    assert!(epigraph_db::ClaimRepository::create_with_id_if_absent_conn(
        &mut conn,
        atom.id,
        &atom.content,
        &atom.content_hash,
        h,
        TruthValue::clamped(0.5),
        &[],
        TenancyDecl::group(group_h),
    )
    .await
    .expect("h's atom"));
    drop(conn);
    seed_pre_246_ingest(&pool, a, group_a, doi).await;
    let mut conn = pool.acquire().await.expect("conn");
    let a_paper = epigraph_db::PaperRepository::get_or_create_stored(
        &mut conn,
        doi,
        Some("Shared Title Paper"),
        None,
        TenancyDecl::group(group_a),
        None,
    )
    .await
    .expect("a's paper")
    .id;

    let got: Vec<Uuid> =
        epigraph_db::PaperRepository::public_twin_recorded_claims_conn(&mut conn, a_paper, group_a)
            .await
            .expect("read")
            .into_iter()
            .map(|(id, _)| id)
            .collect();

    assert_eq!(got.len(), 4, "A's own four rows: {got:?}");
    assert!(
        !got.contains(&atom.id),
        "the read returned another group's non-public row"
    );
}

/// The spine walk re-uses the same pre-246 rows: no structural node is
/// written again under a scoped id.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_spine_of_a_pre_246_ingest_writes_no_new_node(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (a, group_a) = fixture::seed_agent_with_group(&pool, "scoped-pre246-spine").await;
    let doi = "10.9999/scoped-ids-pre246-spine";
    let mut global = seed_pre_246_ingest(&pool, a, group_a, doi).await;
    global.sort();
    global.dedup();

    let r = spine(&pool, &server, a, doi).await;

    assert_eq!(
        claim_ids_of(&pool, a).await,
        global,
        "the spine wrote structural nodes beside the group's own pre-246 rows: {r}"
    );
    assert_eq!(scoped_count(&pool, a).await, 0, "{r}");
    assert_eq!(r["paragraphs_new"], 0, "{r}");
}

/// The own-group read is scoped in its SQL, not by what row security lets the
/// author see. (1) A team's pre-246 rows, readable by a member: that member's
/// PRIVATE ingest of the document writes its own scoped claims and leaves the
/// team's alone. (2) The author's own PUBLIC ingest (owned by its personal
/// group too): its later private ingest of the document writes its own
/// non-public claims rather than folding into the public rows.
#[sqlx::test(migrations = "../../migrations")]
async fn the_own_group_read_stays_inside_the_ingests_non_public_scope(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (h, personal) = fixture::seed_human_operator(&pool, "scoped-own-scope").await;
    let team = fixture::verb_team_group(&pool, "scoped-own-scope-team", h).await;

    // (1) a team's pre-246 rows, which h can read.
    let doi_team = "10.9999/scoped-ids-team-legacy";
    let team_rows =
        seed_global_ingest(&pool, h, team, doi_team, TenancyDecl::public(Uuid::nil())).await;
    let vh = Viewer::resolve(&pool, h).await.expect("viewer h");
    assert!(
        reads(&server, &vh, team_rows[0]).await,
        "control: the team member cannot read the team's row, so the case proves nothing"
    );
    let owned_by = |g: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM claims WHERE owner_group_id = $1 ORDER BY id",
            )
            .bind(g)
            .fetch_all(&pool)
            .await
            .expect("owned")
        }
    };
    let team_before = owned_by(team).await;
    let r1 = ingest(&pool, &server, h, doi_team, VisibilityChoice::Private).await;
    assert_eq!(
        r1["claims_ingested"], 5,
        "the private ingest folded into the team's rows: {r1}"
    );
    assert_eq!(owned_by(team).await, team_before, "{r1}");
    let private_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE owner_group_id = $1 \
            AND visibility::text <> 'public' AND properties ? 'id_scope'",
    )
    .bind(personal)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(private_rows, 5, "{r1}");

    // (2) the author's own public ingest, then a private one.
    let doi_pub = "10.9999/scoped-ids-own-public";
    let rp = ingest(&pool, &server, h, doi_pub, VisibilityChoice::Public).await;
    assert_eq!(rp["claims_ingested"], 5, "{rp}");
    let public_owner: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT owner_group_id FROM claims \
          WHERE visibility::text = 'public' AND agent_id = $1",
    )
    .bind(h)
    .fetch_all(&pool)
    .await
    .expect("public owner");
    assert_eq!(
        public_owner,
        vec![personal],
        "control: the public ingest's rows are not owned by the author's group, so the case \
         proves nothing"
    );
    let r2 = ingest(&pool, &server, h, doi_pub, VisibilityChoice::Private).await;
    assert_eq!(
        r2["claims_ingested"], 5,
        "the private ingest folded into the author's public rows: {r2}"
    );
    let private_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE owner_group_id = $1 \
            AND visibility::text <> 'public' AND properties ? 'id_scope'",
    )
    .bind(personal)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(private_rows, 10, "{r2}");
}

async fn spine(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    agent: Uuid,
    doi: &str,
) -> serde_json::Value {
    let viewer = Viewer::resolve(pool, agent).await.expect("viewer");
    let out = json_of(
        &do_ingest_document_spine(
            server,
            &viewer,
            &extraction(doi),
            Some(&caller_token(agent)),
            VisibilityChoice::Private,
        )
        .await
        .map_err(|e| e.message.to_string())
        .expect("spine ingest"),
    );
    assert!(
        server
            .background_tasks()
            .wait_idle(std::time::Duration::from_secs(60))
            .await,
        "the spine ingest's background work did not finish"
    );
    out
}

/// The spine walk (structural nodes only) derives the same scoped ids as the
/// full walk: a private spine then a private full ingest of one document by
/// one tenant converge node for node, and a second tenant's private spine of
/// the same document gets its own nodes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_spine_is_scoped_and_converges_with_the_full_ingest(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "scoped-spine-a").await;
    let (b, group_b) = fixture::seed_agent_with_group(&pool, "scoped-spine-b").await;
    let doi = "10.9999/scoped-ids-spine";

    let sa = spine(&pool, &server, a, doi).await;
    assert_eq!(sa["paragraphs_new"], 1, "{sa}");
    let a_spine = claim_ids_of(&pool, a).await;
    // thesis, section, paragraph
    assert_eq!(
        a_spine.len(),
        3,
        "A's spine wrote its structural nodes: {sa}"
    );

    let fa = ingest(&pool, &server, a, doi, VisibilityChoice::Private).await;
    assert_eq!(
        fa["claims_skipped_dedup"], 3,
        "the full ingest converges on the spine's three nodes: {fa}"
    );
    assert_eq!(fa["claims_ingested"], 2, "only the two atoms are new: {fa}");
    assert_eq!(claim_ids_of(&pool, a).await.len(), 5);

    let sb = spine(&pool, &server, b, doi).await;
    assert_eq!(
        sb["paragraphs_new"], 1,
        "B's private spine writes its own paragraph: {sb}"
    );
    assert_eq!(sb["already_ingested"], false, "{sb}");
    let sb_text = sb.to_string();
    for id in claim_ids_of(&pool, a).await {
        assert!(
            !sb_text.contains(&id.to_string()),
            "B's spine response names A's claim {id}: {sb}"
        );
    }
    let b_ids = claim_ids_of(&pool, b).await;
    assert_eq!(b_ids.len(), 3, "B has its own structural nodes");
    let owners: Vec<Uuid> =
        sqlx::query_scalar("SELECT DISTINCT owner_group_id FROM claims WHERE agent_id = $1")
            .bind(b)
            .fetch_all(&pool)
            .await
            .expect("owners");
    assert_eq!(owners, vec![group_b]);
}
