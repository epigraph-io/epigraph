//! Deterministic document-ingest authors (backlog 94cc12db, second half).
//!
//! `source.authors[].agent_id` names the EXISTING agent an author is; without
//! it the author is the node `did_key_for_author` derives from the name,
//! exactly as before, and the ingest never attaches the author to another
//! agent that merely shares the name: it reports such agents as `candidates`.
//! Every ingest result that walks the document (`wait: true`, the spine, the
//! core the CLI calls) carries a per-author report in `authors[]`.
//!
//! Pinned here:
//! * an explicit `agent_id` (found with `find_agent`) receives the `authored`
//!   edge and every `asserts` edge, and no name-derived node is created;
//! * an absent `agent_id` whose name equals an existing human's is
//!   `ambiguous`: the human gets NO edge, the name-derived node gets them, and
//!   the human is listed as a candidate with public fields only;
//! * the default path is unchanged: `created` on the first document,
//!   `matched` (the same id the name-derived key always gave) on the next;
//! * a bad `agent_id` (not a UUID, no such agent, a registered system agent,
//!   a role node, on a placeholder name, or the same id twice) is refused
//!   before the `papers` row on the queued path, and before any claim in the
//!   core;
//! * the spine honours `agent_id` and reports it;
//! * workflow ingest refuses an `agent_id` instead of ignoring it.
//!
//! Both of the server's pools run as `epigraph_app`, so row security answers
//! as in production. All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_crypto::AgentSigner;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools;
use epigraph_mcp::types::{
    FindAgentParams, IngestDocumentInlineParams, IngestDocumentParams, IngestDocumentSpineParams,
    IngestWorkflowParams,
};
use rmcp::model::CallToolResult;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// An ingesting server whose plain and scoped pools both run as `epigraph_app`.
async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let embedder = McpEmbedder::new(plain.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(plain, AgentSigner::generate(), embedder, false).with_scoped_pool(scoped)
}

/// A server on the harness (superuser) pools, for workflow ingest, whose
/// refusal under test runs before any database access.
async fn superuser_server(pool: &PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(pool).await;
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool.clone(), AgentSigner::generate(), embedder, false)
        .with_scoped_pool(scoped)
}

/// A registered human operator with `display_name = name`.
async fn human_named(pool: &PgPool, name: &str) -> Uuid {
    let (h, _) = fixture::seed_human_operator(pool, "author-resolution").await;
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(h)
        .bind(name)
        .execute(pool)
        .await
        .expect("name the human");
    h
}

/// The node `did_key_for_author` derives from `name`, if it exists.
async fn name_key_node(pool: &PgPool, name: &str) -> Option<Uuid> {
    let (_did, pk) = epigraph_crypto::did_key::did_key_for_author(None, name);
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(pk.as_slice())
        .fetch_optional(pool)
        .await
        .expect("name-key lookup")
}

async fn authored_edges(pool: &PgPool, agent: Uuid, doi: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges e JOIN papers p ON p.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'authored' AND p.doi = $2",
    )
    .bind(agent)
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("count authored")
}

async fn asserts_edges(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND source_type = 'agent' \
           AND relationship = 'asserts'",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("count asserts")
}

async fn papers_with_doi(pool: &PgPool, doi: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM papers WHERE doi = $1")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("count papers")
}

async fn claims_labelled(pool: &PgPool, doi: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE $1 = ANY(labels)")
        .bind(format!("doi:{doi}"))
        .fetch_one(pool)
        .await
        .expect("count claims")
}

/// A one-section, one-paragraph, one-atom paper by `authors`.
fn doc(doi: &str, authors: Value) -> DocumentExtraction {
    serde_json::from_value(json!({
        "source": {"title": format!("Author resolution {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": authors},
        "thesis": format!("Thesis of {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Paragraph of {doi}."),
            "atoms": [format!("Atom of {doi}.")],
            "generality": [3], "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction parses")
}

fn text(r: &CallToolResult) -> Value {
    let t = &r
        .content
        .first()
        .expect("content")
        .as_text()
        .expect("text")
        .text;
    serde_json::from_str(t).expect("JSON response")
}

async fn ingest_wait(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    extraction: DocumentExtraction,
) -> Value {
    let viewer = fixture::public_viewer(pool).await;
    let r = tools::ingestion::ingest_document_inline(
        server,
        &viewer,
        IngestDocumentInlineParams {
            extraction,
            wait: Some(true),
        },
        None,
    )
    .await
    .expect("ingest succeeds");
    text(&r)
}

/// DONE line of 94cc12db: find the person by name, then ingest a document
/// authored by THAT node. The extraction spells the name differently on
/// purpose: the id, not the name, chooses the node.
#[sqlx::test(migrations = "../../migrations")]
async fn an_explicit_agent_id_found_by_find_agent_receives_every_author_edge(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let human = human_named(&pool, "Lyra Okonkwo-Brandt").await;

    let viewer = fixture::public_viewer(&pool).await;
    let found = tools::agent_lookup::find_agent(
        &server,
        &viewer,
        FindAgentParams {
            name: "lyra okonkwo-brandt".to_string(),
            kind: None,
            role: None,
            limit: None,
        },
    )
    .await
    .expect("find_agent");
    let found = text(&found);
    let id: Uuid = found["results"][0]["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("a hit");
    assert_eq!(id, human, "find_agent names the human: {found}");

    let doi = "10.9999/author-explicit";
    let json = ingest_wait(
        &server,
        &pool,
        doc(
            doi,
            json!([{"name": "L. Okonkwo-Brandt", "agent_id": id.to_string()}]),
        ),
    )
    .await;

    let report = &json["authors"][0];
    assert_eq!(report["agent_id"], human.to_string(), "{json}");
    assert_eq!(report["status"], "explicit", "{json}");
    assert_eq!(report["action"], "attached_given", "{json}");
    assert_eq!(report["display_name"], "Lyra Okonkwo-Brandt", "{json}");
    assert_eq!(report["name"], "L. Okonkwo-Brandt", "{json}");
    assert_eq!(authored_edges(&pool, human, doi).await, 1);
    let claims = json["claims_ingested"].as_i64().expect("claims_ingested");
    assert!(claims > 0, "{json}");
    assert_eq!(
        asserts_edges(&pool, human).await,
        claims,
        "the given agent asserts every claim of the document"
    );
    for spelling in ["L. Okonkwo-Brandt", "Lyra Okonkwo-Brandt"] {
        assert_eq!(
            name_key_node(&pool, spelling).await,
            None,
            "no name-derived node is created for {spelling:?} when an agent_id is given"
        );
    }
}

/// Without an `agent_id`, a name equal to an existing human's is AMBIGUOUS:
/// the ingest attaches the name-derived node (as it always did) and lists the
/// human, never picking it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_absent_agent_id_never_attaches_a_same_named_existing_agent(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let name = "Tamsin Feldgrau";
    let human = human_named(&pool, name).await;

    let doi1 = "10.9999/author-ambiguous-1";
    let json = ingest_wait(&server, &pool, doc(doi1, json!([{"name": name}]))).await;
    let report = &json["authors"][0];
    let key_node = name_key_node(&pool, name)
        .await
        .expect("name-key node made");
    assert_ne!(key_node, human);
    assert_eq!(report["agent_id"], key_node.to_string(), "{json}");
    assert_eq!(report["status"], "ambiguous", "{json}");
    assert_eq!(report["action"], "created_name_key", "{json}");
    let candidates = report["candidates"].as_array().expect("candidates");
    assert_eq!(candidates.len(), 1, "{json}");
    assert_eq!(candidates[0]["agent_id"], human.to_string(), "{json}");
    assert_eq!(candidates[0]["tier"], "exact", "{json}");
    assert_eq!(candidates[0]["display_name"], name, "{json}");
    // Public fields only: never the card's D4-gated or viewer-computed facts.
    let mut keys: Vec<&str> = candidates[0]
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["agent_id", "created_at", "display_name", "tier"]);

    assert_eq!(authored_edges(&pool, human, doi1).await, 0, "never picked");
    assert_eq!(asserts_edges(&pool, human).await, 0, "never picked");
    assert_eq!(authored_edges(&pool, key_node, doi1).await, 1);

    // A second document: the name-derived node is reused, still ambiguous.
    let doi2 = "10.9999/author-ambiguous-2";
    let json = ingest_wait(&server, &pool, doc(doi2, json!([{"name": name}]))).await;
    let report = &json["authors"][0];
    assert_eq!(report["agent_id"], key_node.to_string(), "{json}");
    assert_eq!(report["status"], "ambiguous", "{json}");
    assert_eq!(report["action"], "reused_name_key", "{json}");
    assert_eq!(report["candidates"][0]["agent_id"], human.to_string());
    assert_eq!(asserts_edges(&pool, human).await, 0, "never picked");
}

/// A name shared by more agents than the report lists: the oldest ten, and
/// `candidates_truncated`. Same-named system identities and role nodes are
/// never candidates (neither can author); an accent-folded spelling is.
#[sqlx::test(migrations = "../../migrations")]
async fn same_named_agents_are_listed_to_the_limit_and_system_and_role_nodes_never(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let name = "Wren Halvorsen";
    let mut humans = Vec::new();
    for _ in 0..11 {
        humans.push(human_named(&pool, name).await);
    }
    let folded = human_named(&pool, "WREN HÄLVORSEN").await; // the 12th other
    let (system, _) = fixture::seed_agent_with_group(&pool, "author-system-same-name").await;
    assert!(fixture::register_system_agent(&pool, system).await);
    let role: Uuid = sqlx::query_scalar("SELECT id FROM agents WHERE agent_type = 'role' LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a role node");
    for id in [system, role] {
        sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
            .bind(id)
            .bind(name)
            .execute(&pool)
            .await
            .expect("same name");
    }

    let json = ingest_wait(
        &server,
        &pool,
        doc("10.9999/author-many", json!([{"name": name}])),
    )
    .await;
    let report = &json["authors"][0];
    assert_eq!(report["status"], "ambiguous", "{json}");
    assert_eq!(
        report["candidates_truncated"], true,
        "12 others, 10 listed: {json}"
    );
    let listed: Vec<Uuid> = report["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .map(|c| {
            c["agent_id"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .expect("id")
        })
        .collect();
    assert_eq!(listed.len(), 10, "{json}");
    assert_eq!(listed, humans[..10].to_vec(), "oldest first: {json}");
    for never in [system, role] {
        assert!(!listed.contains(&never), "{never} listed: {json}");
    }
    for id in humans.iter().chain([&folded]) {
        assert_eq!(asserts_edges(&pool, *id).await, 0, "never picked");
    }

    // Case- and accent-folded: an unaccented spelling lists the accented
    // holder, and still never picks it.
    let accented = human_named(&pool, "Søren Ølgaard-Núñez").await;
    let json = ingest_wait(
        &server,
        &pool,
        doc(
            "10.9999/author-folded",
            json!([{"name": "soren olgaard-nunez"}]),
        ),
    )
    .await;
    let report = &json["authors"][0];
    assert_eq!(report["status"], "ambiguous", "{json}");
    assert_eq!(
        report["candidates"][0]["agent_id"],
        accented.to_string(),
        "{json}"
    );
    assert!(report.get("candidates_truncated").is_none(), "{json}");
    assert_eq!(asserts_edges(&pool, accented).await, 0, "never picked");
}

/// The default path is the old one: the same id `did_key_for_author` always
/// produced, `created` the first time and `matched` after.
#[sqlx::test(migrations = "../../migrations")]
async fn an_absent_agent_id_keeps_the_name_derived_node_created_then_matched(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let name = "Quillon Ashgrove";

    let doi1 = "10.9999/author-default-1";
    let json = ingest_wait(&server, &pool, doc(doi1, json!([{"name": name}]))).await;
    let key_node = name_key_node(&pool, name).await.expect("name-key node");
    let report = &json["authors"][0];
    assert_eq!(report["agent_id"], key_node.to_string(), "{json}");
    assert_eq!(report["status"], "created", "{json}");
    assert_eq!(report["action"], "created_name_key", "{json}");
    assert!(report.get("candidates").is_none(), "{json}");

    let doi2 = "10.9999/author-default-2";
    let json = ingest_wait(&server, &pool, doc(doi2, json!([{"name": name}]))).await;
    let report = &json["authors"][0];
    assert_eq!(report["agent_id"], key_node.to_string(), "{json}");
    assert_eq!(report["status"], "matched", "{json}");
    assert_eq!(report["action"], "reused_name_key", "{json}");
    assert!(report.get("candidates").is_none(), "{json}");
    assert_eq!(authored_edges(&pool, key_node, doi2).await, 1);
}

/// Each refusal reaches the caller of the QUEUED path (`wait` omitted), before
/// the eager `papers` row the handler writes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bad_agent_id_is_refused_before_the_paper_row_on_the_queued_path(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let real = human_named(&pool, "Ines Vartanian-Hoff").await;
    let (system, _) = fixture::seed_agent_with_group(&pool, "author-system").await;
    assert!(
        fixture::register_system_agent(&pool, system).await,
        "system agent registered"
    );
    let role: Uuid = sqlx::query_scalar("SELECT id FROM agents WHERE agent_type = 'role' LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a role node exists (migration 123)");
    let missing = Uuid::new_v4();
    let viewer = fixture::public_viewer(&pool).await;

    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "malformed",
            json!([{"name": "A Person", "agent_id": "not-a-uuid"}]),
            "source.authors[0].agent_id",
        ),
        (
            "missing",
            json!([{"name": "A Person", "agent_id": missing.to_string()}]),
            "no agent",
        ),
        (
            "system",
            json!([{"name": "A Person", "agent_id": system.to_string()}]),
            "system",
        ),
        (
            "role",
            json!([{"name": "A Person", "agent_id": role.to_string()}]),
            "role",
        ),
        (
            "placeholder",
            json!([{"name": "Unknown", "agent_id": real.to_string()}]),
            "placeholder",
        ),
        (
            "duplicate",
            json!([
                {"name": "A Person", "agent_id": real.to_string()},
                {"name": "Another Person", "agent_id": real.to_string()}
            ]),
            "source.authors[1].agent_id",
        ),
    ];
    for (tag, authors, needle) in cases {
        let doi = format!("10.9999/author-refused-{tag}");
        let err = tools::ingestion::ingest_document_inline(
            &server,
            &viewer,
            IngestDocumentInlineParams {
                extraction: doc(&doi, authors),
                wait: None,
            },
            None,
        )
        .await
        .expect_err(&format!("{tag}: refused"));
        assert!(
            err.message.contains(needle),
            "{tag}: the refusal names {needle:?}: {}",
            err.message
        );
        assert_eq!(
            papers_with_doi(&pool, &doi).await,
            0,
            "{tag}: no papers row"
        );
    }

    // The file-path handler shares the preflight.
    let doi = "10.9999/author-refused-file";
    let path = std::env::current_dir()
        .expect("cwd")
        .join(format!("author-refused-{}.json", Uuid::new_v4()));
    std::fs::write(
        &path,
        serde_json::to_string(&doc(
            doi,
            json!([{"name": "A Person", "agent_id": missing.to_string()}]),
        ))
        .expect("serialise"),
    )
    .expect("write fixture");
    let outcome = tools::ingestion::ingest_document(
        &server,
        &viewer,
        IngestDocumentParams {
            file_path: path.display().to_string(),
            wait: None,
        },
        None,
    )
    .await;
    let _ = std::fs::remove_file(&path);
    let err = outcome.expect_err("file path: refused");
    assert!(err.message.contains("no agent"), "{}", err.message);
    assert_eq!(
        papers_with_doi(&pool, doi).await,
        0,
        "file path: no papers row"
    );

    // CONTROL: the same document with a valid id ingests.
    let doi = "10.9999/author-refused-control";
    tools::ingestion::ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction: doc(
                doi,
                json!([{"name": "A Person", "agent_id": real.to_string()}]),
            ),
            wait: Some(true),
        },
        None,
    )
    .await
    .expect("CONTROL: a valid agent_id ingests");
    assert_eq!(authored_edges(&pool, real, doi).await, 1, "CONTROL");
}

/// The core the CLI bin and `wait: true` call re-checks inside its
/// transaction: a refusal there writes no claim.
#[sqlx::test(migrations = "../../migrations")]
async fn the_core_refuses_an_unknown_agent_id_and_writes_no_claim(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let doi = "10.9999/author-core-refused";
    let err = tools::ingestion::do_ingest_document(
        &server,
        &viewer,
        &doc(
            doi,
            json!([{"name": "A Person", "agent_id": Uuid::new_v4().to_string()}]),
        ),
        None,
    )
    .await
    .expect_err("refused");
    assert!(err.message.contains("no agent"), "{}", err.message);
    assert_eq!(claims_labelled(&pool, doi).await, 0, "no claim written");
}

/// The spine shares the resolver: an explicit id is honoured and reported.
#[sqlx::test(migrations = "../../migrations")]
async fn the_spine_honours_an_explicit_agent_id(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let human = human_named(&pool, "Oren Vasquez-Lindqvist").await;
    let viewer = fixture::public_viewer(&pool).await;
    let doi = "10.9999/author-spine";
    let r = tools::ingestion::ingest_document_spine(
        &server,
        &viewer,
        IngestDocumentSpineParams {
            extraction: doc(
                doi,
                json!([{"name": "O. Vasquez", "agent_id": human.to_string()}]),
            ),
        },
        None,
    )
    .await
    .expect("spine ingests");
    let json = text(&r);
    assert_eq!(json["authors"][0]["agent_id"], human.to_string(), "{json}");
    assert_eq!(json["authors"][0]["status"], "explicit", "{json}");
    assert_eq!(authored_edges(&pool, human, doi).await, 1);
    assert_eq!(name_key_node(&pool, "O. Vasquez").await, None);
}

fn token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

fn workflow(canonical: &str, authors: Value) -> WorkflowExtraction {
    serde_json::from_value(json!({
        "source": {
            "canonical_name": canonical,
            "goal": format!("author workflow {canonical}: the goal"),
            "generation": 0,
            "authors": authors
        },
        "thesis": format!("author workflow {canonical}: the thesis"),
        "thesis_derivation": "TopDown",
        "phases": [{
            "title": "Body",
            "summary": format!("author workflow {canonical}: the phase"),
            "steps": [{
                "compound": format!("author workflow {canonical}: the step"),
                "rationale": "because",
                "operations": [],
                "generality": [1],
                "confidence": 0.7
            }]
        }],
        "relationships": []
    }))
    .expect("workflow parses")
}

async fn workflows_named(pool: &PgPool, canonical: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
        .bind(canonical)
        .fetch_one(pool)
        .await
        .expect("count workflows")
}

/// Workflow ingest shares `AuthorEntry` but resolves authors by name only, so
/// it refuses an `agent_id` rather than silently ignoring it.
#[sqlx::test(migrations = "../../migrations")]
async fn workflow_ingest_refuses_an_author_agent_id(pool: PgPool) {
    let server = superuser_server(&pool).await;
    let (h, _) = fixture::seed_human_operator(&pool, "author-wf").await;
    let auth = token(h);
    let viewer = tools::viewer::request_viewer(&server, Some(&auth))
        .await
        .expect("viewer");

    let err = tools::workflow_ingest::ingest_workflow(
        &server,
        &viewer,
        IngestWorkflowParams {
            extraction: workflow(
                "author-wf-refused",
                json!([{"name": "A Designer", "agent_id": h.to_string()}]),
            ),
            tenancy: None,
            embed: Some(false),
        },
        Some(&auth),
    )
    .await
    .expect_err("an author agent_id is refused");
    assert!(
        err.message.contains("source.authors[0].agent_id"),
        "{}",
        err.message
    );
    assert_eq!(workflows_named(&pool, "author-wf-refused").await, 0);

    tools::workflow_ingest::ingest_workflow(
        &server,
        &viewer,
        IngestWorkflowParams {
            extraction: workflow("author-wf-control", json!([{"name": "A Designer"}])),
            tenancy: None,
            embed: Some(false),
        },
        Some(&auth),
    )
    .await
    .expect("CONTROL: a name-only author ingests");
    assert_eq!(workflows_named(&pool, "author-wf-control").await, 1);
}
