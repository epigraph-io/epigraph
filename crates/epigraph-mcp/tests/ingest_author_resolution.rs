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
//!   edge and no name-derived node is created; it receives the `asserts`
//!   edges only when the ingester IS that agent or is the human operating
//!   it. Anyone else's naming is `pending_countersign`: `authored` only,
//!   marked with the ingester, and not counted on the agent's card;
//! * a re-ingest with `agent_id` REPLACES the entry's name-derived author
//!   (on the operator CLI's privileged pool), never adds the agent beside it;
//!   an MCP server, which cannot retract those administrative edges, refuses
//!   it and writes nothing; and a later name-only re-ingest keeps the
//!   explicit author;
//! * an explicit id equal to another entry's name-derived node is refused;
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
    FindAgentParams, GetAgentParams, IngestDocumentInlineParams, IngestDocumentParams,
    IngestDocumentSpineParams, IngestWorkflowParams, QueryPaperParams, SubmitClaimParams,
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

/// The operator `ingest-document` CLI's shape: no `ScopedPool`, a DECLARED
/// privileged pool (here the superuser harness pool stands in for
/// `MaintenancePool`), so the walk is a plain transaction row security does
/// not scope.
fn privileged_server(pool: &PgPool) -> EpiGraphMcpFull {
    let embedder = McpEmbedder::new(pool.clone(), None).on_a_privileged_pool("test: operator CLI");
    EpiGraphMcpFull::new(pool.clone(), AgentSigner::generate(), embedder, false)
        .on_a_privileged_pool("test: operator CLI")
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

/// In-force `authored` edges from `agent` into the paper keyed `doi`.
async fn authored_in_force(pool: &PgPool, agent: Uuid, doi: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges e JOIN papers p ON p.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'authored' AND p.doi = $2 \
            AND (e.valid_to IS NULL OR e.valid_to > now())",
    )
    .bind(agent)
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("count in-force authored")
}

/// In-force `asserts` edges from `agent` onto the claims the paper keyed
/// `doi` asserts.
async fn asserts_on_doc(pool: &PgPool, agent: Uuid, doi: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges a \
          WHERE a.source_id = $1 AND a.source_type = 'agent' AND a.relationship = 'asserts' \
            AND (a.valid_to IS NULL OR a.valid_to > now()) \
            AND EXISTS (SELECT 1 FROM edges pc JOIN papers p ON p.id = pc.source_id \
                         WHERE p.doi = $2 AND pc.relationship = 'asserts' \
                           AND pc.target_id = a.target_id)",
    )
    .bind(agent)
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("count asserts on the document")
}

/// Claims the paper keyed `doi` asserts.
async fn paper_claims(pool: &PgPool, doi: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges pc JOIN papers p ON p.id = pc.source_id \
          WHERE p.doi = $1 AND pc.relationship = 'asserts' AND pc.target_type = 'claim'",
    )
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("count the paper's claims")
}

/// The properties of `agent`'s `authored` edge into the paper keyed `doi`.
async fn authored_props(pool: &PgPool, agent: Uuid, doi: &str) -> Value {
    sqlx::query_scalar(
        "SELECT e.properties FROM edges e JOIN papers p ON p.id = e.target_id \
          WHERE e.source_id = $1 AND e.relationship = 'authored' AND p.doi = $2",
    )
    .bind(agent)
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("authored edge properties")
}

/// `get_agent`'s card counts for `id`, as a third party who wrote nothing.
async fn card_counts(server: &EpiGraphMcpFull, pool: &PgPool, id: Uuid) -> Value {
    let viewer = fixture::public_viewer(pool).await;
    let r = tools::agent_lookup::get_agent(
        server,
        &viewer,
        GetAgentParams {
            agent_id: id.to_string(),
        },
    )
    .await
    .expect("get_agent");
    text(&r)["counts"].clone()
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

/// A one-section, one-paragraph paper by `authors` with these atoms.
fn doc_with_atoms(doi: &str, authors: Value, atoms: &[&str]) -> DocumentExtraction {
    let generality: Vec<u8> = atoms.iter().map(|_| 3).collect();
    serde_json::from_value(json!({
        "source": {"title": format!("Author resolution {doi}"), "doi": doi,
                   "source_type": "Paper", "authors": authors},
        "thesis": format!("Thesis of {doi}"),
        "thesis_derivation": "TopDown",
        "sections": [{"title": "S", "paragraphs": [{
            "text": format!("Paragraph of {doi}."),
            "atoms": atoms,
            "generality": generality, "confidence": 0.8
        }]}],
        "relationships": []
    }))
    .expect("extraction parses")
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
///
/// The ingester here (this stdio server's own agent) is neither the person
/// nor operates them, so the explicit-author rule applies: the person is the
/// paper's author (`authored`, marked `pending_countersign` with the
/// ingester as `ingested_by`), asserts NONE of its claims, and a third
/// party's card for them counts nothing until they countersign.
#[sqlx::test(migrations = "../../migrations")]
async fn an_explicit_agent_id_found_by_find_agent_is_the_author_and_a_stranger_cannot_make_it_assert(
    pool: PgPool,
) {
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
    assert_eq!(report["attribution"], "pending_countersign", "{json}");
    assert_eq!(report["asserts_claims"], false, "{json}");
    let ingester = server.server_agent_id().await.expect("server agent");
    assert_eq!(json["ingested_by"], ingester.to_string(), "{json}");
    assert_ne!(
        ingester, human,
        "CALIBRATION: the ingester is not the person"
    );

    assert_eq!(
        authored_edges(&pool, human, doi).await,
        1,
        "the person is an author"
    );
    let props = authored_props(&pool, human, doi).await;
    assert_eq!(props["pending_countersign"], true, "{props}");
    assert_eq!(props["ingested_by"], ingester.to_string(), "{props}");
    assert_eq!(props["explicit_agent_id"], true, "{props}");
    assert_eq!(props["author_name"], "L. Okonkwo-Brandt", "{props}");
    let claims = json["claims_ingested"].as_i64().expect("claims_ingested");
    assert!(claims > 0, "{json}");
    assert_eq!(
        paper_claims(&pool, doi).await,
        claims,
        "CALIBRATION: the paper asserts every claim"
    );
    assert_eq!(
        asserts_edges(&pool, human).await,
        0,
        "a stranger's naming makes the person assert nothing"
    );
    let counts = card_counts(&server, &pool, human).await;
    assert_eq!(
        (&counts["authored_papers"], &counts["asserted_claims"]),
        (&json!(0), &json!(0)),
        "a pending authorship is not on the person's card: {counts}"
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
    for _ in 0..10 {
        humans.push(human_named(&pool, name).await);
    }
    // The 11th other, youngest, so never listed: `candidates_truncated` below
    // is true ONLY if its folded name is counted as a match.
    let folded = human_named(&pool, "WREN HÄLVORSEN").await;
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
        "11 others (10 plain + the case- and accent-folded one), 10 listed: {json}"
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
    assert_eq!(listed, humans, "oldest first: {json}");
    assert!(!listed.contains(&folded), "the youngest is cut: {json}");
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

    // And the other way round: the EXTRACTION is accented, the stored name is
    // not. Folding the query side is what finds it.
    let plain = human_named(&pool, "zoe alvendrup").await;
    let json = ingest_wait(
        &server,
        &pool,
        doc(
            "10.9999/author-folded-query",
            json!([{"name": "Zoë Ålvendrup"}]),
        ),
    )
    .await;
    let report = &json["authors"][0];
    assert_eq!(report["status"], "ambiguous", "{json}");
    assert_eq!(
        report["candidates"][0]["agent_id"],
        plain.to_string(),
        "{json}"
    );
    assert_eq!(asserts_edges(&pool, plain).await, 0, "never picked");
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

/// `ingest_document_spine` on `server`, as a public viewer.
async fn spine(server: &EpiGraphMcpFull, pool: &PgPool, extraction: DocumentExtraction) -> Value {
    let viewer = fixture::public_viewer(pool).await;
    let r = tools::ingestion::ingest_document_spine(
        server,
        &viewer,
        IngestDocumentSpineParams { extraction },
        None,
    )
    .await
    .expect("spine ingests");
    text(&r)
}

/// The spine shares the resolver AND the explicit-author rule: a stranger's
/// naming of a person by id makes them an author (`authored`, pending, marked
/// with the ingester) and asserts NONE of the spine's claims.
#[sqlx::test(migrations = "../../migrations")]
async fn the_spine_honours_an_explicit_agent_id(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let human = human_named(&pool, "Oren Vasquez-Lindqvist").await;
    let doi = "10.9999/author-spine";
    let json = spine(
        &server,
        &pool,
        doc(
            doi,
            json!([{"name": "O. Vasquez", "agent_id": human.to_string()}]),
        ),
    )
    .await;
    assert_eq!(json["authors"][0]["agent_id"], human.to_string(), "{json}");
    assert_eq!(json["authors"][0]["status"], "explicit", "{json}");
    assert_eq!(
        json["authors"][0]["attribution"], "pending_countersign",
        "{json}"
    );
    assert_eq!(json["authors"][0]["asserts_claims"], false, "{json}");
    assert_eq!(authored_edges(&pool, human, doi).await, 1);
    assert_eq!(name_key_node(&pool, "O. Vasquez").await, None);
    let ingester = server.server_agent_id().await.expect("server agent");
    let props = authored_props(&pool, human, doi).await;
    assert_eq!(props["pending_countersign"], true, "{props}");
    assert_eq!(props["ingested_by"], ingester.to_string(), "{props}");
    assert!(
        paper_claims(&pool, doi).await > 0,
        "CALIBRATION: the spine asserted claims"
    );
    assert_eq!(
        asserts_edges(&pool, human).await,
        0,
        "a stranger's naming on the spine makes the person assert nothing"
    );
}

/// CONTROL for the spine's gate: the ingester naming ITSELF asserts every
/// spine claim, so the zero above is the gate's, not an empty spine's.
#[sqlx::test(migrations = "../../migrations")]
async fn the_spine_lets_the_ingester_name_itself_and_assert(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let me = server.server_agent_id().await.expect("server agent");
    let doi = "10.9999/author-spine-self";
    let json = spine(
        &server,
        &pool,
        doc(
            doi,
            json!([{"name": "Spine Self", "agent_id": me.to_string()}]),
        ),
    )
    .await;
    assert_eq!(json["authors"][0]["attribution"], "caller", "{json}");
    assert_eq!(json["authors"][0]["asserts_claims"], true, "{json}");
    let claims = paper_claims(&pool, doi).await;
    assert!(claims > 0, "{json}");
    assert_eq!(asserts_on_doc(&pool, me, doi).await, claims, "{json}");
}

/// The two arms of the explicit-author rule that DO write `asserts`: the
/// ingester names itself, or names an agent it is the human operator of.
/// CONTROL: an agent somebody else operates is `pending_countersign`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ingester_itself_and_the_human_operating_an_agent_make_it_assert(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let me = server.server_agent_id().await.expect("server agent");

    let doi = "10.9999/author-self";
    let json = ingest_wait(
        &server,
        &pool,
        doc(
            doi,
            json!([{"name": "The Ingester", "agent_id": me.to_string()}]),
        ),
    )
    .await;
    let report = &json["authors"][0];
    assert_eq!(report["attribution"], "caller", "{json}");
    assert_eq!(report["asserts_claims"], true, "{json}");
    let claims = paper_claims(&pool, doi).await;
    assert!(claims > 0);
    assert_eq!(
        asserts_on_doc(&pool, me, doi).await,
        claims,
        "self: asserts every claim"
    );
    let props = authored_props(&pool, me, doi).await;
    assert_eq!(props["explicit_agent_id"], true, "{props}");
    assert!(props.get("pending_countersign").is_none(), "{props}");
    assert_eq!(
        card_counts(&server, &pool, me).await["authored_papers"],
        1,
        "a self-attributed paper is on the card"
    );

    // The ingester becomes a registered human and operates a bot.
    fixture::make_human_operator(&pool, me).await;
    let (bot, _) = fixture::seed_agent_with_group(&pool, "author-operated-bot").await;
    let (other_human, _) = fixture::seed_human_operator(&pool, "author-other-human").await;
    let (other_bot, _) = fixture::seed_agent_with_group(&pool, "author-other-bot").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, bot, me)
            .await
            .expect("link the bot");
        epigraph_db::AgentRepository::link_operator(&mut conn, other_bot, other_human)
            .await
            .expect("link the other bot");
        assert_eq!(
            epigraph_db::AgentRepository::human_of(&mut conn, bot, true)
                .await
                .expect("human_of"),
            Some(me),
            "CALIBRATION: the ingester is the bot's human"
        );
    }

    let doi = "10.9999/author-operated";
    let json = ingest_wait(
        &server,
        &pool,
        doc(
            doi,
            json!([{"name": "The Bot", "agent_id": bot.to_string()}]),
        ),
    )
    .await;
    assert_eq!(
        json["authors"][0]["attribution"], "operated_by_caller",
        "{json}"
    );
    assert_eq!(json["authors"][0]["asserts_claims"], true, "{json}");
    assert_eq!(
        asserts_on_doc(&pool, bot, doi).await,
        paper_claims(&pool, doi).await,
        "operated: the bot asserts every claim"
    );

    let doi = "10.9999/author-operated-control";
    let json = ingest_wait(
        &server,
        &pool,
        doc(
            doi,
            json!([{"name": "Their Bot", "agent_id": other_bot.to_string()}]),
        ),
    )
    .await;
    assert_eq!(
        json["authors"][0]["attribution"], "pending_countersign",
        "{json}"
    );
    assert_eq!(
        authored_edges(&pool, other_bot, doi).await,
        1,
        "CONTROL: authored"
    );
    assert_eq!(
        asserts_edges(&pool, other_bot).await,
        0,
        "CONTROL: no asserts"
    );
}

/// An MCP server cannot retract a name-derived author's edges (agent edges
/// are administrative), so a re-ingest with `agent_id` that would REPLACE it
/// is refused, on the queued path, in wait mode and in the core, and nothing
/// moves: in particular the agent is never added BESIDE the old author.
#[sqlx::test(migrations = "../../migrations")]
async fn an_mcp_server_refuses_to_replace_a_name_derived_author_and_writes_nothing(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let name = "Corvin Thale";
    let human = human_named(&pool, name).await;
    let doi = "10.9999/author-replace-refused";

    let first = ingest_wait(&server, &pool, doc(doi, json!([{"name": name}]))).await;
    assert_eq!(first["authors"][0]["status"], "ambiguous", "{first}");
    let key = name_key_node(&pool, name).await.expect("name-key node");
    let before = asserts_on_doc(&pool, key, doi).await;
    assert!(
        before > 0,
        "CALIBRATION: the name-derived node asserts the claims"
    );

    let viewer = fixture::public_viewer(&pool).await;
    let again = || doc(doi, json!([{"name": name, "agent_id": human.to_string()}]));
    for wait in [None, Some(true)] {
        let err = tools::ingestion::ingest_document_inline(
            &server,
            &viewer,
            IngestDocumentInlineParams {
                extraction: again(),
                wait,
            },
            None,
        )
        .await
        .expect_err("a replacement this server cannot make is refused");
        for needle in ["source.authors[0].agent_id", "REPLACE", "ingest-document"] {
            assert!(
                err.message.contains(needle),
                "wait={wait:?}: {needle:?}: {}",
                err.message
            );
        }
    }
    let err = tools::ingestion::do_ingest_document(&server, &viewer, &again(), None)
        .await
        .expect_err("the walk refuses it too");
    assert!(err.message.contains("REPLACE"), "{}", err.message);

    assert_eq!(
        authored_in_force(&pool, key, doi).await,
        1,
        "the old author stays"
    );
    assert_eq!(
        asserts_on_doc(&pool, key, doi).await,
        before,
        "its asserts stay"
    );
    assert_eq!(
        authored_edges(&pool, human, doi).await,
        0,
        "never added beside it"
    );
}

/// The operator CLI (a privileged pool) performs the replacement: the
/// name-derived node's `authored` edge and its `asserts` edges on THIS paper
/// are retracted, except on a claim another of its papers also asserts, and
/// its other paper is untouched. A later name-only re-ingest keeps the
/// explicit author instead of bringing the name-derived node back.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_cli_replaces_the_name_derived_author_and_a_name_only_reingest_keeps_it(
    pool: PgPool,
) {
    let server = privileged_server(&pool);
    let reader = app_role_server(&pool).await;
    // The CLI's maintenance viewer is a bypass viewer; hold its pool.
    let (_maintenance, viewer) = fixture::bypass(&pool).await;
    let name = "Ysolde Marchetti";
    let human = human_named(&pool, name).await;
    let (doi1, doi2) = ("10.9999/author-replace-1", "10.9999/author-replace-2");
    let shared = "Shared atom of the replacement pair.";
    let core = |extraction: DocumentExtraction| {
        let (server, viewer) = (&server, &viewer);
        async move {
            text(
                &tools::ingestion::do_ingest_document(server, viewer, &extraction, None)
                    .await
                    .expect("the core ingests"),
            )
        }
    };

    core(doc_with_atoms(
        doi1,
        json!([{"name": name}]),
        &["Only in the first.", shared],
    ))
    .await;
    core(doc_with_atoms(
        doi2,
        json!([{"name": name}]),
        &["Only in the second.", shared],
    ))
    .await;
    let key = name_key_node(&pool, name).await.expect("name-key node");
    let k1 = asserts_on_doc(&pool, key, doi1).await;
    let k2 = asserts_on_doc(&pool, key, doi2).await;
    let both: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges a JOIN papers p ON p.id = a.source_id AND p.doi = $1 \
           JOIN edges b ON b.target_id = a.target_id AND b.relationship = 'asserts' \
           JOIN papers q ON q.id = b.source_id AND q.doi = $2 \
          WHERE a.relationship = 'asserts'",
    )
    .bind(doi1)
    .bind(doi2)
    .fetch_one(&pool)
    .await
    .expect("shared claims");
    assert!(both >= 1, "CALIBRATION: the two papers share a claim");
    assert_eq!(
        card_counts(&reader, &pool, key).await["authored_papers"],
        2,
        "CALIBRATION"
    );

    let json = core(doc_with_atoms(
        doi1,
        json!([{"name": name, "agent_id": human.to_string()}]),
        &["Only in the first.", shared],
    ))
    .await;
    let report = &json["authors"][0];
    assert_eq!(report["agent_id"], human.to_string(), "{json}");
    assert_eq!(report["replaced"]["agent_id"], key.to_string(), "{json}");
    assert_eq!(report["replaced"]["authored_edges_retracted"], 1, "{json}");
    assert_eq!(
        report["replaced"]["asserts_edges_retracted"],
        k1 - both,
        "{json}"
    );
    assert!(report.get("also_at_position").is_none(), "{json}");

    assert_eq!(
        authored_in_force(&pool, key, doi1).await,
        0,
        "replaced on this paper"
    );
    assert_eq!(
        asserts_on_doc(&pool, key, doi1).await,
        both,
        "only the claim its other paper asserts keeps its edge"
    );
    assert_eq!(
        authored_in_force(&pool, key, doi2).await,
        1,
        "its other paper is untouched"
    );
    assert_eq!(
        asserts_on_doc(&pool, key, doi2).await,
        k2,
        "its other paper is untouched"
    );
    assert_eq!(
        authored_in_force(&pool, human, doi1).await,
        1,
        "one author at the position"
    );
    assert_eq!(
        card_counts(&reader, &pool, key).await["authored_papers"],
        1,
        "a retracted authorship leaves the card"
    );

    // A name-only re-ingest (a pipeline re-run) keeps the explicit author.
    let json = core(doc_with_atoms(
        doi1,
        json!([{"name": name}]),
        &["Only in the first.", shared],
    ))
    .await;
    let report = &json["authors"][0];
    assert_eq!(report["agent_id"], human.to_string(), "{json}");
    assert_eq!(report["status"], "explicit", "{json}");
    assert_eq!(report["action"], "kept_attached", "{json}");
    assert_eq!(
        authored_in_force(&pool, key, doi1).await,
        0,
        "not brought back"
    );
    assert_eq!(
        asserts_on_doc(&pool, key, doi1).await,
        both,
        "not brought back"
    );
    assert_eq!(authored_in_force(&pool, human, doi1).await, 1);
}

/// The default path is unchanged for a name listed twice: one node, one
/// `authored` edge, and the ingest is NOT refused (only an explicit author
/// shared with another entry is).
#[sqlx::test(migrations = "../../migrations")]
async fn a_name_only_document_listing_one_name_twice_still_ingests(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let name = "Li Arvenna";
    let doi = "10.9999/author-same-name-twice";
    let json = ingest_wait(
        &server,
        &pool,
        doc(doi, json!([{"name": name}, {"name": name}])),
    )
    .await;
    let key = name_key_node(&pool, name).await.expect("name-key node");
    let authors = json["authors"].as_array().expect("authors");
    assert_eq!(authors.len(), 2, "{json}");
    for a in authors {
        assert_eq!(a["agent_id"], key.to_string(), "{json}");
        assert_eq!(a["attribution"], "name_derived", "{json}");
    }
    assert_eq!(
        authored_edges(&pool, key, doi).await,
        1,
        "one edge, as always"
    );
    assert_eq!(
        asserts_on_doc(&pool, key, doi).await,
        paper_claims(&pool, doi).await
    );
}

/// Re-running the SAME extraction converges: an explicit author beside a
/// same-spelled name-only entry resolves the second time exactly as the
/// first (the name-only entry does not "keep" the explicit author this very
/// call names), and writes nothing new.
#[sqlx::test(migrations = "../../migrations")]
async fn rerunning_an_extraction_with_an_explicit_and_a_same_named_entry_converges(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let name = "Hesper Quill";
    let human = human_named(&pool, name).await;
    let doi = "10.9999/author-rerun-converges";
    let extraction = || {
        doc(
            doi,
            json!([{"name": name, "agent_id": human.to_string()}, {"name": name}]),
        )
    };
    let edges_now = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM edges")
            .fetch_one(&pool)
            .await
            .expect("count edges")
    };
    let first = ingest_wait(&server, &pool, extraction()).await;
    let key = name_key_node(&pool, name).await.expect("name-key node");
    assert_eq!(
        first["authors"][0]["agent_id"],
        human.to_string(),
        "{first}"
    );
    assert_eq!(first["authors"][1]["agent_id"], key.to_string(), "{first}");
    let before = edges_now().await;

    let second = ingest_wait(&server, &pool, extraction()).await;
    assert_eq!(
        second["authors"][0]["agent_id"],
        human.to_string(),
        "{second}"
    );
    assert_eq!(second["authors"][0]["action"], "attached_given", "{second}");
    assert_eq!(
        second["authors"][1]["agent_id"],
        key.to_string(),
        "{second}"
    );
    assert_eq!(
        second["authors"][1]["action"], "reused_name_key",
        "{second}"
    );
    assert_eq!(edges_now().await, before, "a re-run writes no edge");
}

/// An explicit id that IS another entry's name-derived node would make two
/// entries one agent with one `authored` edge: refused before the paper row.
#[sqlx::test(migrations = "../../migrations")]
async fn an_explicit_id_equal_to_another_entrys_name_derived_node_is_refused(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let name = "Brannoc Ilse";
    ingest_wait(
        &server,
        &pool,
        doc("10.9999/author-dup-seed", json!([{"name": name}])),
    )
    .await;
    let key = name_key_node(&pool, name).await.expect("name-key node");

    let viewer = fixture::public_viewer(&pool).await;
    let doi = "10.9999/author-dup";
    let err = tools::ingestion::ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction: doc(
                doi,
                json!([{"name": "Someone Else", "agent_id": key.to_string()}, {"name": name}]),
            ),
            wait: None,
        },
        None,
    )
    .await
    .expect_err("refused");
    assert!(
        err.message.contains("source.authors[0].agent_id"),
        "{}",
        err.message
    );
    assert!(err.message.contains("source.authors[1]"), "{}", err.message);
    assert_eq!(papers_with_doi(&pool, doi).await, 0, "no papers row");
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

/// `query_paper(doi)` as a public viewer on `server`.
async fn query_paper(server: &EpiGraphMcpFull, pool: &PgPool, doi: &str) -> Value {
    let viewer = fixture::public_viewer(pool).await;
    let r = tools::paper_queries::query_paper(
        server,
        &viewer,
        QueryPaperParams {
            doi: doi.to_string(),
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("query_paper");
    text(&r)
}

/// The paper's author listing (`query_paper`) honours what the ingest
/// records: a RETRACTED author (here the name-derived node the operator CLI
/// replaced) is not listed, an author an ingester named without speaking for
/// them is listed as PENDING with the ingester, and the list is in the
/// extraction's position order, not alphabetical.
#[sqlx::test(migrations = "../../migrations")]
async fn query_paper_lists_only_in_force_authors_in_position_order_and_marks_the_pending(
    pool: PgPool,
) {
    let server = privileged_server(&pool);
    let reader = app_role_server(&pool).await;
    let (_maintenance, viewer) = fixture::bypass(&pool).await;
    let (first, second) = ("Thaddeus Wimbrel", "Abelard Quint");
    let human = human_named(&pool, first).await;
    let doi = "10.9999/author-listing";
    let core = |extraction: DocumentExtraction| {
        let (server, viewer) = (&server, &viewer);
        async move {
            text(
                &tools::ingestion::do_ingest_document(server, viewer, &extraction, None)
                    .await
                    .expect("the core ingests"),
            )
        }
    };
    core(doc(doi, json!([{"name": first}, {"name": second}]))).await;
    let replaced = name_key_node(&pool, first).await.expect("name-key node");
    let kept = name_key_node(&pool, second).await.expect("name-key node");
    let json = core(doc(
        doi,
        json!([{"name": first, "agent_id": human.to_string()}, {"name": second}]),
    ))
    .await;
    assert_eq!(
        json["authors"][0]["replaced"]["agent_id"],
        replaced.to_string(),
        "{json}"
    );
    assert_eq!(
        (
            authored_edges(&pool, replaced, doi).await,
            authored_in_force(&pool, replaced, doi).await
        ),
        (1, 0),
        "CALIBRATION: the replaced author's edge survives, retracted"
    );
    let ingester = server.server_agent_id().await.expect("server agent");

    let listed = query_paper(&reader, &pool, doi).await;
    let authors = listed["authors"].as_array().expect("authors");
    let ids: Vec<&str> = authors
        .iter()
        .map(|a| a["agent_id"].as_str().expect("agent_id"))
        .collect();
    assert_eq!(
        ids,
        vec![human.to_string(), kept.to_string()],
        "in force only, in position order: {listed}"
    );
    assert_eq!(authors[0]["position"], 0, "{listed}");
    assert_eq!(authors[0]["pending_countersign"], true, "{listed}");
    assert_eq!(authors[0]["ingested_by"], ingester.to_string(), "{listed}");
    assert_eq!(authors[1]["position"], 1, "{listed}");
    assert_eq!(authors[1]["pending_countersign"], false, "{listed}");
    assert!(authors[1]["ingested_by"].is_null(), "{listed}");
}

/// `(paper doi, ingested_by, created_claim)` of every `ingested_claim`
/// record on `claim`, sorted.
async fn ingest_records(pool: &PgPool, claim: Uuid) -> Vec<(String, Uuid, bool)> {
    let mut rows: Vec<(String, Uuid, bool)> = sqlx::query_as(
        "SELECT p.doi, (r.properties ->> 'ingested_by')::uuid, \
                COALESCE((r.properties ->> 'created_claim')::boolean, false) \
           FROM edges r JOIN papers p ON p.id = r.source_id \
          WHERE r.target_id = $1 AND r.target_type = 'claim' AND r.source_type = 'paper' \
            AND r.relationship = 'ingested_claim'",
    )
    .bind(claim)
    .fetch_all(pool)
    .await
    .expect("ingest records");
    rows.sort();
    rows
}

/// The claim the paper keyed `doi` asserts whose content is `content`.
async fn claim_of(pool: &PgPool, doi: &str, content: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT c.id FROM claims c JOIN edges pc ON pc.target_id = c.id \
           JOIN papers p ON p.id = pc.source_id \
          WHERE p.doi = $1 AND pc.relationship = 'asserts' AND c.content = $2",
    )
    .bind(doi)
    .bind(content)
    .fetch_one(pool)
    .await
    .expect("the paper asserts the claim")
}

/// What decides a literature claim's primary authors is recorded when the
/// claim is CREATED, never inferred later: every document walk writes one
/// `paper -ingested_claim-> claim` record per (paper, claim, ingester), with
/// `created_claim: true` only on the ingest that created the claim. A second
/// document converging on the claim, the same document re-ingested by
/// another ingester, and a document repeating a claim someone filed directly
/// each add a `created_claim: false` record, and a re-run adds nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ingest_records_which_paper_created_each_claim_and_every_later_ingester(pool: PgPool) {
    let a = app_role_server(&pool).await;
    let b = app_role_server(&pool).await;
    let (a_id, b_id) = (
        a.server_agent_id().await.expect("a"),
        b.server_agent_id().await.expect("b"),
    );
    assert_ne!(a_id, b_id, "CALIBRATION: two ingesters");
    let viewer = fixture::public_viewer(&pool).await;
    let (d1, d2, d3) = (
        "10.9999/ingest-record-1",
        "10.9999/ingest-record-2",
        "10.9999/ingest-record-3",
    );
    let shared = "Shared atom of the ingest-record documents.";
    let author = json!([{"name": "Ingrid Solvang"}]);
    let doc1 = || doc_with_atoms(d1, author.clone(), &[shared, "Only in record one."]);

    ingest_wait(&a, &pool, doc1()).await;
    let x = claim_of(&pool, d1, shared).await;
    let only1 = claim_of(&pool, d1, "Only in record one.").await;
    for c in [x, only1] {
        assert_eq!(
            ingest_records(&pool, c).await,
            vec![(d1.to_string(), a_id, true)],
            "the creating ingest is recorded at creation"
        );
    }

    ingest_wait(
        &b,
        &pool,
        doc_with_atoms(d2, author.clone(), &[shared, "Only in record two."]),
    )
    .await;
    assert_eq!(
        ingest_records(&pool, x).await,
        vec![(d1.to_string(), a_id, true), (d2.to_string(), b_id, false)],
        "a converging document is recorded, never as the creator"
    );
    let only2 = claim_of(&pool, d2, "Only in record two.").await;
    assert_eq!(
        ingest_records(&pool, only2).await,
        vec![(d2.to_string(), b_id, true)]
    );

    // The same document, re-ingested by another ingester.
    tools::ingestion::do_ingest_document(&b, &viewer, &doc1(), None)
        .await
        .expect("b re-ingests the first document");
    assert_eq!(
        ingest_records(&pool, only1).await,
        vec![(d1.to_string(), a_id, true), (d1.to_string(), b_id, false)],
        "every later ingester of the same document is recorded"
    );
    // A re-run by the same ingester adds nothing.
    tools::ingestion::do_ingest_document(&a, &viewer, &doc1(), None)
        .await
        .expect("a re-runs");
    assert_eq!(
        ingest_records(&pool, x).await.len(),
        3,
        "no duplicate record"
    );

    // A claim someone filed DIRECTLY, later repeated by a document.
    let stated = "Directly stated before any document repeated it.";
    tools::claims::submit_claim(
        &a,
        &viewer,
        SubmitClaimParams {
            content: stated.into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.8,
            source_url: None,
            reasoning: None,
            labels: vec![],
            novelty_threshold: None,
        },
        None,
    )
    .await
    .expect("a files the claim directly");
    ingest_wait(&b, &pool, doc_with_atoms(d3, author.clone(), &[stated])).await;
    let direct = claim_of(&pool, d3, stated).await;
    let filer: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(direct)
        .fetch_one(&pool)
        .await
        .expect("filer");
    assert_eq!(
        filer, a_id,
        "CALIBRATION: the document converged on a's claim"
    );
    assert_eq!(
        ingest_records(&pool, direct).await,
        vec![(d3.to_string(), b_id, false)],
        "a document repeating a directly filed claim never becomes its creator"
    );
}
