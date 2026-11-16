//! MCP `screen_claim_atomicity` and `query_compound_claims` (backlogs
//! `72850d43`, `c4a8436b`), on the `epigraph_app` role so row security
//! decides as in production.
//!
//! The world: a public paragraph `P` decomposed into a compound atom `A1`
//! ("..., but ...") and an atomic `A2`; a compound standalone `S` with no
//! edges; a compound atom `A3` of `P` whose only child `C` is public but is
//! reached through a `decomposes_to` edge private to the member's group; and
//! a group-private compound claim `PR`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::atomicity::{query_compound_claims, screen_claim_atomicity};
use epigraph_mcp::types::{QueryCompoundClaimsParams, ScreenClaimAtomicityParams};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

const COMPOUND_ATOM: &str = "The catalyst raised the yield, but it shortened the column life.";
const ATOMIC_ATOM: &str = "The catalyst raised the yield.";
const STANDALONE: &str = "The pump failed; the backup pump took over within seconds.";
const HIDDEN_PARENT_ATOM: &str = "The rotor cracked, and the housing held.";
const PARAGRAPH: &str = "The catalyst raised the yield. It shortened the column life. \
                         The rotor cracked, and the housing held.";
const PRIVATE: &str = "The private run drifted, whereas the control run held steady.";

struct World {
    member: Uuid,
    stranger: Uuid,
    paragraph: Uuid,
    compound_atom: Uuid,
    atomic_atom: Uuid,
    standalone: Uuid,
    hidden_child_atom: Uuid,
    private: Uuid,
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
         properties) VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
         '{}'::jsonb) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .fetch_one(pool)
    .await
    .expect("insert decomposes_to edge")
}

async fn seed(pool: &PgPool) -> World {
    let (member, group) = fixture::seed_agent_with_group(pool, "b42screen").await;
    let (stranger, _) = fixture::seed_agent_with_group(pool, "b42screen-stranger").await;
    let paragraph = fixture::seed_public_claim(pool, member, PARAGRAPH).await;
    let compound_atom = fixture::seed_public_claim(pool, member, COMPOUND_ATOM).await;
    let atomic_atom = fixture::seed_public_claim(pool, member, ATOMIC_ATOM).await;
    let hidden_child_atom = fixture::seed_public_claim(pool, member, HIDDEN_PARENT_ATOM).await;
    let child = fixture::seed_public_claim(pool, member, "The rotor cracked.").await;
    let standalone = fixture::seed_public_claim(pool, member, STANDALONE).await;
    let private = fixture::seed_group_claim(pool, member, group, PRIVATE).await;
    edge(pool, paragraph, compound_atom).await;
    edge(pool, paragraph, atomic_atom).await;
    edge(pool, paragraph, hidden_child_atom).await;
    // Both endpoints public, the EDGE private: only the edge predicate can
    // hide it from the stranger.
    let hidden = edge(pool, hidden_child_atom, child).await;
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(hidden)
    .bind(group)
    .execute(pool)
    .await
    .expect("privatise the child edge");
    // Seeding order is the walk order: pin created_at so two inserts in one
    // microsecond cannot fall back to the random id tiebreak.
    for (i, id) in [
        paragraph,
        compound_atom,
        atomic_atom,
        hidden_child_atom,
        child,
        standalone,
        private,
    ]
    .iter()
    .enumerate()
    {
        sqlx::query(
            "UPDATE claims SET created_at = '2026-01-01T00:00:00Z'::timestamptz \
             + make_interval(mins => $2) WHERE id = $1",
        )
        .bind(id)
        .bind(i as i32)
        .execute(pool)
        .await
        .expect("pin created_at");
    }
    World {
        member,
        stranger,
        paragraph,
        compound_atom,
        atomic_atom,
        standalone,
        hidden_child_atom,
        private,
    }
}

async fn screen(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    caller: Uuid,
    ids: &[Uuid],
) -> Result<Value, epigraph_mcp::errors::McpError> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    screen_claim_atomicity(
        server,
        &viewer,
        ScreenClaimAtomicityParams {
            claim_ids: ids.iter().map(Uuid::to_string).collect(),
        },
    )
    .await
    .map(|r| first_text(&r))
}

fn params(population: Option<&str>, leaves_only: Option<bool>) -> QueryCompoundClaimsParams {
    QueryCompoundClaimsParams {
        population: population.map(str::to_string),
        leaves_only,
        min_conjuncts: None,
        limit: None,
        max_scan: None,
        after: None,
    }
}

async fn compound(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    caller: Uuid,
    p: QueryCompoundClaimsParams,
) -> Result<Value, epigraph_mcp::errors::McpError> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve");
    query_compound_claims(server, &viewer, p)
        .await
        .map(|r| first_text(&r))
}

fn ids_of(doc: &Value) -> Vec<Uuid> {
    doc["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .map(|c| c["claim_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

fn row(doc: &Value, id: Uuid) -> &Value {
    doc["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .find(|c| c["claim_id"] == id.to_string())
        .unwrap_or_else(|| panic!("{id} not in {doc}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn screen_reports_the_count_and_the_decomposition_shape(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed(&pool).await;
    let doc = screen(
        &server,
        &pool,
        w.stranger,
        &[w.compound_atom, w.atomic_atom, w.paragraph, w.compound_atom],
    )
    .await
    .unwrap();
    assert_eq!(
        ids_of(&doc),
        vec![w.compound_atom, w.atomic_atom, w.paragraph],
        "request order, a repeated id once"
    );
    let a1 = row(&doc, w.compound_atom);
    assert_eq!(a1["sentences"], 1);
    assert_eq!(a1["clause_joins"], 1);
    assert_eq!(a1["conjunct_count"], 2);
    assert_eq!(a1["is_compound"], true, "{a1}");
    assert_eq!(a1["decomposes_to_parents"], 1);
    assert_eq!(a1["decomposes_to_children"], 0);
    assert_eq!(a1["labelled_compound_atom"], false);
    let a2 = row(&doc, w.atomic_atom);
    assert_eq!(a2["conjunct_count"], 1);
    assert_eq!(a2["is_compound"], false, "{a2}");
    let p = row(&doc, w.paragraph);
    assert_eq!(p["decomposes_to_children"], 3);
    assert_eq!(p["decomposes_to_parents"], 0);
    assert_eq!(doc["not_found"], serde_json::json!([]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn screen_hides_what_the_caller_cannot_read(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed(&pool).await;
    let absent = Uuid::new_v4();

    // The private claim is screened for its group's member...
    let member = screen(&server, &pool, w.member, &[w.private])
        .await
        .unwrap();
    assert_eq!(ids_of(&member), vec![w.private]);
    assert_eq!(row(&member, w.private)["is_compound"], true);
    // ...and is `not_found` for the stranger, exactly like an id naming nothing.
    let stranger = screen(&server, &pool, w.stranger, &[w.private, absent])
        .await
        .unwrap();
    assert_eq!(ids_of(&stranger), Vec::<Uuid>::new());
    assert_eq!(
        stranger["not_found"],
        serde_json::json!([w.private.to_string(), absent.to_string()])
    );

    // A child reached only through a hidden edge is in no count.
    let s = screen(&server, &pool, w.stranger, &[w.hidden_child_atom])
        .await
        .unwrap();
    assert_eq!(row(&s, w.hidden_child_atom)["decomposes_to_children"], 0);
    let m = screen(&server, &pool, w.member, &[w.hidden_child_atom])
        .await
        .unwrap();
    assert_eq!(
        row(&m, w.hidden_child_atom)["decomposes_to_children"],
        1,
        "calibration: the member sees the edge"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn screen_refuses_an_empty_or_oversized_id_list(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed(&pool).await;
    assert!(screen(&server, &pool, w.member, &[]).await.is_err());
    let many: Vec<Uuid> = (0..201).map(|_| Uuid::new_v4()).collect();
    assert!(screen(&server, &pool, w.member, &many).await.is_err());
    let two_hundred: Vec<Uuid> = (0..200).map(|_| Uuid::new_v4()).collect();
    let ok = screen(&server, &pool, w.member, &two_hundred)
        .await
        .unwrap();
    assert_eq!(ok["not_found"].as_array().unwrap().len(), 200);
}

#[sqlx::test(migrations = "../../migrations")]
async fn discovery_finds_compound_atoms_regardless_of_decomposes_to(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed(&pool).await;

    // Default: atoms, leaves only. The compound atom is found although it is
    // the target of a decomposes_to edge (query_undecomposed_claims excludes
    // it); the atomic atom is not compound; the standalone and the paragraph
    // are not atoms.
    let doc = compound(&server, &pool, w.stranger, params(None, None))
        .await
        .unwrap();
    assert_eq!(
        ids_of(&doc),
        vec![w.compound_atom, w.hidden_child_atom],
        "{doc}"
    );
    assert_eq!(doc["exhausted"], true);
    assert_eq!(doc["next_cursor"], Value::Null);
    assert_eq!(
        doc["scanned"], 3,
        "P's three atoms; the rotor child's only parent edge is hidden, so it is no atom here"
    );

    // The member sees the private child edge, so that atom is no longer a
    // leaf for it.
    let member = compound(&server, &pool, w.member, params(None, None))
        .await
        .unwrap();
    assert_eq!(ids_of(&member), vec![w.compound_atom], "{member}");
    let with_children = compound(&server, &pool, w.member, params(None, Some(false)))
        .await
        .unwrap();
    assert_eq!(
        ids_of(&with_children),
        vec![w.compound_atom, w.hidden_child_atom]
    );

    // population all: the paragraph (it has children, so only with
    // leaves_only=false), the standalone, and the member's private claim.
    let all = compound(&server, &pool, w.member, params(Some("all"), Some(false)))
        .await
        .unwrap();
    assert_eq!(
        ids_of(&all),
        vec![
            w.paragraph,
            w.compound_atom,
            w.hidden_child_atom,
            w.standalone,
            w.private
        ],
        "{all}"
    );
    let stranger_all = compound(&server, &pool, w.stranger, params(Some("all"), None))
        .await
        .unwrap();
    assert_eq!(
        ids_of(&stranger_all),
        vec![w.compound_atom, w.hidden_child_atom, w.standalone],
        "no private claim, and the paragraph has children"
    );

    assert!(
        compound(&server, &pool, w.member, params(Some("bogus"), None))
            .await
            .is_err()
    );
    let mut low = params(None, None);
    low.min_conjuncts = Some(1);
    assert!(compound(&server, &pool, w.member, low).await.is_err());
    let mut bad = params(None, None);
    bad.after = Some("garbage".into());
    assert!(compound(&server, &pool, w.member, bad).await.is_err());
}

#[sqlx::test(migrations = "../../migrations")]
async fn discovery_pages_by_cursor_without_skipping_or_repeating(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let w = seed(&pool).await;
    let whole = compound(&server, &pool, w.member, params(Some("all"), Some(false)))
        .await
        .unwrap();
    let want = ids_of(&whole);
    assert_eq!(want.len(), 5);

    // limit 1: one hit per call, each call resuming after the previous hit.
    let mut got = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..10 {
        let mut p = params(Some("all"), Some(false));
        p.limit = Some(1);
        p.after = after.clone();
        let doc = compound(&server, &pool, w.member, p).await.unwrap();
        got.extend(ids_of(&doc));
        match doc["next_cursor"].as_str() {
            Some(c) => after = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(got, want, "a limit-1 walk returns every hit once, in order");

    // max_scan bounds the reads: one row read, cursor handed back.
    let mut p = params(Some("all"), Some(false));
    p.max_scan = Some(1);
    let doc = compound(&server, &pool, w.member, p).await.unwrap();
    assert_eq!(doc["scanned"], 1);
    assert_eq!(doc["exhausted"], false);
    assert!(doc["next_cursor"].is_string());
}
