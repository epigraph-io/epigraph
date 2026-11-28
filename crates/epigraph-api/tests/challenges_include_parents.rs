//! `include_parents` on `GET /api/v1/claims/:id/challenges` and MCP
//! `list_challenges` (backlog d8108186), on the APPLICATION ROLE.
//!
//! A challenge filed on a compound disputes its atoms too, but an atom's own
//! list never showed it. With `include_parents=true` both surfaces append
//! the OPEN challenges (`pending`, `under_review`) on the atom's in-force
//! `decomposes_to` parents, each tagged `via_parent`, through
//! `ChallengeRepository::list_open_for_parents`, which keeps every
//! visibility predicate (the challenge's, the edge's, the parent's and the
//! atom's) on the viewer-stamped read:
//!
//! - a viewer who can read a parent sees its open challenge, tagged;
//! - a viewer who cannot read a private parent gets nothing from it;
//! - a resolved challenge on a parent is not listed;
//! - with the flag absent (or `false`) the response is exactly the atom's own
//!   challenges, with no `via_parent` key anywhere;
//! - HTTP and MCP return the same set.
//!
//! Both the raw `db_pool` and the stamped `ScopedPool` are `epigraph_app`, as
//! in production, so row security is live under every assertion.
#![cfg(feature = "db")]

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

async fn app_role_scoped(pool: &PgPool) -> ScopedPool {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

async fn spawn_app(pool: &PgPool) -> (SocketAddr, oneshot::Sender<()>) {
    let scoped = app_role_scoped(pool).await;
    let raw = fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    let app = epigraph_api::routes::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (addr, tx)
}

async fn mcp_server(pool: &PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x6Du8; 32]).expect("signer");
    let raw = fixture::downgraded_pool(pool, "epigraph_app").await;
    let embedder = epigraph_mcp::embed::McpEmbedder::new(raw.clone(), None);
    epigraph_mcp::EpiGraphMcpFull::new(raw, signer, embedder, false)
        .with_scoped_pool(app_role_scoped(pool).await)
}

async fn seed_challenge(pool: &PgPool, claim: Uuid, agent: Uuid, explanation: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation) \
         VALUES ($1, $2, 'factual_error', $3) RETURNING id",
    )
    .bind(claim)
    .bind(agent)
    .bind(explanation)
    .fetch_one(pool)
    .await
    .expect("seed challenge")
}

/// `parent -decomposes_to-> child`, in force, its tenancy forced to
/// `(visibility, group)`.
async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid, visibility: &str, group: Uuid) {
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '1 day') RETURNING id",
    )
    .bind(parent)
    .bind(child)
    .fetch_one(pool)
    .await
    .expect("seed decomposes_to");
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

struct World {
    pool: PgPool,
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    owner: Uuid,
    stranger: Uuid,
    atom: Uuid,
    public_parent: Uuid,
    private_parent: Uuid,
    /// The atom's own challenge.
    own: Uuid,
    /// Open, on the public parent.
    on_public_parent: Uuid,
    /// Open, on the group-private parent.
    on_private_parent: Uuid,
    /// A group-private parent joined to the atom by a PUBLIC edge, carrying
    /// an outsider's PUBLIC challenge (migration 168: an outsider's row never
    /// follows the claim). Only the parent's own predicate withholds it.
    hidden_parent: Uuid,
    on_hidden_parent: Uuid,
    /// A group-private atom under the public parent, joined by a PUBLIC edge.
    private_atom: Uuid,
}

async fn world(pool: PgPool) -> World {
    let (owner, owner_group) = fixture::seed_agent_with_group(&pool, "d8108186-owner").await;
    let (stranger, stranger_group) =
        fixture::seed_agent_with_group(&pool, "d8108186-stranger").await;
    let atom = fixture::seed_public_claim(&pool, owner, "d8108186 atom").await;
    let public_parent = fixture::seed_public_claim(&pool, owner, "d8108186 public parent").await;
    let private_parent =
        fixture::seed_group_claim(&pool, owner, owner_group, "d8108186 private parent").await;
    let world_group: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(public_parent)
        .fetch_one(&pool)
        .await
        .expect("public parent's group");
    decomposes_to(&pool, public_parent, atom, "public", world_group).await;
    decomposes_to(&pool, private_parent, atom, "group", owner_group).await;

    let own = seed_challenge(&pool, atom, owner, "the atom's own dispute").await;
    let on_public_parent = seed_challenge(&pool, public_parent, owner, "public parent open").await;
    let on_private_parent =
        seed_challenge(&pool, private_parent, owner, "private parent open").await;
    // A resolved challenge on the public parent: not open, never appended.
    let resolved = seed_challenge(&pool, public_parent, owner, "public parent resolved").await;
    sqlx::query("UPDATE challenges SET state = 'rejected', resolved_at = now() WHERE id = $1")
        .bind(resolved)
        .execute(&pool)
        .await
        .expect("resolve one parent challenge");
    // A retracted decomposition: its parent's open challenge is not appended.
    let former_parent = fixture::seed_public_claim(&pool, owner, "d8108186 former parent").await;
    decomposes_to(&pool, former_parent, atom, "public", world_group).await;
    sqlx::query(
        "UPDATE edges SET valid_to = now() - interval '1 hour' \
          WHERE source_id = $1 AND target_id = $2",
    )
    .bind(former_parent)
    .bind(atom)
    .execute(&pool)
    .await
    .expect("retract the former decomposition");
    seed_challenge(&pool, former_parent, owner, "former parent open").await;

    let hidden_parent =
        fixture::seed_group_claim(&pool, owner, owner_group, "d8108186 hidden parent").await;
    decomposes_to(&pool, hidden_parent, atom, "public", world_group).await;
    let on_hidden_parent = seed_challenge(&pool, hidden_parent, stranger, "hidden open").await;
    sqlx::query(
        "UPDATE challenges SET visibility = 'public', owner_group_id = $2, writer_owned = true \
          WHERE id = $1",
    )
    .bind(on_hidden_parent)
    .bind(stranger_group)
    .execute(&pool)
    .await
    .expect("make the hidden parent's challenge an outsider's public row");

    let private_atom =
        fixture::seed_group_claim(&pool, owner, owner_group, "d8108186 private atom").await;
    decomposes_to(&pool, public_parent, private_atom, "public", world_group).await;

    let (addr, shutdown) = spawn_app(&pool).await;
    World {
        pool,
        addr,
        _shutdown: shutdown,
        owner,
        stranger,
        atom,
        public_parent,
        private_parent,
        own,
        on_public_parent,
        on_private_parent,
        hidden_parent,
        on_hidden_parent,
        private_atom,
    }
}

/// `GET .../challenges{query}` as `agent`: the raw body text.
async fn http_list(w: &World, agent: Uuid, query: &str) -> String {
    let token = common::mint_token_with_agent(&["claims:read"], agent);
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{}/api/v1/claims/{}/challenges{query}",
            w.addr, w.atom
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 200);
    resp.text().await.expect("body")
}

async fn mcp_list(w: &World, agent: Uuid, include_parents: Option<bool>) -> Value {
    let server = mcp_server(&w.pool).await;
    let viewer = Viewer::resolve(&w.pool, agent).await.expect("viewer");
    let result = epigraph_mcp::tools::challenges::list_challenges(
        &server,
        &viewer,
        epigraph_mcp::types::ListChallengesParams {
            claim_id: w.atom.to_string(),
            include_parents,
        },
    )
    .await
    .expect("MCP list_challenges");
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("a text block");
    serde_json::from_str(&text).expect("JSON")
}

/// `(id, via_parent)` of every listed challenge.
fn listed(body: &Value) -> BTreeSet<(Uuid, Option<Uuid>)> {
    body["challenges"]
        .as_array()
        .expect("challenges")
        .iter()
        .map(|c| {
            (
                c["id"].as_str().unwrap().parse().unwrap(),
                c.get("via_parent")
                    .map(|p| p.as_str().unwrap().parse().unwrap()),
            )
        })
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_of_the_parent_sees_its_open_challenge_tagged_on_the_atom(pool: PgPool) {
    let w = world(pool).await;
    let body: Value =
        serde_json::from_str(&http_list(&w, w.owner, "?include_parents=true").await).unwrap();
    assert_eq!(
        listed(&body),
        BTreeSet::from([
            (w.own, None),
            (w.on_public_parent, Some(w.public_parent)),
            (w.on_private_parent, Some(w.private_parent)),
            (w.on_hidden_parent, Some(w.hidden_parent)),
        ]),
        "the owner reads every parent: their open challenges, tagged, and no resolved one \
         or one reached over a retracted edge: {body}"
    );
    assert_eq!(body["total"], 4, "{body}");
    // The atom's own challenge comes first, untagged.
    assert_eq!(body["challenges"][0]["id"], w.own.to_string(), "{body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_viewer_who_cannot_read_a_private_parent_gets_none_of_its_challenges(pool: PgPool) {
    let w = world(pool).await;
    let body: Value =
        serde_json::from_str(&http_list(&w, w.stranger, "?include_parents=true").await).unwrap();
    assert_eq!(
        listed(&body),
        BTreeSet::from([(w.own, None), (w.on_public_parent, Some(w.public_parent))]),
        "the stranger cannot read the private parents: {body}"
    );
    for hidden in [w.private_parent, w.hidden_parent] {
        assert!(
            !body.to_string().contains(&hidden.to_string()),
            "a private parent's id must not leak: {body}"
        );
    }
}

/// The repository's own predicates, on a PRIVILEGED connection (the harness
/// superuser, which row security does not filter) with the stranger's
/// non-bypass viewer: only the spliced predicates stand between the caller
/// and a row. The hidden parent's challenge is public and reached over a
/// public edge, so only the parent's predicate withholds it; the private
/// atom is reached from a public parent, so only the atom's predicate does.
#[sqlx::test(migrations = "../../migrations")]
async fn the_spliced_predicates_alone_withhold_an_unreadable_parent_or_atom(pool: PgPool) {
    let w = world(pool).await;
    let stranger = Viewer::resolve(&w.pool, w.stranger).await.expect("viewer");
    assert!(stranger.group_bind().is_some(), "a non-bypass viewer");

    let ids = |rows: Vec<(epigraph_db::ChallengeRow, Uuid)>| {
        rows.into_iter()
            .map(|(r, parent)| (r.id, parent))
            .collect::<BTreeSet<_>>()
    };
    let on_atom =
        epigraph_db::ChallengeRepository::list_open_for_parents(&w.pool, &stranger, w.atom)
            .await
            .expect("list");
    assert_eq!(
        ids(on_atom),
        BTreeSet::from([(w.on_public_parent, w.public_parent)]),
        "neither private parent's challenge, on a connection row security does not filter"
    );
    let on_private_atom =
        epigraph_db::ChallengeRepository::list_open_for_parents(&w.pool, &stranger, w.private_atom)
            .await
            .expect("list");
    assert!(
        on_private_atom.is_empty(),
        "an atom the viewer cannot read lists nothing: {on_private_atom:?}"
    );

    // Control: the owner, on the same connection, sees all three.
    let owner = Viewer::resolve(&w.pool, w.owner).await.expect("viewer");
    assert_eq!(
        ids(
            epigraph_db::ChallengeRepository::list_open_for_parents(&w.pool, &owner, w.atom)
                .await
                .expect("list")
        ),
        BTreeSet::from([
            (w.on_public_parent, w.public_parent),
            (w.on_private_parent, w.private_parent),
            (w.on_hidden_parent, w.hidden_parent),
        ])
    );
    assert_eq!(
        epigraph_db::ChallengeRepository::list_open_for_parents(&w.pool, &owner, w.private_atom)
            .await
            .expect("list")
            .len(),
        1,
        "the owner reads the private atom and its public parent's open challenge"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn without_the_flag_the_response_is_the_atoms_own_challenges(pool: PgPool) {
    let w = world(pool).await;
    for agent in [w.owner, w.stranger] {
        let absent = http_list(&w, agent, "").await;
        let off = http_list(&w, agent, "?include_parents=false").await;
        assert_eq!(absent, off, "absent and false answer the same bytes");
        assert!(!absent.contains("via_parent"), "{absent}");
        let body: Value = serde_json::from_str(&absent).unwrap();
        assert_eq!(listed(&body), BTreeSet::from([(w.own, None)]), "{absent}");

        let mcp = mcp_list(&w, agent, None).await;
        assert_eq!(mcp, mcp_list(&w, agent, Some(false)).await);
        assert!(!mcp.to_string().contains("via_parent"), "{mcp}");
        assert_eq!(listed(&mcp), BTreeSet::from([(w.own, None)]), "{mcp}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn http_and_mcp_return_the_same_set(pool: PgPool) {
    let w = world(pool).await;
    for agent in [w.owner, w.stranger] {
        let http: Value =
            serde_json::from_str(&http_list(&w, agent, "?include_parents=true").await).unwrap();
        let mcp = mcp_list(&w, agent, Some(true)).await;
        assert_eq!(listed(&http), listed(&mcp), "HTTP {http}\nMCP {mcp}");
        assert_eq!(http["total"], mcp["total"]);
    }
}
