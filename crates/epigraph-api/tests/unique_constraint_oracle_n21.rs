#![cfg(feature = "db")]
//! Acceptance item 21 (`docs/tenancy/FINAL-PLAN.md` §8, §8.5): the
//! unique-constraint / dedup-probe existence oracle, over HTTP.
//!
//! # The rule these tests hold the write paths to
//!
//! §8.5: *any operation on a resource the `Viewer` cannot read returns
//! byte-identical status and body to a nonexistent resource.* Item 21 is the
//! write-side residual of that rule: a unique constraint or a dedup probe
//! answers "this row already exists" whether or not the caller may read the
//! row, so an insert that collides with an invisible row can leak the row's
//! existence (or, for a dedup probe that RETURNS the row, the row itself).
//!
//! # What the plan named, and what is actually on the tree
//!
//! The plan named `idx_edges_unique_triple`. Migrations 017/018 dropped it (and
//! 053 its drifted copy), so there is no edge triple constraint to collide
//! with. What replaced it is WORSE than an oracle: `EdgeRepository`'s
//! `create_if_not_exists` dedup probe, which returned the matching row's id,
//! properties and validity window whoever was asking. The surfaces are
//! therefore:
//!
//! * **edges** — the `if_not_exists` dedup probe behind `POST /api/v1/edges`
//!   and `POST /api/v1/edges/hierarchical`. Fixed to the FULL §8.5 rule: an
//!   invisible match is treated exactly as an absent one (the probe is
//!   Viewer-scoped, and with no triple constraint left the insert succeeds).
//!   The partial symmetric indexes (042/091 `alternative_of`, 090 matcher
//!   `CORROBORATES`/`contradicts`) are the edge-side residual, recorded on the
//!   same obligation as the claims one below.
//! * **claims** — `uq_claims_content_hash_agent UNIQUE (content_hash,
//!   agent_id)` (migration 013), reachable by a stranger because the body's
//!   `agent_id` is not a credential (`D-PR16-claim-authorship-is-not-a-credential`).
//!   Fixed to the WEAKER form item 21 states: a collision with an invisible row
//!   answers with exactly the generic conflict a collision with a visible row
//!   answers with, and never a distinctive error. It still differs from the
//!   ABSENT case (409 vs 201). Closing that needs the constraint keyed on
//!   `owner_group_id`, which is a migration and is recorded as
//!   `D-N21-unique-keys-omit-owner-group` in `docs/tenancy/progress.json`.
//!   Nothing here asserts the residual, so the day that migration lands these
//!   tests stay green and the register entry is what has to move.
//!
//! # Why every claims test first proves the constraint is there
//!
//! Test fixtures in `epigraph-db/tests/claim_repo_helpers.rs` and
//! `epigraph-mcp/tests/common/mod.rs` DROP `uq_claims_content_hash_agent`, and
//! the long-lived production database has lost it to exactly that (see
//! `migrations/README.md`). On a schema without it there is no collision, the
//! stranger's write simply lands, and every "invisible answers like visible"
//! assertion below would pass for the wrong reason. `#[sqlx::test]` builds a
//! fresh database from `migrations/`, so it is present — and asserted.

use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, EdgeRepository};
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

/// Fail loudly if the schema under test has no `(content_hash, agent_id)`
/// constraint: without it the claims arms below are vacuous.
async fn assert_content_hash_constraint_present(pool: &PgPool) {
    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint \
         WHERE conname = 'uq_claims_content_hash_agent' AND conrelid = 'claims'::regclass",
    )
    .fetch_one(pool)
    .await
    .expect("inspect pg_constraint");
    assert_eq!(
        present, 1,
        "uq_claims_content_hash_agent is absent from `claims`. Without it a \
         stranger's write never collides and every assertion in this file \
         passes vacuously; this database has drifted (migrations/README.md)."
    );
}

/// A claim whose `content_hash` is the REAL BLAKE3 of its content.
///
/// `fixture::seed_*_claim` writes a stand-in hash, which is fine for reads and
/// useless here: the collision under test is on `content_hash`, and the write
/// path computes it with `ContentHasher`. A stand-in would never collide.
async fn seed_claim_hashed(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    visibility: &str,
    owner_group_id: Uuid,
) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, 0.5, $3, true, $4, $5) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(visibility)
    .bind(owner_group_id)
    .fetch_one(pool)
    .await
    .expect("seed hashed claim")
}

async fn post_json(
    addr: std::net::SocketAddr,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {path}: {e}"));
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("response body");
    (status, text)
}

async fn visible_to(pool: &PgPool, viewer: &Viewer, claim: Uuid) -> bool {
    ClaimRepository::get_by_id(pool, viewer, ClaimId::from_uuid(claim))
        .await
        .expect("get_by_id")
        .is_some()
}

// ─────────────────────────────────────────────────────────────────────────
// claims — uq_claims_content_hash_agent
// ─────────────────────────────────────────────────────────────────────────

/// A stranger who aims `POST /api/v1/claims` at a victim's `(content, agent_id)`
/// gets, for a row it cannot read, EXACTLY the answer it gets for a row it can:
/// the same status and the same bytes, on both `if_not_exists` settings.
///
/// Before this change the `if_not_exists = true` arm answered an invisible
/// collision with a distinctive error (the re-find after the `23505` found
/// nothing), which is a three-way oracle: 200 visible / 201 absent / that error
/// invisible.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_collision_on_an_invisible_row_answers_exactly_like_a_visible_one(pool: PgPool) {
    assert_content_hash_constraint_present(&pool).await;

    let (victim, victim_group) = fixture::seed_agent_with_group(&pool, "n21-victim").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "n21-stranger").await;

    let private_content = format!("n21 private claim {}", Uuid::new_v4());
    let public_content = format!("n21 public claim {}", Uuid::new_v4());
    let private = seed_claim_hashed(&pool, victim, &private_content, "group", victim_group).await;
    let public = seed_claim_hashed(&pool, victim, &public_content, "public", victim_group).await;

    // PREMISE, both directions: the stranger reads the public row and not the
    // private one, and the victim reads both. Without it "identical" below
    // could mean "both visible" or "both invisible".
    let stranger_viewer = Viewer::resolve(&pool, stranger).await.expect("resolve");
    let victim_viewer = Viewer::resolve(&pool, victim).await.expect("resolve");
    assert!(visible_to(&pool, &stranger_viewer, public).await);
    assert!(!visible_to(&pool, &stranger_viewer, private).await);
    assert!(visible_to(&pool, &victim_viewer, private).await);

    let url = fixture::database_url_for(&pool).await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    let (stranger_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], stranger)
            .await;
    let (victim_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], victim)
            .await;

    let body = |content: &str, if_not_exists: bool| {
        serde_json::json!({
            "content": content,
            "agent_id": victim,
            "if_not_exists": if_not_exists,
        })
    };

    // The reference answer: a collision with a row the stranger CAN read.
    let (visible_status, visible_body) = post_json(
        addr,
        "/api/v1/claims",
        &stranger_token,
        &body(&public_content, false),
    )
    .await;
    assert_eq!(
        visible_status, 409,
        "calibration: a collision with a readable row is a 409; got {visible_status}: \
         {visible_body}"
    );

    for if_not_exists in [false, true] {
        let (status, text) = post_json(
            addr,
            "/api/v1/claims",
            &stranger_token,
            &body(&private_content, if_not_exists),
        )
        .await;
        assert_eq!(
            (status, text.as_str()),
            (visible_status, visible_body.as_str()),
            "if_not_exists={if_not_exists}: a collision with a row the caller \
             CANNOT read must answer byte-for-byte as a collision with one it \
             can. Any difference tells a stranger that the victim holds a \
             private claim with exactly this text."
        );
        for secret in [
            private.to_string(),
            private_content.clone(),
            victim_group.to_string(),
        ] {
            assert!(
                !text.contains(&secret),
                "if_not_exists={if_not_exists}: the refusal names the invisible \
                 row ({secret}): {text}"
            );
        }
    }

    // Nothing the stranger sent was written, on either arm.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE content = $1")
        .bind(&private_content)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 1, "the stranger's colliding writes must not land");

    // CLASS P: the idempotent path still RETURNS the row to a caller who can
    // read it. A fix that answered every collision with the conflict would pass
    // everything above and break `if_not_exists` for its owner.
    let (owner_status, owner_body) = post_json(
        addr,
        "/api/v1/claims",
        &victim_token,
        &body(&private_content, true),
    )
    .await;
    assert_eq!(
        owner_status, 200,
        "the owner's if_not_exists re-assertion must return its own row; got \
         {owner_status}: {owner_body}"
    );
    let owner_json: serde_json::Value = serde_json::from_str(&owner_body).expect("json");
    assert_eq!(
        owner_json["id"].as_str(),
        Some(private.to_string().as_str())
    );

    let _ = shutdown.send(());
}

// ─────────────────────────────────────────────────────────────────────────
// edges — the if_not_exists dedup probe
// ─────────────────────────────────────────────────────────────────────────

/// Two public claims joined by a `relationship` edge that is private to
/// `group`, carrying a marker property. Returns `(source, target, edge)`.
///
/// Public endpoints are the point: the stranger can see and name both, so the
/// only thing standing between it and the edge is the edge's own tenancy —
/// which is the case the dedup probe ignored. `seed_edge_owned_by` forces the
/// stamp because migration 070's trigger would otherwise derive a PUBLIC edge
/// from two public endpoints.
async fn public_pair_with_private_edge(
    pool: &PgPool,
    author: Uuid,
    group: Uuid,
    relationship: &str,
    marker: &str,
) -> (Uuid, Uuid, Uuid) {
    let source = fixture::seed_public_claim(pool, author, &format!("n21 src {marker}")).await;
    let target = fixture::seed_public_claim(pool, author, &format!("n21 tgt {marker}")).await;
    let edge = fixture::seed_edge_owned_by(pool, source, target, "group", group).await;
    sqlx::query("UPDATE edges SET relationship = $2, properties = $3 WHERE id = $1")
        .bind(edge)
        .bind(relationship)
        .bind(serde_json::json!({ "n21_marker": marker }))
        .execute(pool)
        .await
        .expect("shape the private edge");
    (source, target, edge)
}

/// Replace every id the response legitimately differs by with a placeholder,
/// so two responses can be compared for everything else.
fn normalise(body: &str, ids: &[Uuid]) -> String {
    let mut out = body.to_string();
    for (i, id) in ids.iter().enumerate() {
        out = out.replace(&id.to_string(), &format!("<id{i}>"));
    }
    out
}

/// `POST /api/v1/edges {if_not_exists: true}` over an edge the caller cannot
/// read must not hand that edge back — not its id, not its properties — and
/// must answer exactly as it does when no such edge exists.
#[sqlx::test(migrations = "../../migrations")]
async fn edge_dedup_treats_an_invisible_edge_as_absent(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "n21-edge-owner").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "n21-edge-stranger").await;

    let marker = format!("hidden-{}", Uuid::new_v4());
    let (source, target, hidden) =
        public_pair_with_private_edge(&pool, owner, group, "supports", &marker).await;
    let absent_source = fixture::seed_public_claim(&pool, owner, "n21 absent src").await;
    let absent_target = fixture::seed_public_claim(&pool, owner, "n21 absent tgt").await;

    // PREMISE: the edge is invisible to the stranger and visible to the owner.
    let stranger_viewer = Viewer::resolve(&pool, stranger).await.expect("resolve");
    let owner_viewer = Viewer::resolve(&pool, owner).await.expect("resolve");
    let seen = |rows: Vec<epigraph_db::EdgeRow>| rows.iter().any(|r| r.id == hidden);
    assert!(!seen(
        EdgeRepository::get_by_source(&pool, &stranger_viewer, source, "claim")
            .await
            .expect("get_by_source")
    ));
    assert!(seen(
        EdgeRepository::get_by_source(&pool, &owner_viewer, source, "claim")
            .await
            .expect("get_by_source")
    ));

    let url = fixture::database_url_for(&pool).await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    let (stranger_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["edges:write"], stranger)
            .await;
    let (owner_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["edges:write"], owner)
            .await;

    let body = |s: Uuid, t: Uuid| {
        serde_json::json!({
            "source_id": s, "target_id": t,
            "source_type": "claim", "target_type": "claim",
            "relationship": "supports",
            "if_not_exists": true,
        })
    };

    // CLASS P first — before the stranger writes a second row over the same
    // triple and makes the probe's LIMIT 1 ambiguous. A reader still gets the
    // existing edge back: the probe was narrowed, not disabled.
    let (owner_status, owner_body) =
        post_json(addr, "/api/v1/edges", &owner_token, &body(source, target)).await;
    assert_eq!(owner_status, 200, "owner dedup hit: {owner_body}");
    assert!(
        owner_body.contains(&hidden.to_string()),
        "a caller who can read the edge must get it back from the dedup probe: {owner_body}"
    );

    let (hit_status, hit_body) = post_json(
        addr,
        "/api/v1/edges",
        &stranger_token,
        &body(source, target),
    )
    .await;
    let (absent_status, absent_body) = post_json(
        addr,
        "/api/v1/edges",
        &stranger_token,
        &body(absent_source, absent_target),
    )
    .await;

    assert!(
        !hit_body.contains(&hidden.to_string()) && !hit_body.contains(&marker),
        "the dedup probe handed a stranger an edge it cannot read (id {hidden} / \
         marker {marker}): {hit_body}"
    );
    let hit_json: serde_json::Value = serde_json::from_str(&hit_body).expect("json");
    let absent_json: serde_json::Value = serde_json::from_str(&absent_body).expect("json");
    let id_of =
        |v: &serde_json::Value| -> Uuid { v["id"].as_str().expect("id").parse().expect("uuid") };
    assert_eq!(
        (
            hit_status,
            normalise(&hit_body, &[id_of(&hit_json), source, target])
        ),
        (
            absent_status,
            normalise(
                &absent_body,
                &[id_of(&absent_json), absent_source, absent_target]
            )
        ),
        "an invisible matching edge must be indistinguishable from no edge at all \
         (§8.5), once the ids that legitimately differ are normalised out"
    );
    assert_eq!(
        hit_status, 201,
        "the stranger's own edge is created: {hit_body}"
    );

    let _ = shutdown.send(());
}

/// `POST /api/v1/edges/hierarchical` is idempotent on the same probe and had
/// the same leak: `{edge_id: <invisible>, created: false}`.
#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_edge_dedup_treats_an_invisible_edge_as_absent(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "n21-hier-owner").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "n21-hier-stranger").await;

    let marker = format!("hidden-{}", Uuid::new_v4());
    let (source, target, hidden) =
        public_pair_with_private_edge(&pool, owner, group, "decomposes_to", &marker).await;
    let absent_source = fixture::seed_public_claim(&pool, owner, "n21 hier absent src").await;
    let absent_target = fixture::seed_public_claim(&pool, owner, "n21 hier absent tgt").await;

    let url = fixture::database_url_for(&pool).await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    let (stranger_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["edges:write"], stranger)
            .await;
    let (owner_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["edges:write"], owner)
            .await;

    let body = |s: Uuid, t: Uuid| {
        serde_json::json!({
            "source_claim_id": s, "target_claim_id": t,
            "relationship": "decomposes_to",
        })
    };

    let (owner_status, owner_body) = post_json(
        addr,
        "/api/v1/edges/hierarchical",
        &owner_token,
        &body(source, target),
    )
    .await;
    assert_eq!(owner_status, 200, "{owner_body}");
    let owner_json: serde_json::Value = serde_json::from_str(&owner_body).expect("json");
    assert_eq!(
        (
            owner_json["edge_id"].as_str(),
            owner_json["created"].as_bool()
        ),
        (Some(hidden.to_string().as_str()), Some(false)),
        "CLASS P: a reader's re-run is still a dedup hit on the existing edge"
    );

    let (hit_status, hit_body) = post_json(
        addr,
        "/api/v1/edges/hierarchical",
        &stranger_token,
        &body(source, target),
    )
    .await;
    let (absent_status, absent_body) = post_json(
        addr,
        "/api/v1/edges/hierarchical",
        &stranger_token,
        &body(absent_source, absent_target),
    )
    .await;

    assert!(
        !hit_body.contains(&hidden.to_string()),
        "the hierarchical dedup probe handed a stranger an edge it cannot read: {hit_body}"
    );
    let edge_id = |b: &str| -> Uuid {
        let v: serde_json::Value = serde_json::from_str(b).expect("json");
        v["edge_id"]
            .as_str()
            .expect("edge_id")
            .parse()
            .expect("uuid")
    };
    assert_eq!(
        (hit_status, normalise(&hit_body, &[edge_id(&hit_body)])),
        (
            absent_status,
            normalise(&absent_body, &[edge_id(&absent_body)])
        ),
        "an invisible matching edge must be indistinguishable from no edge at all"
    );

    let _ = shutdown.send(());
}

/// The unique-INDEX half on the edge side: `edges_alternative_of_symmetric_uniq`
/// (042, narrowed by 091) refuses a second in-force `alternative_of` row over a
/// claim pair whoever owns the first. Item 21's form holds — a collision with an
/// edge the caller cannot read answers byte-for-byte as a collision with one it
/// can, and names neither — while the ABSENT case still differs (201). That
/// residual is `D-N21-unique-keys-omit-owner-group`, and nothing here asserts it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_symmetric_index_collision_on_an_invisible_edge_answers_like_a_visible_one(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "n21-sym-owner").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "n21-sym-stranger").await;

    let marker = format!("hidden-{}", Uuid::new_v4());
    let (a, b, hidden) =
        public_pair_with_private_edge(&pool, owner, group, "alternative_of", &marker).await;
    // A readable alternative_of edge over another public pair: the reference.
    let c = fixture::seed_public_claim(&pool, owner, "n21 sym visible c").await;
    let d = fixture::seed_public_claim(&pool, owner, "n21 sym visible d").await;
    let visible = fixture::seed_edge(&pool, c, d).await;
    sqlx::query("UPDATE edges SET relationship = 'alternative_of' WHERE id = $1")
        .bind(visible)
        .execute(&pool)
        .await
        .expect("make the visible edge an alternative_of");

    let url = fixture::database_url_for(&pool).await;
    let (addr, shutdown) = common::spawn_app(&url).await;
    let (stranger_token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["edges:write"], stranger)
            .await;
    let body = |s: Uuid, t: Uuid| {
        serde_json::json!({
            "source_id": s, "target_id": t,
            "source_type": "claim", "target_type": "claim",
            "relationship": "alternative_of",
        })
    };

    let (visible_status, visible_body) =
        post_json(addr, "/api/v1/edges", &stranger_token, &body(c, d)).await;
    assert!(
        (400..500).contains(&visible_status),
        "calibration: the index refuses a second alternative_of over a readable \
         pair; got {visible_status}: {visible_body}"
    );
    let (hidden_status, hidden_body) =
        post_json(addr, "/api/v1/edges", &stranger_token, &body(a, b)).await;

    assert_eq!(
        (hidden_status, hidden_body.as_str()),
        (visible_status, visible_body.as_str()),
        "a symmetric-index collision with an edge the caller cannot read must \
         answer exactly as one with an edge it can"
    );
    for secret in [hidden.to_string(), marker.clone(), group.to_string()] {
        assert!(
            !hidden_body.contains(&secret),
            "the refusal names the invisible edge ({secret}): {hidden_body}"
        );
    }

    let _ = shutdown.send(());
}
