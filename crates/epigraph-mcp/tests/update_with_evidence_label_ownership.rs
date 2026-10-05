//! `update_with_evidence`'s label merge takes the same ownership gates as
//! `update_labels` (drain unit U004, review finding I253).
//!
//! `update_with_evidence` decides "foreign" only through
//! `foreign_attach::is_foreign_public_claim`, which is a GROUP test: is the
//! claim's owner group in the caller's writable set? A caller that WRITES the
//! owning group but did not AUTHOR the claim is therefore not foreign, and
//! before this file's fix it reached the additive label merge with no
//! ownership question asked. Two holes followed:
//!
//! * the retirement label: `labels: ["resolved"]` retired a colleague's claim
//!   with no #374 gate, on every transport (over stdio too, where
//!   `update_labels` / `patch_claim` refuse a declared signer that is neither
//!   the author nor under the author's operator);
//! * over HTTP, any free label: `update_labels` gates the WHOLE mutation with
//!   `require_owner_or_admin` (batch H-b review, measured on config A: a team
//!   group writer relabelled a colleague's claim), and `update_with_evidence`
//!   was the same hole one tool over.
//!
//! What stays allowed, and is pinned here as calibration so the refusals above
//! cannot be passed by a blanket gate:
//!
//! * the author adds `resolved` to its own claim;
//! * on stdio, free labels on a claim the server's agent can write stay ungated
//!   (the batch H-b bar, the same as `update_labels`);
//! * a group writer's evidence WITHOUT labels still lands and still moves
//!   `truth_value`. That is the documented "On a claim you can write" contract
//!   (D1); whether it should is an open operator question (drain U004 part 1,
//!   OPERATOR-QUEUE Q3), deliberately not decided by this file.
//!
//! Both of the server's pools are downgraded to `epigraph_app` so
//! `is_foreign_public_claim` and RLS answer as in production (see
//! `writer_owned_attach_app_role.rs` for why a superuser pool proves nothing).
//! Seeding and `Viewer::resolve` run on the superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::types::UpdateWithEvidenceParams;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid) {
    let (plain, scoped) = app_role_pools(pool).await;
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    (server, agent)
}

/// The same app-role server with a per-process GENERATED signer: no declared
/// signer identity (`--agent-key` / `--agent-model` absent), the configuration
/// `common::build_test_server_generated_signer` documents as the one epiclaw
/// agent containers run. `require_owner_or_admin` answers
/// `OwnershipGrant::UndeclaredSigner` for a claim it did not author there, and
/// only `gate_retirement_label` turns that into a refusal for `resolved`.
async fn app_role_server_undeclared(pool: &PgPool) -> (EpiGraphMcpFull, Uuid) {
    let (plain, scoped) = app_role_pools(pool).await;
    let server = build_scoped_test_server_generated_signer(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    (server, agent)
}

async fn app_role_pools(pool: &PgPool) -> (PgPool, ScopedPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    (plain, scoped)
}

/// A human's OAuth token: its graph agent is `agent`, its login principal
/// (`owner_id`) is not, so the legacy token-owner arm cannot admit it.
fn human(agent: Uuid, scopes: &[&str]) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
    }
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

/// A claim authored by `agent`, owned by `group`, with `visibility`, carrying
/// the `backlog` label and `truth_value = 0.5`.
async fn claim_of(
    pool: &PgPool,
    agent: Uuid,
    group: Uuid,
    visibility: &str,
    content: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, $5, $6, ARRAY['backlog'])",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed claim");
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

async fn labels_of(pool: &PgPool, claim_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT COALESCE(labels, ARRAY[]::text[]) FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read labels")
}

async fn evidence_rows(pool: &PgPool, claim_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM evidence WHERE claim_id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("count evidence")
}

async fn truth_of(pool: &PgPool, claim_id: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read truth_value")
}

fn params(claim: Uuid, evidence: &str, labels: &[&str]) -> UpdateWithEvidenceParams {
    UpdateWithEvidenceParams {
        claim_id: claim.to_string(),
        canonical_name: None,
        step_index: None,
        evidence_data: evidence.into(),
        evidence_type: "empirical".into(),
        supports: true,
        strength: 0.9,
        source_url: None,
        labels: labels.iter().map(|s| (*s).to_string()).collect(),
    }
}

/// The refusal leaves the claim exactly as seeded: no new label, `backlog`
/// kept, `truth_value` unmoved, and no evidence row (a refused call that kept
/// its evidence would also block the identical re-submission through
/// `evidence_content_hash_claim_unique`).
async fn assert_nothing_written(pool: &PgPool, claim: Uuid, refused_label: &str) {
    let labels = labels_of(pool, claim).await;
    assert!(
        !labels.contains(&refused_label.to_string()),
        "a refused call must not write `{refused_label}`: {labels:?}"
    );
    assert_eq!(labels, vec!["backlog".to_string()], "labels unchanged");
    assert_eq!(
        evidence_rows(pool, claim).await,
        0,
        "a refused call must write no evidence row"
    );
    assert_eq!(
        truth_of(pool, claim).await,
        0.5,
        "a refused call must not move truth_value"
    );
}

/// Author `h` owns claim `c` in its personal group `hg`; `w` is a `writer` of
/// `hg` and did not author `c`. Memberships are seeded BEFORE any viewer is
/// resolved.
struct TeamFixture {
    h: Uuid,
    w: Uuid,
    c: Uuid,
}

async fn team(pool: &PgPool) -> TeamFixture {
    let (h, hg) = fixture::seed_agent_with_group(pool, "uwe-author").await;
    let (w, _) = fixture::seed_agent_with_group(pool, "uwe-group-writer").await;
    add_member(pool, hg, w, "writer").await;
    let c = claim_of(pool, h, hg, "group", "a colleague's backlog item").await;
    TeamFixture { h, w, c }
}

// ── 2a: the retirement label, HTTP ──────────────────────────────────────────

/// FAILS before the fix: `w` writes `hg`, so `c` is not foreign, and nothing
/// asked whether `w` authored it — the call returned `Ok`, `c` carried
/// `resolved`, and one evidence row existed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writer_cannot_retire_a_colleagues_claim_through_update_with_evidence(
    pool: PgPool,
) {
    let (server, _) = app_role_server(&pool).await;
    let TeamFixture { w, c, .. } = team(&pool).await;

    let err = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer(&pool, w).await,
        params(c, "closing this", &["resolved"]),
        Some(&human(w, &["claims:write"])),
    )
    .await
    .expect_err("a non-author group writer must not add `resolved` via update_with_evidence");
    assert!(
        err.message.contains("ownership"),
        "the refusal must be the ownership rule's: {}",
        err.message
    );
    assert_nothing_written(&pool, c, "resolved").await;
}

// ── 2a: the retirement label, stdio ─────────────────────────────────────────

/// FAILS before the fix. A declared stdio signer (this server's own agent)
/// writes the group that owns another agent's PUBLIC claim — so the claim is
/// not foreign — and shares no operator with its author. `update_labels`
/// refuses it `resolved`; `update_with_evidence` added it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_signer_cannot_retire_another_agents_claim_in_its_own_group(pool: PgPool) {
    let (server, me) = app_role_server(&pool).await;
    let sg = personal_group_of(&pool, me).await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "uwe-other-author").await;
    let c = claim_of(
        &pool,
        other,
        sg,
        "public",
        "another agent's item in my group",
    )
    .await;

    let err = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer(&pool, me).await,
        params(c, "closing this over stdio", &["resolved"]),
        None,
    )
    .await
    .expect_err("a declared stdio signer must not retire a claim it did not author");
    // The DECLARED arm's text (`require_owner_or_admin`), not the
    // undeclared-signer refusal ("has no declared signer identity", from
    // `gate_retirement_label`), which the next test pins: both mention a
    // "declared signer identity", so each test names the arm it reached.
    assert!(
        err.message
            .contains("is this server's declared signer identity")
            && !err.message.contains("no declared signer"),
        "the refusal must be the declared stdio signer's ownership rule: {}",
        err.message
    );
    assert_nothing_written(&pool, c, "resolved").await;
}

/// FAILS before the fix. The production stdio population: a server with NO
/// declared signer (a per-process generated key) writes the group owning
/// another agent's PUBLIC claim. `require_owner_or_admin` cannot decide
/// ownership there and answers `UndeclaredSigner` (an allow), so a bare
/// ownership call would let `resolved` through; `gate_retirement_label`
/// refuses that arm for the retirement label, as `update_labels` does
/// (`retirement_label_ownership.rs::an_undeclared_stdio_signer_cannot_retire_a_claim_it_did_not_author`).
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_stdio_signer_cannot_retire_another_agents_claim_in_its_own_group(
    pool: PgPool,
) {
    let (server, me) = app_role_server_undeclared(&pool).await;
    let sg = personal_group_of(&pool, me).await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "uwe-undeclared-other").await;
    let c = claim_of(
        &pool,
        other,
        sg,
        "public",
        "another agent's item in the undeclared signer's group",
    )
    .await;

    let err = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer(&pool, me).await,
        params(c, "closing this with no declared signer", &["resolved"]),
        None,
    )
    .await
    .expect_err("undecidable ownership must not retire another agent's claim");
    assert!(
        err.message.contains("no declared signer"),
        "the refusal must be the undeclared-signer arm's: {}",
        err.message
    );
    assert_nothing_written(&pool, c, "resolved").await;
}

// ── 2b: any label over HTTP ─────────────────────────────────────────────────

/// FAILS before the fix: the same hole `update_labels` closed in batch H-b, one
/// tool over — a team writer run-tagged a colleague's claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writer_cannot_label_a_colleagues_claim_over_http(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let TeamFixture { w, c, .. } = team(&pool).await;

    let err = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer(&pool, w).await,
        params(c, "run-tagging a colleague's claim", &["topic-x"]),
        Some(&human(w, &["claims:write"])),
    )
    .await
    .expect_err("over HTTP a label merge needs ownership of the claim");
    assert!(
        err.message.contains("ownership"),
        "the refusal must be the ownership rule's: {}",
        err.message
    );
    assert_nothing_written(&pool, c, "topic-x").await;
}

// ── calibrations: the arms that stay allowed (green before AND after) ──────

/// The author retires its own claim over HTTP: proves the app-role DS wiring
/// works on this fixture, so the refusals above fail on `Ok`, not on an
/// unrelated DS/RLS error. The merge is additive: `backlog` survives.
#[sqlx::test(migrations = "../../migrations")]
async fn the_author_retires_its_own_claim_through_update_with_evidence(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let TeamFixture { h, c, .. } = team(&pool).await;

    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer(&pool, h).await,
        params(c, "closing my own item", &["resolved"]),
        Some(&human(h, &["claims:write"])),
    )
    .await
    .expect("the author may retire its own claim");
    let labels = labels_of(&pool, c).await;
    assert!(labels.contains(&"resolved".to_string()), "{labels:?}");
    assert!(labels.contains(&"backlog".to_string()), "{labels:?}");
    assert_eq!(evidence_rows(&pool, c).await, 1);
}

/// The group writer's evidence WITHOUT labels still lands and still moves
/// `truth_value` (the documented D1 contract, U004 part 1 left as is). Pins
/// that the new gates hang off labels, not off the call, and that DS wiring
/// runs under the WRITER's stamp on this fixture.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_writers_evidence_without_labels_still_lands(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let TeamFixture { w, c, .. } = team(&pool).await;

    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer(&pool, w).await,
        params(c, "corroborating a colleague's claim", &[]),
        Some(&human(w, &["claims:write"])),
    )
    .await
    .expect("a group writer may attach evidence without labels");
    assert_eq!(evidence_rows(&pool, c).await, 1);
    assert_ne!(
        truth_of(&pool, c).await,
        0.5,
        "on a claim the caller can write, truth_written=true. This pins drain U004 part 1 \
         OPTION A (a non-author group writer's evidence moves truth_value), the current \
         behaviour pending the operator's ruling; if B or C is chosen, invert THIS assertion"
    );
    assert_eq!(labels_of(&pool, c).await, vec!["backlog".to_string()]);
}

/// `claims:admin` over HTTP passes both label gates on a claim its group
/// writes but it did not author: the group writer `w`, holding the admin
/// scope, retires its colleague's claim. Rules out an over-narrow ownership
/// predicate (`caller == claim.agent_id`), which every refusal arm above would
/// also accept. No `seed_admin_grant`: that record is re-checked only by
/// `update_labels`' audited admin path, which `update_with_evidence` does not
/// have, so seeding it would hide what this calibrates.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_admin_retires_a_colleagues_claim_its_group_writes(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let TeamFixture { w, c, .. } = team(&pool).await;

    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer(&pool, w).await,
        params(c, "closing a colleague's item as admin", &["resolved"]),
        Some(&human(w, &["claims:write", "claims:admin"])),
    )
    .await
    .expect("claims:admin passes require_owner_or_admin and the retirement gate");
    let labels = labels_of(&pool, c).await;
    assert!(labels.contains(&"resolved".to_string()), "{labels:?}");
    assert!(labels.contains(&"backlog".to_string()), "{labels:?}");
    assert_eq!(evidence_rows(&pool, c).await, 1);
}

/// `update_with_evidence` has NO admin path (CLAUDE.md, #374 note): a
/// `claims:admin` caller labelling a PUBLIC claim owned by a group it cannot
/// write is refused with nothing written, where `update_labels` would route the
/// same label through its audited admin path. The admin scope does not lift
/// the foreign-public label refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_admin_cannot_label_a_public_claim_its_group_cannot_write(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "uwe-foreign-author").await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "uwe-outside-admin").await;
    let c = claim_of(
        &pool,
        h,
        hg,
        "public",
        "a public claim outside the admin's groups",
    )
    .await;

    let err = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer(&pool, a).await,
        params(c, "admin labelling a foreign public claim", &["topic-x"]),
        Some(&human(a, &["claims:write", "claims:admin"])),
    )
    .await
    .expect_err("update_with_evidence has no admin path for a label merge");
    assert!(
        err.message
            .contains("its labels belong to the claim's owner"),
        "the refusal must be the foreign-public label rule's: {}",
        err.message
    );
    assert_nothing_written(&pool, c, "topic-x").await;
}

/// On stdio, free labels on a claim this server's agent can write stay ungated
/// (the batch H-b bar, as on `update_labels`); only `resolved` is gated there.
#[sqlx::test(migrations = "../../migrations")]
async fn stdio_free_labels_stay_ungated_on_a_claim_the_signer_can_write(pool: PgPool) {
    let (server, me) = app_role_server(&pool).await;
    let sg = personal_group_of(&pool, me).await;
    let (other, _) = fixture::seed_agent_with_group(&pool, "uwe-other-author").await;
    let c = claim_of(
        &pool,
        other,
        sg,
        "public",
        "another agent's item in my group",
    )
    .await;

    epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer(&pool, me).await,
        params(c, "run-tagging over stdio", &["topic-x"]),
        None,
    )
    .await
    .expect("stdio free labels stay ungated");
    let labels = labels_of(&pool, c).await;
    assert!(labels.contains(&"topic-x".to_string()), "{labels:?}");
    assert!(labels.contains(&"backlog".to_string()), "{labels:?}");
    assert_eq!(evidence_rows(&pool, c).await, 1);
}

// ── the contract an agent reads ─────────────────────────────────────────────

/// The tool description is what a calling agent plans from, and before this
/// change it said only "On a claim you can write, … truth_written=true", which
/// a team writer could read as licence to label a colleague's claim. Pins the
/// new label-ownership sentence positively, and that it states the stdio
/// carve-out rather than a blanket rule.
#[test]
fn the_tool_description_states_the_label_ownership_rule() {
    let tools = epigraph_mcp::EpiGraphMcpFull::all_tools_json();
    let description = tools
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == "update_with_evidence")
        .and_then(|t| t["description"].as_str())
        .expect("update_with_evidence is registered with a description")
        .to_string();
    for needle in [
        "LABELS take update_labels' ownership rule even on a claim you can write",
        "a writer of the owning group who did not author the claim is refused with nothing written",
        "on stdio only the 'resolved' label is gated",
    ] {
        assert!(
            description.contains(needle),
            "update_with_evidence's description must say {needle:?}; got: {description}"
        );
    }
}
