//! Batch OA1 (operator decision D1): `supersede_claim` and `mark_duplicate` at
//! `claims:write`, on the APPLICATION ROLE, for a HUMAN caller that is not the
//! MCP server's own agent.
//!
//! Before OA1 both tools were mapped to `claims:admin`, a scope no registration
//! path grants to a human client, so a human could not retire even their own
//! claim over OAuth. D1 says the act is the caller's own write and only the
//! cascade is administrative; these tests pin that split end to end:
//!
//! * the author retires its own claim with `claims:write` (the act lands on a
//!   transaction stamped with the CALLER's authority, the cascade defers with a
//!   `cascade.deferred` row naming the caller, and the replay applies it on the
//!   maintenance connection);
//! * a writer of the claim's owning group may do the same;
//! * authorship alone is not write authority: an author whose membership in
//!   the owning group was revoked, or who is only a reader there, is refused
//!   by name on both tools, and the act never borrows the MCP server agent's
//!   stamp for it;
//! * a bystander with `claims:write` is refused by name on a claim it can read,
//!   and on a claim it cannot read gets exactly the answer a random id gets
//!   (duplicate and canonical alike);
//! * `claims:admin` admits a claim the caller neither wrote nor writes.
//!
//! Both of the server's pools are downgraded to `epigraph_app` (see
//! `writer_owned_attach_app_role.rs` for why a superuser pool proves nothing
//! here). Seeding and `Viewer::resolve` run on the superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::supersede::{mark_duplicate, supersede_claim};
use epigraph_mcp::types::{MarkDuplicateParams, SupersedeClaimParams};
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid) {
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
    let server = build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    (server, agent)
}

/// The token a human's OAuth client presents: its graph agent is `agent`, and
/// its login principal (`owner_id`) is NOT that agent, so the pre-OA1
/// token-owner rule cannot be what admits it.
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

/// A claim authored by `agent`, owned by `group`, with `visibility`.
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
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, $5, $6)",
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

async fn edge_between(pool: &PgPool, source: Uuid, target: Uuid) -> Uuid {
    let e = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports')",
    )
    .bind(e)
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("seed edge");
    e
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

async fn revoke(pool: &PgPool, group: Uuid, agent: Uuid) {
    let n = sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("revoke")
    .rows_affected();
    assert_eq!(n, 1, "exactly one membership revoked");
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

async fn successors(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("successors")
}

async fn edge_target(pool: &PgPool, edge: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge")
}

/// The `cascade.deferred` row a result names: `(agent_id, cause)`.
async fn deferral(pool: &PgPool, body: &serde_json::Value) -> (Option<Uuid>, String) {
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");
    let id: Uuid = body["cascade"]["audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("the deferral carries its audit row id");
    let (et, who, cause): (String, Option<Uuid>, String) = sqlx::query_as(
        "SELECT event_type::text, agent_id, details->>'cause' FROM security_events WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("the deferral row");
    assert_eq!(et, "cascade.deferred");
    (who, cause)
}

async fn replay_now(pool: &PgPool, label: &str) -> epigraph_engine::admin_cascade::ReplayReport {
    let url = fixture::database_url_for(pool).await;
    let maintenance = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("ScopedPool")
            .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    session
        .assert_privileged()
        .await
        .expect("the replay's connection is privileged");
    let (conn, admin_viewer) = session.split();
    epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        label,
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay")
}

fn supersede_params(claim: Uuid) -> SupersedeClaimParams {
    SupersedeClaimParams {
        claim_id: claim.to_string(),
        content: format!("a correction of {claim}"),
        truth_value: 0.6,
        reason: "oa1 test".to_string(),
    }
}

fn dedup_params(dup: Uuid, canonical: Uuid) -> MarkDuplicateParams {
    MarkDuplicateParams {
        claim_id: dup.to_string(),
        canonical_id: canonical.to_string(),
        reason: None,
    }
}

/// The claims:write scope is what the tool map asks, and the per-claim rule is
/// what admits the author: the scope check is asserted on the same token the
/// tool is then driven with.
fn assert_scope_admits(auth: &AuthContext, tool: &str) {
    EpiGraphMcpFull::enforce_tool_scope(Some(auth), tool)
        .unwrap_or_else(|e| panic!("{tool} must be reachable at claims:write: {e:?}"));
}

/// The named refusal: `data.error = not_owner`, `data.rule = not_claim_writer`.
fn assert_not_claim_writer(err: &epigraph_mcp::errors::McpError, claim: Uuid) {
    let data = err.data.as_ref().unwrap_or_else(|| panic!("{err:?}"));
    assert_eq!(data["error"], "not_owner", "{err:?}");
    assert_eq!(data["rule"], "not_claim_writer", "{err:?}");
    assert_eq!(data["claim_id"], claim.to_string(), "{err:?}");
}

/// The answer for `hidden` and for a random id, with each id replaced by a
/// placeholder: they must be identical, or the refusal is an existence oracle.
fn assert_same_as_missing(
    hidden: &epigraph_mcp::errors::McpError,
    hidden_id: Uuid,
    missing: &epigraph_mcp::errors::McpError,
    missing_id: Uuid,
) {
    let h = hidden.message.replace(&hidden_id.to_string(), "<id>");
    let m = missing.message.replace(&missing_id.to_string(), "<id>");
    assert_eq!(h, m, "hidden={hidden:?} missing={missing:?}");
    assert_eq!(
        hidden.code, missing.code,
        "hidden={hidden:?} missing={missing:?}"
    );
    assert_eq!(
        hidden.data, missing.data,
        "hidden={hidden:?} missing={missing:?}"
    );
    assert!(h.contains("not found"), "{h}");
}

// ─────────────────────────────────────────────────────────────────────────────
// The author
// ─────────────────────────────────────────────────────────────────────────────

/// The author supersedes its own claim with `claims:write` alone: the act lands
/// under the CALLER's stamp (the deferral row names the human, not the server
/// agent), the cascade defers, and the replay moves another writer's edge onto
/// the replacement.
#[sqlx::test(migrations = "../../migrations")]
async fn the_author_supersedes_its_own_claim_with_claims_write(pool: PgPool) {
    let (server, server_agent) = app_role_server(&pool).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "oa1-human").await;
    let (x, xg) = fixture::seed_agent_with_group(&pool, "oa1-writer-x").await;
    let old = claim_of(&pool, h, hg, "public", "the human's claim").await;
    let xc = claim_of(&pool, x, xg, "public", "X cites the human's claim").await;
    let incoming = edge_between(&pool, xc, old).await;
    let auth = human(h, &["claims:read", "claims:write"]);
    assert_scope_admits(&auth, "supersede_claim");

    let r = supersede_claim(
        &server,
        &viewer(&pool, h).await,
        supersede_params(old),
        Some(&auth),
    )
    .await
    .expect("the author's supersede lands at claims:write");
    let body = first_text(&r);
    let new: Uuid = parse_uuid_field(&body, "new_claim_id");
    assert!(!is_current(&pool, old).await, "the act retired the claim");
    let (supersedes, new_owner): (Option<Uuid>, Uuid) =
        sqlx::query_as("SELECT supersedes, owner_group_id FROM claims WHERE id = $1")
            .bind(new)
            .fetch_one(&pool)
            .await
            .expect("replacement");
    assert_eq!(supersedes, Some(old));
    assert_eq!(new_owner, hg, "the replacement inherits the claim's owner");

    let (who, cause) = deferral(&pool, &body).await;
    assert_eq!(cause, "supersede");
    assert_eq!(
        who,
        Some(h),
        "the act was stamped with the CALLER's authority, not the server agent {server_agent}'s"
    );
    assert_eq!(
        edge_target(&pool, incoming).await,
        old,
        "the deferred cascade has not run yet"
    );

    let report = replay_now(&pool, "oa1-supersede").await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert_eq!(
        edge_target(&pool, incoming).await,
        new,
        "the replay moved another writer's edge onto the replacement with admin authority"
    );
}

/// The author marks its own claim a duplicate of another claim it writes, with
/// `claims:write` alone; the replay re-points another writer's edge onto the
/// canonical.
#[sqlx::test(migrations = "../../migrations")]
async fn the_author_dedups_its_own_claim_with_claims_write(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "oa1-human").await;
    let (x, xg) = fixture::seed_agent_with_group(&pool, "oa1-writer-x").await;
    let dup = claim_of(&pool, h, hg, "public", "the human's duplicate").await;
    let canonical = claim_of(&pool, h, hg, "public", "the human's canonical").await;
    let xc = claim_of(&pool, x, xg, "public", "X cites the duplicate").await;
    let incoming = edge_between(&pool, xc, dup).await;
    let auth = human(h, &["claims:read", "claims:write"]);
    assert_scope_admits(&auth, "mark_duplicate");

    let r = mark_duplicate(
        &server,
        &viewer(&pool, h).await,
        dedup_params(dup, canonical),
        Some(&auth),
    )
    .await
    .expect("the author's dedup lands at claims:write");
    let body = first_text(&r);
    let (current, supersedes): (bool, Option<Uuid>) =
        sqlx::query_as("SELECT is_current, supersedes FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("dup");
    assert!(!current);
    assert_eq!(supersedes, Some(canonical));
    let (who, cause) = deferral(&pool, &body).await;
    assert_eq!((who, cause.as_str()), (Some(h), "dedup"));

    let report = replay_now(&pool, "oa1-dedup").await;
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");
    assert_eq!(edge_target(&pool, incoming).await, canonical);
}

/// The canonical is a target claim too (brief (a)): the cascade re-points other
/// writers' edges and BBAs onto it with administrative authority, so at
/// `claims:write` the caller must write the canonical's owning group as well.
/// A readable public canonical in another writer's group is refused BY NAME,
/// the refusal naming the canonical, nothing written and no cascade recorded;
/// `claims:admin` admits the same dedup.
#[sqlx::test(migrations = "../../migrations")]
async fn a_canonical_the_caller_cannot_write_is_refused_at_claims_write(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "oa1-human").await;
    let (x, xg) = fixture::seed_agent_with_group(&pool, "oa1-writer-x").await;
    let dup = claim_of(&pool, h, hg, "public", "the human's duplicate").await;
    let theirs = claim_of(&pool, x, xg, "public", "X's attractive canonical").await;
    let hv = viewer(&pool, h).await;

    let err = mark_duplicate(
        &server,
        &hv,
        dedup_params(dup, theirs),
        Some(&human(h, &["claims:read", "claims:write"])),
    )
    .await
    .expect_err("a canonical the caller cannot write is refused at claims:write");
    assert_not_claim_writer(&err, theirs);
    assert!(is_current(&pool, dup).await, "nothing was written");
    let deferrals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'cascade.deferred'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(deferrals, 0, "a refused act records no cascade");

    let r = mark_duplicate(
        &server,
        &hv,
        dedup_params(dup, theirs),
        Some(&human(h, &["claims:write", "claims:admin"])),
    )
    .await
    .expect("claims:admin admits any readable canonical");
    let (who, cause) = deferral(&pool, &first_text(&r)).await;
    assert_eq!((who, cause.as_str()), (Some(h), "dedup"));
    let supersedes: Option<Uuid> =
        sqlx::query_scalar("SELECT supersedes FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("dup");
    assert_eq!(supersedes, Some(theirs));
}

/// Authorship is not write authority. The human wrote the claim while a
/// `writer` of the server agent's group, then that membership was REVOKED; a
/// second author is only a `reader` there. Neither writes the owning group, so
/// both are refused by name on both tools, nothing is written, no cascade is
/// recorded, and in particular the act does not run on the MCP server agent's
/// stamp (which CAN write that group: before this rule a `claims:write` author
/// retired and rewrote the group's claim through it).
///
/// Each author's dedup names a canonical in THAT author's own personal group,
/// which the author writes, so the canonical check admits it and the
/// duplicate alone decides. (A canonical the author cannot write would be
/// refused first, naming the canonical, and the duplicate's gate would never
/// be reached.)
#[sqlx::test(migrations = "../../migrations")]
async fn an_author_who_no_longer_writes_the_owning_group_is_refused(pool: PgPool) {
    let (server, server_agent) = app_role_server(&pool).await;
    let server_group = personal_group_of(&pool, server_agent).await;
    let (revoked, revoked_g) = fixture::seed_agent_with_group(&pool, "oa1-revoked-author").await;
    let (reader, rg) = fixture::seed_agent_with_group(&pool, "oa1-reader-author").await;
    add_member(&pool, server_group, revoked, "writer").await;
    add_member(&pool, server_group, reader, "reader").await;
    let by_revoked = claim_of(
        &pool,
        revoked,
        server_group,
        "public",
        "written while a member",
    )
    .await;
    let by_reader = claim_of(
        &pool,
        reader,
        server_group,
        "group",
        "group-private, author only reads",
    )
    .await;
    let revoked_own = claim_of(
        &pool,
        revoked,
        revoked_g,
        "public",
        "the revoked author's own claim",
    )
    .await;
    let reader_own = claim_of(&pool, reader, rg, "public", "the reader's own claim").await;
    revoke(&pool, server_group, revoked).await;

    for (author, own_group, c, canonical) in [
        (revoked, revoked_g, by_revoked, revoked_own),
        (reader, rg, by_reader, reader_own),
    ] {
        let v = viewer(&pool, author).await;
        assert!(
            !v.writable_groups().contains(&server_group),
            "fixture: the author does not write the owning group"
        );
        assert!(
            v.writable_groups().contains(&own_group),
            "fixture: the author writes the canonical's group"
        );
        let auth = human(author, &["claims:read", "claims:write"]);

        let mut p = supersede_params(c);
        p.content = "content the author may not write into this group".to_string();
        let err = supersede_claim(&server, &v, p, Some(&auth))
            .await
            .expect_err("an author without write authority may not supersede");
        assert_not_claim_writer(&err, c);

        // The canonical is the author's OWN claim, in a group it writes, so
        // the canonical check admits it and only the duplicate decides: the
        // refusal must name the duplicate `c`, not the canonical.
        let err = mark_duplicate(&server, &v, dedup_params(c, canonical), Some(&auth))
            .await
            .expect_err("an author without write authority may not mark a duplicate");
        assert_not_claim_writer(&err, c);

        assert!(is_current(&pool, c).await, "nothing was written");
        assert!(is_current(&pool, canonical).await, "nothing was written");
        assert_eq!(successors(&pool, c).await, 0, "no replacement exists");
    }
    let deferrals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'cascade.deferred'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(deferrals, 0, "a refused act records no cascade");
}

// ─────────────────────────────────────────────────────────────────────────────
// A writer of the owning group
// ─────────────────────────────────────────────────────────────────────────────

/// A `writer` of the group that owns the claim, who did not author it, may
/// retire it; a `reader` of the same group may not (the arm is write
/// authority, not membership).
#[sqlx::test(migrations = "../../migrations")]
async fn a_writer_of_the_owning_group_may_retire_its_claim_and_a_reader_may_not(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "oa1-human").await;
    let (w, _) = fixture::seed_agent_with_group(&pool, "oa1-group-writer").await;
    let (rd, _) = fixture::seed_agent_with_group(&pool, "oa1-group-reader").await;
    add_member(&pool, hg, w, "writer").await;
    add_member(&pool, hg, rd, "reader").await;
    let c = claim_of(&pool, h, hg, "group", "the group's claim").await;

    let err = supersede_claim(
        &server,
        &viewer(&pool, rd).await,
        supersede_params(c),
        Some(&human(rd, &["claims:write"])),
    )
    .await
    .expect_err("a reader of the owning group may read but not retire");
    assert_not_claim_writer(&err, c);
    assert!(is_current(&pool, c).await);

    let r = supersede_claim(
        &server,
        &viewer(&pool, w).await,
        supersede_params(c),
        Some(&human(w, &["claims:write"])),
    )
    .await
    .expect("a writer of the owning group retires its claim");
    let (who, _) = deferral(&pool, &first_text(&r)).await;
    assert_eq!(who, Some(w), "stamped with the writer's own authority");
    assert!(!is_current(&pool, c).await);
}

// ─────────────────────────────────────────────────────────────────────────────
// A bystander
// ─────────────────────────────────────────────────────────────────────────────

/// A bystander holding `claims:write` is refused by name on a claim it can
/// read, and nothing is written, on both tools.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bystander_with_claims_write_is_refused_by_name(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "oa1-human").await;
    let (b, bg) = fixture::seed_agent_with_group(&pool, "oa1-bystander").await;
    let c = claim_of(&pool, h, hg, "public", "the human's public claim").await;
    let mine = claim_of(&pool, b, bg, "public", "the bystander's own claim").await;
    let bv = viewer(&pool, b).await;
    let auth = human(b, &["claims:read", "claims:write"]);

    let err = supersede_claim(&server, &bv, supersede_params(c), Some(&auth))
        .await
        .expect_err("a bystander may not supersede another's claim");
    assert_not_claim_writer(&err, c);

    let err = mark_duplicate(&server, &bv, dedup_params(c, mine), Some(&auth))
        .await
        .expect_err("a bystander may not mark another's claim a duplicate");
    assert_not_claim_writer(&err, c);

    assert!(is_current(&pool, c).await, "nothing was written");
    assert_eq!(successors(&pool, c).await, 0);
    let deferrals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'cascade.deferred'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(deferrals, 0, "a refused act records no cascade");
}

/// A claim the bystander cannot read answers exactly like a random id: for the
/// supersede target, the duplicate, and the canonical.
///
/// Two hidden claims, because WHOSE authority reads the gate matters: one
/// private to the human's group (no party in play but the human reads it), and
/// one private to the MCP SERVER AGENT's own group, which the server agent can
/// read and the bystander cannot. A gate that read through the server agent's
/// authority instead of the caller's would find the second one and answer
/// `not_owner` for it (an existence oracle over everything the server agent
/// reads, which on the HTTP transport is the signer's group) while still
/// answering "not found" for the first.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bystander_cannot_learn_whether_a_hidden_claim_exists(pool: PgPool) {
    let (server, server_agent) = app_role_server(&pool).await;
    let server_group = personal_group_of(&pool, server_agent).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "oa1-human").await;
    let (b, bg) = fixture::seed_agent_with_group(&pool, "oa1-bystander").await;
    let hidden_h = claim_of(&pool, h, hg, "group", "the human's private claim").await;
    let hidden_s = claim_of(
        &pool,
        server_agent,
        server_group,
        "group",
        "the server agent's private claim",
    )
    .await;
    let mine = claim_of(&pool, b, bg, "public", "the bystander's own claim").await;
    let random = Uuid::new_v4();
    let bv = viewer(&pool, b).await;
    let sv = viewer(&pool, server_agent).await;
    assert!(
        sv.group_bind().is_some_and(|g| g.contains(&server_group)),
        "fixture: the server agent reads its own group's private claim"
    );
    let auth = human(b, &["claims:read", "claims:write"]);

    for hidden in [hidden_h, hidden_s] {
        let e_hidden = supersede_claim(&server, &bv, supersede_params(hidden), Some(&auth))
            .await
            .expect_err("hidden");
        let e_random = supersede_claim(&server, &bv, supersede_params(random), Some(&auth))
            .await
            .expect_err("random");
        assert_same_as_missing(&e_hidden, hidden, &e_random, random);

        // The duplicate hidden.
        let e_hidden = mark_duplicate(&server, &bv, dedup_params(hidden, mine), Some(&auth))
            .await
            .expect_err("hidden duplicate");
        let e_random = mark_duplicate(&server, &bv, dedup_params(random, mine), Some(&auth))
            .await
            .expect_err("random duplicate");
        assert_same_as_missing(&e_hidden, hidden, &e_random, random);

        // The canonical hidden, the duplicate the bystander's OWN claim: the act
        // would be admitted, so only the canonical's visibility decides.
        let e_hidden = mark_duplicate(&server, &bv, dedup_params(mine, hidden), Some(&auth))
            .await
            .expect_err("hidden canonical");
        let e_random = mark_duplicate(&server, &bv, dedup_params(mine, random), Some(&auth))
            .await
            .expect_err("random canonical");
        assert_same_as_missing(&e_hidden, hidden, &e_random, random);

        assert!(is_current(&pool, hidden).await);
    }
    assert!(is_current(&pool, mine).await, "nothing was written");
}

// ─────────────────────────────────────────────────────────────────────────────
// claims:admin
// ─────────────────────────────────────────────────────────────────────────────

/// `claims:admin` admits a claim the caller neither authored nor writes, where
/// the same caller with `claims:write` alone is refused by name. The claim is
/// owned by the server agent's group, so the act runs on the server agent's
/// stamp (the caller cannot write that group) and lands.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_admin_admits_a_claim_the_caller_neither_wrote_nor_writes(pool: PgPool) {
    let (server, server_agent) = app_role_server(&pool).await;
    let server_group = personal_group_of(&pool, server_agent).await;
    let (x, _) = fixture::seed_agent_with_group(&pool, "oa1-author-x").await;
    let (a, _) = fixture::seed_agent_with_group(&pool, "oa1-admin").await;
    let c = claim_of(
        &pool,
        x,
        server_group,
        "public",
        "X's claim in the server's group",
    )
    .await;
    let av = viewer(&pool, a).await;

    let err = supersede_claim(
        &server,
        &av,
        supersede_params(c),
        Some(&human(a, &["claims:write"])),
    )
    .await
    .expect_err("without claims:admin the caller is a bystander");
    assert_not_claim_writer(&err, c);

    let r = supersede_claim(
        &server,
        &av,
        supersede_params(c),
        Some(&human(a, &["claims:write", "claims:admin"])),
    )
    .await
    .expect("claims:admin admits it");
    assert!(!is_current(&pool, c).await, "the act landed");
    let (who, _) = deferral(&pool, &first_text(&r)).await;
    assert_eq!(
        who,
        Some(server_agent),
        "a caller that cannot write the group acts on the server agent's stamp"
    );
}
