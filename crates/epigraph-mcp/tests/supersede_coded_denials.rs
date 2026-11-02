//! K5 (supersede SPEC §11 phase 1; backlog 09c2f9d0 part 3, 80be64b5): a
//! refused `supersede_claim` answers a CODED denial, `INVALID_REQUEST`, with
//! nothing written, on the APPLICATION ROLE.
//!
//! Before K5 the tool mapped only `DbError::WriteRefused` to a caller error;
//! every other refusal went to `internal_error`:
//!
//! * the operator binding's OPL01 / OPL02 (migration 122, armed) became the
//!   redacted `-32603` "internal error" (`DbError::OperatorLinkRequired` /
//!   `OperatorScopeRefused` are not designed refusals `internal_error` relays);
//! * migration 120's CX03, raised by the act's cascade deferral, was relayed
//!   with its text but as `-32603`, a server fault, so an agent retried it;
//! * the database's own row-security refusal of the act (`42501`, "new row
//!   violates row-level security policy"), which is what a stamp that does not
//!   write the claim's group actually meets at head, was the redacted
//!   `-32603`.
//!
//! CX03 is not reached by a supersede on a clean schema at head: every
//! transport's stamp is refused by `claims_tenancy`'s WITH CHECK (the same
//! writable set `epigraph_session_writes_node` reads) before the deferral
//! runs. So its mapping is pinned on a REAL CX03 raised by the deferral
//! definer for a supersession that never happened, both through the mapper and
//! through the deferral path `supersede_claim` uses; the realistic refusal is
//! driven end to end (the `claims:admin` borrow and the stdio author arm onto
//! a group the stamp does not write). No test here installs a policy.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_engine::admin_cascade::{CascadeCause, CascadeTrigger};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::supersede::{
    supersede_claim, supersede_refusal, supersede_session_or_deferral,
};
use epigraph_mcp::types::SupersedeClaimParams;
use rmcp::model::ErrorCode;
use sqlx::PgPool;
use uuid::Uuid;

/// The text a stamp that does not write the claim's group gets (HTTP's
/// `write_refused("claim")`, the same words on both transports).
const GROUP_WRITE_REFUSED: &str = "no write authority over the group that owns this claim";

async fn app_scoped(pool: &PgPool) -> ScopedPool {
    let url = fixture::database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// A server whose two pools are `epigraph_app` and which holds no maintenance
/// connection, so every act defers its cascade in the act's own transaction.
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
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = build_scoped_test_server(plain, app_scoped(pool).await);
    let agent = server.server_agent_id().await.expect("server agent");
    (server, agent)
}

fn human(agent: Uuid, scopes: &[&str]) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn viewer(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

async fn claim_of(pool: &PgPool, agent: Uuid, group: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
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

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
}

async fn arm(pool: &PgPool) {
    sqlx::query("INSERT INTO operator_binding_arming DEFAULT VALUES")
        .execute(pool)
        .await
        .expect("arm (the harness stands in for the maintenance role)");
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

async fn deferrals(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type = 'cascade.deferred'")
        .fetch_one(pool)
        .await
        .expect("count deferrals")
}

fn params(claim: Uuid) -> SupersedeClaimParams {
    SupersedeClaimParams {
        claim_id: claim.to_string(),
        content: format!("a correction of {claim}"),
        truth_value: 0.6,
        reason: "k5 coded denial".to_string(),
    }
}

async fn supersede_as(
    pool: &PgPool,
    server: &EpiGraphMcpFull,
    caller: Uuid,
    claim: Uuid,
) -> Result<rmcp::model::CallToolResult, epigraph_mcp::errors::McpError> {
    supersede_claim(
        server,
        &viewer(pool, caller).await,
        params(claim),
        Some(&human(caller, &["claims:write"])),
    )
    .await
}

/// The refusal wrote nothing: `claim` is current, has no successor, and no
/// cascade deferral was recorded.
async fn assert_nothing_written(pool: &PgPool, claim: Uuid, what: &str) {
    assert!(is_current(pool, claim).await, "{what}: nothing retired");
    assert_eq!(successors(pool, claim).await, 0, "{what}: no successor");
    assert_eq!(deferrals(pool).await, 0, "{what}: no cascade deferral");
}

/// A CX03 raised for real by migration 120's deferral definer: a supersede
/// deferral, on an application-role transaction stamped as `agent`, for a
/// supersession of `claim` that never happened (the claim is still current),
/// so the definer's "a committed act of its own session" test fails.
fn phantom_supersede(agent: Uuid, claim: Uuid) -> CascadeTrigger {
    CascadeTrigger::new(
        CascadeCause::Supersede,
        Some(agent),
        None,
        claim,
        Some(Uuid::new_v4()),
    )
}

/// K5 / addendum (c1): CX03 (SQLSTATE 42501, message `CX03: ...`) answers
/// `INVALID_REQUEST` with the code and the claim in the text, through the
/// mapper and through the deferral path `supersede_claim` takes. Red before
/// K5: the mapper relayed it as `-32603` (a server fault).
#[sqlx::test(migrations = "../../migrations")]
async fn a_cx03_from_the_supersede_deferral_is_a_coded_invalid_request(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "k5-cx03-author").await;
    let c = claim_of(&pool, h, hg, "a claim that was never superseded").await;
    let hv = viewer(&pool, h).await;
    let scoped = app_scoped(&pool).await;
    let trigger = phantom_supersede(h, c);

    // The raw refusal, as the definer raises it.
    let raw = {
        let mut tx = scoped.begin_as(&hv).await.expect("stamped tx");
        epigraph_engine::admin_cascade::record_deferral(&mut *tx, &trigger, "k5 test")
            .await
            .expect_err("a deferral for a supersession that never happened is refused")
    };
    let db = match &raw {
        epigraph_db::DbError::QueryFailed {
            source: sqlx::Error::Database(d),
        } => d,
        other => panic!("calibration: CX03 arrives as a database error: {other:?}"),
    };
    assert_eq!(db.code().as_deref(), Some("42501"), "calibration: {raw:?}");
    assert!(
        db.message().starts_with("CX03:"),
        "calibration: the definer's refusal is CX03: {raw:?}"
    );

    let mapped = supersede_refusal(c, raw);
    assert_eq!(mapped.code, ErrorCode::INVALID_REQUEST, "{mapped:?}");
    assert!(
        mapped.message.starts_with("CX03:")
            && mapped.message.contains(&c.to_string())
            && mapped.message.contains("does not write the group")
            && mapped.message.contains("nothing was written"),
        "the denial carries the code, the claim and what it means: {mapped:?}"
    );

    // The same refusal through the deferral path `supersede_claim` uses (this
    // server holds no maintenance connection, so it records the deferral).
    let mut tx = scoped.begin_as(&hv).await.expect("stamped tx");
    let via_path = match supersede_session_or_deferral(&server, &mut tx, &trigger).await {
        Ok(_) => panic!("the phantom supersede's deferral must be refused"),
        Err(e) => e,
    };
    drop(tx);
    assert_eq!(via_path.code, ErrorCode::INVALID_REQUEST, "{via_path:?}");
    assert_eq!(
        via_path.message, mapped.message,
        "the deferral path answers exactly what the mapper answers"
    );
    assert_eq!(deferrals(&pool).await, 0, "no deferral was recorded");
}

/// An armed fixture: human A (group `ag`) with live agent X, whose public claim
/// `x_claim` is in `ag`.
struct Armed {
    server: EpiGraphMcpFull,
    a: Uuid,
    ag: Uuid,
    x: Uuid,
    x_claim: Uuid,
}

async fn armed(pool: &PgPool, label: &str) -> Armed {
    let (server, _) = app_role_server(pool).await;
    let (a, ag) = fixture::seed_human_operator(pool, &format!("{label}-human-a")).await;
    let (x, _) = fixture::seed_agent_with_group(pool, &format!("{label}-a-agent-x")).await;
    link(pool, x, a).await;
    let x_claim = claim_of(pool, x, ag, "X's claim").await;
    Armed {
        server,
        a,
        ag,
        x,
        x_claim,
    }
}

/// K5, OPL01 (migration 122): U writes A's group but is bound to no human, so
/// once armed the database refuses its supersede of X's claim. The answer is
/// `INVALID_REQUEST` naming OPL01, and nothing is written. Red before K5: the
/// redacted `-32603`.
///
/// CONTROL: once U is linked to A the same call lands, so the refusal was U's
/// binding and nothing else.
#[sqlx::test(migrations = "../../migrations")]
async fn an_opl01_supersede_is_a_coded_invalid_request(pool: PgPool) {
    let s = armed(&pool, "k5-opl01").await;
    let (u, _) = fixture::seed_agent_with_group(&pool, "k5-opl01-unbound-u").await;
    add_member(&pool, s.ag, u, "writer").await;
    arm(&pool).await;

    let err = supersede_as(&pool, &s.server, u, s.x_claim)
        .await
        .expect_err("an unbound caller may not supersede once armed");
    assert_eq!(err.code, ErrorCode::INVALID_REQUEST, "{err:?}");
    assert!(err.message.contains("OPL01"), "the code is named: {err:?}");
    assert_nothing_written(&pool, s.x_claim, "OPL01").await;

    link(&pool, u, s.a).await;
    supersede_as(&pool, &s.server, u, s.x_claim)
        .await
        .unwrap_or_else(|e| panic!("CONTROL: U, now bound to A, supersedes: {e:?}"));
    assert!(!is_current(&pool, s.x_claim).await, "CONTROL: it landed");
}

/// K5, OPL02 (migration 122 section 1b): Z writes A's group and is bound, but
/// to human C, who does not write that group, so once armed the database
/// refuses Z's supersede of X's claim. `INVALID_REQUEST` naming OPL02, nothing
/// written. Red before K5: the redacted `-32603`.
///
/// CONTROL: once C writes A's group the same call lands, so the refusal was
/// C's scope and nothing else.
#[sqlx::test(migrations = "../../migrations")]
async fn an_opl02_supersede_is_a_coded_invalid_request(pool: PgPool) {
    let s = armed(&pool, "k5-opl02").await;
    let (c_human, _) = fixture::seed_human_operator(&pool, "k5-opl02-human-c").await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "k5-opl02-c-agent-z").await;
    link(&pool, z, c_human).await;
    add_member(&pool, s.ag, z, "writer").await;
    arm(&pool).await;

    let err = supersede_as(&pool, &s.server, z, s.x_claim)
        .await
        .expect_err("an agent whose human does not write the group may not supersede");
    assert_eq!(err.code, ErrorCode::INVALID_REQUEST, "{err:?}");
    assert!(err.message.contains("OPL02"), "the code is named: {err:?}");
    assert!(
        !err.message.contains("OPL01"),
        "calibration: Z is bound, so this is the scope refusal: {err:?}"
    );
    assert_nothing_written(&pool, s.x_claim, "OPL02").await;

    add_member(&pool, s.ag, c_human, "writer").await;
    let r = supersede_as(&pool, &s.server, z, s.x_claim)
        .await
        .unwrap_or_else(|e| panic!("CONTROL: C now writes the group: {e:?}"));
    assert!(!is_current(&pool, s.x_claim).await, "CONTROL: it landed");
    let new: Uuid = first_text(&r)["new_claim_id"]
        .as_str()
        .and_then(|v| v.parse().ok())
        .expect("new_claim_id");
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(new)
        .fetch_one(&pool)
        .await
        .expect("successor");
    assert_eq!(author, s.x, "CONTROL: the successor keeps X");
}

/// K5 / addendum (c2), the realistic refusal: a `claims:admin` caller borrows
/// the server agent's stamp onto a PUBLIC claim owned by a group the server
/// agent does not write. Row security refuses the act (the deferral, and so
/// CX03, is never reached): `INVALID_REQUEST` with the group-write denial,
/// nothing written, no deferral. Red before K5: the redacted `-32603`.
///
/// CONTROL: the same token on a claim in the server agent's own group lands
/// on the borrowed stamp, so the refusal is the owner group's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_borrow_onto_a_group_the_server_does_not_write_is_a_named_denial(pool: PgPool) {
    let (server, server_agent) = app_role_server(&pool).await;
    let server_group = personal_group_of(&pool, server_agent).await;
    let (x, xg) = fixture::seed_agent_with_group(&pool, "k5-borrow-author-x").await;
    let (admin, _) = fixture::seed_agent_with_group(&pool, "k5-borrow-admin").await;
    let c = claim_of(&pool, x, xg, "X's public claim, X's group").await;
    let token = human(admin, &["claims:write", "claims:admin"]);
    seed_admin_grant(&pool, &token).await;
    let av = viewer(&pool, admin).await;
    let sv = viewer(&pool, server_agent).await;
    assert!(
        !sv.writable_groups().contains(&xg),
        "fixture: the server agent does not write X's group"
    );

    let err = supersede_claim(&server, &av, params(c), Some(&token))
        .await
        .expect_err("the borrowed stamp cannot write X's group");
    assert_eq!(err.code, ErrorCode::INVALID_REQUEST, "{err:?}");
    assert!(
        err.message.contains(GROUP_WRITE_REFUSED) && err.message.contains("nothing was written"),
        "the named group-write denial: {err:?}"
    );
    assert!(
        !err.message.contains("CX03"),
        "row security refuses the act before the deferral runs: {err:?}"
    );
    assert_nothing_written(&pool, c, "borrow").await;

    let mine = claim_of(&pool, x, server_group, "X's claim, server group").await;
    supersede_claim(&server, &av, params(mine), Some(&token))
        .await
        .unwrap_or_else(|e| panic!("CONTROL: the borrow writes the server's group: {e:?}"));
    assert!(!is_current(&pool, mine).await, "CONTROL: it landed");
}

/// K5 / addendum (c2) on stdio: the server agent AUTHORED a public claim that
/// is owned by a group it does not write. stdio admits the act by authorship
/// (`require_owner_or_admin`), and row security then refuses it on the server
/// agent's stamp: `INVALID_REQUEST` with the group-write denial, nothing
/// written, no deferral. Red before K5: the redacted `-32603`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_author_outside_the_owner_group_is_a_named_denial(pool: PgPool) {
    let (server, server_agent) = app_role_server(&pool).await;
    let (_, xg) = fixture::seed_agent_with_group(&pool, "k5-stdio-other-group").await;
    let c = claim_of(
        &pool,
        server_agent,
        xg,
        "the server agent's claim, another group",
    )
    .await;
    let sv = viewer(&pool, server_agent).await;
    assert!(
        !sv.writable_groups().contains(&xg),
        "fixture: the server agent does not write the owner group"
    );

    let err = supersede_claim(&server, &sv, params(c), None)
        .await
        .expect_err("authorship admits the call; row security refuses the write");
    assert_eq!(err.code, ErrorCode::INVALID_REQUEST, "{err:?}");
    assert!(
        err.message.contains(GROUP_WRITE_REFUSED),
        "the named group-write denial: {err:?}"
    );
    assert!(!err.message.contains("CX03"), "{err:?}");
    assert_nothing_written(&pool, c, "stdio").await;
}

/// Revoke the application role's EXECUTE on migration 120's deferral definer,
/// the deploy fault a missing grant is: the deferral then fails with an
/// UNCODED `42501` ("permission denied for function ...") that is no refusal
/// of the caller. Calibrated: the role really lost the privilege.
async fn revoke_deferral_execute(pool: &PgPool) {
    const DEFERRAL: &str = "public.epigraph_record_cascade_deferral(text, uuid, uuid, uuid, \
                            uuid[], jsonb, text)";
    sqlx::query(&format!(
        "REVOKE EXECUTE ON FUNCTION {DEFERRAL} FROM epigraph_app, PUBLIC"
    ))
    .execute(pool)
    .await
    .expect("revoke the deferral's EXECUTE");
    let granted: bool =
        sqlx::query_scalar("SELECT has_function_privilege('epigraph_app', $1, 'EXECUTE')")
            .bind(DEFERRAL)
            .fetch_one(pool)
            .await
            .expect("read the privilege");
    assert!(
        !granted,
        "calibration: epigraph_app no longer runs the deferral"
    );
}

/// K5, the deferral's fault arm (code-lens review): the supersede deferral
/// answers ONLY CX03 as the caller's denial. Any other deferral error is the
/// server's fault and stays `INTERNAL_ERROR`, as `admin_session_or_deferral`
/// answers it for the other claim acts; it is never the group-write denial,
/// which would tell an author who writes the group that it does not.
///
/// Driven end to end: the author supersedes its own claim on an app-role
/// server with no maintenance connection, so the act lands in the transaction
/// and the deferral INSERT then fails on the revoked grant. Nothing commits.
/// Red before the fix: `INVALID_REQUEST` with the group-write words.
///
/// CONTROL first: before the revoke the same author's supersession lands and
/// records its deferral, so the fault is the grant and nothing else.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deferral_fault_that_is_not_cx03_stays_a_server_fault(pool: PgPool) {
    let (server, _) = app_role_server(&pool).await;
    let (h, hg) = fixture::seed_agent_with_group(&pool, "k5-fault-author").await;

    let control = claim_of(
        &pool,
        h,
        hg,
        "the author's claim, superseded before the fault",
    )
    .await;
    supersede_as(&pool, &server, h, control)
        .await
        .unwrap_or_else(|e| panic!("CONTROL: the author supersedes its own claim: {e:?}"));
    assert!(!is_current(&pool, control).await, "CONTROL: it landed");
    assert_eq!(
        deferrals(&pool).await,
        1,
        "CONTROL: its deferral was recorded"
    );

    revoke_deferral_execute(&pool).await;
    let c = claim_of(
        &pool,
        h,
        hg,
        "the author's claim, superseded after the fault",
    )
    .await;
    let err = supersede_as(&pool, &server, h, c)
        .await
        .expect_err("the deferral cannot be recorded, so nothing commits");
    assert_eq!(
        err.code,
        ErrorCode::INTERNAL_ERROR,
        "a missing grant is a server fault, not the caller's denial: {err:?}"
    );
    assert!(
        !err.message.contains(GROUP_WRITE_REFUSED),
        "the author writes the group; the reply must not say it does not: {err:?}"
    );
    assert!(is_current(&pool, c).await, "nothing retired");
    assert_eq!(successors(&pool, c).await, 0, "no successor");
    assert_eq!(deferrals(&pool).await, 1, "no second deferral");
}

/// A REAL database error with SQLSTATE `42501` and `message`, raised on the
/// harness connection (no policy, no grant change) and converted as every repo
/// call converts it. Calibrated: it arrives as `DbError::QueryFailed` carrying
/// the database error, which is the shape the supersede mappers read.
async fn raised_42501(pool: &PgPool, message: &str) -> epigraph_db::DbError {
    let sql = format!(
        "DO $$ BEGIN RAISE EXCEPTION '{}' USING ERRCODE = '42501'; END $$",
        message.replace('\'', "''")
    );
    let raw = sqlx::query(&sql)
        .execute(pool)
        .await
        .expect_err("the DO block raises");
    let e = epigraph_db::DbError::from(raw);
    match &e {
        epigraph_db::DbError::QueryFailed {
            source: sqlx::Error::Database(d),
        } => {
            assert_eq!(d.code().as_deref(), Some("42501"), "calibration: {e:?}");
            assert_eq!(d.message(), message, "calibration: {e:?}");
        }
        other => panic!("calibration: a raw 42501 arrives as QueryFailed: {other:?}"),
    }
    e
}

/// K5, the coded-versus-uncoded `42501` split (test-lens review): a `42501`
/// whose message opens with a refusal code OTHER than CX03 keeps its code. It
/// is not rewritten to the group-write denial (that arm is for row security's
/// uncoded text), and goes on to `errors::db_caller_error`, the shared mapper
/// a reviewed refusal list will extend.
///
/// The code is `ZZ99`, which no `DbError` arm claims (RT07, also `42501`, is
/// converted to `Refused` before any mapper sees it). Today's class is pinned:
/// `db_caller_error` relays an unlisted coded refusal as `INTERNAL_ERROR` with
/// its text, so a reviewed list turning it into `INVALID_REQUEST` is a visible
/// change here.
///
/// CONTROL: an uncoded `42501` (row security's words) through the same mapper
/// is the group-write denial, so the split is what decides.
#[sqlx::test(migrations = "../../migrations")]
async fn a_coded_42501_other_than_cx03_keeps_its_code(pool: PgPool) {
    let claim = Uuid::new_v4();
    let coded = supersede_refusal(claim, raised_42501(&pool, "ZZ99: a probe refusal").await);
    assert!(
        coded.message.starts_with("ZZ99:"),
        "a coded refusal keeps its code: {coded:?}"
    );
    assert!(
        !coded.message.contains(GROUP_WRITE_REFUSED),
        "a coded refusal is not the group-write denial: {coded:?}"
    );
    assert_eq!(
        coded.code,
        ErrorCode::INTERNAL_ERROR,
        "pinned: db_caller_error relays an unlisted coded refusal as INTERNAL_ERROR: {coded:?}"
    );

    let uncoded = supersede_refusal(
        claim,
        raised_42501(
            &pool,
            "new row violates row-level security policy for table \"claims\"",
        )
        .await,
    );
    assert_eq!(
        uncoded.code,
        ErrorCode::INVALID_REQUEST,
        "CONTROL: {uncoded:?}"
    );
    assert!(
        uncoded.message.contains(GROUP_WRITE_REFUSED),
        "CONTROL: row security's uncoded 42501 is the group-write denial: {uncoded:?}"
    );
}
