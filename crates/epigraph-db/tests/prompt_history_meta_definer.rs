//! Migration 268's `epigraph_agent_prompt_history_meta`: the content-free,
//! paged prompt-history definer (backlog bedd59b7, 24a9f4fa).
//!
//! * the catalog shape: a SECURITY DEFINER owned by `epigraph_maintenance`,
//!   STABLE, on 172's `pg_catalog, pg_temp` path, EXECUTE-able by the
//!   application and maintenance roles and not by PUBLIC; its result is 161's
//!   columns without the four content columns (plus the walk's extent), and
//!   its body never names `agent_prompt_blobs`;
//! * content-free in fact: with the owner's SELECT on `agent_prompt_blobs`
//!   revoked, 161 can no longer answer (CALIBRATION) and 268 still returns
//!   161's rows, keys and all;
//! * the gate is 161's: the admin assignment and the per-member readable mark
//!   are the same text as 161's current body, on every caller shape built
//!   here 268 refuses (AID06) exactly when 161 does, and as an operator (and
//!   a custodian) on an application session it lists exactly 161's rows;
//! * paging: at every page size the pages, followed by their cursors, are the
//!   unpaged listing in order, once each, across a tie in `first_seen` and a
//!   row with no snapshot; a half cursor is refused 22023.
//!
//! Each gate call runs on a session whose `session_user` IS `epigraph_app`
//! (`SET SESSION AUTHORIZATION`), stamped with the principal under test: on the
//! superuser connection `epigraph_bypass()` is true and every caller would be
//! an admin. Fixture rows are seeded on the superuser connection.

#[path = "viewer_fixture.rs"]
mod fixture;

use chrono::{DateTime, Duration, Utc};
use epigraph_db::{
    AgentIdentityRepository, AgentRepository, IdentityRegistration, PromptFile,
    PromptHistoryCursor, PromptHistoryIndexEntry, PromptHistoryPage,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const META: &str =
    "public.epigraph_agent_prompt_history_meta(uuid, integer, uuid, timestamptz, uuid, integer)";
const HISTORY: &str = "public.epigraph_agent_prompt_history(uuid)";
const ATTESTOR: &str = "epigraph_identity_attestor";

fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

async fn human_operator(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(random32().as_slice())
        .execute(pool)
        .await
        .expect("seed operator agent");
    fixture::make_human_operator(pool, agent).await;
    agent
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "CALIBRATION: the manual link is live");
}

/// A registered identity in `group`, with a stored LEARNED.md, through the
/// attestor role: `(agent, snapshot)`.
async fn register(pool: &PgPool, group: &str, parent: Option<Uuid>) -> (Uuid, Uuid) {
    let pubkey = random32();
    let reg = IdentityRegistration {
        identity_pubkey: pubkey,
        parent_agent_id: parent,
        model: "model-x".into(),
        prompt_hash: blake3::hash(&pubkey).to_hex().to_string(),
        group_folder: group.into(),
        signing_pubkey: Some(random32()),
        identity_md: PromptFile::Absent,
        global_claude_md: PromptFile::Absent,
        group_claude_md: PromptFile::Stored(b"group rules\n".to_vec()),
        learned_md: PromptFile::Stored(format!("lesson of {group}\n").into_bytes()),
        in_prompt: json!({"identity_md": false, "global_claude_md": false,
                          "group_claude_md": true, "learned_md": true}),
        runner_version: Some("runner-test".into()),
        host_sha: None,
    };
    fixture::as_role(pool, ATTESTOR, |mut conn| async move {
        let r = AgentIdentityRepository::register(&mut conn, &reg).await;
        (conn, r)
    })
    .await
    .map(|r| (r.agent_id, r.snapshot_id))
    .expect("the attestor registers")
}

/// A snapshot row written directly (superuser) at a chosen `first_seen`.
async fn snapshot_row(pool: &PgPool, agent: Uuid, tag: &str, first_seen: DateTime<Utc>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agent_prompt_snapshots \
             (agent_id, group_folder, model, prompt_hash, in_prompt, first_seen, last_seen) \
         VALUES ($1, $2, 'model-x', $3, '{}'::jsonb, $4, $4) RETURNING id",
    )
    .bind(agent)
    .bind(format!("g-{tag}"))
    .bind(blake3::hash(agent.as_bytes()).to_hex().to_string())
    .bind(first_seen)
    .fetch_one(pool)
    .await
    .expect("seed snapshot")
}

/// Whether `sql` (one `$1` = the agent) admits `principal` on an
/// `epigraph_app` session: `true` when it answers, `false` when it refuses
/// AID06 (any other error fails the test).
async fn admits(pool: &PgPool, sql: &'static str, principal: Option<Uuid>, agent: Uuid) -> bool {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        // ALWAYS set it ('' = none): a session setting survives on a pooled
        // connection.
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.map(|p| p.to_string()).unwrap_or_default())
            .execute(&mut *conn)
            .await
            .expect("set principal");
        let r = sqlx::query_scalar::<_, i64>(sql)
            .bind(agent)
            .fetch_one(&mut *conn)
            .await;
        let admitted = match r {
            Ok(_) => true,
            Err(e) => {
                let code = e
                    .as_database_error()
                    .and_then(|d| d.code())
                    .map(|c| c.to_string());
                assert_eq!(code.as_deref(), Some("AID06"), "{sql}: {e}");
                false
            }
        };
        (conn, admitted)
    })
    .await
}

const COUNT_161: &str = "SELECT count(*) FROM public.epigraph_agent_prompt_history($1)";
const COUNT_268: &str =
    "SELECT count(*) FROM public.epigraph_agent_prompt_history_meta($1, NULL, NULL, NULL, NULL, NULL)";

/// The comparable part of a row, as both definers name it.
type Key = (
    Uuid,
    String,
    i32,
    bool,
    Option<Uuid>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

const ROWS_161: &str = "SELECT agent_id, relation, depth, readable, snapshot_id, \
                                group_claude_md_hash, learned_md_hash \
                           FROM public.epigraph_agent_prompt_history($1)";
const ROWS_268: &str = "SELECT agent_id, relation, depth, readable, snapshot_id, \
                                group_claude_md_hash, learned_md_hash \
                           FROM public.epigraph_agent_prompt_history_meta(\
                                $1, NULL, NULL, NULL, NULL, NULL)";

/// Every row of `sql` (161's or 268's listing) on the superuser connection,
/// where `epigraph_bypass()` makes the caller an admin.
async fn rows_admin(pool: &PgPool, sql: &'static str, agent: Uuid) -> Vec<Key> {
    let mut rows: Vec<Key> = sqlx::query_as(sql)
        .bind(agent)
        .fetch_all(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
    rows.sort();
    rows
}

async fn rows_161(pool: &PgPool, agent: Uuid) -> Vec<Key> {
    rows_admin(pool, ROWS_161, agent).await
}

async fn rows_268(pool: &PgPool, agent: Uuid) -> Vec<Key> {
    rows_admin(pool, ROWS_268, agent).await
}

/// Every row of `sql` as `principal` on an `epigraph_app` session, where the
/// per-member `readable` mark (and any per-snapshot filter) actually applies.
async fn rows_as(pool: &PgPool, sql: &'static str, principal: Uuid, agent: Uuid) -> Vec<Key> {
    let mut rows = fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.to_string())
            .execute(&mut *conn)
            .await
            .expect("set principal");
        let r: Result<Vec<Key>, _> = sqlx::query_as(sql).bind(agent).fetch_all(&mut *conn).await;
        (conn, r)
    })
    .await
    .unwrap_or_else(|e| panic!("{sql}: {e}"));
    rows.sort();
    rows
}

#[derive(sqlx::FromRow)]
struct Catalog {
    prosecdef: bool,
    owner: String,
    provolatile: String,
    proconfig: Option<Vec<String>>,
    result: String,
    src: String,
}

async fn catalog(pool: &PgPool, sig: &str) -> Catalog {
    sqlx::query_as(
        "SELECT p.prosecdef, r.rolname::text AS owner, p.provolatile::text, p.proconfig, \
                pg_get_function_result(p.oid) AS result, p.prosrc AS src \
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
          WHERE p.oid = to_regprocedure($1)",
    )
    .bind(sig)
    .fetch_optional(pool)
    .await
    .expect("pg_proc")
    .unwrap_or_else(|| panic!("{sig} must exist"))
}

/// `TABLE(a uuid, b text)` -> `["a uuid", "b text"]`.
fn columns(result: &str) -> Vec<String> {
    result
        .strip_prefix("TABLE(")
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("a TABLE result: {result}"))
        .split(", ")
        .map(str::to_string)
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_is_owned_pinned_content_free_and_granted_to_the_request_role(pool: PgPool) {
    let c = catalog(&pool, META).await;
    assert!(c.prosecdef, "SECURITY DEFINER");
    assert_eq!(c.owner, "epigraph_maintenance", "owner");
    assert_eq!(c.provolatile, "s", "STABLE");
    assert_eq!(
        c.proconfig,
        Some(vec!["search_path=pg_catalog, pg_temp".to_string()]),
        "172's path"
    );
    for (role, expected) in [
        ("public", false),
        ("epigraph_app", true),
        ("epigraph_maintenance", true),
        (ATTESTOR, false),
    ] {
        let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
            .bind(role)
            .bind(META)
            .fetch_one(&pool)
            .await
            .expect("privilege");
        assert_eq!(can, expected, "{role} EXECUTE");
    }

    let content = [
        "identity_md bytea",
        "global_claude_md bytea",
        "group_claude_md bytea",
        "learned_md bytea",
    ];
    let full = columns(&catalog(&pool, HISTORY).await.result);
    for col in content {
        assert!(
            full.iter().any(|c| c == col),
            "CALIBRATION: 161 returns {col}: {full:?}"
        );
    }
    let mut want: Vec<String> = full
        .into_iter()
        .filter(|c| !content.contains(&c.as_str()))
        .collect();
    want.extend([
        "lineage_min_depth integer".to_string(),
        "lineage_max_depth integer".to_string(),
    ]);
    assert_eq!(
        columns(&c.result),
        want,
        "268 is 161's result without the content columns, plus the walk's extent"
    );
    assert!(
        !c.src.contains("agent_prompt_blobs"),
        "268 never reads the blob table"
    );
}

/// The listing does not depend on the blob table at all: with the owner's
/// SELECT on `agent_prompt_blobs` revoked, 161 errors (CALIBRATION: it does
/// read the blobs) while 268 still returns exactly the rows 161 returned
/// before, with every file's key.
#[sqlx::test(migrations = "../../migrations")]
async fn the_listing_reads_no_blob_and_returns_161s_rows(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let (parent, _) = register(&pool, "g-meta", None).await;
    link(&pool, parent, operator).await;
    let (child, _) = register(&pool, "g-meta", Some(parent)).await;

    let before = rows_161(&pool, child).await;
    assert_eq!(before.len(), 2, "CALIBRATION: self and parent: {before:?}");
    assert!(
        before.iter().all(|r| r.6.is_some()),
        "CALIBRATION: every snapshot names a stored file: {before:?}"
    );
    assert_eq!(rows_268(&pool, child).await, before, "the same rows");

    sqlx::query("REVOKE SELECT ON public.agent_prompt_blobs FROM epigraph_maintenance")
        .execute(&pool)
        .await
        .expect("revoke");
    let err = sqlx::query("SELECT count(*) FROM public.epigraph_agent_prompt_history($1)")
        .bind(child)
        .execute(&pool)
        .await
        .expect_err("CALIBRATION: 161 reads the blob table");
    assert_eq!(
        err.as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.to_string())
            .as_deref(),
        Some("42501"),
        "{err}"
    );
    assert_eq!(
        rows_268(&pool, child).await,
        before,
        "268 answers without the blob table"
    );
}

/// 161's admin assignment, `v_admin := ... END);`, and its operator test
/// appear in 268's body token for token (whitespace removed), so the two
/// gates cannot drift apart silently.
#[sqlx::test(migrations = "../../migrations")]
async fn the_gate_is_the_text_of_161s(pool: PgPool) {
    let strip = |s: String| -> String { s.split_whitespace().collect() };
    let history = strip(catalog(&pool, HISTORY).await.src);
    let meta = strip(catalog(&pool, META).await.src);
    let start = history.find("v_admin:=").expect("161 assigns v_admin");
    let len = history[start..].find("END);").expect("ends the CASE") + "END);".len();
    let gate = &history[start..start + len];
    assert!(
        gate.contains("epigraph_is_instance_admin") && gate.contains("epigraph_is_elevated"),
        "CALIBRATION: the extracted text is the admin test: {gate}"
    );
    assert!(meta.contains(gate), "268's admin test is 161's: {gate}");
    let refusal = "IFNOTv_adminAND(v_principalISNULLORpublic.epigraph_human_of(p_agent,false)\
                   ISDISTINCTFROMv_principal)THEN";
    assert!(history.contains(refusal), "CALIBRATION: 161's refusal");
    assert!(meta.contains(refusal), "268's refusal is 161's");
    // The per-member readable mark, taken from 161's CURRENT body (a later
    // re-statement of 161 is what this guards against): 161 names its walk
    // `l`, 268 names it `w`, so only the alias is renamed.
    let mark_start = history
        .find("COALESCE(l.id=p_agent")
        .expect("CALIBRATION: 161 marks each member `l` readable");
    let mark_len = history[mark_start..]
        .find("ASok")
        .expect("CALIBRATION: 161 names the mark `ok`")
        + "ASok".len();
    let mark_161 = &history[mark_start..mark_start + mark_len];
    assert!(
        mark_161.contains("public.epigraph_human_of(l.id,false)=v_principal"),
        "CALIBRATION: the extracted text is the operator test: {mark_161}"
    );
    let mark_268 = mark_161.replace("l.id", "w.id");
    assert!(
        meta.contains(&mark_268),
        "268's per-member readable mark is 161's: {mark_268}"
    );
}

/// As the agent's operator (and as an unarmed custodian), on an
/// `epigraph_app` session, 268 lists exactly 161's rows: the same members
/// marked readable, and none of the unreadable member's snapshots. On the
/// superuser connection every member is readable, so only here is the mark,
/// or any per-snapshot filter a later re-statement of 161 adds, compared.
#[sqlx::test(migrations = "../../migrations")]
async fn as_the_operator_268_lists_and_marks_exactly_161s_rows(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let other = human_operator(&pool).await;
    let custodian = human_operator(&pool).await;
    fixture::make_custodian(&pool, custodian).await;
    // Link after both registrations: a child registered under a linked
    // parent inherits the parent's link.
    let (parent, _) = register(&pool, "g-mark", None).await;
    let (agent, _) = register(&pool, "g-mark", Some(parent)).await;
    link(&pool, agent, operator).await;
    link(&pool, parent, other).await;
    let (_child, _) = register(&pool, "g-mark", Some(agent)).await;
    let hidden = snapshot_row(&pool, parent, "hidden", Utc::now() - Duration::days(2)).await;

    let as_operator = rows_as(&pool, ROWS_161, operator, agent).await;
    assert!(
        as_operator
            .iter()
            .any(|r| r.0 == parent && !r.3 && r.4.is_none()),
        "CALIBRATION: 161 lists the other operator's parent by id only: {as_operator:?}"
    );
    assert!(
        as_operator
            .iter()
            .any(|r| r.0 == agent && r.3 && r.4.is_some()),
        "CALIBRATION: 161 lists the agent's own snapshot: {as_operator:?}"
    );
    assert!(
        as_operator.iter().all(|r| r.4 != Some(hidden)),
        "CALIBRATION: 161 hides the parent's snapshot: {as_operator:?}"
    );
    assert_eq!(
        rows_as(&pool, ROWS_268, operator, agent).await,
        as_operator,
        "268 as the operator"
    );

    let as_custodian = rows_as(&pool, ROWS_161, custodian, agent).await;
    assert!(
        as_custodian.iter().any(|r| r.4 == Some(hidden)),
        "CALIBRATION: the unarmed custodian reads the parent's snapshot: {as_custodian:?}"
    );
    assert_eq!(
        rows_as(&pool, ROWS_268, custodian, agent).await,
        as_custodian,
        "268 as the custodian"
    );
}

/// On every caller shape built here, 268 refuses (AID06) exactly when 161
/// does, unarmed and armed.
#[sqlx::test(migrations = "../../migrations")]
async fn the_gate_admits_exactly_whom_161_admits(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let retired_operator = human_operator(&pool).await;
    let stranger = human_operator(&pool).await;
    let custodian = human_operator(&pool).await;
    fixture::make_custodian(&pool, custodian).await;

    let (agent, _) = register(&pool, "g-parity", None).await;
    link(&pool, agent, operator).await;
    let (retired_agent, _) = register(&pool, "g-parity-r", None).await;
    link(&pool, retired_agent, retired_operator).await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query("SELECT * FROM public.epigraph_retire_operator_link($1, 'test', true)")
            .bind(retired_agent)
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await
    .expect("retire the link");

    let unarmed: Vec<(&str, Option<Uuid>, Uuid, bool)> = vec![
        ("operator, live link", Some(operator), agent, true),
        (
            "operator, retired link",
            Some(retired_operator),
            retired_agent,
            true,
        ),
        ("another human", Some(stranger), agent, false),
        ("an unknown principal", Some(Uuid::new_v4()), agent, false),
        ("no principal", None, agent, false),
        ("the agent itself", Some(agent), agent, false),
        ("custodian, scopes unarmed", Some(custodian), agent, true),
    ];
    for (what, who, target, admitted) in &unarmed {
        assert_eq!(
            admits(&pool, COUNT_161, *who, *target).await,
            *admitted,
            "CALIBRATION: 161 on {what}"
        );
        assert_eq!(
            admits(&pool, COUNT_268, *who, *target).await,
            *admitted,
            "268 on {what}"
        );
    }

    sqlx::query("SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'meta')")
        .execute(&pool)
        .await
        .expect("arm admin scopes");
    let armed: Vec<(&str, Option<Uuid>, Uuid, bool)> = vec![
        (
            "custodian, armed, not elevated",
            Some(custodian),
            agent,
            false,
        ),
        ("operator, armed", Some(operator), agent, true),
        ("stranger, armed", Some(stranger), agent, false),
    ];
    for (what, who, target, admitted) in &armed {
        assert_eq!(
            admits(&pool, COUNT_161, *who, *target).await,
            *admitted,
            "CALIBRATION: 161 on {what}"
        );
        assert_eq!(
            admits(&pool, COUNT_268, *who, *target).await,
            *admitted,
            "268 on {what}"
        );
    }
}

/// One page as `principal` on an `epigraph_app` session, or, with `None`, on
/// the superuser connection (an admin read).
async fn page_as(
    pool: &PgPool,
    principal: Option<Uuid>,
    agent: Uuid,
    after: Option<PromptHistoryCursor>,
    limit: u32,
) -> PromptHistoryPage {
    let Some(principal) = principal else {
        let mut conn = pool.acquire().await.expect("connection");
        return AgentIdentityRepository::prompt_history_page(
            &mut conn,
            agent,
            after.as_ref(),
            limit,
        )
        .await
        .expect("an admin page");
    };
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.to_string())
            .execute(&mut *conn)
            .await
            .expect("set principal");
        let r =
            AgentIdentityRepository::prompt_history_page(&mut conn, agent, after.as_ref(), limit)
                .await;
        (conn, r)
    })
    .await
    .expect("the operator reads a page")
}

/// Every page of `agent`'s listing at `limit`, following the cursors.
async fn all_pages(
    pool: &PgPool,
    principal: Option<Uuid>,
    agent: Uuid,
    limit: u32,
) -> Vec<PromptHistoryIndexEntry> {
    let mut rows = Vec::new();
    let mut after: Option<PromptHistoryCursor> = None;
    for _ in 0..50 {
        let page = page_as(pool, principal, agent, after, limit).await;
        assert!(page.rows.len() <= limit as usize, "at most `limit` rows");
        if page.rows.is_empty() {
            // Past the last row (the previous page was exactly full): no row,
            // so no extent either.
            assert_eq!(
                (page.lineage_min_depth, page.lineage_max_depth),
                (None, None)
            );
            return rows;
        }
        assert_eq!(
            (page.lineage_min_depth, page.lineage_max_depth),
            (Some(-1), Some(1)),
            "every page carries the whole walk's extent (limit {limit})"
        );
        let full = page.rows.len() == limit as usize;
        after = page.rows.last().map(PromptHistoryIndexEntry::cursor);
        rows.extend(page.rows);
        if !full {
            return rows;
        }
    }
    panic!("limit {limit}: the pages do not advance");
}

fn key(r: &PromptHistoryIndexEntry) -> (Uuid, i32, Option<Uuid>) {
    (r.agent_id, r.depth, r.snapshot.as_ref().map(|s| s.id))
}

/// At every page size, the pages followed by their cursors are the unpaged
/// listing, in order, each row once. The lineage holds a tie in `first_seen`
/// (two snapshots of the agent itself), a member with no snapshot (an
/// unreadable parent, as its child's operator sees it) and a descendant, so
/// with `limit` 1 a page boundary falls on every one of them; the same holds
/// for an admin, who reads the parent's snapshot instead.
#[sqlx::test(migrations = "../../migrations")]
async fn pages_followed_by_cursor_are_the_whole_listing_once_in_order(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let other = human_operator(&pool).await;
    let (parent, _) = register(&pool, "g-page", None).await;
    let (agent, _) = register(&pool, "g-page", Some(parent)).await;
    link(&pool, agent, operator).await;
    link(&pool, parent, other).await;
    let (child, _) = register(&pool, "g-page", Some(agent)).await;
    let tie = DateTime::from_timestamp_micros((Utc::now() - Duration::days(1)).timestamp_micros())
        .expect("instant");
    let t1 = snapshot_row(&pool, agent, "tie-1", tie).await;
    let t2 = snapshot_row(&pool, agent, "tie-2", tie).await;

    let whole: Vec<_> = page_as(&pool, Some(operator), agent, None, 1000)
        .await
        .rows
        .iter()
        .map(key)
        .collect();
    let (lo, hi) = (t1.min(t2), t1.max(t2));
    assert_eq!(whole.len(), 5, "CALIBRATION: {whole:?}");
    assert_eq!(whole[0].0, agent, "the agent itself first: {whole:?}");
    assert_eq!(
        (whole[0].2, whole[1].2),
        (Some(lo), Some(hi)),
        "the tie, broken by id, before the later registration: {whole:?}"
    );
    assert_eq!(whole[2].0, agent);
    assert_eq!(
        whole[3],
        (parent, -1, None),
        "the unreadable parent, by id only, before the child at the same distance"
    );
    assert_eq!(whole[4].0, child);

    let admin: Vec<_> = page_as(&pool, None, agent, None, 1000)
        .await
        .rows
        .iter()
        .map(key)
        .collect();
    assert!(
        matches!(admin[3], (p, -1, Some(_)) if p == parent),
        "CALIBRATION: the admin reads the parent's snapshot: {admin:?}"
    );

    for (who, unpaged) in [(Some(operator), &whole), (None, &admin)] {
        for limit in 1..=6 {
            let flat: Vec<_> = all_pages(&pool, who, agent, limit)
                .await
                .iter()
                .map(key)
                .collect();
            assert_eq!(
                &flat, unpaged,
                "{who:?}, limit {limit}: every row once, in order"
            );
        }
    }
}

/// A position names a depth and an agent together, or neither.
#[sqlx::test(migrations = "../../migrations")]
async fn a_half_cursor_is_refused(pool: PgPool) {
    let (agent, _) = register(&pool, "g-half", None).await;
    for sql in [
        "SELECT count(*) FROM public.epigraph_agent_prompt_history_meta($1, 0, NULL, NULL, NULL, 10)",
        "SELECT count(*) FROM public.epigraph_agent_prompt_history_meta($1, NULL, $1, NULL, NULL, 10)",
    ] {
        let err = sqlx::query(sql)
            .bind(agent)
            .execute(&pool)
            .await
            .expect_err("refused");
        assert_eq!(
            err.as_database_error()
                .and_then(|d| d.code())
                .map(|c| c.to_string())
                .as_deref(),
            Some("22023"),
            "{sql}: {err}"
        );
    }
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.epigraph_agent_prompt_history_meta($1, 0, $1, NULL, NULL, 10)",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("CONTROL: a whole cursor reads");
    assert_eq!(
        n, 1,
        "CONTROL: the agent's own snapshot sorts after its no-snapshot position"
    );
}

/// The undo runbook drops 268's definer and nothing else (161's stays), and a
/// second run changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_undo_drops_only_the_definer_and_is_idempotent(pool: PgPool) {
    const UNDO: &str = include_str!("../../../docs/runbooks/268-undo.sql");
    let exists = |sig: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>("SELECT to_regprocedure($1) IS NOT NULL")
                .bind(sig)
                .fetch_one(&pool)
                .await
                .expect("regprocedure")
        }
    };
    assert!(exists(META).await, "CALIBRATION: 268 is applied");
    for run in 1..=2 {
        sqlx::raw_sql(UNDO)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("undo run {run}: {e}"));
        assert!(!exists(META).await, "run {run}: 268's definer is gone");
        assert!(exists(HISTORY).await, "run {run}: 161's definer stays");
    }
}
