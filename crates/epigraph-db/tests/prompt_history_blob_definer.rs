//! Migration 276's `epigraph_agent_prompt_history_blob`: the one-file
//! prompt-history read behind `GET /api/v1/agents/:id/prompt-history/blobs/:hash`
//! (backlog aaaf3cad).
//!
//! * ONE FILE IS READ: a read of one file, through the definer and through
//!   [`AgentIdentityRepository::prompt_history_blob`], fetches exactly one row
//!   of `agent_prompt_blobs` (counted in `pg_stat_xact_user_tables`), where
//!   161's `epigraph_agent_prompt_history` fetches every file the lineage
//!   names (CALIBRATION, measured the same way);
//! * the catalog shape: a SECURITY DEFINER owned by `epigraph_maintenance`,
//!   STABLE, on `pg_catalog, pg_temp`, EXECUTE-able by the application and
//!   maintenance roles and not by PUBLIC or the attestor;
//! * the gate is 161's: the admin assignment, the refusal and the per-member
//!   readable mark are the text of 161's current body, and on every caller
//!   shape built here 276 refuses (AID06) exactly when 161 does;
//! * the answer is 161's: for every file the lineage names, as the operator
//!   and as an unarmed custodian, 276 returns the bytes 161 returns for that
//!   key from a readable row, and nothing for a key only an unreadable member
//!   names or no snapshot names;
//! * a missing agent or key is refused 22004; the undo drops only 276.
//!
//! Each caller-dependent call runs on a session whose `session_user` IS
//! `epigraph_app` (`SET SESSION AUTHORIZATION`), stamped with the principal
//! under test: on the superuser connection `epigraph_bypass()` is true and
//! every caller would be an admin. Fixture rows are seeded on the superuser
//! connection.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{
    AgentIdentityRepository, AgentRepository, IdentityRegistration, PromptBlobRead, PromptFile,
};
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

const BLOB: &str = "public.epigraph_agent_prompt_history_blob(uuid, bytea)";
const HISTORY: &str = "public.epigraph_agent_prompt_history(uuid)";
const META: &str =
    "public.epigraph_agent_prompt_history_meta(uuid, integer, uuid, timestamptz, uuid, integer)";
const ATTESTOR: &str = "epigraph_identity_attestor";

fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

fn key_of(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
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

/// The LEARNED.md a registration in `group` stores.
fn learned_of(group: &str) -> Vec<u8> {
    format!("lesson of {group}\n").into_bytes()
}

/// The CLAUDE.md every registration here shares.
const SHARED: &[u8] = b"group rules\n";

/// A registered identity in `group`, storing the shared CLAUDE.md and its own
/// LEARNED.md, through the attestor role.
async fn register(pool: &PgPool, group: &str, parent: Option<Uuid>) -> Uuid {
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
        group_claude_md: PromptFile::Stored(SHARED.to_vec()),
        learned_md: PromptFile::Stored(learned_of(group)),
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
    .map(|r| r.agent_id)
    .expect("the attestor registers")
}

/// A three-generation lineage all linked to `operator` (a child registered
/// under a linked parent inherits the link): `(parent, agent, child)`. It
/// names four distinct stored files: the shared CLAUDE.md and one LEARNED.md
/// per generation.
async fn family(pool: &PgPool, operator: Uuid, tag: &str) -> (Uuid, Uuid, Uuid) {
    let parent = register(pool, &format!("{tag}-p"), None).await;
    link(pool, parent, operator).await;
    let agent = register(pool, &format!("{tag}-a"), Some(parent)).await;
    let child = register(pool, &format!("{tag}-c"), Some(agent)).await;
    (parent, agent, child)
}

async fn set_principal(conn: &mut PgConnection, principal: Option<Uuid>) {
    // ALWAYS set it ('' = none): a session setting survives on a pooled
    // connection.
    sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
        .bind(principal.map(|p| p.to_string()).unwrap_or_default())
        .execute(&mut *conn)
        .await
        .expect("set principal");
}

/// This backend's `agent_prompt_blobs` read counters not yet flushed to the
/// cumulative statistics: `(seq_scan, seq_tup_read, idx_tup_fetch)`.
async fn blob_reads(conn: &mut PgConnection) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT seq_scan, seq_tup_read, idx_tup_fetch FROM pg_catalog.pg_stat_xact_user_tables \
          WHERE relid = 'public.agent_prompt_blobs'::regclass",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("pg_stat_xact_user_tables")
}

/// How the counted read is made.
#[derive(Clone, Copy, Debug)]
enum Read {
    /// [`AgentIdentityRepository::prompt_history_blob`], the route's read.
    Repo,
    /// 276's definer, directly.
    Definer276,
    /// 161's whole-history definer, filtered to the key afterwards: what the
    /// route read before 276 (CALIBRATION).
    History161,
}

/// Read the file `key` of `agent`'s history as `principal` on an
/// `epigraph_app` session, in ONE transaction with sequential scans off, and
/// count the `agent_prompt_blobs` rows that read fetched. Returns the
/// raw file content the read produced (`None` when it named none) and the
/// counts.
///
/// Sequential scans are off so that the count says which rows the read ASKED
/// for: a sequential scan fetches every row of the table whatever the query
/// wants. `seq_scan` is returned so a test can see the setting held.
async fn counted_read(
    pool: &PgPool,
    how: Read,
    principal: Uuid,
    agent: Uuid,
    key: [u8; 32],
) -> (Option<Vec<u8>>, (i64, i64, i64)) {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        set_principal(&mut conn, Some(principal)).await;
        let mut tx = conn.begin().await.expect("begin");
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *tx)
            .await
            .expect("seqscan off");
        // The "xact" counters also hold this backend's not-yet-flushed counts
        // of earlier transactions (PostgreSQL 15+ flushes them only while the
        // backend is idle outside a transaction), so the read is the
        // difference across it; nothing is flushed inside a transaction block.
        let before = blob_reads(&mut tx).await;
        let content = match how {
            Read::Repo => {
                match AgentIdentityRepository::prompt_history_blob(&mut tx, agent, &key)
                    .await
                    .expect("the repository reads")
                {
                    PromptBlobRead::Verified(b) => Some(b.bytes),
                    PromptBlobRead::NotNamed => None,
                    PromptBlobRead::Withheld(why) => panic!("withheld: {why}"),
                }
            }
            Read::Definer276 => sqlx::query_scalar::<_, Option<Vec<u8>>>(
                "SELECT content FROM public.epigraph_agent_prompt_history_blob($1, $2)",
            )
            .bind(agent)
            .bind(key.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .expect("276 reads")
            .flatten()
            .map(|z| zstd::decode_all(z.as_slice()).expect("a zstd frame")),
            Read::History161 => sqlx::query_scalar::<_, Option<Vec<u8>>>(
                "SELECT CASE $2 WHEN identity_md_hash      THEN identity_md \
                                WHEN global_claude_md_hash THEN global_claude_md \
                                WHEN group_claude_md_hash  THEN group_claude_md \
                                ELSE learned_md END \
                   FROM public.epigraph_agent_prompt_history($1) \
                  WHERE readable \
                    AND $2 IN (identity_md_hash, global_claude_md_hash, group_claude_md_hash, \
                               learned_md_hash) \
                  LIMIT 1",
            )
            .bind(agent)
            .bind(key.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .expect("161 reads")
            .flatten()
            .map(|z| zstd::decode_all(z.as_slice()).expect("a zstd frame")),
        };
        let after = blob_reads(&mut tx).await;
        let counts = (after.0 - before.0, after.1 - before.1, after.2 - before.2);
        tx.commit().await.expect("commit");
        (conn, (content, counts))
    })
    .await
}

/// THE PROPERTY (backlog aaaf3cad). Reading one file of a three-generation
/// history fetches ONE row of `agent_prompt_blobs`, through the repository
/// the route calls and through 276 itself, for each of the four files the
/// lineage names; 161's whole-history read, measured the same way, fetches at
/// least every file the lineage names (CALIBRATION: the count sees a
/// whole-lineage read).
#[sqlx::test(migrations = "../../migrations")]
async fn reading_one_file_fetches_only_that_files_blob(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let (_parent, agent, _child) = family(&pool, operator, "g-one").await;
    let files: Vec<Vec<u8>> = vec![
        SHARED.to_vec(),
        learned_of("g-one-p"),
        learned_of("g-one-a"),
        learned_of("g-one-c"),
    ];

    let (content, (seq, _, fetched)) = counted_read(
        &pool,
        Read::History161,
        operator,
        agent,
        key_of(&learned_of("g-one-a")),
    )
    .await;
    assert_eq!(
        content.as_deref(),
        Some(learned_of("g-one-a").as_slice()),
        "CALIBRATION: 161 serves the file"
    );
    assert_eq!(seq, 0, "CALIBRATION: no sequential scan of the blob table");
    assert!(
        fetched >= files.len() as i64,
        "CALIBRATION: 161 fetches every file the lineage names ({} files), got {fetched}",
        files.len()
    );

    for how in [Read::Repo, Read::Definer276] {
        for file in &files {
            let (content, (seq, seq_rows, fetched)) =
                counted_read(&pool, how, operator, agent, key_of(file)).await;
            assert_eq!(
                content.as_deref(),
                Some(file.as_slice()),
                "{how:?} serves the file"
            );
            assert_eq!(
                (seq, seq_rows),
                (0, 0),
                "CALIBRATION ({how:?}): no sequential scan of the blob table"
            );
            assert_eq!(
                fetched, 1,
                "{how:?}: one file read fetches exactly that file's blob row"
            );
        }
    }
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

#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_is_owned_pinned_and_granted_to_the_request_role(pool: PgPool) {
    let c = catalog(&pool, BLOB).await;
    assert!(c.prosecdef, "SECURITY DEFINER");
    assert_eq!(c.owner, "epigraph_maintenance", "owner");
    assert_eq!(c.provolatile, "s", "STABLE");
    assert_eq!(
        c.proconfig,
        Some(vec!["search_path=pg_catalog, pg_temp".to_string()]),
        "172's path"
    );
    assert_eq!(c.result, "TABLE(content bytea)", "one content column");
    for (role, expected) in [
        ("public", false),
        ("epigraph_app", true),
        ("epigraph_maintenance", true),
        (ATTESTOR, false),
    ] {
        let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
            .bind(role)
            .bind(BLOB)
            .fetch_one(&pool)
            .await
            .expect("privilege");
        assert_eq!(can, expected, "{role} EXECUTE");
    }
}

/// 161's admin assignment, its refusal and its per-member readable mark
/// appear in 276's body token for token (whitespace removed), taken from
/// 161's CURRENT body, so the gates cannot drift apart silently.
#[sqlx::test(migrations = "../../migrations")]
async fn the_gate_and_the_readable_mark_are_the_text_of_161s(pool: PgPool) {
    let strip = |s: String| -> String { s.split_whitespace().collect() };
    let history = strip(catalog(&pool, HISTORY).await.src);
    let blob = strip(catalog(&pool, BLOB).await.src);
    let start = history.find("v_admin:=").expect("161 assigns v_admin");
    let len = history[start..].find("END);").expect("ends the CASE") + "END);".len();
    let gate = &history[start..start + len];
    assert!(
        gate.contains("epigraph_is_instance_admin") && gate.contains("epigraph_is_elevated"),
        "CALIBRATION: the extracted text is the admin test: {gate}"
    );
    assert!(blob.contains(gate), "276's admin test is 161's: {gate}");
    let refusal = "IFNOTv_adminAND(v_principalISNULLORpublic.epigraph_human_of(p_agent,false)\
                   ISDISTINCTFROMv_principal)THEN";
    assert!(history.contains(refusal), "CALIBRATION: 161's refusal");
    assert!(blob.contains(refusal), "276's refusal is 161's");
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
    let mark_276 = mark_161.replace("l.id", "w.id");
    assert!(
        blob.contains(&mark_276),
        "276's per-member readable mark is 161's: {mark_276}"
    );
    // The walk is 161's too: 64 generations each way.
    assert_eq!(
        history.matches("v_level<64").count(),
        2,
        "CALIBRATION: 161 bounds both directions"
    );
    assert_eq!(
        blob.matches("v_level<64").count(),
        2,
        "276 bounds both directions"
    );
}

/// Whether `sql` (`$1` the agent, `$2` a key) admits `principal` on an
/// `epigraph_app` session: `true` when it answers, `false` when it refuses
/// AID06 (any other error fails the test).
async fn admits(pool: &PgPool, sql: &'static str, principal: Option<Uuid>, agent: Uuid) -> bool {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        set_principal(&mut conn, principal).await;
        let r = sqlx::query_scalar::<_, i64>(sql)
            .bind(agent)
            .bind(random32().as_slice())
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

// `$2` is unused by 161; `$2 IS NOT NULL` keeps both statements binding it.
const COUNT_161: &str =
    "SELECT count(*) FROM public.epigraph_agent_prompt_history($1) WHERE $2::bytea IS NOT NULL";
const COUNT_276: &str =
    "SELECT count(*) FROM public.epigraph_agent_prompt_history_blob($1, $2::bytea)";

/// On every caller shape built here, 276 refuses (AID06) exactly when 161
/// does, unarmed and armed, and for a key no snapshot names (the gate runs
/// before the key is looked at, so a refused caller cannot probe keys).
#[sqlx::test(migrations = "../../migrations")]
async fn the_gate_admits_exactly_whom_161_admits(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let retired_operator = human_operator(&pool).await;
    let stranger = human_operator(&pool).await;
    let custodian = human_operator(&pool).await;
    fixture::make_custodian(&pool, custodian).await;

    let agent = register(&pool, "g-parity", None).await;
    link(&pool, agent, operator).await;
    let retired_agent = register(&pool, "g-parity-r", None).await;
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
            admits(&pool, COUNT_276, *who, *target).await,
            *admitted,
            "276 on {what}"
        );
    }

    sqlx::query("SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'blob')")
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
            admits(&pool, COUNT_276, *who, *target).await,
            *admitted,
            "276 on {what}"
        );
    }
}

/// The content `sql` returns for `key` as `principal` on an `epigraph_app`
/// session (`None`: no row, or a NULL).
async fn content_as(
    pool: &PgPool,
    sql: &'static str,
    principal: Uuid,
    agent: Uuid,
    key: [u8; 32],
) -> Option<Vec<u8>> {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        set_principal(&mut conn, Some(principal)).await;
        let r = sqlx::query_scalar::<_, Option<Vec<u8>>>(sql)
            .bind(agent)
            .bind(key.as_slice())
            .fetch_optional(&mut *conn)
            .await;
        (conn, r)
    })
    .await
    .unwrap_or_else(|e| panic!("{sql}: {e}"))
    .flatten()
}

/// 161's answer for one key: the content of the first readable row that
/// names it (the route's read before 276).
const FILE_161: &str = "SELECT CASE $2 WHEN identity_md_hash      THEN identity_md \
                                       WHEN global_claude_md_hash THEN global_claude_md \
                                       WHEN group_claude_md_hash  THEN group_claude_md \
                                       ELSE learned_md END \
                          FROM public.epigraph_agent_prompt_history($1) \
                         WHERE readable \
                           AND $2 IN (identity_md_hash, global_claude_md_hash, \
                                      group_claude_md_hash, learned_md_hash) \
                         LIMIT 1";
const FILE_276: &str = "SELECT content FROM public.epigraph_agent_prompt_history_blob($1, $2)";

/// As the agent's operator and as an unarmed custodian, 276 answers every key
/// exactly as 161 does: the same stored bytes for a file a readable member
/// names (its own, a readable descendant's), nothing for the file only the
/// other operator's parent names (an unreadable member, for the operator),
/// and nothing for a key no snapshot names.
#[sqlx::test(migrations = "../../migrations")]
async fn every_key_is_answered_as_161_answers_it(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let other = human_operator(&pool).await;
    let custodian = human_operator(&pool).await;
    fixture::make_custodian(&pool, custodian).await;
    // Link after the agent's registration: a child registered under a linked
    // parent inherits the parent's link.
    let parent = register(&pool, "g-ans-p", None).await;
    let agent = register(&pool, "g-ans-a", Some(parent)).await;
    link(&pool, agent, operator).await;
    link(&pool, parent, other).await;
    let _child = register(&pool, "g-ans-c", Some(agent)).await;

    let parents_only = key_of(&learned_of("g-ans-p"));
    let keys = [
        key_of(SHARED),
        key_of(&learned_of("g-ans-a")),
        key_of(&learned_of("g-ans-c")),
        parents_only,
        random32(),
    ];
    for (who, label) in [(operator, "operator"), (custodian, "custodian")] {
        for key in keys {
            let want = content_as(&pool, FILE_161, who, agent, key).await;
            let got = content_as(&pool, FILE_276, who, agent, key).await;
            assert_eq!(got, want, "{label}, key {}", hex::encode(key));
        }
    }
    assert!(
        content_as(&pool, FILE_161, operator, agent, key_of(SHARED))
            .await
            .is_some(),
        "CALIBRATION: the operator reads a file its own snapshot names"
    );
    assert!(
        content_as(&pool, FILE_161, operator, agent, parents_only)
            .await
            .is_none(),
        "CALIBRATION: the operator cannot read the other operator's parent's file"
    );
    assert!(
        content_as(&pool, FILE_161, custodian, agent, parents_only)
            .await
            .is_some(),
        "CALIBRATION: the unarmed custodian reads it"
    );
}

/// An agent and a key are both required (22004), as 161 requires an agent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_agent_or_key_is_refused(pool: PgPool) {
    let agent = register(&pool, "g-null", None).await;
    for (what, a, k) in [
        ("no agent", None, Some(random32().to_vec())),
        ("no key", Some(agent), None),
    ] {
        let err = sqlx::query(
            "SELECT count(*) FROM public.epigraph_agent_prompt_history_blob($1, $2::bytea)",
        )
        .bind(a)
        .bind(k)
        .execute(&pool)
        .await
        .expect_err("refused");
        assert_eq!(
            err.as_database_error()
                .and_then(|d| d.code())
                .map(|c| c.to_string())
                .as_deref(),
            Some("22004"),
            "{what}: {err}"
        );
    }
}

/// The undo runbook drops 276's definer and nothing else (161's and 268's
/// stay), and a second run changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_undo_drops_only_the_definer_and_is_idempotent(pool: PgPool) {
    const UNDO: &str = include_str!("../../../docs/runbooks/276-undo.sql");
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
    assert!(exists(BLOB).await, "CALIBRATION: 276 is applied");
    for run in 1..=2 {
        sqlx::raw_sql(UNDO)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("undo run {run}: {e}"));
        assert!(!exists(BLOB).await, "run {run}: 276's definer is gone");
        assert!(exists(HISTORY).await, "run {run}: 161's definer stays");
        assert!(exists(META).await, "run {run}: 268's definer stays");
    }
}
