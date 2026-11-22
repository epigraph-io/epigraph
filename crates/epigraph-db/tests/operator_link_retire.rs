//! Migration 191 (backlog 4dec90c2): retiring an existing LIVE operator link
//! is an audited, maintenance-only act.
//!
//! Before 191 no definer updated `operator_links`, the table had no UPDATE
//! policy and the maintenance role no UPDATE grant, and its audit trigger
//! fired on INSERT only, so the only way to retire a live link was a raw
//! superuser UPDATE that left no `security_events` row. These tests pin:
//!
//! * every flip of `retired`, on every path (the definer, a direct statement,
//!   a superuser's), writes one `operator.link_retired` /
//!   `operator.link_unretired` audit row;
//! * `epigraph_retire_operator_link` retires a live link once (idempotent: a
//!   repeat returns `already_retired` and writes nothing), refuses while the
//!   agent still holds a live writer/admin row in the operator's group unless
//!   asked to revoke it in the same act, refuses a registered system agent
//!   (148's trigger), and reports an agent with no link without writing;
//! * only a maintenance session may call it, a maintenance session can never
//!   un-retire or re-point a link, and the application role can neither call
//!   it, write the column, nor forge its audit row;
//! * since migration 257 (backlog 9cec11f7) the verb is the ONLY
//!   non-superuser path: a maintenance login's direct UPDATE is refused
//!   (the column belongs to the verb's own owner role), and an audit row's
//!   `via` and reason come from the verb's arguments or not at all.
//!
//! Each test names the mutation it was verified against.

mod viewer_fixture;

use epigraph_db::AgentRepository;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

const RETIRE: &str = "SELECT outcome, operator_id, operator_group_id, memberships_revoked \
                      FROM public.epigraph_retire_operator_link($1, $2, $3)";

type RetireRow = (String, Option<Uuid>, Option<Uuid>, i32);

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.to_string())
}

/// A human operator and an agent LIVE-linked to it through the real link
/// definer (which also records the agent's writer row in the operator's
/// group). Returns `(human, agent, operator group)`.
async fn live_linked(pool: &PgPool, label: &str) -> (Uuid, Uuid, Uuid) {
    let (human, _) = fixture::seed_human_operator(pool, &format!("{label}-human")).await;
    let (agent, _) = fixture::seed_agent_with_group(pool, &format!("{label}-agent")).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("live link");
    assert!(out.link_live, "CALIBRATION: the link is live");
    assert!(
        out.membership_live,
        "CALIBRATION: the link records a writer row"
    );
    (human, agent, out.operator_group_id)
}

async fn link_retired(pool: &PgPool, agent: Uuid) -> Option<bool> {
    sqlx::query_scalar("SELECT retired FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_optional(pool)
        .await
        .expect("link row")
}

async fn live_writer_rows(pool: &PgPool, group: Uuid, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL \
            AND role IN ('writer', 'admin')",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("membership count")
}

/// Every `operator.link_retired` / `operator.link_unretired` row for `agent`,
/// oldest first: `(event_type, details)`.
async fn retire_audit(pool: &PgPool, agent: Uuid) -> Vec<(String, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type, details FROM security_events \
          WHERE agent_id = $1 \
            AND event_type IN ('operator.link_retired', 'operator.link_unretired') \
          ORDER BY created_at, id",
    )
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

/// Row counts of every table the verb can touch, so "nothing changed" is
/// measured, plus the agent's link and membership state.
async fn footprint(pool: &PgPool, agent: Uuid) -> Vec<String> {
    let mut out = Vec::new();
    for t in ["operator_links", "group_memberships", "security_events"] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{t}"))
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("count {t}: {e}"));
        out.push(format!("{t}={n}"));
    }
    let state: Option<String> = sqlx::query_scalar(
        "SELECT (SELECT retired::text FROM operator_links WHERE agent_id = $1) || '/' || \
                (SELECT count(*)::text FROM group_memberships \
                  WHERE agent_id = $1 AND revoked_at IS NULL)",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("agent state");
    out.push(format!("agent={state:?}"));
    out
}

async fn retire_as(
    pool: &PgPool,
    role: &str,
    agent: Uuid,
    reason: Option<&str>,
    revoke: bool,
) -> Result<RetireRow, sqlx::Error> {
    let reason = reason.map(str::to_string);
    fixture::as_role(pool, role, |mut conn| async move {
        let r = sqlx::query_as::<_, RetireRow>(RETIRE)
            .bind(agent)
            .bind(reason)
            .bind(revoke)
            .fetch_one(&mut *conn)
            .await;
        (conn, r)
    })
    .await
}

/// Whatever path flips `retired`, it is audited: a superuser's direct UPDATE
/// (the shape of the hand-run retirement this item records) writes exactly
/// one `operator.link_retired` row naming the operator, the before/after
/// state and the session, with `via = direct` and no reason. Before 191 the
/// trigger fired on INSERT only and this wrote nothing.
///
/// Verified to fail: 191's `operator_links_audit` re-created `AFTER INSERT`
/// only -> zero rows.
#[sqlx::test(migrations = "../../migrations")]
async fn a_direct_retire_of_a_live_link_is_audited(pool: PgPool) {
    let (human, agent, group) = live_linked(&pool, "direct").await;
    assert!(
        retire_audit(&pool, agent).await.is_empty(),
        "CALIBRATION: no retire audit row before the retire"
    );
    sqlx::query("UPDATE operator_links SET retired = true WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .expect("a superuser retires the link directly");

    let rows = retire_audit(&pool, agent).await;
    assert_eq!(rows.len(), 1, "exactly one audit row: {rows:?}");
    let (kind, d) = &rows[0];
    assert_eq!(kind, "operator.link_retired");
    assert_eq!(d["operator_id"], serde_json::json!(human));
    assert_eq!(d["operator_group_id"], serde_json::json!(group));
    assert_eq!(d["retired_before"], serde_json::json!(false));
    assert_eq!(d["retired"], serde_json::json!(true));
    assert_eq!(d["via"], serde_json::json!("direct"));
    assert!(d["reason"].is_null(), "{d}");
    let me: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&pool)
        .await
        .expect("session user");
    assert_eq!(d["recorded_by"], serde_json::json!(me));

    // An UPDATE that leaves `retired` as it is records nothing.
    sqlx::query("UPDATE operator_links SET retired = true WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .expect("a no-op update");
    assert_eq!(
        retire_audit(&pool, agent).await.len(),
        1,
        "no row for a no-op"
    );

    // A superuser stays outside the retire-only guard (it can disable a
    // trigger anyway), so its un-retire is possible; it is audited too.
    sqlx::query("UPDATE operator_links SET retired = false WHERE agent_id = $1")
        .bind(agent)
        .execute(&pool)
        .await
        .expect("a superuser un-retires the link directly");
    let rows = retire_audit(&pool, agent).await;
    assert_eq!(rows.len(), 2, "the un-retire writes one more row: {rows:?}");
    let (kind, d) = &rows[1];
    assert_eq!(kind, "operator.link_unretired");
    assert_eq!(d["retired_before"], serde_json::json!(true));
    assert_eq!(d["retired"], serde_json::json!(false));
    assert_eq!(d["via"], serde_json::json!("direct"));
    assert_eq!(d["recorded_by"], serde_json::json!(me));
}

/// The verb's audit context (reason, revoked count, `via`) is its own
/// UPDATE's only: it is cleared right after, so a later direct retire in the
/// SAME transaction is audited `via = direct` with no reason, never with the
/// verb's.
///
/// Verified to fail: the clearing `set_config(..., '', true)` after the verb's
/// UPDATE removed -> agent B's row carries the verb's reason and `via`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_verbs_audit_context_does_not_leak_to_a_later_retire(pool: PgPool) {
    let (_, a, _) = live_linked(&pool, "ctx-a").await;
    let (_, b, _) = live_linked(&pool, "ctx-b").await;
    let mut tx = pool.begin().await.expect("begin");
    let r: RetireRow = sqlx::query_as(RETIRE)
        .bind(a)
        .bind("verb reason")
        .bind(true)
        .fetch_one(&mut *tx)
        .await
        .expect("the verb retires A");
    assert_eq!(r.0, "retired");
    sqlx::query("UPDATE operator_links SET retired = true WHERE agent_id = $1")
        .bind(b)
        .execute(&mut *tx)
        .await
        .expect("a direct retire of B in the same transaction");
    tx.commit().await.expect("commit");

    let ra = retire_audit(&pool, a).await;
    assert_eq!(ra.len(), 1, "{ra:?}");
    assert_eq!(ra[0].1["reason"], serde_json::json!("verb reason"));
    assert_eq!(
        ra[0].1["via"],
        serde_json::json!("epigraph_retire_operator_link")
    );
    let rb = retire_audit(&pool, b).await;
    assert_eq!(rb.len(), 1, "{rb:?}");
    assert_eq!(rb[0].1["via"], serde_json::json!("direct"), "{}", rb[0].1);
    assert!(rb[0].1["reason"].is_null(), "{}", rb[0].1);
    assert!(rb[0].1["memberships_revoked"].is_null(), "{}", rb[0].1);
}

/// A fresh NOSUPERUSER LOGIN in `epigraph_maintenance`, as operations
/// provision one (the CLI tests' shape). Returns its name.
async fn maintenance_login(pool: &PgPool) -> String {
    let role = format!("olr_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create the maintenance login");
    role
}

async fn drop_role(pool: &PgPool, role: &str) {
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(pool)
        .await
        .expect("drop role");
}

/// The verb's audit context, as a session would forge it before a direct
/// UPDATE: claims the verb, with a reason the verb never saw.
const FORGED_CONTEXT: &str =
    r#"{"via": "epigraph_retire_operator_link", "reason": "forged", "memberships_revoked": 0}"#;

/// `UPDATE operator_links SET retired = true` for `agent` as `role`, in one
/// transaction that first forges the verb's audit context and, when
/// `set_role` is given, `SET ROLE`s to it. Rolled back on error.
async fn direct_retire_as(
    pool: &PgPool,
    role: &str,
    set_role: Option<&'static str>,
    agent: Uuid,
) -> Result<u64, sqlx::Error> {
    fixture::as_role(pool, role, |mut conn| async move {
        let r = async {
            let mut tx = sqlx::Connection::begin(&mut *conn).await?;
            sqlx::query("SELECT pg_catalog.set_config('epigraph.operator_link_retire', $1, true)")
                .bind(FORGED_CONTEXT)
                .execute(&mut *tx)
                .await?;
            if let Some(r) = set_role {
                sqlx::query(&format!("SET LOCAL ROLE {r}"))
                    .execute(&mut *tx)
                    .await?;
            }
            let n =
                sqlx::query("UPDATE public.operator_links SET retired = true WHERE agent_id = $1")
                    .bind(agent)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
            tx.commit().await?;
            Ok(n)
        }
        .await;
        (conn, r)
    })
    .await
}

/// Backlog 9cec11f7 (migration 257): a maintenance login can no longer retire
/// a link with a direct UPDATE, however it is posed: as the login, after `SET
/// ROLE epigraph_maintenance`, or as the maintenance role itself, each with
/// the verb's audit context forged first and with the agent already holding
/// zero write authority (so 191's OLR03 is not what refuses). Each is refused
/// 42501 and nothing is written: no flip, no audit row. Before 257 every one
/// of them landed, unserialised against the link writers (191 took no lock on
/// that path), and audited `via = epigraph_retire_operator_link` with the
/// forged reason. CONTROL: the verb on the same login still retires the link,
/// audited with ITS reason and naming the login.
///
/// Verified to fail: 257 removed -> the first direct UPDATE lands (1 row) and
/// its audit row claims the verb with the reason "forged".
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_login_cannot_retire_a_link_directly(pool: PgPool) {
    let (_, agent, group) = live_linked(&pool, "maint-direct").await;
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("the writer row is revoked first");
    assert_eq!(live_writer_rows(&pool, group, agent).await, 0, "PREMISE");
    let login = maintenance_login(&pool).await;

    let before = footprint(&pool, agent).await;
    for (who, set_role) in [
        (login.as_str(), None),
        (login.as_str(), Some("epigraph_maintenance")),
        ("epigraph_maintenance", None),
    ] {
        let r = direct_retire_as(&pool, who, set_role, agent).await;
        let err = match r {
            Ok(n) => {
                let rows = retire_audit(&pool, agent).await;
                drop_role(&pool, &login).await;
                panic!(
                    "{who} (SET ROLE {set_role:?}) retired the link directly ({n} row): {rows:?}"
                )
            }
            Err(e) => e,
        };
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("42501"),
            "{who} (SET ROLE {set_role:?}): {err}"
        );
        assert_eq!(
            footprint(&pool, agent).await,
            before,
            "{who}: a refused direct retire writes nothing"
        );
    }
    assert_eq!(link_retired(&pool, agent).await, Some(false));
    assert!(retire_audit(&pool, agent).await.is_empty());

    let login_c = login.clone();
    let done = retire_as(&pool, &login_c, agent, Some("the verb's reason"), false)
        .await
        .expect("CONTROL: the verb retires the link on the same login");
    drop_role(&pool, &login).await;
    assert_eq!(done.0, "retired");
    let rows = retire_audit(&pool, agent).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0].1;
    assert_eq!(d["via"], serde_json::json!("epigraph_retire_operator_link"));
    assert_eq!(d["reason"], serde_json::json!("the verb's reason"));
    assert_eq!(d["recorded_by"], serde_json::json!(login));
    assert_eq!(d["revoked_memberships"], serde_json::json!([]), "{d}");
}

/// Backlog 9cec11f7 (migration 257): the audit's `via` and reason come from
/// the verb's own arguments or not at all. A superuser (still outside every
/// guard, and so still able to retire directly) that forges the verb's audit
/// context before its direct UPDATE is recorded `via = direct` with no
/// reason, never as the verb.
///
/// Verified to fail: 257 removed -> the row says `via =
/// epigraph_retire_operator_link` with the reason "forged".
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_audit_context_is_recorded_as_a_direct_retire(pool: PgPool) {
    let (_, agent, _) = live_linked(&pool, "forged").await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT pg_catalog.set_config('epigraph.operator_link_retire', $1, true)")
        .bind(FORGED_CONTEXT)
        .execute(&mut *tx)
        .await
        .expect("forge the context");
    sqlx::query("UPDATE operator_links SET retired = true WHERE agent_id = $1")
        .bind(agent)
        .execute(&mut *tx)
        .await
        .expect("a superuser retires the link directly");
    tx.commit().await.expect("commit");

    let rows = retire_audit(&pool, agent).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let d = &rows[0].1;
    assert_eq!(d["via"], serde_json::json!("direct"), "{d}");
    assert!(d["reason"].is_null(), "{d}");
    assert!(d["memberships_revoked"].is_null(), "{d}");
}

/// Backlog 9cec11f7 (migration 257), defence in depth: the table guard, not
/// only the missing grant, keeps the direct path shut. With UPDATE (retired)
/// re-granted to the maintenance role on this database (a later migration or
/// a hand grant could do it), its direct retire is still refused by the guard
/// (OLR05, 42501), and an un-retire by OLR04, with nothing written.
///
/// Verified to fail: 257's OLR05 arm removed from
/// `epigraph_operator_links_retire_only` -> the re-granted direct retire lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_regranted_column_does_not_reopen_the_direct_retire(pool: PgPool) {
    let (_, agent, group) = live_linked(&pool, "regrant").await;
    let (_, retired, _) = live_linked(&pool, "regrant-retired").await;
    retire_as(&pool, "epigraph_maintenance", retired, Some("x"), true)
        .await
        .expect("the verb retires the second link");
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("the writer row is revoked first");
    sqlx::query("GRANT UPDATE (retired) ON public.operator_links TO epigraph_maintenance")
        .execute(&pool)
        .await
        .expect("re-grant the column on this database");

    let before = footprint(&pool, agent).await;
    let err = direct_retire_as(&pool, "epigraph_maintenance", None, agent)
        .await
        .expect_err("the guard refuses a direct retire");
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{err}");
    assert!(err.to_string().contains("OLR05"), "{err}");
    assert_eq!(footprint(&pool, agent).await, before);

    let err = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = sqlx::query("UPDATE public.operator_links SET retired = false WHERE agent_id = $1")
            .bind(retired)
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await
    .expect_err("the guard refuses an un-retire");
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{err}");
    assert!(err.to_string().contains("OLR04"), "{err}");
    assert_eq!(link_retired(&pool, retired).await, Some(true));
}

/// The verb, on a maintenance session (`session_user` = the NOSUPERUSER
/// maintenance role): with the agent's live writer row still in the
/// operator's group it REFUSES (OLR03, nothing changed: a retire that did not
/// de-authorize is a refusal, as 107's retire rules); asked to revoke that
/// row too, it revokes it and retires the link in one act, with ONE audit row
/// carrying the reason, the revoked count, `via` and the session; a repeat is
/// `already_retired` and writes nothing; the agent's binding is no longer a
/// live link.
///
/// Since 257 (backlog 452a1330) the audit row also names each membership the
/// verb revoked, with its role before the revoke, so the revocation can be
/// reviewed and reversed from the record alone.
///
/// Verified to fail: the membership check removed -> the first call retires
/// with the writer row live; the `AND NOT l.retired` / early `already_retired`
/// return removed -> a second audit row; 257's verb and audit re-bodies
/// removed -> no `revoked_memberships` in the audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_maintenance_verb_retires_a_live_link_once_and_audits_it(pool: PgPool) {
    let (human, agent, group) = live_linked(&pool, "verb").await;
    assert_eq!(live_writer_rows(&pool, group, agent).await, 1, "PREMISE");
    let (membership, role): (Uuid, String) = sqlx::query_as(
        "SELECT id, role FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("the live writer row");

    let before = footprint(&pool, agent).await;
    let err = retire_as(
        &pool,
        "epigraph_maintenance",
        agent,
        Some("retired: test"),
        false,
    )
    .await
    .expect_err("a live writer row refuses the retire");
    assert_eq!(sqlstate(&err).as_deref(), Some("55000"), "{err}");
    assert!(err.to_string().contains("OLR03"), "{err}");
    assert_eq!(
        footprint(&pool, agent).await,
        before,
        "OLR03 changes nothing"
    );

    let (outcome, op, g, revoked) = retire_as(
        &pool,
        "epigraph_maintenance",
        agent,
        Some("retired: test"),
        true,
    )
    .await
    .expect("the maintenance session retires the link");
    assert_eq!(outcome, "retired");
    assert_eq!((op, g, revoked), (Some(human), Some(group), 1));
    assert_eq!(link_retired(&pool, agent).await, Some(true));
    assert_eq!(live_writer_rows(&pool, group, agent).await, 0);
    let binding: Option<String> = sqlx::query_scalar("SELECT public.epigraph_author_binding($1)")
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("binding");
    assert_ne!(binding.as_deref(), Some("live_link"), "{binding:?}");

    let rows = retire_audit(&pool, agent).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (kind, d) = &rows[0];
    assert_eq!(kind, "operator.link_retired");
    assert_eq!(d["reason"], serde_json::json!("retired: test"));
    assert_eq!(d["memberships_revoked"], serde_json::json!(1));
    assert_eq!(
        d["revoked_memberships"],
        serde_json::json!([{ "membership_id": membership, "role": role }]),
        "{d}"
    );
    assert_eq!(d["via"], serde_json::json!("epigraph_retire_operator_link"));
    assert_eq!(d["recorded_by"], serde_json::json!("epigraph_maintenance"));
    assert_eq!(d["operator_id"], serde_json::json!(human));

    let after = footprint(&pool, agent).await;
    let again = retire_as(&pool, "epigraph_maintenance", agent, Some("again"), true)
        .await
        .expect("a repeat is not an error");
    assert_eq!(
        again,
        ("already_retired".to_string(), Some(human), Some(group), 0)
    );
    assert_eq!(
        footprint(&pool, agent).await,
        after,
        "a repeat writes nothing"
    );
}

/// An agent with no link at all is reported, never an error and never a
/// write; a missing reason is refused before anything (22004).
///
/// Verified to fail: the `NOT FOUND` early return removed -> `retired` is
/// reported for a row that does not exist.
#[sqlx::test(migrations = "../../migrations")]
async fn no_link_and_no_reason_write_nothing(pool: PgPool) {
    let (stray, _) = fixture::seed_agent_with_group(&pool, "stray").await;
    let before = footprint(&pool, stray).await;
    let r = retire_as(&pool, "epigraph_maintenance", stray, Some("x"), true)
        .await
        .expect("no link is an outcome");
    assert_eq!(r, ("no_link".to_string(), None, None, 0));
    assert_eq!(footprint(&pool, stray).await, before);

    let (_, agent, _) = live_linked(&pool, "reasonless").await;
    let before = footprint(&pool, agent).await;
    for reason in [None, Some("   ")] {
        let err = retire_as(&pool, "epigraph_maintenance", agent, reason, true)
            .await
            .expect_err("a reason is required");
        assert_eq!(sqlstate(&err).as_deref(), Some("22004"), "{err}");
    }
    assert_eq!(footprint(&pool, agent).await, before);
}

/// A registered system agent is never retire-linked (148): its LIVE link is
/// refused by `operator_links_refuse_retired_system_agent`, which fires on
/// the verb's UPDATE as on every retired-link definer's INSERT; nothing is
/// written, its writer row included.
///
/// Verified to fail: 148's trigger dropped -> the system agent's link retires.
#[sqlx::test(migrations = "../../migrations")]
async fn a_registered_system_agent_is_refused(pool: PgPool) {
    let (_, agent, _) = live_linked(&pool, "system").await;
    assert!(
        fixture::register_system_agent(&pool, agent).await,
        "PREMISE"
    );
    let before = footprint(&pool, agent).await;
    let err = retire_as(&pool, "epigraph_maintenance", agent, Some("x"), true)
        .await
        .expect_err("a system agent's link is never retired");
    assert_eq!(sqlstate(&err).as_deref(), Some("55000"), "{err}");
    assert!(
        err.to_string().contains("registered system agent"),
        "148's trigger refused it: {err}"
    );
    assert_eq!(footprint(&pool, agent).await, before);
}

/// The application role can neither call the verb, flip the column directly,
/// nor forge the verb's audit row (191 reserves both event types). CONTROL:
/// the app role still inserts an ordinary audit row.
///
/// Verified to fail: 191's `security_events_operator_link_retire_privileged`
/// policy not created -> the forged row lands.
#[sqlx::test(migrations = "../../migrations")]
async fn the_application_role_cannot_retire_or_forge_the_audit(pool: PgPool) {
    let (_, agent, _) = live_linked(&pool, "app").await;
    let before = footprint(&pool, agent).await;
    let err = retire_as(&pool, "epigraph_app", agent, Some("x"), true)
        .await
        .expect_err("the app role cannot call the verb");
    assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{err}");

    let direct = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = sqlx::query("UPDATE public.operator_links SET retired = true WHERE agent_id = $1")
            .bind(agent)
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await
    .expect_err("the app role cannot update the column");
    assert_eq!(sqlstate(&direct).as_deref(), Some("42501"), "{direct}");
    assert_eq!(footprint(&pool, agent).await, before);

    for (event, forged) in [
        ("operator.link_retired", true),
        ("Operator.Link_Unretired ", true),
        ("operator.link_recorded_note", false),
    ] {
        let r = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let r = sqlx::query(
                "INSERT INTO security_events (event_type, agent_id, success, details) \
                 VALUES ($1, $2, true, '{}'::jsonb)",
            )
            .bind(event)
            .bind(agent)
            .execute(&mut *conn)
            .await;
            (conn, r)
        })
        .await;
        if forged {
            let e = r.expect_err("a reserved event type is refused to the app role");
            assert_eq!(sqlstate(&e).as_deref(), Some("42501"), "{event}: {e}");
        } else {
            r.unwrap_or_else(|e| panic!("CONTROL: {event} is an ordinary type: {e}"));
        }
    }
}

/// A retired link is permanent and a link is never re-pointed: a maintenance
/// session's direct UPDATE that un-retires or re-points a link is refused
/// 42501 and changes nothing. Since 257 the maintenance role holds no UPDATE
/// on the table at all, so the privilege check refuses both before 191's
/// guard runs; `a_regranted_column_does_not_reopen_the_direct_retire` pins
/// the guard's own OLR04 / OLR05 arms with the column re-granted.
///
/// Verified to fail: 191's `operator_links_retire_only` trigger dropped and
/// 257 removed -> the un-retire lands.
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_session_cannot_unretire_or_repoint_a_link(pool: PgPool) {
    let (_, agent, _) = live_linked(&pool, "permanent").await;
    let (other, _) = fixture::seed_human_operator(&pool, "other-human").await;
    retire_as(&pool, "epigraph_maintenance", agent, Some("x"), true)
        .await
        .expect("retire");
    let before = footprint(&pool, agent).await;
    for (what, sql) in [
        (
            "un-retire",
            "UPDATE public.operator_links SET retired = false WHERE agent_id = $1 AND $2::uuid IS NOT NULL",
        ),
        (
            "re-point",
            "UPDATE public.operator_links SET operator_id = $2 WHERE agent_id = $1",
        ),
    ] {
        let err = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r = sqlx::query(sql)
                .bind(agent)
                .bind(other)
                .execute(&mut *conn)
                .await;
            (conn, r)
        })
        .await
        .expect_err("the link row is retire-only");
        assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{what}: {err}");
    }
    assert_eq!(footprint(&pool, agent).await, before);
}

/// Migration 257's role block, the `(a)-(c)` DO block that creates and checks
/// the retirer role and re-owns the verb, read from the migration file.
fn role_block_257() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../migrations/257_operator_link_retire_owner_role.sql");
    let sql = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    let marker = "-- (a)-(c) THE ROLE, THE OWNER, THE COLUMN GRANT";
    let at = sql.find(marker).expect("257's role block marker");
    let rest = &sql[at..];
    let start = rest.find("DO $$").expect("257's role block DO");
    rest[start..].to_string()
}

/// Re-runs 257's role block inside ONE transaction that is always rolled
/// back, after `setup` (role DDL in the same transaction). Roles are
/// cluster-wide: committing an offending role would make 257 refuse to apply
/// in every database migrating beside this test. `Err` is the block's error.
async fn role_block_after(pool: &PgPool, setup: &[String]) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await.expect("begin");
    for stmt in setup {
        sqlx::query(stmt)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("`{stmt}`: {e}"));
    }
    let out = sqlx::raw_sql(&role_block_257())
        .execute(&mut *tx)
        .await
        .map(|_| ());
    tx.rollback().await.expect("rollback: nothing is committed");
    out
}

/// T69 review of migration 257: the retirer role's isolation check refuses a
/// non-superuser that holds the role WITH ADMIN OPTION only (on PostgreSQL 16
/// that confers neither USAGE nor SET, but its holder can GRANT the role to
/// itself and then run as it), and a non-superuser CREATEROLE login (which
/// can administer roles). Each is 55000 naming the offender, and the block
/// changes nothing. CONTROL: the same block, re-run on a clean catalog,
/// applies (so a refusal is the check, not a mis-read block).
///
/// Verified to fail: 257's check restored to the USAGE / SET predicate with
/// no ADMIN OPTION or CREATEROLE arm -> both re-runs apply cleanly.
#[sqlx::test(migrations = "../../migrations")]
async fn the_257_role_block_refuses_a_retirer_that_is_not_isolated(pool: PgPool) {
    role_block_after(&pool, &[])
        .await
        .expect("CONTROL: 257's role block re-applies on a clean catalog");

    let pg16: bool =
        sqlx::query_scalar("SELECT current_setting('server_version_num')::integer >= 160000")
            .fetch_one(&pool)
            .await
            .expect("server version");
    let suffix = Uuid::new_v4().simple().to_string();
    let admin_only = format!("t69_admin_only_{suffix}");
    let creator = format!("t69_createrole_{suffix}");
    let grant = if pg16 {
        format!(
            "GRANT epigraph_operator_link_retirer TO {admin_only} \
             WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
        )
    } else {
        format!("GRANT epigraph_operator_link_retirer TO {admin_only} WITH ADMIN OPTION")
    };
    let cases = [
        (
            "an ADMIN-only holder",
            vec![format!("CREATE ROLE {admin_only} NOLOGIN NOINHERIT"), grant],
            admin_only.clone(),
        ),
        (
            "a CREATEROLE login",
            vec![format!("CREATE ROLE {creator} LOGIN CREATEROLE")],
            creator.clone(),
        ),
    ];
    for (what, setup, offender) in cases {
        let err = role_block_after(&pool, &setup)
            .await
            .expect_err(&format!("257's role block refuses {what}"));
        assert_eq!(sqlstate(&err).as_deref(), Some("55000"), "{what}: {err}");
        assert!(
            err.to_string().contains(&offender),
            "{what}: the refusal names {offender}: {err}"
        );
    }
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_roles WHERE rolname LIKE $1")
        .bind(format!("t69_%_{suffix}"))
        .fetch_one(&pool)
        .await
        .expect("roles left");
    assert_eq!(left, 0, "no test role was committed");
}
