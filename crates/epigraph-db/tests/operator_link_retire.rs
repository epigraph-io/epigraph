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
//! * only a maintenance session may call it or flip the column, a maintenance
//!   session can never un-retire or re-point a link, and the application role
//!   can neither call it, write the column, nor forge its audit row.
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

/// A maintenance login's DIRECT `UPDATE operator_links SET retired = true`
/// (191 grants it the column, because the verb runs as that role) meets the
/// verb's precondition on the table: while the agent still holds a live
/// writer/admin row in the operator group it is refused (OLR03, 55000) and
/// nothing changes, so a retired identity never keeps write authority there.
/// Once that row is gone the same statement lands and is audited `via =
/// direct`, naming the session, with no reason (the direct path carries none).
///
/// Verified to fail: the writer-row check removed from 191's
/// `operator_links_retire_only` -> the first direct UPDATE lands with the
/// writer row live.
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_direct_retire_needs_zero_write_authority(pool: PgPool) {
    let (_, agent, group) = live_linked(&pool, "maint-direct").await;
    assert_eq!(live_writer_rows(&pool, group, agent).await, 1, "PREMISE");
    let direct = |pool: PgPool| async move {
        fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let r =
                sqlx::query("UPDATE public.operator_links SET retired = true WHERE agent_id = $1")
                    .bind(agent)
                    .execute(&mut *conn)
                    .await;
            (conn, r)
        })
        .await
    };

    let before = footprint(&pool, agent).await;
    let err = direct(pool.clone())
        .await
        .expect_err("a live writer row refuses the direct retire");
    let db = err.as_database_error().expect("a database error");
    assert_eq!(db.code().as_deref(), Some("55000"), "{db}");
    assert!(db.message().starts_with("OLR03:"), "{}", db.message());
    assert_eq!(
        footprint(&pool, agent).await,
        before,
        "OLR03 changes nothing"
    );

    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() \
          WHERE group_id = $1 AND agent_id = $2 AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .execute(&pool)
    .await
    .expect("the writer row is revoked first");
    let done = direct(pool.clone())
        .await
        .expect("with zero write authority the direct retire lands");
    assert_eq!(done.rows_affected(), 1);
    assert_eq!(link_retired(&pool, agent).await, Some(true));
    let rows = retire_audit(&pool, agent).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (kind, d) = &rows[0];
    assert_eq!(kind, "operator.link_retired");
    assert_eq!(d["via"], serde_json::json!("direct"));
    assert_eq!(d["recorded_by"], serde_json::json!("epigraph_maintenance"));
    assert!(d["reason"].is_null(), "{d}");
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
/// Verified to fail: the membership check removed -> the first call retires
/// with the writer row live; the `AND NOT l.retired` / early `already_retired`
/// return removed -> a second audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_maintenance_verb_retires_a_live_link_once_and_audits_it(pool: PgPool) {
    let (human, agent, group) = live_linked(&pool, "verb").await;
    assert_eq!(live_writer_rows(&pool, group, agent).await, 1, "PREMISE");

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
/// session's direct UPDATE that un-retires (OLR04) or re-points (no column
/// grant) a link is refused 42501 and changes nothing. (191 lets the same
/// session flip `retired` to true only once the agent holds no live
/// writer/admin row in the operator group: see
/// `a_maintenance_direct_retire_needs_zero_write_authority`.)
///
/// Verified to fail: 191's `operator_links_retire_only` trigger dropped -> the
/// un-retire lands.
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
        if what == "un-retire" {
            assert!(err.to_string().contains("OLR04"), "{err}");
        }
    }
    assert_eq!(footprint(&pool, agent).await, before);
}
