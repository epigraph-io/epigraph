//! Migration 199's `epigraph_agent_prompt_snapshot_at(agent, at, open)`: the
//! prompt snapshot an agent was running at an instant, for a claim's
//! `authored_by.prompt_snapshot`.
//!
//! * the catalog shape: a SECURITY DEFINER owned by `epigraph_maintenance`,
//!   STABLE, on 172's `pg_catalog, pg_temp` path, EXECUTE-able by the
//!   application and maintenance roles and not by PUBLIC;
//! * the gate is 161's prompt-history gate: its admin assignment is the same
//!   text as 161's, and on every caller shape this file can build, "161
//!   refuses AID06" is exactly "199 returns no row" while a snapshot exists;
//!   with `open` every caller gets the row;
//! * which snapshot: the latest recorded start at or before the instant, where
//!   a recurring state's latest start is its `last_seen`.
//!
//! Each gate call runs on a session whose `session_user` IS `epigraph_app`
//! (`SET SESSION AUTHORIZATION`), stamped with the principal under test: on the
//! superuser connection `epigraph_bypass()` is true and every caller would be
//! an admin. Fixture rows are seeded on the superuser connection.

#[path = "viewer_fixture.rs"]
mod fixture;

use chrono::{DateTime, Duration, Utc};
use epigraph_db::AgentRepository;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const DEFINER: &str = "public.epigraph_agent_prompt_snapshot_at(uuid, timestamptz, boolean)";
const ATTESTOR: &str = "epigraph_identity_attestor";

fn random32() -> Vec<u8> {
    [
        Uuid::new_v4().as_bytes().as_slice(),
        Uuid::new_v4().as_bytes().as_slice(),
    ]
    .concat()
}

async fn human_operator(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(random32())
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

/// A registered identity (no parent) in `group`, through the attestor role:
/// `(agent, snapshot)`.
async fn register(pool: &PgPool, group: &str) -> (Uuid, Uuid) {
    let pubkey = random32();
    let hash = blake3::hash(&pubkey).to_hex().to_string();
    let signing = random32();
    let group = group.to_string();
    let snap: Value = json!({
        "identity_md": null, "global_claude_md": null, "group_claude_md": null,
        "learned_md": null,
        "in_prompt": {"identity_md": false, "global_claude_md": false,
                      "group_claude_md": false, "learned_md": false},
        "runner_version": "runner-test", "host_sha": null
    });
    fixture::as_role(pool, ATTESTOR, |mut conn| async move {
        let r: (Uuid, Uuid) = sqlx::query_as(
            "SELECT agent_id, snapshot_id \
               FROM public.epigraph_register_agent_identity($1, NULL, 'model-x', $2, $3, $4, $5)",
        )
        .bind(&pubkey)
        .bind(&hash)
        .bind(&group)
        .bind(&signing)
        .bind(&snap)
        .fetch_one(&mut *conn)
        .await
        .expect("the attestor registers");
        (conn, r)
    })
    .await
}

/// A snapshot row written directly (superuser), with chosen start times.
async fn snapshot_row(
    pool: &PgPool,
    agent: Uuid,
    tag: &str,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agent_prompt_snapshots \
             (agent_id, group_folder, model, prompt_hash, in_prompt, first_seen, last_seen) \
         VALUES ($1, $2, 'model-y', $3, '{}'::jsonb, $4, $5) RETURNING id",
    )
    .bind(agent)
    .bind(format!("g-{tag}"))
    .bind(blake3::hash(agent.as_bytes()).to_hex().to_string())
    .bind(first_seen)
    .bind(last_seen)
    .fetch_one(pool)
    .await
    .expect("seed snapshot")
}

/// 199 on an `epigraph_app` session stamped as `principal`:
/// `(snapshot_id, started_at)` rows.
async fn at_as(
    pool: &PgPool,
    principal: Option<Uuid>,
    agent: Uuid,
    at: DateTime<Utc>,
    open: bool,
) -> Vec<(Uuid, DateTime<Utc>)> {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        // ALWAYS set it ('' = none): a session setting survives on a pooled
        // connection.
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.map(|p| p.to_string()).unwrap_or_default())
            .execute(&mut *conn)
            .await
            .expect("set principal");
        let rows: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT snapshot_id, started_at \
               FROM public.epigraph_agent_prompt_snapshot_at($1, $2, $3)",
        )
        .bind(agent)
        .bind(at)
        .bind(open)
        .fetch_all(&mut *conn)
        .await
        .expect("199 never raises for a refused caller");
        (conn, rows)
    })
    .await
}

/// 161's prompt history on the same kind of session: `Ok(true)` when read,
/// `Ok(false)` when refused AID06.
async fn history_admits(pool: &PgPool, principal: Option<Uuid>, agent: Uuid) -> bool {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.map(|p| p.to_string()).unwrap_or_default())
            .execute(&mut *conn)
            .await
            .expect("set principal");
        let r = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.epigraph_agent_prompt_history($1)",
        )
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
                assert_eq!(
                    code.as_deref(),
                    Some("AID06"),
                    "161 refuses only AID06: {e}"
                );
                false
            }
        };
        (conn, admitted)
    })
    .await
}

#[derive(sqlx::FromRow)]
struct Catalog {
    prosecdef: bool,
    owner: String,
    provolatile: String,
    proconfig: Option<Vec<String>>,
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_is_owned_pinned_and_granted_to_the_request_role(pool: PgPool) {
    let c: Catalog = sqlx::query_as(
        "SELECT p.prosecdef, r.rolname::text AS owner, p.provolatile::text, p.proconfig \
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
          WHERE p.oid = to_regprocedure($1)",
    )
    .bind(DEFINER)
    .fetch_optional(&pool)
    .await
    .expect("pg_proc")
    .unwrap_or_else(|| panic!("{DEFINER} must exist (migration 199)"));
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
    ] {
        let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
            .bind(role)
            .bind(DEFINER)
            .fetch_one(&pool)
            .await
            .expect("privilege");
        assert_eq!(can, expected, "{role} EXECUTE");
    }
}

/// 161's admin assignment, `v_admin := ... END);`, appears in 199's body
/// token for token (whitespace removed), so the two gates cannot drift
/// apart silently.
#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_test_is_the_text_of_161s(pool: PgPool) {
    async fn body(pool: &PgPool, sig: &str) -> String {
        let src: String =
            sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid = to_regprocedure($1)")
                .bind(sig)
                .fetch_one(pool)
                .await
                .expect("prosrc");
        src.split_whitespace().collect()
    }
    let history = body(&pool, "public.epigraph_agent_prompt_history(uuid)").await;
    let at = body(&pool, DEFINER).await;
    let start = history.find("v_admin:=").expect("161 assigns v_admin");
    let len = history[start..].find("END);").expect("ends the CASE") + "END);".len();
    let gate = &history[start..start + len];
    assert!(
        gate.contains("epigraph_is_instance_admin") && gate.contains("epigraph_is_elevated"),
        "CALIBRATION: the extracted text is the admin test: {gate}"
    );
    assert!(at.contains(gate), "199's admin test is 161's: {gate}");
    assert!(
        at.contains("public.epigraph_human_of(p_agent,false)ISDISTINCTFROMv_principal"),
        "199's operator test is 161's"
    );
}

/// On every caller shape built here, 199 gated returns the row exactly when
/// 161 admits the caller, and 199 open returns it to everyone.
#[sqlx::test(migrations = "../../migrations")]
async fn the_gate_admits_exactly_whom_the_prompt_history_admits(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let retired_operator = human_operator(&pool).await;
    let stranger = human_operator(&pool).await;
    let custodian = human_operator(&pool).await;
    fixture::make_custodian(&pool, custodian).await;

    let (agent, snap) = register(&pool, "g-parity").await;
    link(&pool, agent, operator).await;
    let (retired_agent, _) = register(&pool, "g-parity-r").await;
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

    let now = Utc::now() + Duration::seconds(5);
    let mut cases: Vec<(&str, Option<Uuid>, Uuid, bool)> = vec![
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
    for (what, who, target, admitted) in &cases {
        assert_eq!(
            history_admits(&pool, *who, *target).await,
            *admitted,
            "CALIBRATION: 161 on {what}"
        );
        let gated = at_as(&pool, *who, *target, now, false).await;
        assert_eq!(
            !gated.is_empty(),
            *admitted,
            "199 gated on {what}: {gated:?}"
        );
        let open = at_as(&pool, *who, *target, now, true).await;
        assert_eq!(open.len(), 1, "199 open on {what}");
    }
    assert_eq!(
        at_as(&pool, Some(operator), agent, now, false).await[0].0,
        snap
    );

    sqlx::query("SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'authored_by')")
        .execute(&pool)
        .await
        .expect("arm admin scopes");
    cases.clear();
    cases.push((
        "custodian, armed, not elevated",
        Some(custodian),
        agent,
        false,
    ));
    cases.push(("operator, armed", Some(operator), agent, true));
    for (what, who, target, admitted) in &cases {
        assert_eq!(
            history_admits(&pool, *who, *target).await,
            *admitted,
            "CALIBRATION: 161 on {what}"
        );
        let gated = at_as(&pool, *who, *target, now, false).await;
        assert_eq!(!gated.is_empty(), *admitted, "199 gated on {what}");
    }
}

/// A refused caller's answer is the answer for an agent with no snapshot:
/// zero rows, no error.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_caller_sees_what_an_agent_with_no_snapshot_shows(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let stranger = human_operator(&pool).await;
    let (agent, _) = register(&pool, "g-none").await;
    link(&pool, agent, operator).await;
    let (bare, _) = fixture::seed_agent_with_group(&pool, "bare").await;
    let now = Utc::now() + Duration::seconds(5);
    assert!(
        !at_as(&pool, Some(operator), agent, now, false)
            .await
            .is_empty(),
        "CONTROL: the operator sees the snapshot"
    );
    let absent = at_as(&pool, None, bare, now, true).await;
    assert!(
        absent.is_empty(),
        "CALIBRATION: an agent with no snapshot has none"
    );
    assert_eq!(
        at_as(&pool, Some(stranger), agent, now, false).await,
        absent,
        "hidden and absent are the same answer"
    );
}

/// The snapshot active at an instant is the one with the latest recorded
/// start at or before it, a recurring state's latest start being its
/// `last_seen`: an agent that ran A (t1), then B (t3), then A again (t5) was
/// running B at t4 and A at t6.
#[sqlx::test(migrations = "../../migrations")]
async fn the_active_snapshot_is_the_latest_start_at_or_before_the_instant(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "recur").await;
    // Whole microseconds: what a timestamptz stores.
    let t0 = DateTime::from_timestamp_micros((Utc::now() - Duration::days(10)).timestamp_micros())
        .expect("a valid instant");
    let t = |n: i64| t0 + Duration::hours(n);
    let a = snapshot_row(&pool, agent, "a", t(1), t(5)).await;
    let b = snapshot_row(&pool, agent, "b", t(3), t(3)).await;
    for (at, want) in [
        (t(0), None),
        (t(1), Some((a, t(1)))),
        (t(2), Some((a, t(1)))),
        (t(3), Some((b, t(3)))),
        (t(4), Some((b, t(3)))),
        (t(5), Some((a, t(5)))),
        (t(6), Some((a, t(5)))),
    ] {
        let got = at_as(&pool, None, agent, at, true).await;
        assert!(got.len() <= 1, "one snapshot at most");
        assert_eq!(got.first().copied(), want, "at {at}");
    }
}
