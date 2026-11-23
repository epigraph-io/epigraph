//! `epigraph-operator role-attach` / `role-detach` (backlog 89bce232): the
//! audited verbs over migration 166's attach and detach definers, driven
//! through the real binary against a `#[sqlx::test]` database migrated
//! 001 -> head, as a REAL `NOSUPERUSER` maintenance login (a superuser run
//! would hide a missing grant on the definers, `role_agents`,
//! `agent_succession` or the derivation).
//!
//! The world: a human `h` holds `ROLE`, which is bound to a team group in
//! 179's `attached_agents` mode; three identities `P -> A -> D` are
//! registered through the attestor in one folder (`D` succeeded `A`, which
//! succeeded `P`), and `P` is linked to `h`.
//!
//! What is pinned:
//! * the pre-connection checks (a role key of the wrong shape, a blank
//!   reason, a window that ends before it starts) refuse with no DSN at all;
//! * a dry-run attach of `P` prints the attachment, a `COPY` line for EACH
//!   succession copy, `A`'s and `D`'s (195 chains them: `D`'s copy names
//!   `A`'s, not the new row), and `MEMBERSHIP GAINED` for all three, and
//!   writes nothing (no `role_agents` row, no audit row);
//! * `--apply` commits the same three rows, and all three derive the group;
//! * a dry-run detach of `A` prints the row it would end and `LOST` for `A`
//!   and `D` (the copy chained through `A`), and writes nothing;
//! * `--apply` detaches `A`'s row only; `A` and `D` derive nothing and `P`
//!   keeps the group;
//! * a second detach finds nothing to detach and changes nothing.
//!
//! The cluster-level maintenance login each DB test creates is removed by
//! [`with_maintenance_login`] even when the test panics.

mod viewer_fixture;

use epigraph_db::AgentRepository;
use futures::FutureExt;
use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const ROLE: &str = "role:synthetic-attach-team";
const FOLDER: &str = "g-role-attach-cli";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn show(&self) -> String {
        format!(
            "exit={}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }

    fn lines_starting(&self, prefix: &str) -> Vec<&str> {
        self.stdout
            .lines()
            .filter(|l| l.starts_with(prefix))
            .collect()
    }
}

fn run_with(args: &[&str], dsn: Option<&str>) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env_remove(DSN_ENV);
    if let Some(dsn) = dsn {
        cmd.env(DSN_ENV, dsn);
    }
    let out = cmd.output().expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Create a NOSUPERUSER login in `epigraph_maintenance` and return
/// `(role, dsn)`. Use it through [`with_maintenance_login`], which drops it.
async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("ra_maint_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE epigraph_maintenance"
    ))
    .execute(pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    (role.clone(), format!("{scheme}://{role}:probe-only@{host}"))
}

/// Run `body` with a fresh maintenance login `(role, dsn)` and ALWAYS drop
/// that role afterwards. A role is cluster-wide: a panic between its
/// `CREATE ROLE` and its `DROP ROLE` (a fixture's `expect`, a failed
/// assertion) would otherwise leak it past the throwaway test database. The
/// panic is caught, the role dropped, and the panic resumed.
async fn with_maintenance_login<T, F, Fut>(pool: &PgPool, body: F) -> T
where
    F: FnOnce(String, String) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let (login, dsn) = maintenance_login(pool).await;
    let caught = std::panic::AssertUnwindSafe(body(login.clone(), dsn))
        .catch_unwind()
        .await;
    sqlx::query(&format!("DROP ROLE {login}"))
        .execute(pool)
        .await
        .expect("drop the maintenance login");
    match caught {
        Ok(t) => t,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn role_exists(pool: &PgPool, role: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
        .bind(role)
        .fetch_one(pool)
        .await
        .expect("read pg_roles")
}

async fn as_maintenance<T, F, Fut>(pool: &PgPool, f: F) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    fixture::as_role(pool, "epigraph_maintenance", f).await
}

/// A keyless team group (164's verb) with `ROLE` defined and bound to it at
/// `writer` in 179's `attached_agents` mode. Returns the group.
async fn attached_group(pool: &PgPool) -> Uuid {
    let (owner, _) = fixture::seed_human_operator(pool, "ra-owner").await;
    as_maintenance(pool, |mut c| async move {
        let group: Uuid =
            sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
                .bind("Synthetic Role Attach CLI Team")
                .bind(owner)
                .bind("role-attach cli test")
                .fetch_one(&mut *c)
                .await
                .expect("create the team group");
        sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_define_group_role($1, $2, $3, $4, $5::text, $6)",
        )
        .bind(ROLE)
        .bind("synthetic attached-mode role")
        .bind(group)
        .bind("writer")
        .bind("attached_agents")
        .bind("role-attach cli test")
        .fetch_one(&mut *c)
        .await
        .expect("define the role, attached agents only");
        (c, group)
    })
    .await
}

/// Grant `ROLE` to `holder`, open-ended, from now (123's bootstrap grant).
async fn grant(pool: &PgPool, holder: Uuid) {
    as_maintenance(pool, |mut c| async move {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_grant_role($1, $2, now(), NULL, NULL, 'role-attach cli test')",
        )
        .bind(ROLE)
        .bind(holder)
        .fetch_one(&mut *c)
        .await
        .expect("grant the role");
        (c, ())
    })
    .await;
}

/// Register an identity through the attestor in [`FOLDER`], naming `parent`.
async fn register(pool: &PgPool, parent: Option<Uuid>) -> Uuid {
    let key = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let hash = blake3::hash(&key).to_hex().to_string();
    fixture::as_role(pool, "epigraph_identity_attestor", |mut c| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT agent_id FROM public.epigraph_register_agent_identity( \
                 $1, $2, 'test-model-role-attach', $3, $4, NULL, $5)",
        )
        .bind(&key)
        .bind(parent)
        .bind(&hash)
        .bind(FOLDER)
        .bind(serde_json::json!({"in_prompt": {}}))
        .fetch_one(&mut *c)
        .await
        .expect("the attestor registers the identity");
        (c, id)
    })
    .await
}

/// The role-derived memberships of `agent` in `group` now, as a superuser.
async fn derived_in(pool: &PgPool, agent: Uuid, group: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT role FROM public.epigraph_role_derived_memberships($1, now()) \
          WHERE group_id = $2 ORDER BY role",
    )
    .bind(agent)
    .bind(group)
    .fetch_all(pool)
    .await
    .expect("derived memberships")
}

/// `(rows, un-detached rows)` of `role_agents` for `ROLE`.
async fn role_rows(pool: &PgPool) -> (i64, i64) {
    sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE detached_at IS NULL) FROM role_agents \
          WHERE role = $1",
    )
    .bind(ROLE)
    .fetch_one(pool)
    .await
    .expect("role_agents rows")
}

async fn events(pool: &PgPool, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM security_events WHERE event_type = $1")
        .bind(event_type)
        .fetch_one(pool)
        .await
        .expect("events")
}

/// The `details` of every `security_events` row of `event_type`.
async fn event_details(pool: &PgPool, event_type: &str) -> Vec<serde_json::Value> {
    sqlx::query_scalar("SELECT details FROM security_events WHERE event_type = $1 ORDER BY id")
        .bind(event_type)
        .fetch_all(pool)
        .await
        .expect("event details")
}

fn has_line(r: &Run, prefix: &str, needles: &[String]) -> bool {
    r.lines_starting(prefix)
        .iter()
        .any(|l| needles.iter().all(|n| l.contains(n.as_str())))
}

#[test]
fn role_attach_and_detach_refuse_bad_input_before_connecting() {
    let agent = Uuid::new_v4().to_string();
    for (args, what) in [
        (
            vec![
                "role-attach",
                "--role",
                "ops",
                "--agent",
                &agent,
                "--reason",
                "x",
            ],
            "a role key without the role: prefix",
        ),
        (
            vec![
                "role-attach",
                "--role",
                "role:ops",
                "--agent",
                &agent,
                "--reason",
                "  ",
            ],
            "a blank reason",
        ),
        (
            vec![
                "role-attach",
                "--role",
                "role:ops",
                "--agent",
                &agent,
                "--valid-from",
                "2030-01-02T00:00:00Z",
                "--valid-to",
                "2030-01-01T00:00:00Z",
                "--reason",
                "x",
            ],
            "a window that ends before it starts",
        ),
        (
            vec![
                "role-detach",
                "--role",
                "role:Ops",
                "--agent",
                &agent,
                "--reason",
                "x",
            ],
            "an upper-case role key",
        ),
        (
            vec![
                "role-detach",
                "--role",
                "role:ops",
                "--agent",
                &agent,
                "--reason",
                "",
            ],
            "an empty detach reason",
        ),
    ] {
        // No DSN at all: a refusal here is decided before any connection.
        let r = run_with(&args, None);
        assert_ne!(r.code, 0, "{what} is refused\n{}", r.show());
        assert!(
            r.stderr.contains("nothing was done"),
            "{what} is refused by the pre-connection check, not a connection error\n{}",
            r.show()
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn role_attach_follows_the_chained_lineage_and_role_detach_cuts_it_off(pool: PgPool) {
    let group = attached_group(&pool).await;
    let (h, _) = fixture::seed_human_operator(&pool, "ra-holder").await;
    grant(&pool, h).await;
    let p = register(&pool, None).await;
    {
        let mut c = pool.acquire().await.expect("acquire");
        let out = AgentRepository::link_operator(&mut c, p, h)
            .await
            .expect("link P to its human");
        assert!(out.link_live, "PREMISE: a live link: {out:?}");
    }
    let a = register(&pool, Some(p)).await;
    let d = register(&pool, Some(a)).await;
    for x in [p, a, d] {
        assert!(
            derived_in(&pool, x, group).await.is_empty(),
            "PREMISE: nothing is attached yet"
        );
    }

    let (ps, as_, ds) = (p.to_string(), a.to_string(), d.to_string());
    let (ps2, as2) = (ps.clone(), as_.clone());
    let pool2 = pool.clone();
    let (
        login,
        dry,
        rows_after_dry,
        events_after_dry,
        applied,
        rows_after_apply,
        attached_events,
        derived_after_attach,
        ddry,
        rows_after_ddry,
        detached_after_ddry,
        dapplied,
        rows_after_detach,
        detached_events,
        derived_after_detach,
        again,
        rows_after_again,
    ) = with_maintenance_login(&pool, |login, dsn| async move {
        let (pool, ps, as_) = (pool2, ps2, as2);
        let attach = |apply: bool| {
            let mut args = vec![
                "role-attach",
                "--role",
                ROLE,
                "--agent",
                ps.as_str(),
                "--reason",
                "role-attach cli test",
            ];
            if apply {
                args.push("--apply");
            }
            run_with(&args, Some(&dsn))
        };
        let detach = |apply: bool| {
            let mut args = vec![
                "role-detach",
                "--role",
                ROLE,
                "--agent",
                as_.as_str(),
                "--reason",
                "role-detach cli test",
            ];
            if apply {
                args.push("--apply");
            }
            run_with(&args, Some(&dsn))
        };

        // ---- attach, dry run ----
        let dry = attach(false);
        let (rows_after_dry, events_after_dry) = (
            role_rows(&pool).await,
            events(&pool, "platform.role_agent_attached").await,
        );
        // ---- attach, apply ----
        let applied = attach(true);
        let rows_after_apply = role_rows(&pool).await;
        let attached_events = event_details(&pool, "platform.role_agent_attached").await;
        let derived_after_attach = (
            derived_in(&pool, p, group).await,
            derived_in(&pool, a, group).await,
            derived_in(&pool, d, group).await,
        );
        // ---- detach A, dry run ----
        let ddry = detach(false);
        let rows_after_ddry = role_rows(&pool).await;
        let detached_after_ddry = events(&pool, "platform.role_agent_detached").await;
        // ---- detach A, apply; then again ----
        let dapplied = detach(true);
        let rows_after_detach = role_rows(&pool).await;
        let detached_events = event_details(&pool, "platform.role_agent_detached").await;
        let derived_after_detach = (
            derived_in(&pool, p, group).await,
            derived_in(&pool, a, group).await,
            derived_in(&pool, d, group).await,
        );
        let again = detach(true);
        let rows_after_again = role_rows(&pool).await;
        (
            login,
            dry,
            rows_after_dry,
            events_after_dry,
            applied,
            rows_after_apply,
            attached_events,
            derived_after_attach,
            ddry,
            rows_after_ddry,
            detached_after_ddry,
            dapplied,
            rows_after_detach,
            detached_events,
            derived_after_detach,
            again,
            rows_after_again,
        )
    })
    .await;
    assert!(!role_exists(&pool, &login).await, "the login is dropped");

    // The dry-run attach: the row by name, BOTH copies (D's chained through
    // A's), three GAINED lines, and nothing written.
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        has_line(&dry, "WOULD BE ATTACHED", &[format!("agent={p}")]),
        "{}",
        dry.show()
    );
    assert_eq!(dry.lines_starting("COPY\t").len(), 2, "{}", dry.show());
    assert!(
        has_line(&dry, "COPY\t", &[format!("agent={a}")]),
        "A's copy\n{}",
        dry.show()
    );
    assert!(
        has_line(&dry, "COPY\t", &[format!("agent={d}")]),
        "D's copy, chained through A's (195), is reported too\n{}",
        dry.show()
    );
    for x in [&ps, &as_, &ds] {
        assert!(
            has_line(
                &dry,
                "MEMBERSHIP\tGAINED",
                &[
                    format!("agent={x}"),
                    format!("group={group}"),
                    "role=writer".into()
                ]
            ),
            "agent {x} gains the group\n{}",
            dry.show()
        );
    }
    assert!(dry.stdout.contains("DRY RUN"), "{}", dry.show());
    assert_eq!(rows_after_dry, (0, 0), "a dry-run attach writes no row");
    assert_eq!(events_after_dry, 0, "a dry-run attach writes no audit row");

    // The applied attach.
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(
        has_line(&applied, "ATTACHED", &[format!("agent={p}")]),
        "{}",
        applied.show()
    );
    assert!(!applied.stdout.contains("WOULD BE"), "{}", applied.show());
    assert_eq!(rows_after_apply, (3, 3), "P's row and two copies");
    // The audit trail (166's trigger): one attached event per row, the row
    // made by name carrying the operator's reason and the writing login.
    assert_eq!(
        attached_events.len(),
        3,
        "one audit row per attachment: {attached_events:?}"
    );
    let by_name: Vec<&serde_json::Value> = attached_events
        .iter()
        .filter(|d| d["inherited_from"].is_null())
        .collect();
    assert_eq!(by_name.len(), 1, "{attached_events:?}");
    assert_eq!(by_name[0]["agent"], ps.as_str(), "{}", by_name[0]);
    assert_eq!(
        by_name[0]["reason"], "role-attach cli test",
        "{}",
        by_name[0]
    );
    assert_eq!(by_name[0]["attached_by"], login.as_str(), "{}", by_name[0]);
    assert_eq!(
        derived_after_attach,
        (
            vec!["writer".to_string()],
            vec!["writer".to_string()],
            vec!["writer".to_string()]
        ),
        "P, A and D derive the group"
    );

    // The dry-run detach of A: its row, LOST for A and D (D's copy is chained
    // through A's), P untouched (not affected), nothing written.
    assert_eq!(ddry.code, 0, "{}", ddry.show());
    assert_eq!(
        ddry.lines_starting("WOULD BE DETACHED\t").len(),
        1,
        "{}",
        ddry.show()
    );
    assert!(
        has_line(&ddry, "WOULD BE DETACHED\t", &[format!("agent={a}")]),
        "{}",
        ddry.show()
    );
    for x in [&as_, &ds] {
        assert!(
            has_line(
                &ddry,
                "MEMBERSHIP\tLOST",
                &[format!("agent={x}"), format!("group={group}")]
            ),
            "agent {x} loses the group\n{}",
            ddry.show()
        );
    }
    assert!(
        !ddry.stdout.contains(&format!("agent={p}\tgroup")),
        "P is not an identity a detach of A can change\n{}",
        ddry.show()
    );
    assert_eq!(rows_after_ddry, (3, 3), "a dry-run detach changes no row");
    assert_eq!(
        detached_after_ddry, 0,
        "a dry-run detach writes no audit row"
    );

    // The applied detach.
    assert_eq!(dapplied.code, 0, "{}", dapplied.show());
    assert_eq!(rows_after_detach, (3, 2), "A's row only is detached");
    assert_eq!(
        detached_events.len(),
        1,
        "one audit row for the one detached row: {detached_events:?}"
    );
    assert_eq!(detached_events[0]["agent"], as_.as_str());
    assert_eq!(detached_events[0]["detach_reason"], "role-detach cli test");
    assert_eq!(detached_events[0]["detached_by"], login.as_str());
    assert_eq!(
        derived_after_detach,
        (vec!["writer".to_string()], vec![], vec![]),
        "P keeps the group; A and D lose it"
    );

    // Again: nothing to detach, nothing changed.
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(
        again.stdout.contains("NOTHING-TO-DETACH"),
        "{}",
        again.show()
    );
    assert_eq!(rows_after_again, (3, 2));
}

/// A test-only panic inside [`with_maintenance_login`]'s body still drops
/// the login (and the panic reaches the test).
#[sqlx::test(migrations = "../../migrations")]
async fn a_panicking_body_still_drops_its_maintenance_login(pool: PgPool) {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let s2 = seen.clone();
    let caught =
        std::panic::AssertUnwindSafe(with_maintenance_login(&pool, |login, _dsn| async move {
            *s2.lock().unwrap() = login;
            panic!("T94 probe panic");
        }))
        .catch_unwind()
        .await;
    let login = seen.lock().unwrap().clone();
    assert!(!login.is_empty(), "the body ran");
    let panic = caught.expect_err("the body's panic is resumed");
    assert_eq!(
        panic.downcast_ref::<&str>().copied(),
        Some("T94 probe panic"),
        "the body's own panic"
    );
    assert!(
        !role_exists(&pool, &login).await,
        "the login {login} is dropped although the body panicked"
    );
}
