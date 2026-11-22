//! `epigraph-operator restore-role-successor` (backlog 9073f0a5, migration
//! 264), driven through the real binary against a `#[sqlx::test]` database
//! migrated 001 -> head, as a real NOSUPERUSER maintenance login.
//!
//! What is pinned: after the root identity of a role was detached, its
//! successor is out; the dry run prints what it WOULD do and changes and
//! records nothing; `--apply` re-attaches the root by name, detaches the
//! successor's stale copy, attaches it by name (the derivation admits it
//! again) and writes one `platform.role_successor_restored` audit row naming
//! the login and the reason; naming a root the copy did not come from is
//! refused `ROL04`, exit 1, nothing written.

mod viewer_fixture;

use epigraph_db::AgentRepository;
use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const ROLE: &str = "role:team-member";

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
}

fn run_dsn(args: &[&str], dsn: &str) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env(DSN_ENV, dsn)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A fresh NOSUPERUSER login in `epigraph_maintenance`: `(role, dsn)`. The
/// caller drops the role before asserting.
async fn maintenance_login(pool: &PgPool) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("restore_maint_{}", Uuid::new_v4().simple());
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

/// One statement on a session whose `session_user` is the maintenance role.
async fn as_maintenance(pool: &PgPool, sql: &str, binds: &[Uuid]) {
    let sql = sql.to_string();
    let binds = binds.to_vec();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let mut q = sqlx::query(&sql);
        for b in binds {
            q = q.bind(b);
        }
        q.execute(&mut *conn).await.expect(&sql);
        (conn, ())
    })
    .await;
}

async fn register_in(pool: &PgPool, parent: Option<Uuid>, folder: &str) -> Uuid {
    let key = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let hash = blake3::hash(&key).to_hex().to_string();
    let folder = folder.to_string();
    fixture::as_role(pool, "epigraph_identity_attestor", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT agent_id FROM public.epigraph_register_agent_identity( \
                 $1, $2, 'test-model-264-cli', $3, $4, NULL, $5)",
        )
        .bind(&key)
        .bind(parent)
        .bind(&hash)
        .bind(&folder)
        .bind(serde_json::json!({"in_prompt": {}}))
        .fetch_one(&mut *conn)
        .await
        .expect("the attestor registers the identity");
        (conn, id)
    })
    .await
}

/// `root -> successor` in one folder, the root linked to `h` and attached by
/// name to ROLE.
async fn lineage(pool: &PgPool, h: Uuid) -> (Uuid, Uuid) {
    let root = register_in(pool, None, "g-cli-job").await;
    let mut c = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut c, root, h)
        .await
        .expect("link the root");
    drop(c);
    as_maintenance(
        pool,
        "SELECT public.epigraph_attach_agent_to_role('role:team-member', $1, \
                now() - interval '5 seconds', NULL, 'cli restore test attach')",
        &[root],
    )
    .await;
    let successor = register_in(pool, Some(root), "g-cli-job").await;
    (root, successor)
}

/// `(derivation rows for the successor, live rows made by name of the root,
/// of the successor, restore audit rows)`.
async fn state(pool: &PgPool, root: Uuid, successor: Uuid) -> (i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM public.epigraph_role_derived_memberships($2, now())), \
                (SELECT count(*) FROM role_agents WHERE agent_id = $1 AND role = $3 \
                    AND inherited_from IS NULL AND detached_at IS NULL), \
                (SELECT count(*) FROM role_agents WHERE agent_id = $2 AND role = $3 \
                    AND inherited_from IS NULL AND detached_at IS NULL), \
                (SELECT count(*) FROM security_events \
                  WHERE event_type = 'platform.role_successor_restored')",
    )
    .bind(root)
    .bind(successor)
    .bind(ROLE)
    .fetch_one(pool)
    .await
    .expect("state")
}

/// The whole verb, end to end.
///
/// Verified to fail: the dry run committing -> its "changes nothing"
/// assertion fails; `--reason` not passed through -> the audit row's reason
/// differs.
#[sqlx::test(migrations = "../../migrations")]
async fn restore_role_successor_gives_the_running_successor_the_group_back(pool: PgPool) {
    let (owner, _) = fixture::seed_human_operator(&pool, "restore-cli-owner").await;
    let (h, _) = fixture::seed_human_operator(&pool, "restore-cli-holder").await;
    let group: Uuid = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let g: Uuid = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
            .bind("Synthetic CLI Restore Team")
            .bind(owner)
            .bind("cli restore test")
            .fetch_one(&mut *conn)
            .await
            .expect("team group");
        (conn, g)
    })
    .await;
    as_maintenance(
        &pool,
        "SELECT public.epigraph_define_group_role('role:team-member', 'synthetic', $1, \
                'writer', 'attached_agents'::text, 'cli restore test')",
        &[group],
    )
    .await;
    as_maintenance(
        &pool,
        "SELECT public.epigraph_grant_role('role:team-member', $1, now(), NULL, NULL, \
                'cli restore test')",
        &[h],
    )
    .await;
    let (root, successor) = lineage(&pool, h).await;
    let (other, _) = lineage(&pool, h).await;
    assert_eq!(
        state(&pool, root, successor).await.0,
        1,
        "PREMISE: a member"
    );
    as_maintenance(
        &pool,
        "SELECT public.epigraph_detach_agent_from_role('role:team-member', $1, 'cli test')",
        &[root],
    )
    .await;
    let cut_off = state(&pool, root, successor).await;
    assert_eq!(cut_off, (0, 0, 0, 0), "PREMISE: cut off, nothing by name");

    let (login, dsn) = maintenance_login(&pool).await;
    let (r, s, o) = (root.to_string(), successor.to_string(), other.to_string());
    let args = |root: &str, extra: &[&'static str]| {
        let mut v = vec![
            "restore-role-successor".to_string(),
            "--role".into(),
            ROLE.into(),
            "--root".into(),
            root.to_string(),
            "--successor".into(),
            s.clone(),
            "--reason".into(),
            "job resumed after review".into(),
        ];
        v.extend(extra.iter().map(|x| (*x).to_string()));
        v
    };
    let call = |v: Vec<String>| {
        let refs: Vec<&str> = v.iter().map(String::as_str).collect();
        run_dsn(&refs, &dsn)
    };

    let dry = call(args(&r, &[]));
    let dry_state = state(&pool, root, successor).await;
    let refused = call(args(&o, &["--apply"]));
    let refused_state = state(&pool, root, successor).await;
    let applied = call(args(&r, &["--apply"]));
    let applied_state = state(&pool, root, successor).await;
    let audit: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT details ->> 'recorded_by', details ->> 'reason' FROM security_events \
          WHERE agent_id = $1 AND event_type = 'platform.role_successor_restored'",
    )
    .bind(successor)
    .fetch_optional(&pool)
    .await
    .expect("audit row");
    // Drop the cluster-global role BEFORE asserting, so a failure cannot leak it.
    sqlx::query(&format!("DROP ROLE {login}"))
        .execute(&pool)
        .await
        .expect("drop role");

    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("WOULD ROOT-ATTACHED\t"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains("WOULD COPY-DETACHED\t"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout
            .contains(&format!("WOULD SUCCESSOR-ATTACHED\tagent={s}")),
        "{}",
        dry.show()
    );
    assert!(dry.stdout.contains("DRY RUN"), "{}", dry.show());
    assert_eq!(dry_state, cut_off, "a dry run changes nothing");

    assert_ne!(refused.code, 0, "{}", refused.show());
    assert!(refused.stderr.contains("ROL04"), "{}", refused.show());
    assert_eq!(refused_state, cut_off, "a refusal changes nothing");

    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(
        applied
            .stdout
            .contains(&format!("SUCCESSOR-ATTACHED\tagent={s}")),
        "{}",
        applied.show()
    );
    assert!(!applied.stdout.contains("WOULD"), "{}", applied.show());
    assert_eq!(
        applied_state,
        (1, 1, 1, 1),
        "the successor is admitted again; root and successor attached by name; one audit row"
    );
    assert_eq!(
        audit,
        Some((Some(login), Some("job resumed after review".to_string()))),
        "the audit row names the login and the reason"
    );
}
