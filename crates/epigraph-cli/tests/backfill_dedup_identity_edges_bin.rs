//! `backfill_dedup_identity_edges` (backlog d5781a48), driven as the real
//! process an operator runs, on real non-superuser LOGIN roles: an
//! `epigraph_app` login as `DATABASE_URL` and an `epigraph_maintenance` login
//! as `MAINTENANCE_DATABASE_URL`, as on a deployment.
//!
//! The operator contract this file pins:
//!
//! * no configured `MAINTENANCE_DATABASE_URL`: refused, nothing written (the
//!   fallback to the application DSN is never used for a corpus-wide write);
//! * no flag (and `--dry-run`): prints the selection, `applied: false`, and
//!   writes nothing; `--apply` with `--dry-run` is refused;
//! * `--apply`: writes the identity edge, and a second `--apply` selects and
//!   writes nothing.
//!
//! The legacy duplicate and its canonical are GROUP-private, in a group the
//! maintenance login has no part in, so a run that only saw public rows (an
//! unprivileged session under row security) would select nothing and fail
//! these assertions. `ClaimRepository::backfill_legacy_dedup_identity_edges_conn`'s
//! selection rule itself is covered in
//! `epigraph-db/tests/legacy_dedup_identity_backfill.rs`.
//!
//! The process environment is CLEARED (and the working directory is the temp
//! dir): the binary loads a `.env`, and an inherited `MAINTENANCE_DATABASE_URL`
//! would point it elsewhere or mask the refusal.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_backfill_dedup_identity_edges");
const REFUSAL: &str = "runs only on an explicitly configured MAINTENANCE_DATABASE_URL";

/// A per-test LOGIN role in `parent` (roles are cluster-global, so the name
/// is unique), and its DSN on the test database.
async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("d5781a48_{}_{}", parent, Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' IN ROLE {parent}"
    ))
    .execute(pool)
    .await
    .expect("create the login");
    let base = viewer_fixture::database_url_for(pool).await;
    let scheme_end = base.find("://").expect("a scheme") + 3;
    let host_path = &base[base.find('@').expect("credentials in the DSN") + 1..];
    let url = format!("{}{role}:{password}@{host_path}", &base[..scheme_end]);
    (role, url)
}

async fn drop_login(pool: &PgPool, role: &str) {
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(pool)
        .await;
}

struct Logins {
    app: (String, String),
    maint: (String, String),
}

impl Logins {
    async fn new(pool: &PgPool) -> Self {
        Self {
            app: create_login(pool, "epigraph_app").await,
            maint: create_login(pool, "epigraph_maintenance").await,
        }
    }

    async fn drop(self, pool: &PgPool) {
        drop_login(pool, &self.app.0).await;
        drop_login(pool, &self.maint.0).await;
    }
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn report(&self) -> serde_json::Value {
        assert_eq!(self.code, Some(0), "the run failed: {}", self.stderr);
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("stdout is not the JSON report ({e}): {}", self.stdout))
    }
}

fn run(args: &[&str], database_url: &str, maintenance_url: Option<&str>) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(std::env::temp_dir());
    if let Some(m) = maintenance_url {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
    }
    let out = cmd.output().expect("run the binary");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A group-private canonical and a duplicate retired onto it exactly as the
/// legacy `scripts/fuzzy_dedup_claims.py` step 7 did (no identity edge).
async fn legacy_pair(pool: &PgPool, tag: &str) -> (Uuid, Uuid) {
    let (agent, group) = viewer_fixture::seed_agent_with_group(pool, tag).await;
    let canonical = viewer_fixture::seed_group_claim(pool, agent, group, "legacy canonical").await;
    let dup = viewer_fixture::seed_group_claim(pool, agent, group, "legacy duplicate").await;
    sqlx::query(
        "UPDATE claims \
            SET supersedes = $1, is_current = false, embedding = NULL, \
                embedding_3072 = NULL, updated_at = NOW(), \
                labels = array_append(COALESCE(labels, ARRAY[]::text[]), 'deduped'), \
                properties = COALESCE(properties, '{}'::jsonb) \
                           || jsonb_build_object('deduped_into', $1::text, \
                                                 'deduped_by', 'fuzzy_dedup_claims', \
                                                 'deduped_at', now()::text) \
          WHERE id = $2",
    )
    .bind(canonical)
    .bind(dup)
    .execute(pool)
    .await
    .expect("legacy mark");
    (canonical, dup)
}

/// Every `same_as` edge out of `dup`, as (target, properties.dedup.tool).
async fn identity_edges(pool: &PgPool, dup: Uuid) -> Vec<(Uuid, Option<String>)> {
    sqlx::query_as(
        "SELECT target_id, properties->'dedup'->>'tool' FROM edges \
          WHERE source_id = $1 AND relationship = 'same_as' ORDER BY created_at, id",
    )
    .bind(dup)
    .fetch_all(pool)
    .await
    .expect("identity edges")
}

#[sqlx::test(migrations = "../../migrations")]
async fn without_a_configured_maintenance_dsn_it_refuses_and_writes_nothing(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let (_, dup) = legacy_pair(&pool, "d5781a48-bin-refuse").await;

    // The maintenance login itself as DATABASE_URL: a privileged DSN that
    // reaches the binary only through the fallback is still refused, and the
    // refusal cannot be the missing privilege of an application login.
    for args in [&[][..], &["--apply"][..]] {
        let r = run(args, &logins.maint.1, None);
        assert_ne!(r.code, Some(0), "{args:?}: {}", r.stdout);
        assert!(r.stderr.contains(REFUSAL), "{args:?}: {}", r.stderr);
    }
    assert!(
        identity_edges(&pool, dup).await.is_empty(),
        "a refused run wrote an edge"
    );
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn by_default_it_is_a_dry_run_on_the_maintenance_login(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let (canonical, dup) = legacy_pair(&pool, "d5781a48-bin-dry").await;

    for args in [&[][..], &["--dry-run"][..]] {
        let report = run(args, &logins.app.1, Some(&logins.maint.1)).report();
        assert_eq!(report["applied"], false, "{args:?}: {report}");
        assert_eq!(report["inserted"], 0, "{args:?}: {report}");
        assert_eq!(
            report["duplicates"],
            serde_json::json!([{
                "duplicate": dup, "canonical": canonical, "identity_edge": null,
            }]),
            "{args:?}: the group-private legacy mark is selected on the maintenance login"
        );
    }
    // Asking for both is refused at parse time, before any connection.
    let both = run(
        &["--apply", "--dry-run"],
        &logins.app.1,
        Some(&logins.maint.1),
    );
    assert_ne!(
        both.code,
        Some(0),
        "--apply with --dry-run ran: {}",
        both.stdout
    );
    assert!(
        both.stderr.contains("cannot be used with"),
        "{}",
        both.stderr
    );
    assert!(
        identity_edges(&pool, dup).await.is_empty(),
        "a dry run wrote an edge"
    );
    logins.drop(&pool).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn apply_writes_the_identity_edge_once_on_the_maintenance_login(pool: PgPool) {
    let logins = Logins::new(&pool).await;
    let (canonical, dup) = legacy_pair(&pool, "d5781a48-bin-apply").await;

    let report = run(&["--apply"], &logins.app.1, Some(&logins.maint.1)).report();
    assert_eq!(report["applied"], true, "{report}");
    assert_eq!(report["inserted"], 1, "{report}");
    let edges = identity_edges(&pool, dup).await;
    assert_eq!(
        edges,
        vec![(canonical, Some("fuzzy_dedup_claims".to_string()))],
        "{report}"
    );
    let edge_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE source_id = $1 AND relationship = 'same_as'",
    )
    .bind(dup)
    .fetch_one(&pool)
    .await
    .expect("the edge id");
    assert_eq!(
        report["duplicates"][0]["identity_edge"],
        serde_json::json!(edge_id),
        "the report names the edge it wrote: {report}"
    );

    let again = run(&["--apply"], &logins.app.1, Some(&logins.maint.1)).report();
    assert_eq!(again["inserted"], 0, "{again}");
    assert_eq!(again["duplicates"], serde_json::json!([]), "{again}");
    assert_eq!(identity_edges(&pool, dup).await.len(), 1, "a re-run wrote");
    logins.drop(&pool).await;
}
