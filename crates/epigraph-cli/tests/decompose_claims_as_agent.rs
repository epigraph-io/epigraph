//! `decompose_claims --as-agent <id>`: the scheduled decomposition job on the
//! ordinary application login, through row-level security, with NO
//! maintenance DSN (backlogs 9a877b7c and 68d03c24, operator ruling
//! 2026-10-20: a non-bypass read path, no maintenance DSN in agent containers
//! and no host timer).
//!
//! Driven as the real binary on real LOGIN roles, created per test (roles are
//! cluster-global, so each name is unique) and dropped at the end:
//!
//! * an `epigraph_app` login, the shape of the fleet login an agent container
//!   holds as `DATABASE_URL`;
//! * an `epigraph_maintenance` login, the corpus-wide view the job used to
//!   need, as the comparison the coverage measurement is taken against.
//!
//! The superuser fixture pool only seeds rows and reads results. Every test
//! database is fresh, so selection assertions are by claim id.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::path::{Path, PathBuf};
use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BIN: &str = env!("CARGO_BIN_EXE_decompose_claims");

/// The refusal a fleet-login run hit on 2026-10-17 (backlog 9a877b7c). The
/// `--as-agent` path must never reach it.
const BYPASS_REFUSAL: &str = "epigraph_bypass";

/// The zero-visible guard's message: the property the old refusal protected
/// (no silent zero-row run) restated for a session that is not privileged.
const ZERO_VISIBLE: &str = "sees no undecomposed claim";

async fn create_login(pool: &PgPool, parent: &str) -> (String, String) {
    let role = format!("decomp_{}_{}", parent, Uuid::new_v4().simple());
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

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    #[track_caller]
    fn ok(self) -> Self {
        assert_eq!(
            self.code,
            Some(0),
            "decompose_claims failed\nstdout:\n{}\nstderr:\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    /// Claim ids `--dry-run` listed on stdout (`<id>\t<content>` lines).
    fn listed(&self) -> Vec<Uuid> {
        self.stdout
            .lines()
            .filter_map(|l| l.split('\t').next())
            .filter_map(|id| Uuid::parse_str(id).ok())
            .collect()
    }

    /// The first stderr line starting `selection: priority=`.
    #[track_caller]
    fn selection_line(&self) -> &str {
        self.stderr
            .lines()
            .find(|l| l.starts_with("selection: priority="))
            .unwrap_or_else(|| panic!("no selection: line:\n{}", self.stderr))
    }

    /// The integer after ` key=` on the `selection: priority=` line.
    #[track_caller]
    fn selection_count(&self, key: &str) -> usize {
        let line = self.selection_line();
        let at = line
            .find(&format!(" {key}="))
            .unwrap_or_else(|| panic!("no `{key}=` in: {line}"));
        line[at + key.len() + 2..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or_else(|e| panic!("`{key}=` is not a count ({e}): {line}"))
    }
}

/// Run the binary with a clean environment: `DATABASE_URL` only, plus `env`.
/// No `MAINTENANCE_DATABASE_URL` unless a caller passes it, which is exactly
/// the agent container's environment (backlog 9a877b7c).
fn run(database_url: &str, args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", database_url)
        .env("RUST_LOG", "warn")
        .args(args)
        .current_dir(std::env::temp_dir());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run decompose_claims");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn temp_path(stem: &str, ext: &str) -> PathBuf {
    std::env::temp_dir().join(format!("decomp-as-agent-{stem}-{}.{ext}", Uuid::new_v4()))
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A `decomposes_to` edge, stamped by the tenancy trigger from its endpoints
/// (public/public is public; a private endpoint gives the private meet).
async fn seed_decomposes_to(pool: &PgPool, parent: Uuid, atom: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(parent)
    .bind(atom)
    .execute(pool)
    .await
    .expect("seed decomposes_to edge");
}

/// The selection a fleet login makes is NOT refused, reads what RLS shows it,
/// and the coverage difference against the maintenance view is exactly the
/// two classes the design names:
///
/// * a GROUP-PRIVATE undecomposed parent is invisible to the fleet session
///   (`scanned` drops by one). It is never decomposed on either path:
///   selection skips every non-public parent (`skipped_not_public` on the
///   maintenance line), so no decomposition is lost.
/// * a PUBLIC parent whose only `decomposes_to` edge points at a private atom
///   (the edge takes the private meet) LOOKS undecomposed to the fleet
///   session, because RLS also filters the `NOT EXISTS` edge probe. The fleet
///   path selects it; the maintenance path does not. That is the one real
///   difference, pinned here so a change to it is a visible diff.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fleet_login_selects_what_rls_shows_and_is_not_refused(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let (acting, _acting_group) =
        viewer_fixture::seed_agent_with_group(&pool, "decomp-acting").await;
    let (author, author_group) =
        viewer_fixture::seed_agent_with_group(&pool, "decomp-author").await;

    let p = viewer_fixture::seed_public_claim(
        &pool,
        author,
        "Fleet parent P has a first part. Fleet parent P also has a second part.",
    )
    .await;
    let g = viewer_fixture::seed_group_claim(
        &pool,
        author,
        author_group,
        "Private parent G has a first part. Private parent G also has a second part.",
    )
    .await;
    let d = viewer_fixture::seed_public_claim(
        &pool,
        author,
        "Decomposed parent D has a first part. Decomposed parent D has a second part.",
    )
    .await;
    let d_atom = viewer_fixture::seed_public_claim(&pool, author, "D atom.").await;
    seed_decomposes_to(&pool, d, d_atom).await;
    let m = viewer_fixture::seed_public_claim(
        &pool,
        author,
        "Mixed parent M has a first part. Mixed parent M also has a second part.",
    )
    .await;
    let m_atom =
        viewer_fixture::seed_group_claim(&pool, author, author_group, "M private atom.").await;
    seed_decomposes_to(&pool, m, m_atom).await;
    let m_edge_visibility: String = sqlx::query_scalar(
        "SELECT visibility FROM edges WHERE source_id = $1 AND relationship = 'decomposes_to'",
    )
    .bind(m)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(
        m_edge_visibility, "public",
        "CALIBRATION: M's decomposes_to edge must take the private meet"
    );

    let args = [
        "--dry-run",
        "--priority",
        "oldest",
        "--limit",
        "10000",
        "--count-eligible",
    ];
    let acting_s = acting.to_string();
    let mut fleet_args = vec!["--as-agent", acting_s.as_str()];
    fleet_args.extend_from_slice(&args);

    // The fleet login, exactly as the agent container holds it: DATABASE_URL
    // only.
    let fleet = run(&app_url, &fleet_args, &[]);
    assert!(
        !fleet.stderr.contains(BYPASS_REFUSAL),
        "the --as-agent path reached the maintenance-privilege refusal:\n{}",
        fleet.stderr
    );
    let fleet = fleet.ok();

    // The maintenance view, for the comparison.
    let maint = run(
        &maint_url,
        &args,
        &[("MAINTENANCE_DATABASE_URL", &maint_url)],
    )
    .ok();

    // The measurement the PR body quotes.
    eprintln!("MEASURED fleet:       {}", fleet.selection_line());
    eprintln!("MEASURED maintenance: {}", maint.selection_line());

    let fl = fleet.listed();
    let ml = maint.listed();
    assert!(
        fl.contains(&p),
        "the visible undecomposed parent was not selected:\n{}",
        fleet.stderr
    );
    assert!(ml.contains(&p), "{}", maint.stderr);
    assert!(
        !fl.contains(&g) && !ml.contains(&g),
        "a group-private parent was selected"
    );
    assert!(
        !fl.contains(&d) && !ml.contains(&d),
        "a decomposed parent was selected"
    );
    assert!(
        !fl.contains(&d_atom) && !ml.contains(&d_atom),
        "an atom was selected"
    );
    assert!(
        !ml.contains(&m),
        "the maintenance view sees M's private decomposes_to edge: {}",
        maint.stderr
    );
    assert!(
        fl.contains(&m),
        "the fleet session cannot see M's private decomposes_to edge, so M reads as \
         undecomposed; if this changed, the coverage note in decompose_claims' module doc \
         is stale:\n{}",
        fleet.stderr
    );

    // G is read only by the maintenance view, and skipped there as not public.
    assert_eq!(
        maint.selection_count("skipped_not_public"),
        1,
        "{}",
        maint.stderr
    );
    assert_eq!(
        fleet.selection_count("skipped_not_public"),
        0,
        "{}",
        fleet.stderr
    );
    // Population: the maintenance view reads {P, G} (M is decomposed for it);
    // the fleet session reads {P, M} (G is invisible, M's edge is invisible).
    // The same count here, for different rows.
    assert_eq!(
        maint.selection_count("scanned"),
        2,
        "maintenance reads P and G: {}",
        maint.stderr
    );
    assert_eq!(
        fleet.selection_count("scanned"),
        2,
        "the fleet session reads P and M: {}",
        fleet.stderr
    );

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}

/// The old refusal existed so a job on an unprivileged connection could not
/// read zero rows and exit 0. On the `--as-agent` path the session is
/// unprivileged on purpose, so the same property is kept by the result: a
/// population scan that sees NO undecomposed claim fails, naming the login.
///
/// A visible population with nothing eligible (`chosen=0`) is the steady
/// state, not an error, and must still exit 0.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fleet_session_that_sees_no_undecomposed_claim_fails_loudly(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (maint_role, maint_url) = create_login(&pool, "epigraph_maintenance").await;
    let (acting, _) = viewer_fixture::seed_agent_with_group(&pool, "decomp-zero").await;
    let (author, author_group) =
        viewer_fixture::seed_agent_with_group(&pool, "decomp-zero-a").await;

    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        before, 0,
        "CALIBRATION: a fresh test database holds no claim"
    );
    viewer_fixture::seed_group_claim(
        &pool,
        author,
        author_group,
        "Only private G has a first part. Only private G also has a second part.",
    )
    .await;

    let acting_s = acting.to_string();
    let dry = [
        "--as-agent",
        acting_s.as_str(),
        "--dry-run",
        "--priority",
        "recent",
        "--limit",
        "50",
    ];

    // The row exists: the maintenance view reads it.
    let maint = run(
        &maint_url,
        &["--dry-run", "--priority", "recent", "--limit", "50"],
        &[("MAINTENANCE_DATABASE_URL", &maint_url)],
    )
    .ok();
    assert_eq!(maint.selection_count("scanned"), 1, "{}", maint.stderr);

    // The fleet session sees none of it: a loud failure, not exit 0.
    let zero = run(&app_url, &dry, &[]);
    assert_ne!(
        zero.code,
        Some(0),
        "a zero-row run exited 0:\n{}",
        zero.stderr
    );
    assert!(
        zero.stderr.contains(ZERO_VISIBLE),
        "the zero-visible guard's message is missing:\n{}",
        zero.stderr
    );
    assert!(
        !zero.stderr.contains(BYPASS_REFUSAL),
        "this is the maintenance-privilege refusal, not the zero-visible guard:\n{}",
        zero.stderr
    );

    // A visible, ineligible population (one short sentence: looks atomic) is
    // the steady state: exit 0 with nothing chosen.
    viewer_fixture::seed_public_claim(&pool, author, "Short atomic claim.").await;
    let steady = run(&app_url, &dry, &[]).ok();
    assert_eq!(steady.selection_count("scanned"), 1, "{}", steady.stderr);
    assert_eq!(steady.selection_count("chosen"), 0, "{}", steady.stderr);
    assert_eq!(
        steady.selection_count("skipped_looks_atomic"),
        1,
        "{}",
        steady.stderr
    );

    drop_login(&pool, &app_role).await;
    drop_login(&pool, &maint_role).await;
}

/// A decomposing `--as-agent` run on the fleet login writes its
/// `decomposes_to` edges AS THE ACTING AGENT: the edge records the agent's
/// writable group (`writer_group_id`, migration 120). An unstamped write on
/// the same login would also succeed, through 077's world arm, but would land
/// ownerless (`writer_group_id` NULL, administrative) — so "the edge exists"
/// alone would pass for the wrong write.
///
/// Atoms go through the API, which is mocked here: it answers each atom POST
/// with the id of a pre-seeded public atom and requires the bearer token.
#[sqlx::test(migrations = "../../migrations")]
async fn a_fleet_run_writes_decomposes_to_edges_as_the_acting_agent(pool: PgPool) {
    let (app_role, app_url) = create_login(&pool, "epigraph_app").await;
    let (acting, acting_group) =
        viewer_fixture::seed_agent_with_group(&pool, "decomp-writer").await;
    let (author, _) = viewer_fixture::seed_agent_with_group(&pool, "decomp-writer-a").await;

    let parent_text =
        "Writer parent W turns freely. Writer parent W has a friction coefficient of 4e-22.";
    let atom1_text = "Writer parent W turns freely.";
    let atom2_text = "Writer parent W has a friction coefficient of 4e-22.";
    let w = viewer_fixture::seed_public_claim(&pool, author, parent_text).await;
    let a1 = viewer_fixture::seed_public_claim(&pool, author, atom1_text).await;
    let a2 = viewer_fixture::seed_public_claim(&pool, author, atom2_text).await;

    let api = MockServer::start().await;
    for (text, id) in [(atom1_text, a1), (atom2_text, a2)] {
        Mock::given(method("POST"))
            .and(path("/api/v1/claims"))
            .and(header("authorization", "Bearer decomp-test-token"))
            .and(body_string_contains(text))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": id})))
            .expect(1)
            .mount(&api)
            .await;
    }

    let fixture = temp_path("fixture", "json");
    std::fs::write(
        &fixture,
        serde_json::json!({ parent_text: {"atoms": [atom1_text, atom2_text], "generality": [0, 1]} })
            .to_string(),
    )
    .unwrap();
    let ids = temp_path("ids", "txt");
    std::fs::write(&ids, format!("{w}\n")).unwrap();

    let acting_s = acting.to_string();
    let api_uri = api.uri();
    let r = run(
        &app_url,
        &[
            "--as-agent",
            acting_s.as_str(),
            "--provider",
            "fixture",
            "--ids-file",
            s(&ids),
        ],
        &[
            ("EPIGRAPH_API", api_uri.as_str()),
            ("EPIGRAPH_TOKEN", "decomp-test-token"),
            ("DECOMPOSE_FIXTURE_PATH", s(&fixture)),
        ],
    );
    assert!(!r.stderr.contains(BYPASS_REFUSAL), "{}", r.stderr);
    let r = r.ok();
    assert!(
        r.stderr
            .contains("decompose complete: 2 atoms, 2 decomposes_to edges"),
        "{}",
        r.stderr
    );

    let edges: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT target_id, visibility, writer_group_id FROM edges \
         WHERE source_id = $1 AND relationship = 'decomposes_to' ORDER BY target_id",
    )
    .bind(w)
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut want = vec![a1, a2];
    want.sort();
    assert_eq!(
        edges.iter().map(|e| e.0).collect::<Vec<_>>(),
        want,
        "both atoms wired: {edges:?}"
    );
    for (target, visibility, writer) in &edges {
        assert_eq!(visibility, "public", "edge to {target}");
        assert_eq!(
            *writer,
            Some(acting_group),
            "the edge to {target} was not written as the acting agent (writer_group_id); an \
             unstamped write lands ownerless"
        );
    }

    // The parent left the population: the next fleet selection does not
    // choose it again.
    let next = run(
        &app_url,
        &[
            "--as-agent",
            acting_s.as_str(),
            "--dry-run",
            "--ids-file",
            s(&ids),
        ],
        &[],
    )
    .ok();
    assert!(!next.listed().contains(&w), "{}", next.stderr);

    for p in [&fixture, &ids] {
        std::fs::remove_file(p).ok();
    }
    drop_login(&pool, &app_role).await;
}
