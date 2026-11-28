//! `epigraph-operator reprovision-write-scopes` (backlog c841b15f, migration
//! 362), driven through the real binary against a `#[sqlx::test]` database
//! migrated 001 -> head, as a real NOSUPERUSER maintenance login, and checked
//! against the real `/oauth/token` endpoint.
//!
//! What is pinned:
//! * a refresh chain minted BEFORE the run mints an access token carrying
//!   `edges:write` and `evidence:write` after it (the refresh grant issues
//!   stored ∩ granted, so the client grant alone would not reach it);
//! * suspended, revoked and pending clients, an active client without
//!   `claims:write`, and a live chain that never consented to `claims:write`
//!   are untouched; every change adds only the two scopes, appended;
//! * the dry run and a wrong `--confirm-count` change nothing; one
//!   `oauth.write_scopes_reprovisioned` row per changed client; a re-run finds
//!   nothing to do;
//! * `--reverse --manifest` restores the exact prior arrays (order and a
//!   pre-existing `evidence:write` in `allowed_scopes` kept), restores a chain
//!   by family (the successor a rotation minted since), and HOLDS a client
//!   whose arrays changed since (exit 3);
//! * the definers refuse any scope outside {edges:write, evidence:write}
//!   (admin-only included), a forged reverse line, and a non-maintenance
//!   login; they are maintenance-owned and not executable by the app role;
//!   `docs/runbooks/362-undo.sql` drops both.

mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::process::Command;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";
const ADDED: [&str; 2] = ["edges:write", "evidence:write"];

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

/// A fresh NOSUPERUSER login in `in_role`: `(role, dsn)`.
async fn login_in(pool: &PgPool, in_role: &str) -> (String, String) {
    let url = fixture::database_url_for(pool).await;
    let role = format!("rws_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD 'probe-only' NOSUPERUSER IN ROLE {in_role}"
    ))
    .execute(pool)
    .await
    .expect("create role");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (_, host) = rest.split_once('@').expect("credentials");
    (role.clone(), format!("{scheme}://{role}:probe-only@{host}"))
}

async fn drop_role(pool: &PgPool, role: &str) {
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(pool)
        .await
        .expect("drop role");
}

fn v(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_string()).collect()
}

/// A service client with a known secret: `(oauth_clients.id, client_id, secret)`.
async fn service_client(
    pool: &PgPool,
    status: &str,
    allowed: &[&str],
    granted: &[&str],
) -> (Uuid, String, String) {
    let (agent, _) = fixture::seed_agent_with_group(pool, "rws-service").await;
    let secret_bytes: [u8; 32] = *blake3::hash(agent.as_bytes()).as_bytes();
    let secret = hex::encode(secret_bytes);
    let client_id = format!("epigraph_{}", hex::encode(&secret_bytes[..16]));
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, agent_id, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, 'rws test service', 'service', $3, $4, $5, $6, 'Fixture Org', \
                 'fixture@example.invalid') RETURNING id",
    )
    .bind(&client_id)
    .bind(blake3::hash(&secret_bytes).as_bytes().as_slice())
    .bind(v(allowed))
    .bind(v(granted))
    .bind(status)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the service client");
    (id, client_id, secret)
}

/// A live refresh token row with `scopes`, inserted directly.
async fn live_token(pool: &PgPool, client: Uuid, scopes: &[&str]) -> Uuid {
    let raw: [u8; 32] = *blake3::hash(Uuid::new_v4().as_bytes()).as_bytes();
    sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, $3, now() + interval '1 day') RETURNING id",
    )
    .bind(blake3::hash(&raw).as_bytes().as_slice())
    .bind(client)
    .bind(v(scopes))
    .fetch_one(pool)
    .await
    .expect("a live refresh token")
}

/// `POST /oauth/token` with `body`: `(status, body)`.
async fn token(pool: &PgPool, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let app = epigraph_api::create_router(epigraph_api::AppState::with_db(
        pool.clone(),
        epigraph_api::ApiConfig::default(),
    ));
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, json)
}

/// Refresh `refresh` as the service client: `(status, scope words, next refresh)`.
async fn refresh(
    pool: &PgPool,
    client_id: &str,
    secret: &str,
    refresh: &str,
) -> (StatusCode, Vec<String>, String, serde_json::Value) {
    let (status, body) = token(
        pool,
        serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_id,
            "client_secret": secret,
        }),
    )
    .await;
    let scopes = body["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let next = body["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (status, scopes, next, body)
}

/// Per client: `(status, allowed, granted, {token id: (scopes, live)})`.
type Snap = BTreeMap<
    Uuid,
    (
        String,
        Vec<String>,
        Vec<String>,
        BTreeMap<Uuid, (Vec<String>, bool)>,
    ),
>;

async fn snapshot(pool: &PgPool, clients: &[Uuid]) -> Snap {
    let mut out = Snap::new();
    for c in clients {
        let (status, allowed, granted): (String, Vec<String>, Vec<String>) = sqlx::query_as(
            "SELECT status::text, allowed_scopes, granted_scopes FROM oauth_clients WHERE id = $1",
        )
        .bind(c)
        .fetch_one(pool)
        .await
        .expect("client");
        let tokens: Vec<(Uuid, Vec<String>, bool)> = sqlx::query_as(
            "SELECT id, scopes, (revoked_at IS NULL AND expires_at > now()) \
               FROM refresh_tokens WHERE client_id = $1",
        )
        .bind(c)
        .fetch_all(pool)
        .await
        .expect("tokens");
        out.insert(
            *c,
            (
                status,
                allowed,
                granted,
                tokens.into_iter().map(|(i, s, l)| (i, (s, l))).collect(),
            ),
        );
    }
    out
}

async fn audit_rows(pool: &PgPool, event: &str, client: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = $1 AND details -> 'client' ->> 'id' = $2::text \
          ORDER BY created_at, id",
    )
    .bind(event)
    .bind(client)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

/// `N` from a forward report's first line (`...: N client(s), ...`).
fn client_count(stdout: &str) -> usize {
    let first = stdout.lines().next().unwrap_or_default();
    let before = first
        .split(" client(s)")
        .next()
        .unwrap_or_default()
        .rsplit(' ')
        .next()
        .unwrap_or_default();
    before
        .parse()
        .unwrap_or_else(|_| panic!("no client count in {first:?}"))
}

/// The whole act, end to end.
///
/// Verified to fail (each mutation applied to migration 362 alone, then
/// reverted): the definer's token UPDATE removed -> a live claims:write
/// token keeps its old stored scopes (H's token assertion); `oc.status =
/// 'active'` removed -> the dry run lists the suspended, revoked and pending
/// clients; the reverse setting each array to `after` minus the two scopes
/// instead of the recorded `before` -> client A's restored `allowed_scopes`
/// loses its pre-existing `evidence:write`. On the tree before this change
/// the verb does not exist (clap: unrecognized subcommand) and the dry-run
/// assertion fails.
#[sqlx::test(migrations = "../../migrations")]
async fn reprovision_widens_live_chains_of_active_writers_and_reverses_exactly(pool: PgPool) {
    // A: active writer, `evidence:write` already in allowed (not granted),
    // arrays in a non-sorted order.
    let a_allowed = ["claims:write", "claims:read", "evidence:write"];
    let a_granted = ["claims:write", "claims:read"];
    let (a, a_cid, a_secret) = service_client(&pool, "active", &a_allowed, &a_granted).await;
    // H: active writer that also holds an admin-only scope.
    let (h, _, _) = service_client(
        &pool,
        "active",
        &["claims:admin", "claims:write"],
        &["claims:admin", "claims:write"],
    )
    .await;
    // Not candidates.
    let w = ["claims:read", "claims:write"];
    let (s, _, _) = service_client(&pool, "suspended", &w, &w).await;
    let (r, _, _) = service_client(&pool, "revoked", &w, &w).await;
    let (p, _, _) = service_client(&pool, "pending", &w, &w).await;
    let (ro, _, _) = service_client(&pool, "active", &["claims:read"], &["claims:read"]).await;
    for c in [s, r, p, ro] {
        live_token(&pool, c, &w).await;
    }
    // A's chain that never consented to claims:write.
    let a_read_only = live_token(&pool, a, &["claims:read"]).await;
    let h_token = live_token(&pool, h, &["claims:write", "claims:admin"]).await;

    // A's pre-existing chain, minted by the real endpoint, then rotated once.
    let (st, first) = token(
        &pool,
        serde_json::json!({ "grant_type": "client_credentials", "client_id": a_cid,
                            "client_secret": a_secret }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "CALIBRATION: {first}");
    let r0 = first["refresh_token"]
        .as_str()
        .expect("refresh")
        .to_string();
    let (st, pre_scopes, r1, body) = refresh(&pool, &a_cid, &a_secret, &r0).await;
    assert_eq!(st, StatusCode::OK, "CALIBRATION refresh: {body}");
    assert!(
        ADDED
            .iter()
            .all(|x| !pre_scopes.contains(&(*x).to_string())),
        "PREMISE: the chain mints neither scope before the run: {pre_scopes:?}"
    );

    let watched = [a, h, s, r, p, ro];
    let before = snapshot(&pool, &watched).await;
    let (role, dsn) = login_in(&pool, "epigraph_maintenance").await;
    let manifest = std::env::temp_dir().join(format!("rws-{}.jsonl", Uuid::new_v4().simple()));
    let m = manifest.to_str().expect("utf-8");
    let reason = "gate the scope remap";

    let dry = run_dsn(&["reprovision-write-scopes", "--reason", reason], &dsn);
    let dry_state = snapshot(&pool, &watched).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(dry.stdout.starts_with("DRY RUN: "), "{}", dry.show());
    let n = client_count(&dry.stdout);
    for c in [a, h] {
        assert!(
            dry.stdout.contains(&format!("CLIENT\t{c}")),
            "{c} listed: {}",
            dry.show()
        );
    }
    for c in [s, r, p, ro] {
        assert!(
            !dry.stdout.contains(&c.to_string()),
            "{c} not listed: {}",
            dry.show()
        );
    }
    assert_eq!(dry_state, before, "a dry run changes nothing");
    assert!(audit_rows(&pool, "oauth.write_scopes_reprovisioned", a)
        .await
        .is_empty());

    let wrong = (n + 1).to_string();
    let miscounted = run_dsn(
        &[
            "reprovision-write-scopes",
            "--reason",
            reason,
            "--apply",
            "--confirm-count",
            wrong.as_str(),
            "--manifest-out",
            m,
        ],
        &dsn,
    );
    assert_ne!(miscounted.code, 0, "{}", miscounted.show());
    assert_eq!(
        snapshot(&pool, &watched).await,
        before,
        "a wrong count changes nothing"
    );
    assert!(!manifest.exists(), "no manifest for a refused apply");

    let count = n.to_string();
    let applied = run_dsn(
        &[
            "reprovision-write-scopes",
            "--reason",
            reason,
            "--apply",
            "--confirm-count",
            count.as_str(),
            "--manifest-out",
            m,
        ],
        &dsn,
    );
    assert_eq!(applied.code, 0, "{}", applied.show());
    let after = snapshot(&pool, &watched).await;

    // A: appended, order kept; evidence:write not duplicated in allowed.
    assert_eq!(
        after[&a].1,
        v(&[
            "claims:write",
            "claims:read",
            "evidence:write",
            "edges:write"
        ])
    );
    assert_eq!(
        after[&a].2,
        v(&[
            "claims:write",
            "claims:read",
            "edges:write",
            "evidence:write"
        ])
    );
    assert_eq!(
        after[&a].3[&a_read_only].0,
        v(&["claims:read"]),
        "a chain without claims:write is not widened"
    );
    // H: the two added, its admin-only scope kept, nothing admin-only added.
    assert_eq!(
        after[&h].2,
        v(&[
            "claims:admin",
            "claims:write",
            "edges:write",
            "evidence:write"
        ])
    );
    assert_eq!(
        after[&h].3[&h_token].0,
        v(&[
            "claims:write",
            "claims:admin",
            "edges:write",
            "evidence:write"
        ])
    );
    // Untouched: not active, or not a writer.
    for c in [s, r, p, ro] {
        assert_eq!(after[&c], before[&c], "client {c} is untouched");
    }
    // Every change is an append of only the two scopes.
    for c in watched {
        let (_, ab, gb, tb) = &before[&c];
        let (_, aa, ga, ta) = &after[&c];
        for (b, x) in [(ab, aa), (gb, ga)]
            .into_iter()
            .chain(tb.iter().map(|(id, (sb, _))| (sb, &ta[id].0)))
        {
            assert_eq!(&x[..b.len()], &b[..], "{c}: a prefix is kept");
            assert!(
                x[b.len()..].iter().all(|s| ADDED.contains(&s.as_str())),
                "{c}: only the two scopes are added: {b:?} -> {x:?}"
            );
        }
    }
    let rows = audit_rows(&pool, "oauth.write_scopes_reprovisioned", a).await;
    assert_eq!(rows.len(), 1, "one audit row per client: {rows:?}");
    assert_eq!(rows[0]["reason"], reason);
    assert_eq!(rows[0]["session_user"], role.as_str());
    assert_eq!(rows[0]["refresh_tokens_widened"], 1);
    for c in [s, r, p, ro] {
        assert!(audit_rows(&pool, "oauth.write_scopes_reprovisioned", c)
            .await
            .is_empty());
    }

    // THE POINT: the chain minted before the run now mints both scopes.
    let (st, post_scopes, r2, body) = refresh(&pool, &a_cid, &a_secret, &r1).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    for x in ADDED {
        assert!(
            post_scopes.contains(&x.to_string()),
            "the pre-existing chain mints {x}: {post_scopes:?}"
        );
    }

    let rerun = run_dsn(&["reprovision-write-scopes", "--reason", reason], &dsn);
    assert_eq!(rerun.code, 0, "{}", rerun.show());
    assert_eq!(
        client_count(&rerun.stdout),
        0,
        "a re-run finds nothing: {}",
        rerun.show()
    );

    // H changes after the run: its reverse must HOLD it.
    sqlx::query(
        "UPDATE oauth_clients SET granted_scopes = granted_scopes || ARRAY['agents:read'] \
          WHERE id = $1",
    )
    .bind(h)
    .execute(&pool)
    .await
    .expect("move H");
    let h_moved = snapshot(&pool, &[h]).await;

    let rev_dry = run_dsn(
        &[
            "reprovision-write-scopes",
            "--reverse",
            "--manifest",
            m,
            "--reason",
            "undo",
        ],
        &dsn,
    );
    assert_eq!(
        snapshot(&pool, &[a]).await[&a].1,
        after[&a].1,
        "a reverse dry run changes nothing: {}",
        rev_dry.show()
    );
    let rev = run_dsn(
        &[
            "reprovision-write-scopes",
            "--reverse",
            "--manifest",
            m,
            "--reason",
            "undo",
            "--apply",
        ],
        &dsn,
    );
    let restored = snapshot(&pool, &watched).await;
    drop_role(&pool, &role).await;
    let _ = std::fs::remove_file(&manifest);

    assert_eq!(rev.code, 3, "a held client exits 3: {}", rev.show());
    assert!(
        rev.stdout.contains(&format!("RESTORED\t{a}")),
        "{}",
        rev.show()
    );
    assert!(rev.stdout.contains(&format!("HELD\t{h}")), "{}", rev.show());
    assert_eq!(restored[&a].1, v(&a_allowed), "A's allowed_scopes exactly");
    assert_eq!(restored[&a].2, v(&a_granted), "A's granted_scopes exactly");
    // The successor minted by the post-run refresh is restored by family.
    let live: Vec<&Vec<String>> = restored[&a]
        .3
        .iter()
        .filter(|(id, (_, l))| *l && **id != a_read_only)
        .map(|(_, (sc, _))| sc)
        .collect();
    assert_eq!(
        live.len(),
        1,
        "one live claims:write chain: {:?}",
        restored[&a].3
    );
    assert!(
        ADDED.iter().all(|x| !live[0].contains(&(*x).to_string())),
        "the successor's scopes are restored: {live:?}"
    );
    assert_eq!(restored[&h], h_moved[&h], "a held client is left alone");
    for c in [s, r, p, ro] {
        assert_eq!(restored[&c], before[&c]);
    }
    assert_eq!(
        audit_rows(&pool, "oauth.write_scopes_reprovision_reversed", a)
            .await
            .len(),
        1
    );
    let (st, back_scopes, _, body) = refresh(&pool, &a_cid, &a_secret, &r2).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(
        ADDED
            .iter()
            .all(|x| !back_scopes.contains(&(*x).to_string())),
        "after the reverse the chain mints neither: {back_scopes:?}"
    );
}

/// The definers' own refusals and their privilege shape.
///
/// Verified to fail: the definer's closed-set check removed -> the
/// `{claims:admin}` call succeeds; the reverse's client-array shape refusal
/// downgraded to a NOTICE -> the forged line that would put `claims:admin`
/// in place of `claims:read` is accepted. On the tree before this change the
/// function does not exist (42883, not 22023).
#[sqlx::test(migrations = "../../migrations")]
async fn the_definers_refuse_other_scopes_forged_lines_and_non_maintenance_logins(pool: PgPool) {
    let w = ["claims:read", "claims:write"];
    let (a, _, _) = service_client(&pool, "active", &w, &w).await;
    let before = snapshot(&pool, &[a]).await;

    // As a superuser session (the harness): only the closed set is accepted.
    for bad in [
        vec!["claims:admin"],
        vec!["edges:write", "claims:admin"],
        vec!["platform:admin"],
        vec!["claims:write"],
        vec!["edges:write", "edges:write"],
        vec![],
    ] {
        let err = sqlx::query(
            "SELECT * FROM public.epigraph_reprovision_write_scopes($1, 'r', '{}'::jsonb)",
        )
        .bind(v(&bad))
        .execute(&pool)
        .await
        .expect_err(&format!("{bad:?} must be refused"));
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .unwrap_or_default();
        assert_eq!(code, "22023", "{bad:?}: {err}");
    }
    assert_eq!(snapshot(&pool, &[a]).await, before, "nothing was written");

    // A forged reverse line that would grant or strip something else.
    for (b, x) in [
        (v(&["claims:read"]), v(&["claims:admin"])),
        (v(&["claims:read"]), v(&["claims:read", "claims:admin"])),
        (v(&["claims:read", "claims:write"]), v(&["claims:read"])),
    ] {
        let err = sqlx::query(
            "SELECT * FROM public.epigraph_reprovision_write_scopes_reverse(\
                 $1, $2, $2, $3, $3, '[]'::jsonb, 'r', '{}'::jsonb)",
        )
        .bind(a)
        .bind(&b)
        .bind(&x)
        .execute(&pool)
        .await
        .expect_err("a forged line is refused");
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .unwrap_or_default();
        assert_eq!(code, "22023", "{b:?} -> {x:?}: {err}");
    }
    assert_eq!(snapshot(&pool, &[a]).await, before, "nothing was written");

    // Owned by the maintenance role, SECURITY DEFINER, pinned path, and no
    // EXECUTE for PUBLIC or the application role.
    for sig in [
        "public.epigraph_reprovision_write_scopes(text[], text, jsonb)",
        "public.epigraph_reprovision_write_scopes_reverse(uuid, text[], text[], text[], text[], \
         jsonb, text, jsonb)",
    ] {
        let (definer, owner, config, app, public): (bool, String, Vec<String>, bool, bool) =
            sqlx::query_as(
                "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                        COALESCE(p.proconfig, ARRAY[]::text[]), \
                        has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                        EXISTS (SELECT 1 FROM aclexplode(p.proacl) x \
                                 WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE') \
                   FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
            )
            .bind(sig)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("{sig}: {e}"));
        assert!(definer, "{sig} is SECURITY DEFINER");
        assert_eq!(owner, "epigraph_maintenance", "{sig}");
        assert_eq!(config, v(&["search_path=pg_catalog, pg_temp"]), "{sig}");
        assert!(!app, "{sig}: no EXECUTE for epigraph_app");
        assert!(!public, "{sig}: no EXECUTE for PUBLIC");
    }

    // An application login cannot run the verb (nothing changes), and the
    // binary refuses a login outside epigraph_maintenance.
    let (app_role, app_dsn) = login_in(&pool, "epigraph_app").await;
    let app_pool = PgPool::connect(&app_dsn).await.expect("app login");
    let err = sqlx::query(
        "SELECT * FROM public.epigraph_reprovision_write_scopes(\
             ARRAY['edges:write'], 'r', '{}'::jsonb)",
    )
    .execute(&app_pool)
    .await
    .expect_err("the app login is refused");
    app_pool.close().await;
    let refused = run_dsn(
        &[
            "reprovision-write-scopes",
            "--reason",
            "r",
            "--apply",
            "--confirm-count",
            "1",
            "--manifest-out",
            "/nonexistent-dir/rws.jsonl",
        ],
        &app_dsn,
    );
    drop_role(&pool, &app_role).await;
    assert_eq!(
        err.as_database_error()
            .and_then(|d| d.code())
            .unwrap_or_default(),
        "42501",
        "{err}"
    );
    assert_ne!(refused.code, 0, "{}", refused.show());
    assert_eq!(snapshot(&pool, &[a]).await, before, "nothing was written");

    // The undo runbook drops both functions, and is idempotent.
    let undo = include_str!("../../../docs/runbooks/362-undo.sql");
    for _ in 0..2 {
        sqlx::raw_sql(undo).execute(&pool).await.expect("362-undo");
    }
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_proc WHERE proname LIKE 'epigraph_reprovision_write_scopes%'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(left, 0, "362-undo drops both functions");
}
