//! Migration 118 (batch W11): the application role loses direct UPDATE/DELETE
//! on credential and ledger tables, measured AS the application role.
//!
//! Every write under test runs on a pool whose connections are
//! `SET SESSION AUTHORIZATION epigraph_app` (non-bypassing; `session_user` is
//! then `epigraph_app`, which is what 118's privilege test reads). Fixtures are
//! seeded and read back on the superuser pool.
//!
//! The first test is a CATALOG RATCHET: no public table may be both without row
//! security and UPDATE/DELETE-able by `epigraph_app`, unless it is on
//! [`ALLOWLIST`] with a reason. The allowlist must also stay exact: an entry
//! that no longer violates fails the test until it is removed, so the list only
//! shrinks.
//!
//! # Verified to fail
//!
//! Each mutation of migration 118 applied alone, then restored and rebuilt:
//!
//! * `oauth_clients` dropped from the credential REVOKE: fails
//!   `no_rowless_table_is_app_writable_unless_allowlisted` and
//!   `credential_and_ledger_tables_refuse_direct_app_writes`.
//! * rotation as check-then-update (SELECT the live row, then UPDATE by hash):
//!   fails `concurrent_rotations_of_one_token_admit_exactly_one` (8 of 8
//!   rotations succeeded with a 50 ms gap between the two statements; without
//!   the gap it failed 2 runs of 3, so the gap is what makes the kill
//!   deterministic, not what makes the mutant wrong).
//! * reuse detection disabled (`on_reuse` always `invalid`): fails
//!   `refresh_rotation_chains_a_family_and_reuse_revokes_it` and the
//!   concurrency test.
//! * the stale guard's condition forced false: fails
//!   `the_app_role_cannot_make_a_match_candidate_stale`.
//! * table-level UPDATE on `agents` kept: fails
//!   `agents_identity_columns_are_not_app_updatable`.
//! * the maintenance role's DELETE on the derived rows withheld: fails
//!   `the_app_role_cannot_make_a_match_candidate_stale` (42501 on
//!   `bp_messages` during the maintenance-role retirement).
//! * the rotation's `service` cap cut from 90 days to 24 hours, or its `ELSE`
//!   (agent) cap lengthened to 30 days: fails
//!   `rotation_caps_each_client_types_successor_at_its_refresh_ttl`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::agent_key::AgentKeyRepository;
use epigraph_db::repos::authorization_code::AuthorizationCodeRepository;
use epigraph_db::repos::authorize_session::AuthorizeSessionRepository;
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use epigraph_db::repos::refresh_token::{
    RefreshCheck, RefreshRevokeReason, RefreshRotateOutcome, RefreshTokenRepository,
};
use epigraph_db::{AgentRepository, MatchCandidateRepo};
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

/// Why each remaining table keeps application UPDATE/DELETE without row
/// security. One reason per class; migration 118's header names the tables it
/// closed. A table leaves this list when its privilege is revoked, its writes
/// move into a definer, or it gains row security.
const DERIVED_BP: &str = "derived belief-propagation state: written on the application role \
    by the request path and by invoker triggers (edges_auto_factor inserts factors, \
    claims_deactivate_factors deletes them); tenancy for derived rows is a follow-up";
const DERIVED_CLUSTER: &str = "derived clustering / theme / neighbourhood state, rebuilt by \
    jobs and the clusters routes; no credential or authority content";
const OPERATIONAL: &str = "an operational record the request path writes on the application \
    role through its repository; owner-scoped RLS is a follow-up";
const REGISTRY: &str = "a shared registry the request path extends on the application role \
    (entity/method/paper/type upserts)";
const SCRIPT_UPSERT: &str = "upserted by the clustering scripts (cluster_claims.py, \
    evidential_clustering.py, refine_clusters.py), which connect through maintenance_dsn(): that \
    falls back to DATABASE_URL, the application role, when MAINTENANCE_DATABASE_URL is unset";
const MATCH: &str = "UPDATE kept for the matcher upsert and decide; 118's \
    match_candidates_stale_guard refuses the transition to stale on a non-privileged \
    session and DELETE is revoked";
const COMMUNITY: &str = "rows written by 106's community definer; removal deletes in the \
    caller's statement because the maintenance role holds no DELETE (106)";

const ALLOWLIST: &[(&str, &str)] = &[
    ("activities", OPERATIONAL),
    ("agent_spans", OPERATIONAL),
    ("bp_messages", DERIVED_BP),
    ("claim_themes", DERIVED_CLUSTER),
    ("cluster_centroids", SCRIPT_UPSERT),
    ("cluster_edges", DERIVED_CLUSTER),
    ("cluster_labels", SCRIPT_UPSERT),
    ("community_members", COMMUNITY),
    ("edges_staging", OPERATIONAL),
    ("entities", REGISTRY),
    ("entity_types", REGISTRY),
    ("events", OPERATIONAL),
    ("experiment_results", OPERATIONAL),
    ("experiments", OPERATIONAL),
    ("factors", DERIVED_BP),
    ("graph_cluster_runs", DERIVED_CLUSTER),
    ("graph_clusters", DERIVED_CLUSTER),
    ("match_candidates", MATCH),
    ("method_capabilities", REGISTRY),
    ("methods", REGISTRY),
    ("papers", REGISTRY),
    ("tasks", OPERATIONAL),
    ("webhook_subscriptions", OPERATIONAL),
    ("workflow_executions", OPERATIONAL),
    ("workflows", OPERATIONAL),
];

/// Credential, authority and ledger tables: never allowlisted, and the
/// application role must hold neither UPDATE nor DELETE on any of them.
/// (`provenance_log` is the signed append-only ledger; `agent_capabilities`
/// holds `privileged_access` and `can_modify_policies`.)
const CLOSED: &[&str] = &[
    "_sqlx_migrations",
    "agent_capabilities",
    "agent_keys",
    "oauth_authorization_codes",
    "oauth_authorize_sessions",
    "oauth_clients",
    "provenance_log",
    "refresh_tokens",
    "tenancy_backfill_progress",
    "tenancy_exempt",
    "tenancy_transcription_log",
    "tenancy_undeclared_writes",
];

/// A pool whose connections are `SET SESSION AUTHORIZATION <role>` (a
/// test-local literal).
async fn role_pool(pool: &PgPool, role: &'static str) -> PgPool {
    use sqlx::Executor;
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                conn.execute(format!("SET SESSION AUTHORIZATION {role}").as_str())
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("role pool")
}

/// A pool acting as the deployed application role, with no tenancy GUCs.
async fn app_pool(pool: &PgPool, max: u32) -> PgPool {
    use sqlx::Executor;
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("app pool")
}

/// A pool acting as `epigraph_app` stamped as `principal`.
async fn app_pool_as(pool: &PgPool, principal: Uuid) -> PgPool {
    use sqlx::Executor;
    let url = fixture::database_url_for(pool).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
                    .bind(principal.to_string())
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("app pool as principal")
}

fn sqlstate<T: std::fmt::Debug>(r: Result<T, sqlx::Error>) -> Option<String> {
    match r {
        Ok(v) => panic!("expected a database error, got Ok({v:?})"),
        Err(e) => e
            .as_database_error()
            .and_then(|d| d.code().map(|c| c.to_string())),
    }
}

fn db_err_code(e: &epigraph_db::DbError) -> Option<String> {
    match e {
        epigraph_db::DbError::QueryFailed { source } => source
            .as_database_error()
            .and_then(|d| d.code().map(|c| c.to_string())),
        _ => None,
    }
}

async fn violating_tables(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relrowsecurity \
            AND (has_table_privilege('epigraph_app', c.oid, 'UPDATE') \
                 OR has_table_privilege('epigraph_app', c.oid, 'DELETE'))",
    )
    .fetch_all(pool)
    .await
    .expect("catalog read")
    .into_iter()
    .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn no_rowless_table_is_app_writable_unless_allowlisted(pool: PgPool) {
    let violating = violating_tables(&pool).await;
    let allowed: BTreeSet<String> = ALLOWLIST.iter().map(|(t, _)| (*t).to_string()).collect();
    assert_eq!(allowed.len(), ALLOWLIST.len(), "duplicate allowlist entry");
    for (t, reason) in ALLOWLIST {
        assert!(!reason.trim().is_empty(), "{t} has no justification");
        assert!(
            !CLOSED.contains(t),
            "{t} is a credential/ledger table and cannot be allowlisted"
        );
    }

    let unlisted: Vec<_> = violating.difference(&allowed).collect();
    assert!(
        unlisted.is_empty(),
        "these tables have no row security and grant epigraph_app UPDATE or DELETE, and are \
         not on the allowlist: {unlisted:?}. Revoke the privilege, move the write into an \
         audited definer, enable RLS, or add a justified allowlist entry."
    );
    let stale: Vec<_> = allowed.difference(&violating).collect();
    assert!(
        stale.is_empty(),
        "these allowlist entries no longer violate (RLS enabled or privilege revoked): \
         {stale:?}. Remove them so the list only shrinks."
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn credential_and_ledger_tables_refuse_direct_app_writes(pool: PgPool) {
    let app = app_pool(&pool, 2).await;
    for t in CLOSED {
        let upd = sqlx::query(&format!(
            "UPDATE public.{t} SET {col} = {col}",
            col = first_column(&pool, t).await
        ))
        .execute(&app)
        .await;
        assert_eq!(
            sqlstate(upd).as_deref(),
            Some("42501"),
            "UPDATE {t} as epigraph_app"
        );
        let del = sqlx::query(&format!("DELETE FROM public.{t}"))
            .execute(&app)
            .await;
        assert_eq!(
            sqlstate(del).as_deref(),
            Some("42501"),
            "DELETE {t} as epigraph_app"
        );
    }
    // The ledgers refuse INSERT too: nothing on the application role appends
    // to the migration ledger or the tenancy bookkeeping.
    let ins = sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (999999, 'forged', true, '\\x00', 0)",
    )
    .execute(&app)
    .await;
    assert_eq!(
        sqlstate(ins).as_deref(),
        Some("42501"),
        "INSERT _sqlx_migrations"
    );
    // `SELECT ... FOR UPDATE` needs the UPDATE privilege: the lock the mint
    // path takes now comes from the definer.
    let lock = sqlx::query("SELECT id FROM oauth_clients FOR UPDATE")
        .execute(&app)
        .await;
    assert_eq!(
        sqlstate(lock).as_deref(),
        Some("42501"),
        "FOR UPDATE oauth_clients"
    );

    // The application still READS the migration ledger (the head check).
    let head: Option<i64> = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&app)
        .await
        .expect("the application role reads _sqlx_migrations");
    assert!(head.unwrap_or(0) >= 118);

    // The maintenance role cannot rewrite the ledger either.
    for privilege in ["INSERT", "UPDATE", "DELETE"] {
        let held: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('epigraph_maintenance', 'public._sqlx_migrations', $1)",
        )
        .bind(privilege)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !held,
            "epigraph_maintenance holds {privilege} on _sqlx_migrations"
        );
    }
}

async fn first_column(pool: &PgPool, table: &str) -> String {
    sqlx::query_scalar(
        "SELECT attname::text FROM pg_attribute WHERE attrelid = ('public.' || $1)::regclass \
           AND attnum = 1",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .expect("first column")
}

#[sqlx::test(migrations = "../../migrations")]
async fn agents_identity_columns_are_not_app_updatable(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "w11-agent").await;
    let app = app_pool_as(&pool, agent).await;
    for col in [
        "id",
        "public_key",
        "key_kind",
        "agent_type",
        "role",
        "state",
        "metadata",
    ] {
        let r = sqlx::query(&format!("UPDATE agents SET {col} = {col} WHERE id = $1"))
            .bind(agent)
            .execute(&app)
            .await;
        assert_eq!(
            sqlstate(r).as_deref(),
            Some("42501"),
            "agents.{col} as its own agent"
        );
    }
    let r = sqlx::query("DELETE FROM agents WHERE id = $1")
        .bind(agent)
        .execute(&app)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("42501"), "DELETE agents");

    // The profile columns the live paths write still work, on the own row.
    let n = sqlx::query(
        "UPDATE agents SET display_name = 'w11', labels = '{a}', properties = properties, \
                orcid = NULL, ror_id = NULL, updated_at = now() \
          WHERE id = $1",
    )
    .bind(agent)
    .execute(&app)
    .await
    .expect("profile update as the agent itself")
    .rows_affected();
    assert_eq!(n, 1);
    AgentRepository::set_llm_properties(&app, agent, "model-x", "hash-y")
        .await
        .expect("set_llm_properties on the application role");
}

async fn seed_client(pool: &PgPool, status: &str) -> Uuid {
    OAuthClientRepository::create(
        pool,
        &format!("w11_{}", Uuid::new_v4().simple()),
        None,
        "w11 client",
        "human",
        &["claims:read".to_string()],
        &["claims:read".to_string()],
        status,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("seed client")
}

fn h(tag: &str) -> Vec<u8> {
    blake3::hash(format!("{tag}-{}", Uuid::new_v4()).as_bytes())
        .as_bytes()
        .to_vec()
}

async fn live_in_family(pool: &PgPool, token_hash: &[u8]) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens t \
          WHERE COALESCE(t.family_id, t.id) = (SELECT COALESCE(family_id, id) \
                                                 FROM refresh_tokens WHERE token_hash = $1) \
            AND t.revoked_at IS NULL",
    )
    .bind(token_hash)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn reuse_events(pool: &PgPool, client: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'oauth.refresh_token_reuse' \
            AND details->>'client_id' = $1::text",
    )
    .bind(client)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Move a rotated token's `revoked_at` `secs` seconds into the past (on the
/// superuser pool), so a test can stand on either side of the grace window
/// without sleeping.
async fn backdate_rotation(pool: &PgPool, token_hash: &[u8], secs: i32) {
    let n = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() - make_interval(secs => $2) \
          WHERE token_hash = $1 AND revoked_reason = 'rotated'",
    )
    .bind(token_hash)
    .bind(f64::from(secs))
    .execute(pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(n, 1, "backdate a rotated token");
}

async fn grace_events(pool: &PgPool, client: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'oauth.refresh_token_grace' \
            AND details->>'client_id' = $1::text",
    )
    .bind(client)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The grace window's boundary, on both definers. A token re-presented 29 s
/// after its own rotation is refused and its family stays live; at 31 s it is
/// reuse and the family is revoked. (The 1 s case is the chain test above and
/// the concurrent race below.)
///
/// Verified to fail, each mutant of `epigraph_refresh_token_on_reuse` applied
/// alone and restored: the window at 0 s (fails the 29 s arm), at 3600 s
/// (fails the 31 s arm), `>` turned into `<` (fails the 29 s arm), and the
/// time predicate removed (fails the 31 s arm).
#[sqlx::test(migrations = "../../migrations")]
async fn the_grace_window_is_thirty_seconds_from_the_tokens_own_rotation(pool: PgPool) {
    let client = seed_client(&pool, "active").await;
    let app = app_pool(&pool, 2).await;
    let scopes = vec!["claims:read".to_string()];
    let exp = chrono::Utc::now() + chrono::Duration::hours(1);

    for via_rotate in [false, true] {
        // 29 s: grace. The successor stays live, no reuse event.
        let (a0, a1) = (h("a0"), h("a1"));
        RefreshTokenRepository::create(&app, &a0, client, &scopes, exp)
            .await
            .unwrap();
        assert!(matches!(
            RefreshTokenRepository::rotate(&app, &a0, &a1, exp)
                .await
                .unwrap(),
            RefreshRotateOutcome::Rotated { .. }
        ));
        backdate_rotation(&pool, &a0, 29).await;
        let before = grace_events(&pool, client).await;
        let reuse_at_start = reuse_events(&pool, client).await;
        if via_rotate {
            assert_eq!(
                RefreshTokenRepository::rotate(&app, &a0, &h("a2"), exp)
                    .await
                    .unwrap(),
                RefreshRotateOutcome::Grace,
                "29 s after rotation, via rotate"
            );
        } else {
            assert_eq!(
                RefreshTokenRepository::check(&app, &a0).await.unwrap(),
                RefreshCheck::Grace,
                "29 s after rotation, via check"
            );
        }
        assert_eq!(
            live_in_family(&pool, &a1).await,
            1,
            "grace keeps the family"
        );
        assert_eq!(
            reuse_events(&pool, client).await,
            reuse_at_start,
            "grace writes no reuse event"
        );
        assert_eq!(grace_events(&pool, client).await, before + 1);

        // 31 s: reuse. The family is revoked and the event written.
        let (b0, b1) = (h("b0"), h("b1"));
        RefreshTokenRepository::create(&app, &b0, client, &scopes, exp)
            .await
            .unwrap();
        assert!(matches!(
            RefreshTokenRepository::rotate(&app, &b0, &b1, exp)
                .await
                .unwrap(),
            RefreshRotateOutcome::Rotated { .. }
        ));
        backdate_rotation(&pool, &b0, 31).await;
        let reuse_before = reuse_events(&pool, client).await;
        if via_rotate {
            assert_eq!(
                RefreshTokenRepository::rotate(&app, &b0, &h("b2"), exp)
                    .await
                    .unwrap(),
                RefreshRotateOutcome::Reuse,
                "31 s after rotation, via rotate"
            );
        } else {
            assert_eq!(
                RefreshTokenRepository::check(&app, &b0).await.unwrap(),
                RefreshCheck::Reuse,
                "31 s after rotation, via check"
            );
        }
        assert_eq!(
            live_in_family(&pool, &b1).await,
            0,
            "reuse revokes the family"
        );
        assert_eq!(reuse_events(&pool, client).await, reuse_before + 1);
        // The family revoked above stays revoked.
        assert_eq!(
            RefreshTokenRepository::check(&app, &b1).await.unwrap(),
            RefreshCheck::Invalid
        );
    }
}

/// The rotation derives the successor's authority from the client, not from
/// the caller, and the application role cannot read the hashes that name a
/// chain.
#[sqlx::test(migrations = "../../migrations")]
async fn rotation_caps_expiry_and_derives_scopes_and_token_hash_is_unreadable(pool: PgPool) {
    let client = seed_client(&pool, "active").await; // human, granted {claims:read}
    let app = app_pool(&pool, 2).await;
    let wide = vec!["claims:read".to_string(), "claims:admin".to_string()];
    let t0 = h("cap0");
    RefreshTokenRepository::create(
        &app,
        &t0,
        client,
        &wide,
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .await
    .unwrap();
    let t1 = h("cap1");
    let century = chrono::Utc::now() + chrono::Duration::days(36_500);
    assert!(matches!(
        RefreshTokenRepository::rotate(&app, &t0, &t1, century)
            .await
            .unwrap(),
        RefreshRotateOutcome::Rotated { .. }
    ));
    let (scopes, capped): (Vec<String>, bool) = sqlx::query_as(
        "SELECT scopes, expires_at <= now() + interval '30 days' + interval '1 minute' \
           FROM refresh_tokens WHERE token_hash = $1",
    )
    .bind(&t1)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(capped, "a 100-year successor is capped at the human TTL");
    assert_eq!(
        scopes,
        vec!["claims:read"],
        "the successor carries the client's granted scopes, not the caller's"
    );
    // A shorter expiry than the TTL is kept (the caller may shorten).
    let t2 = h("cap2");
    let soon = chrono::Utc::now() + chrono::Duration::minutes(10);
    RefreshTokenRepository::rotate(&app, &t1, &t2, soon)
        .await
        .unwrap();
    let short: bool = sqlx::query_scalar(
        "SELECT expires_at <= now() + interval '11 minutes' FROM refresh_tokens \
          WHERE token_hash = $1",
    )
    .bind(&t2)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(short, "a caller-shortened expiry is kept");

    // token_hash is not readable on the application role; the rest is.
    let r = sqlx::query("SELECT token_hash FROM refresh_tokens")
        .execute(&app)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("42501"), "SELECT token_hash");
    let r = sqlx::query("SELECT * FROM refresh_tokens")
        .execute(&app)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("42501"), "SELECT *");
    let n: i64 = sqlx::query_scalar(
        "SELECT count(id) FROM refresh_tokens WHERE client_id = $1 AND revoked_at IS NULL",
    )
    .bind(client)
    .fetch_one(&app)
    .await
    .expect("the other columns stay readable");
    assert_eq!(n, 1);

    // /oauth/revoke goes by hash through the definer; idempotent.
    assert!(RefreshTokenRepository::revoke_by_hash(&app, &t2)
        .await
        .unwrap());
    assert!(!RefreshTokenRepository::revoke_by_hash(&app, &t2)
        .await
        .unwrap());
    assert!(!RefreshTokenRepository::revoke_by_hash(&app, &h("unknown"))
        .await
        .unwrap());
    let reason: Option<String> =
        sqlx::query_scalar("SELECT revoked_reason FROM refresh_tokens WHERE token_hash = $1")
            .bind(&t2)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason.as_deref(), Some("revoked"));
}

/// The rotation's expiry cap is the client type's refresh TTL, row by row: the
/// same table as `oauth/token.rs::handle_refresh_token`'s `refresh_ttl` (agent
/// 24 h, human 30 d, service 90 d). A 100-year successor must land in a
/// two-sided band around each TTL, so a shortened cap fails as well as a
/// lengthened one. `oauth_clients_client_type_check` admits only these three
/// types, so the definer's `ELSE` arm is reached by `agent` alone, and the
/// agent row is what pins it.
#[sqlx::test(migrations = "../../migrations")]
async fn rotation_caps_each_client_types_successor_at_its_refresh_ttl(pool: PgPool) {
    let human = seed_client(&pool, "active").await;
    let insert = |client_type: &'static str, owner: Option<Uuid>| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                     granted_scopes, status, owner_id, legal_entity_name, legal_contact_email) \
                 VALUES ($1, 'w11 ttl', $2, '{claims:read}', '{claims:read}', 'active', $3, \
                         'W11 Ltd', 'w11@example.invalid') RETURNING id",
            )
            .bind(format!("w11_{}", Uuid::new_v4().simple()))
            .bind(client_type)
            .bind(owner)
            .fetch_one(&pool)
            .await
            .expect("seed client")
        }
    };
    let agent = insert("agent", Some(human)).await;
    let service = insert("service", None).await;

    let app = app_pool(&pool, 2).await;
    let century = chrono::Utc::now() + chrono::Duration::days(36_500);
    for (client, client_type, ttl) in [
        (agent, "agent", "24 hours"),
        (human, "human", "30 days"),
        (service, "service", "90 days"),
    ] {
        let t0 = h(&format!("ttl0-{client_type}"));
        RefreshTokenRepository::create(
            &app,
            &t0,
            client,
            &["claims:read".to_string()],
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
        let t1 = h(&format!("ttl1-{client_type}"));
        assert!(
            matches!(
                RefreshTokenRepository::rotate(&app, &t0, &t1, century)
                    .await
                    .unwrap(),
                RefreshRotateOutcome::Rotated { .. }
            ),
            "{client_type} rotation"
        );
        let in_band: bool = sqlx::query_scalar(
            "SELECT expires_at BETWEEN now() + $2::interval - interval '1 minute' \
                                   AND now() + $2::interval + interval '1 minute' \
               FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(&t1)
        .bind(ttl)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            in_band,
            "a 100-year {client_type} successor is capped at exactly {ttl}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_rotation_chains_a_family_and_reuse_revokes_it(pool: PgPool) {
    let client = seed_client(&pool, "active").await;
    let app = app_pool(&pool, 2).await;
    let scopes = vec!["claims:read".to_string()];
    let exp = chrono::Utc::now() + chrono::Duration::hours(1);

    // Minted on the application role (INSERT is kept).
    let t0 = h("t0");
    RefreshTokenRepository::create(&app, &t0, client, &scopes, exp)
        .await
        .expect("mint on the application role");
    let RefreshCheck::Valid { client_id, .. } =
        RefreshTokenRepository::check(&app, &t0).await.unwrap()
    else {
        panic!("a fresh token is valid");
    };
    assert_eq!(client_id, client);
    assert_eq!(
        live_in_family(&pool, &t0).await,
        1,
        "check has no side effect"
    );

    let t1 = h("t1");
    assert!(matches!(
        RefreshTokenRepository::rotate(&app, &t0, &t1, exp)
            .await
            .unwrap(),
        RefreshRotateOutcome::Rotated { .. }
    ));
    let t2 = h("t2");
    assert!(matches!(
        RefreshTokenRepository::rotate(&app, &t1, &t2, exp)
            .await
            .unwrap(),
        RefreshRotateOutcome::Rotated { .. }
    ));
    let family: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT revoked_reason FROM refresh_tokens WHERE client_id = $1 ORDER BY created_at, id",
    )
    .bind(client)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        family
            .iter()
            .filter(|r| r.as_deref() == Some("rotated"))
            .count(),
        2
    );
    assert_eq!(
        live_in_family(&pool, &t2).await,
        1,
        "exactly the newest is live"
    );
    let families: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT COALESCE(family_id, id)) FROM refresh_tokens WHERE client_id = $1",
    )
    .bind(client)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(families, 1, "rotation keeps one family");

    // Presented again straight after its own rotation, t0 is inside the grace
    // window: refused, nothing revoked, no reuse event.
    assert_eq!(
        RefreshTokenRepository::check(&app, &t0).await.unwrap(),
        RefreshCheck::Grace
    );
    assert_eq!(
        live_in_family(&pool, &t2).await,
        1,
        "grace leaves the family live"
    );
    assert_eq!(reuse_events(&pool, client).await, 0);

    // Past the window, presenting the spent t0 again is reuse: the live t2
    // dies with it, and a security event records it.
    backdate_rotation(&pool, &t0, 31).await;
    backdate_rotation(&pool, &t1, 31).await;
    assert_eq!(
        RefreshTokenRepository::check(&app, &t0).await.unwrap(),
        RefreshCheck::Reuse
    );
    assert_eq!(
        live_in_family(&pool, &t2).await,
        0,
        "reuse revokes the family"
    );
    assert_eq!(reuse_events(&pool, client).await, 1);
    // The same through rotate (a replay straight at the rotation).
    let t3 = h("t3");
    assert_eq!(
        RefreshTokenRepository::rotate(&app, &t1, &t3, exp)
            .await
            .unwrap(),
        RefreshRotateOutcome::Reuse
    );
    let t3_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE token_hash = $1")
            .bind(&t3)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(t3_rows, 0, "a refused rotation mints nothing");
    assert_eq!(reuse_events(&pool, client).await, 2);
    assert_eq!(
        RefreshTokenRepository::check(&app, &t2).await.unwrap(),
        RefreshCheck::Invalid,
        "a token revoked BY the reuse detector is not itself a rotation to detect"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_denied_revoked_or_expired_token_is_invalid_not_reuse(pool: PgPool) {
    let client = seed_client(&pool, "active").await;
    let app = app_pool(&pool, 2).await;
    let scopes = vec!["claims:read".to_string()];
    let exp = chrono::Utc::now() + chrono::Duration::hours(1);

    for reason in [RefreshRevokeReason::Denied, RefreshRevokeReason::Revoked] {
        let t = h("burn");
        let id = RefreshTokenRepository::create(&app, &t, client, &scopes, exp)
            .await
            .unwrap();
        assert!(RefreshTokenRepository::revoke(&app, id, reason)
            .await
            .unwrap());
        assert!(
            !RefreshTokenRepository::revoke(&app, id, reason)
                .await
                .unwrap(),
            "a second revoke touches nothing"
        );
        assert_eq!(
            RefreshTokenRepository::check(&app, &t).await.unwrap(),
            RefreshCheck::Invalid
        );
        assert_eq!(
            RefreshTokenRepository::rotate(&app, &t, &h("n"), exp)
                .await
                .unwrap(),
            RefreshRotateOutcome::Invalid
        );
    }
    let expired = h("expired");
    RefreshTokenRepository::create(
        &pool,
        &expired,
        client,
        &scopes,
        chrono::Utc::now() - chrono::Duration::minutes(1),
    )
    .await
    .unwrap();
    assert_eq!(
        RefreshTokenRepository::check(&app, &expired).await.unwrap(),
        RefreshCheck::Invalid
    );
    assert_eq!(
        reuse_events(&pool, client).await,
        0,
        "no reuse was presented"
    );

    // The definer refuses the detector's own reasons.
    let t = h("forge");
    let id = RefreshTokenRepository::create(&app, &t, client, &scopes, exp)
        .await
        .unwrap();
    let forged = sqlx::query("SELECT public.epigraph_refresh_token_revoke($1, 'rotated')")
        .bind(id)
        .execute(&app)
        .await;
    assert_eq!(sqlstate(forged).as_deref(), Some("22023"));

    // revoke_all_for_client revokes every not-yet-revoked row of the client
    // (the forge token and the expired one), and nothing twice.
    let n = RefreshTokenRepository::revoke_all_for_client(&app, client)
        .await
        .unwrap();
    assert_eq!(n, 2);
    let n = RefreshTokenRepository::revoke_all_for_client(&app, client)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_rotations_of_one_token_admit_exactly_one(pool: PgPool) {
    const N: usize = 8;
    let client = seed_client(&pool, "active").await;
    let app = app_pool(&pool, N as u32).await;
    let scopes = vec!["claims:read".to_string()];
    let exp = chrono::Utc::now() + chrono::Duration::hours(1);
    let t0 = h("shared");
    RefreshTokenRepository::create(&app, &t0, client, &scopes, exp)
        .await
        .unwrap();

    // Open all N connections first, so the rotations below race on the row and
    // not on connection setup (which would serialize them and let a
    // check-then-update rotation pass).
    let mut warm = Vec::new();
    for _ in 0..N {
        warm.push(app.acquire().await.expect("warm connection"));
    }
    drop(warm);

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(N));
    let mut handles = Vec::new();
    for i in 0..N {
        let (app, t0, barrier) = (app.clone(), t0.clone(), barrier.clone());
        handles.push(tokio::spawn(async move {
            let next = h(&format!("next{i}"));
            barrier.wait().await;
            RefreshTokenRepository::rotate(&app, &t0, &next, exp)
                .await
                .expect("rotate")
        }));
    }
    let mut outcomes = Vec::new();
    for handle in handles {
        outcomes.push(handle.await.unwrap());
    }
    let rotated = outcomes
        .iter()
        .filter(|o| matches!(o, RefreshRotateOutcome::Rotated { .. }))
        .count();
    assert_eq!(
        rotated, 1,
        "exactly one rotation may claim the token: {outcomes:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| **o == RefreshRotateOutcome::Grace)
            .count(),
        N - 1,
        "every other presenter found it spent by a rotation inside the grace window: \
         {outcomes:?}"
    );
    // A benign race does not end the chain: the winner's successor stays live
    // and no reuse event is written.
    let minted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE client_id = $1")
            .bind(client)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(minted, 2, "one successor, not one per presenter");
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE client_id = $1 AND revoked_at IS NULL",
    )
    .bind(client)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live, 1, "the winner's successor survives the race");
    assert_eq!(reuse_events(&pool, client).await, 0, "a race is not reuse");
}

#[sqlx::test(migrations = "../../migrations")]
async fn authorization_codes_and_consent_sessions_are_single_use_on_the_app_role(pool: PgPool) {
    let client = seed_client(&pool, "active").await;
    let app = app_pool(&pool, 2).await;
    let code = h("code");
    AuthorizationCodeRepository::create(
        &app,
        &code,
        "w11-code-client",
        client,
        "https://claude.ai/api/mcp/auth_callback",
        "challenge",
        &["claims:read".to_string()],
        None,
        chrono::Utc::now() + chrono::Duration::minutes(5),
    )
    .await
    .expect("create code on the application role");
    let first = AuthorizationCodeRepository::consume(&app, &code)
        .await
        .unwrap();
    assert_eq!(first.expect("first consume").oauth_client_id, client);
    assert!(
        AuthorizationCodeRepository::consume(&app, &code)
            .await
            .unwrap()
            .is_none(),
        "a code is single use"
    );

    let state = format!("w11-state-{}", Uuid::new_v4().simple());
    AuthorizeSessionRepository::create(
        &app,
        &state,
        "w11-code-client",
        "https://claude.ai/api/mcp/auth_callback",
        "challenge",
        Some("claims:read"),
        None,
        "google-verifier",
        chrono::Utc::now() + chrono::Duration::minutes(5),
    )
    .await
    .expect("create session on the application role");
    let consent = format!("w11-consent-{}", Uuid::new_v4().simple());
    let moved = AuthorizeSessionRepository::transition_to_consent(
        &app,
        &state,
        &consent,
        client,
        &["claims:read".to_string()],
    )
    .await
    .unwrap()
    .expect("transition");
    assert_eq!(moved.resolved_oauth_client_id, Some(client));
    assert!(
        AuthorizeSessionRepository::transition_to_consent(&app, &state, "again", client, &[])
            .await
            .unwrap()
            .is_none()
    );
    assert!(AuthorizeSessionRepository::take(&app, &consent)
        .await
        .unwrap()
        .is_some());
    assert!(
        AuthorizeSessionRepository::take(&app, &consent)
            .await
            .unwrap()
            .is_none(),
        "a consent ticket is single use"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn oauth_client_link_is_write_once_and_approval_is_audited(pool: PgPool) {
    let client = seed_client(&pool, "pending").await;
    let (a1, _) = fixture::seed_agent_with_group(&pool, "w11-link-1").await;
    let (a2, _) = fixture::seed_agent_with_group(&pool, "w11-link-2").await;
    let app = app_pool(&pool, 2).await;

    let mut conn = app.acquire().await.unwrap();
    assert!(OAuthClientRepository::set_agent_id(&mut conn, client, a1)
        .await
        .unwrap());
    assert!(
        !OAuthClientRepository::set_agent_id(&mut conn, client, a2)
            .await
            .unwrap(),
        "a linked client is never re-bound"
    );
    let e = OAuthClientRepository::set_agent_id(
        &mut conn,
        seed_client(&pool, "active").await,
        Uuid::new_v4(),
    )
    .await
    .expect_err("an agent that does not exist");
    assert_eq!(db_err_code(&e).as_deref(), Some("23503"));
    drop(conn);
    let linked: Option<Uuid> =
        sqlx::query_scalar("SELECT agent_id FROM oauth_clients WHERE id = $1")
            .bind(client)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(linked, Some(a1));

    let approver = seed_client(&pool, "active").await;
    OAuthClientRepository::approve(
        &app,
        client,
        &["claims:read".into(), "claims:write".into()],
        approver,
    )
    .await
    .expect("approve on the application role");
    let (status, scopes): (String, Vec<String>) =
        sqlx::query_as("SELECT status, granted_scopes FROM oauth_clients WHERE id = $1")
            .bind(client)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "active");
    assert_eq!(scopes, vec!["claims:read", "claims:write"]);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'oauth.client_approved' \
            AND details->>'oauth_client_id' = $1::text AND details->>'approved_by' = $2::text",
    )
    .bind(client)
    .bind(approver)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited, 1, "an approval leaves an audit row");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_mint_path_links_a_client_on_the_app_role(pool: PgPool) {
    let client = seed_client(&pool, "active").await;
    let app = app_pool(&pool, 2).await;
    let mut tx = app.begin().await.unwrap();
    let agent = AgentRepository::ensure_for_client(&mut tx, client)
        .await
        .expect("ensure_for_client on the application role");
    tx.commit().await.unwrap();
    let mut tx = app.begin().await.unwrap();
    let again = AgentRepository::ensure_for_client(&mut tx, client)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(agent, again, "the warm path returns the linked agent");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_key_never_leaves_revoked(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "w11-key").await;
    let app = app_pool(&pool, 2).await;
    let now = chrono::Utc::now();
    let pk: Vec<u8> = Uuid::new_v4().as_bytes().repeat(2);
    let key = AgentKeyRepository::store(
        &app,
        Uuid::new_v4(),
        epigraph_core::AgentId::from_uuid(agent),
        &pk,
        "signing",
        "active",
        now,
        None,
        now,
    )
    .await
    .expect("store on the application role");
    let rotated = AgentKeyRepository::update_status(&app, key.id, "rotated", None, None)
        .await
        .expect("active -> rotated");
    assert_eq!(rotated.status, "rotated");
    let revoked =
        AgentKeyRepository::update_status(&app, key.id, "revoked", Some("lost"), Some(agent))
            .await
            .expect("rotated -> revoked");
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.revocation_reason.as_deref(), Some("lost"));
    for back in ["active", "rotated", "revoked"] {
        let e = AgentKeyRepository::update_status(&app, key.id, back, None, None)
            .await
            .expect_err("a revoked key stays revoked");
        assert!(
            format!("{e}").contains("AK01") || db_err_code(&e).is_some(),
            "{e}"
        );
    }
    let status: String = sqlx::query_scalar("SELECT status FROM agent_keys WHERE id = $1")
        .bind(key.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "revoked");
}

async fn seed_candidate(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let (agent, _) = fixture::seed_agent_with_group(pool, "w11-match").await;
    let a = fixture::seed_public_claim(pool, agent, &format!("w11 a {}", Uuid::new_v4())).await;
    let b = fixture::seed_public_claim(pool, agent, &format!("w11 b {}", Uuid::new_v4())).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let id = MatchCandidateRepo::new(pool.clone())
        .upsert(
            lo,
            hi,
            0.9,
            serde_json::json!({}),
            "pending",
            None,
            None,
            None,
        )
        .await
        .expect("seed candidate")
        .id;
    (id, lo, hi)
}

/// The stale guard's refusal: SQLSTATE 42501 AND its own `MC01` tag.
///
/// Verified to fail: with `REVOKE EXECUTE ON FUNCTION epigraph_definer_bypass()
/// FROM epigraph_app` appended to 118 (restored afterwards), the app-role
/// statements still fail with 42501, but from the helper, not the guard, and
/// this assertion names the difference.
fn assert_mc01(e: &sqlx::Error, what: &str) {
    let d = e
        .as_database_error()
        .unwrap_or_else(|| panic!("{what}: not a database error: {e}"));
    assert_eq!(
        d.code().as_deref(),
        Some("42501"),
        "{what}: {}",
        d.message()
    );
    assert!(
        d.message().contains("MC01"),
        "{what}: refused, but not by the stale guard: {}",
        d.message()
    );
}

async fn status_of(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_make_a_match_candidate_stale(pool: PgPool) {
    let (id, lo, hi) = seed_candidate(&pool).await;
    let app = app_pool(&pool, 2).await;
    let repo = MatchCandidateRepo::new(app.clone());

    // The matcher and the decide path keep working on the application role.
    repo.upsert(
        lo,
        hi,
        0.95,
        serde_json::json!({"k": 1}),
        "pending",
        None,
        Some("same"),
        None,
    )
    .await
    .expect("matcher upsert on the application role");
    repo.set_status(id, "promoted", Some(Uuid::new_v4()))
        .await
        .expect("decide on the application role");
    assert_eq!(status_of(&pool, id).await, "promoted");

    // Retirement does not, by any route, and each refusal is the stale
    // guard's own (MC01), not some other 42501 on the way (a lost EXECUTE on a
    // privilege helper, a missing table grant in the cascade).
    let e = repo
        .retire(id, None)
        .await
        .expect_err("retire on the application role");
    assert_mc01(&e, "retire");
    let e = repo
        .set_status(id, "stale", None)
        .await
        .expect_err("set_status stale");
    assert_mc01(&e, "set_status stale");
    let e = sqlx::query("UPDATE match_candidates SET status = 'stale' WHERE id = $1")
        .bind(id)
        .execute(&app)
        .await
        .expect_err("raw UPDATE to stale");
    assert_mc01(&e, "raw UPDATE to stale");
    let (agent, _) = fixture::seed_agent_with_group(&pool, "w11-match-ins").await;
    let c = fixture::seed_public_claim(&pool, agent, &format!("w11 c {}", Uuid::new_v4())).await;
    let d = fixture::seed_public_claim(&pool, agent, &format!("w11 d {}", Uuid::new_v4())).await;
    let (lo2, hi2) = if c < d { (c, d) } else { (d, c) };
    let ins = repo
        .upsert(
            lo2,
            hi2,
            0.5,
            serde_json::json!({}),
            "stale",
            None,
            None,
            None,
        )
        .await;
    assert_mc01(&ins.expect_err("INSERT as stale"), "INSERT as stale");
    let del = sqlx::query("DELETE FROM match_candidates WHERE id = $1")
        .bind(id)
        .execute(&app)
        .await;
    assert_eq!(sqlstate(del).as_deref(), Some("42501"), "DELETE");
    assert_eq!(status_of(&pool, id).await, "promoted", "nothing changed");

    // The MAINTENANCE role (not a superuser) retires, cascade included: 118
    // grants it the DELETEs on the derived rows the cascade removes. Then the
    // matcher's later re-touch of the now stale, decided row keeps it stale and
    // is not refused.
    let maint = role_pool(&pool, "epigraph_maintenance").await;
    MatchCandidateRepo::new(maint)
        .retire(id, None)
        .await
        .expect("retire on the maintenance role");
    assert_eq!(status_of(&pool, id).await, "stale");
    repo.upsert(
        lo,
        hi,
        0.97,
        serde_json::json!({"k": 2}),
        "pending",
        None,
        None,
        None,
    )
    .await
    .expect("matcher re-touch of a stale row on the application role");
    assert_eq!(status_of(&pool, id).await, "stale");
}

/// The derived BP tables stay writable by the application role (they are on the
/// allowlist): factor insert, BP-message upsert (INSERT ... ON CONFLICT DO
/// UPDATE, which needs UPDATE) and the clear before a propagation run.
#[sqlx::test(migrations = "../../migrations")]
async fn factor_and_bp_message_writes_still_work_on_the_app_role(pool: PgPool) {
    use epigraph_db::FactorRepository;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "w11-bp").await;
    let a = fixture::seed_public_claim(&pool, agent, &format!("w11 bp a {}", Uuid::new_v4())).await;
    let b = fixture::seed_public_claim(&pool, agent, &format!("w11 bp b {}", Uuid::new_v4())).await;
    let app = app_pool(&pool, 2).await;

    let factor = FactorRepository::insert(
        &app,
        "evidential_support",
        &[a, b],
        &serde_json::json!({"strength": 0.7}),
        Some("w11 app-role factor"),
        None,
    )
    .await
    .expect("factor insert on the application role");
    for iteration in [1, 2] {
        FactorRepository::upsert_bp_message(
            &app,
            factor,
            a,
            "factor_to_var",
            &serde_json::json!([0.6, 0.4]),
            iteration,
        )
        .await
        .expect("bp message upsert on the application role");
    }
    let iteration: i32 = sqlx::query_scalar(
        "SELECT iteration FROM bp_messages WHERE factor_id = $1 AND variable_id = $2",
    )
    .bind(factor)
    .bind(a)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        iteration, 2,
        "the second upsert took the ON CONFLICT DO UPDATE arm"
    );
    let cleared = FactorRepository::clear_bp_messages(&app)
        .await
        .expect("clear on the application role");
    assert!(cleared >= 1);
}

/// Migration 118 section 6: the append-only tables keep INSERT and lose
/// UPDATE/DELETE, the writer-less ones lose every write, and rows removed by a
/// foreign-key cascade from a table the application still deletes
/// (graph_cluster_runs -> graph_neighborhoods -> neighborhood_edges) still go:
/// the referential action does not need the session to hold DELETE on the
/// child.
#[sqlx::test(migrations = "../../migrations")]
async fn append_only_tables_keep_insert_and_cascades_still_clear_them(pool: PgPool) {
    let app = app_pool(&pool, 2).await;

    let theme: Uuid =
        sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ('w11') RETURNING id")
            .fetch_one(&app)
            .await
            .expect("claim_themes insert on the application role");
    let run = Uuid::new_v4();
    sqlx::query("INSERT INTO graph_cluster_runs (run_id, cluster_count) VALUES ($1, 2)")
        .bind(run)
        .execute(&app)
        .await
        .expect("graph_cluster_runs insert on the application role");
    let mut hoods = Vec::new();
    for label in ["a", "b"] {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO graph_neighborhoods (run_id, theme_id, label, size) \
             VALUES ($1, $2, $3, 1) RETURNING id",
        )
        .bind(run)
        .bind(theme)
        .bind(label)
        .fetch_one(&app)
        .await
        .expect("graph_neighborhoods INSERT is kept");
        hoods.push(id);
    }
    hoods.sort();
    sqlx::query(
        "INSERT INTO neighborhood_edges (run_id, neighborhood_a, neighborhood_b, weight) \
         VALUES ($1, $2, $3, 0.5)",
    )
    .bind(run)
    .bind(hoods[0])
    .bind(hoods[1])
    .execute(&app)
    .await
    .expect("neighborhood_edges INSERT is kept");

    for (t, set) in [
        ("graph_neighborhoods", "size = size"),
        ("neighborhood_edges", "weight = weight"),
        ("provenance_log", "id = id"),
        ("learning_events", "id = id"),
        ("trace_parents", "trace_id = trace_id"),
    ] {
        let r = sqlx::query(&format!("UPDATE {t} SET {set}"))
            .execute(&app)
            .await;
        assert_eq!(sqlstate(r).as_deref(), Some("42501"), "UPDATE {t}");
        let r = sqlx::query(&format!("DELETE FROM {t}")).execute(&app).await;
        assert_eq!(sqlstate(r).as_deref(), Some("42501"), "DELETE {t}");
    }
    for t in [
        "agent_capabilities",
        "source_artifacts",
        "harvester_sources",
    ] {
        let r = sqlx::query(&format!("INSERT INTO {t} DEFAULT VALUES"))
            .execute(&app)
            .await;
        assert_eq!(
            sqlstate(r).as_deref(),
            Some("42501"),
            "INSERT {t} (no writer)"
        );
    }

    // The cascade: deleting the run (still application-deletable, derived
    // clustering state) removes its neighborhoods and their edges.
    let n = sqlx::query("DELETE FROM graph_cluster_runs WHERE run_id = $1")
        .bind(run)
        .execute(&app)
        .await
        .expect("a cascading delete from a parent the application still deletes")
        .rows_affected();
    assert_eq!(n, 1);
    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM graph_neighborhoods WHERE run_id = $1) \
              + (SELECT count(*) FROM neighborhood_edges WHERE run_id = $1)",
    )
    .bind(run)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0, "the cascade cleared the children");
}

/// Migration 118 section 7: an application session cannot write an `oauth.`
/// audit event (only the definers can), while its own `oauth_...` provisioning
/// events and unrelated events still land.
#[sqlx::test(migrations = "../../migrations")]
async fn oauth_audit_events_are_written_only_by_the_definers(pool: PgPool) {
    let app = app_pool(&pool, 2).await;
    for forged in [
        "oauth.client_approved",
        "oauth.refresh_token_reuse",
        "oauth.refresh_token_grace",
    ] {
        let r = sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ($1, NULL, true, '{}'::jsonb)",
        )
        .bind(forged)
        .execute(&app)
        .await;
        assert_eq!(sqlstate(r).as_deref(), Some("42501"), "forged {forged}");
    }
    for own in [
        "oauth_provision_denied",
        "oauth_human_provisioned",
        "rate_limited",
    ] {
        sqlx::query(
            "INSERT INTO security_events (event_type, agent_id, success, details) \
             VALUES ($1, NULL, false, '{}'::jsonb)",
        )
        .bind(own)
        .execute(&app)
        .await
        .unwrap_or_else(|e| panic!("{own} on the application role: {e}"));
    }
}

/// Migration 118 section 8: an agent may still record its LLM properties, but
/// may not rewrite the competence scopes the belief route discounts it by.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_cannot_rewrite_its_own_competence_scopes(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "w11-competence").await;
    sqlx::query(
        "UPDATE agents SET properties = properties || '{\"competence_scopes\": [\"chemistry\"]}' \
          WHERE id = $1",
    )
    .bind(agent)
    .execute(&pool)
    .await
    .expect("a privileged connection sets the scopes");
    let app = app_pool_as(&pool, agent).await;

    for patch in [
        "properties - 'competence_scopes'",
        "properties || '{\"competence_scopes\": [\"everything\"]}'",
    ] {
        let e = sqlx::query(&format!(
            "UPDATE agents SET properties = {patch} WHERE id = $1"
        ))
        .bind(agent)
        .execute(&app)
        .await
        .expect_err("the agent rewrites its own competence scopes");
        let d = e.as_database_error().expect("database error");
        assert_eq!(d.code().as_deref(), Some("42501"));
        assert!(d.message().contains("AG01"), "{}", d.message());
    }
    AgentRepository::set_llm_properties(&app, agent, "model-z", "hash-z")
        .await
        .expect("the LLM-property merge leaves the scopes alone and still works");
    let scopes: serde_json::Value =
        sqlx::query_scalar("SELECT properties -> 'competence_scopes' FROM agents WHERE id = $1")
            .bind(agent)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(scopes, serde_json::json!(["chemistry"]));
}
