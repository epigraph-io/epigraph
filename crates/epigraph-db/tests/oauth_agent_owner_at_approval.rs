//! Migration 312 (backlog be024524): an agent client's owner is named by the
//! operator at approval, never guessed at registration.
//!
//! Before 312, `/oauth/register` stamped every self-registered agent with the
//! OLDEST ACTIVE HUMAN client as its `owner_id` (001's `agents_must_have_owner`
//! refused a NULL), so `OAuthClientRepository::suspend_by_owner(<that human>)`
//! suspended every approved self-registered agent, and the agent's token
//! carried that human as its owner. 312 lets a NOT-YET-ACTIVE agent have no
//! owner and adds a four-argument `epigraph_oauth_client_approve` that must
//! name the owner of an agent.
//!
//! What is pinned, each on a database migrated 001 -> head:
//! * the approval naming an owner writes it (over an inherited one too), and
//!   suspending an unrelated human leaves the agent active while suspending
//!   the named owner suspends it;
//! * an agent approval with no owner named is refused (22004) whatever the
//!   row already holds, and the three-argument approval cannot activate an
//!   ownerless agent (23514); nothing changes on either refusal;
//! * a named owner is another, active client;
//! * a non-agent client approves with no owner named and keeps its owner, and
//!   is refused one (22023, nothing changed);
//! * on a database at 311, 312 clears the owner of a pending agent
//!   `/oauth/register` wrote (agent_id NULL), audited, and of no other row;
//!   the three-argument approval then cannot activate it (23514);
//! * the CHECK: only an ACTIVE agent needs an owner;
//! * the new definer is a maintenance act (owner, path, no PUBLIC or
//!   application EXECUTE);
//! * `docs/runbooks/312-undo.sql` restores 001's CHECK and drops the overload,
//!   and refuses while an agent has no owner.
//!
//! Fails on 311 and earlier: the four-argument definer does not exist (42883)
//! and 001's CHECK refuses the ownerless pending agent every test seeds.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::oauth_client::OAuthClientRepository;
use sqlx::PgPool;
use uuid::Uuid;

const APPROVE4: &str = "SELECT public.epigraph_oauth_client_approve($1, $2, $3, $4)";
const APPROVE3: &str = "SELECT public.epigraph_oauth_client_approve($1, $2, $3)";
const SIG4: &str = "public.epigraph_oauth_client_approve(uuid, text[], uuid, uuid)";

/// A pool whose connections are `SET SESSION AUTHORIZATION <role>`.
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

/// An OAuth client row, seeded on the superuser pool. `created_at` is set
/// explicitly so "the oldest human" is the one the test means.
async fn client(
    pool: &PgPool,
    client_type: &str,
    status: &str,
    owner: Option<Uuid>,
    age_days: i32,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, owner_id, legal_entity_name, \
                                    legal_contact_email, created_at) \
         VALUES ($1, $2, $3, ARRAY['claims:read','claims:write'], '{}', $4, $5, \
                 CASE WHEN $3 = 'service' THEN 'Probe Ltd' END, \
                 CASE WHEN $3 = 'service' THEN 'probe@example.invalid' END, \
                 now() - make_interval(days => $6)) \
         RETURNING id",
    )
    .bind(format!("o312_{}", Uuid::new_v4().simple()))
    .bind(format!("{client_type} {status}"))
    .bind(client_type)
    .bind(status)
    .bind(owner)
    .bind(age_days)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed {client_type} {status} client: {e}"))
}

/// `(status, owner_id, granted_scopes, oauth.client_approved rows)`.
async fn state(pool: &PgPool, id: Uuid) -> (String, Option<Uuid>, Vec<String>, i64) {
    sqlx::query_as(
        "SELECT c.status::text, c.owner_id, c.granted_scopes, \
                (SELECT count(*) FROM security_events e \
                  WHERE e.event_type = 'oauth.client_approved' \
                    AND e.details->>'oauth_client_id' = c.id::text) \
           FROM oauth_clients c WHERE c.id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("client state")
}

fn scopes(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_string()).collect()
}

/// The approval names the owner, the owner is written, and suspension follows
/// the NAMED owner only.
///
/// Mutation probes: the definer writing `COALESCE(owner_id, p_owner_id)` (the
/// row's inherited owner wins) fails the inherited-owner half; the definer not
/// writing `owner_id` fails the first `owner` assertion.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_approval_writes_the_named_owner_and_suspension_follows_it(pool: PgPool) {
    let oldest_human = client(&pool, "human", "active", None, 30).await;
    let named = client(&pool, "human", "active", None, 1).await;
    let approver = client(&pool, "human", "active", None, 1).await;
    // What `/oauth/register` writes since 312: pending, no owner.
    let agent = client(&pool, "agent", "pending", None, 0).await;
    let maint = role_pool(&pool, "epigraph_maintenance").await;

    OAuthClientRepository::approve(
        &maint,
        agent,
        &scopes(&["claims:read"]),
        approver,
        Some(named),
    )
    .await
    .expect("approve the agent naming its owner, on the maintenance role");
    assert_eq!(
        state(&pool, agent).await,
        (
            "active".to_string(),
            Some(named),
            scopes(&["claims:read"]),
            1
        )
    );
    let audit: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = 'oauth.client_approved' \
            AND details->>'oauth_client_id' = $1::text",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit["owner_id"], serde_json::json!(named), "{audit}");
    assert!(audit["previous_owner_id"].is_null(), "{audit}");
    assert_eq!(audit["approved_by"], serde_json::json!(approver), "{audit}");
    assert_eq!(audit["migration"], serde_json::json!(312), "{audit}");

    // THE DEFECT: suspending the oldest human used to suspend every approved
    // self-registered agent with it.
    let n = OAuthClientRepository::suspend_by_owner(&pool, oldest_human)
        .await
        .unwrap();
    assert_eq!(n, 0, "the oldest human owns no agent");
    assert_eq!(state(&pool, agent).await.0, "active");
    // Control: suspension does follow the owner the operator named.
    let n = OAuthClientRepository::suspend_by_owner(&pool, named)
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(state(&pool, agent).await.0, "suspended");

    // A pending agent registered BEFORE 312 carries the oldest human as its
    // owner; the approval's named owner replaces it, and the audit row keeps
    // the one it replaced.
    let inherited = client(&pool, "agent", "pending", Some(oldest_human), 0).await;
    OAuthClientRepository::approve(
        &maint,
        inherited,
        &scopes(&["claims:read"]),
        approver,
        Some(named),
    )
    .await
    .expect("approve the inherited-owner agent naming its owner");
    assert_eq!(state(&pool, inherited).await.1, Some(named));
    let prev: Option<String> = sqlx::query_scalar(
        "SELECT details->>'previous_owner_id' FROM security_events \
          WHERE event_type = 'oauth.client_approved' AND details->>'oauth_client_id' = $1::text",
    )
    .bind(inherited)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(prev, Some(oldest_human.to_string()));
}

/// An agent is never activated without a named owner: the four-argument
/// approval refuses a NULL owner even when the row already holds one (rows
/// registered before 312 hold the oldest human), and the three-argument
/// approval cannot activate an ownerless agent. Nothing changes.
///
/// Mutation probes: dropping the definer's agent-owner refusal turns the
/// ownerless case into 23514 (the CHECK) and lets the inherited-owner case
/// approve; reverting the CHECK to 001's makes the seed itself fail.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_approval_without_a_named_owner_is_refused(pool: PgPool) {
    let oldest_human = client(&pool, "human", "active", None, 30).await;
    let ownerless = client(&pool, "agent", "pending", None, 0).await;
    let inherited = client(&pool, "agent", "pending", Some(oldest_human), 0).await;
    let maint = role_pool(&pool, "epigraph_maintenance").await;

    for agent in [ownerless, inherited] {
        let r = sqlx::query_scalar::<_, bool>(APPROVE4)
            .bind(agent)
            .bind(scopes(&["claims:read"]))
            .bind(None::<Uuid>)
            .bind(None::<Uuid>)
            .fetch_one(&maint)
            .await;
        assert_eq!(sqlstate(r).as_deref(), Some("22004"), "agent {agent}");
        let e = OAuthClientRepository::approve(
            &maint,
            agent,
            &scopes(&["claims:read"]),
            oldest_human,
            None,
        )
        .await
        .expect_err("the repository approval with no owner");
        assert_eq!(db_err_code(&e).as_deref(), Some("22004"));
    }
    // 118's three-argument approval (an older CLI, a hand-written SELECT)
    // reaches the CHECK.
    let r = sqlx::query_scalar::<_, bool>(APPROVE3)
        .bind(ownerless)
        .bind(scopes(&["claims:read"]))
        .bind(None::<Uuid>)
        .fetch_one(&maint)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("23514"));

    assert_eq!(
        state(&pool, ownerless).await,
        ("pending".to_string(), None, vec![], 0)
    );
    assert_eq!(
        state(&pool, inherited).await,
        ("pending".to_string(), Some(oldest_human), vec![], 0)
    );
}

/// A named owner is another client, and an active one.
///
/// Mutation probe: dropping the owner-status check lets the suspended owner
/// approve.
#[sqlx::test(migrations = "../../migrations")]
async fn a_named_owner_is_another_active_client(pool: PgPool) {
    let suspended = client(&pool, "human", "suspended", None, 3).await;
    let agent = client(&pool, "agent", "pending", None, 0).await;
    let maint = role_pool(&pool, "epigraph_maintenance").await;

    for (owner, code) in [
        (agent, "22023"),
        (Uuid::new_v4(), "23503"),
        (suspended, "22023"),
    ] {
        let r = sqlx::query_scalar::<_, bool>(APPROVE4)
            .bind(agent)
            .bind(scopes(&["claims:read"]))
            .bind(None::<Uuid>)
            .bind(owner)
            .fetch_one(&maint)
            .await;
        assert_eq!(sqlstate(r).as_deref(), Some(code), "owner {owner}");
    }
    assert_eq!(
        state(&pool, agent).await,
        ("pending".to_string(), None, vec![], 0)
    );
    // An unknown client is still `false`, not an error (118's contract).
    let found: bool = sqlx::query_scalar(APPROVE4)
        .bind(Uuid::new_v4())
        .bind(scopes(&["claims:read"]))
        .bind(None::<Uuid>)
        .bind(None::<Uuid>)
        .fetch_one(&maint)
        .await
        .unwrap();
    assert!(!found);
}

/// A non-agent client needs no owner: approving it with none named keeps its
/// owner (NULL here, an owner there). Naming one is refused (22023) with
/// nothing changed: an owner at approval is for an agent only, and on a
/// service or human client it would make that client's tokens carry another
/// principal's `owner_id`.
///
/// Mutation probe: dropping the definer's non-agent refusal lets the first
/// loop approve the service with `other` as its owner.
#[sqlx::test(migrations = "../../migrations")]
async fn a_non_agent_approval_keeps_its_owner_when_none_is_named(pool: PgPool) {
    let owner = client(&pool, "human", "active", None, 3).await;
    let other = client(&pool, "human", "active", None, 2).await;
    let service = client(&pool, "service", "pending", None, 0).await;
    let owned_service = client(&pool, "service", "pending", Some(owner), 0).await;
    let human = client(&pool, "human", "pending", None, 0).await;
    let maint = role_pool(&pool, "epigraph_maintenance").await;
    for s in [service, owned_service, human] {
        let r = sqlx::query_scalar::<_, bool>(APPROVE4)
            .bind(s)
            .bind(scopes(&["claims:read"]))
            .bind(None::<Uuid>)
            .bind(other)
            .fetch_one(&maint)
            .await;
        assert_eq!(sqlstate(r).as_deref(), Some("22023"), "client {s}");
        let e = OAuthClientRepository::approve(
            &maint,
            s,
            &scopes(&["claims:read"]),
            owner,
            Some(other),
        )
        .await
        .expect_err("the repository approval naming an owner for a non-agent");
        assert_eq!(db_err_code(&e).as_deref(), Some("22023"));
    }
    assert_eq!(
        state(&pool, owned_service).await,
        ("pending".to_string(), Some(owner), vec![], 0)
    );
    assert_eq!(
        state(&pool, human).await,
        ("pending".to_string(), None, vec![], 0)
    );
    for s in [service, owned_service] {
        OAuthClientRepository::approve(&maint, s, &scopes(&["claims:read"]), owner, None)
            .await
            .expect("approve a service with no owner named");
    }
    assert_eq!(
        state(&pool, service).await,
        ("active".to_string(), None, scopes(&["claims:read"]), 1)
    );
    assert_eq!(state(&pool, owned_service).await.1, Some(owner));
}

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Run every migration below 312 (or, with `None`, the rest) on one
/// connection, then reset it: 001's pg_dump header leaves session-level SETs
/// behind.
async fn migrate(pool: &PgPool, below: Option<i64>) {
    use sqlx::Executor;
    let m = match below {
        Some(v) => sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .migrations
                    .iter()
                    .filter(|m| m.version < v)
                    .cloned()
                    .collect(),
            ),
            ignore_missing: false,
            locking: true,
            no_tx: false,
        },
        None => sqlx::migrate::Migrator {
            migrations: MIGRATOR.migrations.clone(),
            ignore_missing: false,
            locking: true,
            no_tx: false,
        },
    };
    let mut conn = pool.acquire().await.expect("acquire");
    m.run(&mut *conn).await.expect("migrate");
    conn.execute("RESET ALL").await.expect("RESET ALL");
}

/// 312 (c), on a database that holds what 311 deployments hold: the PENDING
/// agent `/oauth/register` wrote (no `agent_id`, the oldest human guessed as
/// its owner) loses that owner, with one `oauth.client_owner_cleared` row
/// keeping the previous one; a pending agent `POST /api/v1/agents` created
/// (its `agent_id` set, its creator as owner), an ACTIVE agent and a pending
/// service keep theirs. After 312 the three-argument approval (an older CLI,
/// a hand-written `SELECT`) cannot activate the cleared row (23514), where
/// before it would have activated it with the guessed owner.
///
/// Mutation probes: without (c) the cleared row keeps the oldest human and
/// the three-argument approval activates it; without `agent_id IS NULL` the
/// `POST /api/v1/agents` row is cleared too; reading the previous owner from
/// `RETURNING` (the updated row) records NULL as `previous_owner_id`.
#[sqlx::test(migrations = false)]
async fn migration_312_clears_the_guessed_owner_of_pending_self_registered_agents(pool: PgPool) {
    migrate(&pool, Some(312)).await;
    let oldest_human = client(&pool, "human", "active", None, 30).await;
    let creator = client(&pool, "service", "active", None, 10).await;
    // `/oauth/register`'s agent arm before this change.
    let registered = client(&pool, "agent", "pending", Some(oldest_human), 0).await;
    // `POST /api/v1/agents`: the agent it created, its creator as owner.
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "o312 provisioned").await;
    let provisioned = client(&pool, "agent", "pending", Some(creator), 0).await;
    sqlx::query("UPDATE oauth_clients SET agent_id = $2 WHERE id = $1")
        .bind(provisioned)
        .bind(agent)
        .execute(&pool)
        .await
        .expect("link the provisioned client");
    // Already approved before 312 (not 312's to re-own), and a service.
    let active = client(&pool, "agent", "active", Some(oldest_human), 0).await;
    let service = client(&pool, "service", "pending", Some(creator), 0).await;

    migrate(&pool, None).await;

    assert_eq!(
        state(&pool, registered).await,
        ("pending".to_string(), None, vec![], 0)
    );
    let cleared: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT details FROM security_events WHERE event_type = 'oauth.client_owner_cleared' \
          ORDER BY created_at",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(cleared.len(), 1, "{cleared:?}");
    assert_eq!(cleared[0]["oauth_client_id"], serde_json::json!(registered));
    assert_eq!(
        cleared[0]["previous_owner_id"],
        serde_json::json!(oldest_human)
    );
    assert_eq!(cleared[0]["migration"], serde_json::json!(312));
    assert_eq!(state(&pool, provisioned).await.1, Some(creator));
    assert_eq!(state(&pool, active).await.1, Some(oldest_human));
    assert_eq!(state(&pool, service).await.1, Some(creator));

    let maint = role_pool(&pool, "epigraph_maintenance").await;
    let r = sqlx::query_scalar::<_, bool>(APPROVE3)
        .bind(registered)
        .bind(scopes(&["claims:read"]))
        .bind(None::<Uuid>)
        .fetch_one(&maint)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("23514"));
    assert_eq!(
        state(&pool, registered).await,
        ("pending".to_string(), None, vec![], 0)
    );
}

/// 312's CHECK: an ACTIVE agent has an owner; a pending, suspended or revoked
/// one may have none (so an unapproved registration can be revoked).
#[sqlx::test(migrations = "../../migrations")]
async fn only_an_active_agent_must_have_an_owner(pool: PgPool) {
    let pending = client(&pool, "agent", "pending", None, 0).await;
    sqlx::query("UPDATE oauth_clients SET status = 'revoked' WHERE id = $1")
        .bind(pending)
        .execute(&pool)
        .await
        .expect("revoke an ownerless pending agent");

    let other = client(&pool, "agent", "pending", None, 0).await;
    let r = sqlx::query("UPDATE oauth_clients SET status = 'active' WHERE id = $1")
        .bind(other)
        .execute(&pool)
        .await;
    assert_eq!(sqlstate(r.map(|_| ())).as_deref(), Some("23514"));

    let r = sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, status) \
         VALUES ($1, 'active ownerless', 'agent', '{}', 'active')",
    )
    .bind(format!("o312_{}", Uuid::new_v4().simple()))
    .execute(&pool)
    .await;
    assert_eq!(sqlstate(r.map(|_| ())).as_deref(), Some("23514"));
}

/// The owner-naming approval is a maintenance act, as 188 made the
/// three-argument one: owned by `epigraph_maintenance`, SECURITY DEFINER on
/// `pg_catalog, pg_temp`, and EXECUTE-able by neither PUBLIC nor the
/// application role.
///
/// Mutation probe: removing the `REVOKE .. FROM PUBLIC` lets the application
/// role execute it (PUBLIC's default grant).
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_naming_approval_is_a_maintenance_act(pool: PgPool) {
    let (owner, secdef, config, public_exec, app_exec): (
        String,
        bool,
        Option<Vec<String>>,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT p.proowner::regrole::text, p.prosecdef, p.proconfig, \
                EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a \
                         WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'), \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE') \
           FROM pg_proc p WHERE p.oid = $1::text::regprocedure",
    )
    .bind(SIG4)
    .fetch_one(&pool)
    .await
    .expect("the four-argument approval exists");
    assert_eq!(owner, "epigraph_maintenance");
    assert!(secdef);
    assert_eq!(
        config,
        Some(vec!["search_path=pg_catalog, pg_temp".to_string()])
    );
    assert!(!public_exec, "PUBLIC must not EXECUTE {SIG4}");
    assert!(!app_exec, "epigraph_app must not EXECUTE {SIG4}");

    let agent = client(&pool, "agent", "pending", None, 0).await;
    let human = client(&pool, "human", "active", None, 1).await;
    let app = role_pool(&pool, "epigraph_app").await;
    let r = sqlx::query_scalar::<_, bool>(APPROVE4)
        .bind(agent)
        .bind(scopes(&["claims:admin"]))
        .bind(None::<Uuid>)
        .bind(human)
        .fetch_one(&app)
        .await;
    assert_eq!(sqlstate(r).as_deref(), Some("42501"));
    assert_eq!(
        state(&pool, agent).await,
        ("pending".to_string(), None, vec![], 0)
    );
}

/// Run a runbook on ONE connection; on failure roll its open transaction back
/// and return the SQLSTATE.
async fn run_undo(pool: &PgPool) -> Result<(), String> {
    let sql = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/312-undo.sql"),
    )
    .expect("read 312-undo.sql");
    let mut conn = pool.acquire().await.unwrap();
    match sqlx::raw_sql(&sql).execute(&mut *conn).await {
        Ok(_) => Ok(()),
        Err(e) => {
            let code = e
                .as_database_error()
                .and_then(|d| d.code().map(|c| c.to_string()))
                .unwrap_or_else(|| e.to_string());
            sqlx::raw_sql("ROLLBACK").execute(&mut *conn).await.ok();
            Err(code)
        }
    }
}

/// `docs/runbooks/312-undo.sql`: refuses (55000, nothing changed) while an
/// agent has no owner; otherwise drops the overload, leaves 118's
/// three-argument approval, and restores 001's CHECK. Idempotent.
#[sqlx::test(migrations = "../../migrations")]
async fn the_312_undo_restores_001s_check(pool: PgPool) {
    let sig4_exists = |pool: PgPool| async move {
        sqlx::query_scalar::<_, bool>("SELECT to_regprocedure($1) IS NOT NULL")
            .bind(SIG4)
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let ownerless = client(&pool, "agent", "pending", None, 0).await;
    assert_eq!(run_undo(&pool).await, Err("55000".to_string()));
    assert!(
        sig4_exists(pool.clone()).await,
        "a refused undo changed nothing"
    );

    sqlx::query("DELETE FROM oauth_clients WHERE id = $1")
        .bind(ownerless)
        .execute(&pool)
        .await
        .unwrap();
    run_undo(&pool).await.expect("the undo");
    run_undo(&pool).await.expect("the undo again (idempotent)");
    assert!(!sig4_exists(pool.clone()).await);
    let three: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('public.epigraph_oauth_client_approve(uuid, text[], uuid)') \
             IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(three, "118's approval is not 312's to drop");
    let def: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
          WHERE conrelid = 'public.oauth_clients'::regclass AND conname = 'agents_must_have_owner'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        def,
        "CHECK ((((client_type)::text <> 'agent'::text) OR (owner_id IS NOT NULL)))"
    );
    let r = sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, status) \
         VALUES ($1, 'pending ownerless', 'agent', '{}', 'pending')",
    )
    .bind(format!("o312_{}", Uuid::new_v4().simple()))
    .execute(&pool)
    .await;
    assert_eq!(sqlstate(r.map(|_| ())).as_deref(), Some("23514"));
}
