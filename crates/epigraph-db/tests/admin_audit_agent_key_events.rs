//! Migration 252 (backlog 6492de67): migration 112's admin audit definer,
//! `epigraph_admin_audit_write`, accepts the two agent-key admin events
//! (`agent_keys.admin_rotate`, `agent_keys.admin_revoke`) besides
//! `workflows.admin_write`, and nothing else; its grant re-check, path and
//! precondition; and `docs/runbooks/252-undo.sql`. Each test measures the
//! catalog or the rows the definer wrote.

use sqlx::PgPool;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const UNDO_252: &str = include_str!("../../../docs/runbooks/252-undo.sql");

/// md5 of 112's `prosrc` (190 changed the function's path, not its body).
const BODY_112_MD5: &str = "6c9a51969e80c7d47233cbc85659d911";

const SIGNATURE: &str = "public.epigraph_admin_audit_write(uuid, uuid, uuid, text, jsonb)";

fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) -> Result<(), String> {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = migrator.run(&mut *conn).await.map_err(|e| format!("{e:?}"));
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    out
}

/// An agent and an `oauth_clients` row bound to it. `admin` decides whether
/// the client grants `claims:admin`. Returns (agent id, client row id).
async fn seed_client(pool: &PgPool, admin: bool) -> (Uuid, Uuid) {
    let agent = Uuid::new_v4();
    let pk: Vec<u8> = agent.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    let client = Uuid::new_v4();
    let scopes: Vec<&str> = if admin {
        vec!["agents:write", "claims:admin"]
    } else {
        vec!["agents:write"]
    };
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, legal_entity_name, \
                                    legal_contact_email, allowed_scopes, granted_scopes, status, \
                                    agent_id) \
         VALUES ($1, $2, 'test', 'service', 'Test Entity', 'test@example.com', $3, $3, 'active', \
                 $4)",
    )
    .bind(client)
    .bind(client.to_string())
    .bind(&scopes)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed oauth client");
    (agent, client)
}

/// Call the definer; `Err` carries the SQLSTATE.
async fn audit(
    pool: &PgPool,
    client: Uuid,
    jti: Uuid,
    admin: Uuid,
    event_type: &str,
) -> Result<(), String> {
    sqlx::query("SELECT public.epigraph_admin_audit_write($1, $2, $3, $4, $5)")
        .bind(client)
        .bind(jti)
        .bind(admin)
        .bind(event_type)
        .bind(serde_json::json!({"probe": event_type}))
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| {
            e.as_database_error()
                .and_then(|d| d.code().map(|c| c.into_owned()))
                .unwrap_or_else(|| format!("{e}"))
        })
}

/// (event_type, agent_id, correlation_id, details) of every row with `jti`.
async fn rows_for(
    pool: &PgPool,
    jti: Uuid,
) -> Vec<(String, Option<Uuid>, Option<String>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT event_type::text, agent_id, correlation_id::text, details \
           FROM security_events WHERE details->>'token_jti' = $1::text ORDER BY event_type",
    )
    .bind(jti)
    .fetch_all(pool)
    .await
    .expect("read security_events")
}

async fn body_md5(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT md5(prosrc) FROM pg_proc WHERE oid = to_regprocedure($1)")
        .bind(SIGNATURE)
        .fetch_one(pool)
        .await
        .expect("the definer exists")
}

async fn proconfig(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, Option<Vec<String>>>(
        "SELECT proconfig FROM pg_proc WHERE oid = to_regprocedure($1)",
    )
    .bind(SIGNATURE)
    .fetch_one(pool)
    .await
    .expect("proconfig")
    .unwrap_or_default()
}

/// At head: the two agent-key events are written, attributed to the admin,
/// alongside the workflow event; any other type is still ADM03 (22023), a
/// client without a live `claims:admin` grant is still ADM02 (42501), and a
/// refusal writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_definer_accepts_the_agent_key_events_and_no_others(pool: PgPool) {
    let (admin, client) = seed_client(&pool, true).await;
    let jti = Uuid::new_v4();
    for event in [
        "agent_keys.admin_rotate",
        "agent_keys.admin_revoke",
        "workflows.admin_write",
    ] {
        audit(&pool, client, jti, admin, event)
            .await
            .unwrap_or_else(|e| panic!("{event} must be accepted, got {e}"));
    }
    let rows = rows_for(&pool, jti).await;
    let events: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        events,
        [
            "agent_keys.admin_revoke",
            "agent_keys.admin_rotate",
            "workflows.admin_write"
        ]
    );
    for (event, agent, correlation, details) in &rows {
        assert_eq!(*agent, Some(admin), "{event}: attributed to the admin");
        assert_eq!(correlation.as_deref(), Some(jti.to_string().as_str()));
        assert_eq!(details["client_id"], serde_json::json!(client));
        assert_eq!(details["admin_agent_id"], serde_json::json!(admin));
        assert_eq!(details["probe"], serde_json::json!(event));
    }

    let jti = Uuid::new_v4();
    for event in ["agent_keys.admin_delete", "agent_keys.rotate", ""] {
        assert_eq!(
            audit(&pool, client, jti, admin, event).await,
            Err("22023".to_string()),
            "{event:?} must stay ADM03"
        );
    }
    let (plain, plain_client) = seed_client(&pool, false).await;
    assert_eq!(
        audit(&pool, plain_client, jti, plain, "agent_keys.admin_rotate").await,
        Err("42501".to_string()),
        "a client without claims:admin is ADM02"
    );
    assert_eq!(
        audit(&pool, client, jti, plain, "agent_keys.admin_revoke").await,
        Err("42501".to_string()),
        "an admin client bound to ANOTHER agent is ADM02"
    );
    assert!(
        rows_for(&pool, jti).await.is_empty(),
        "a refusal writes nothing"
    );

    let config = proconfig(&pool).await;
    assert_eq!(
        config,
        ["search_path=pg_catalog, public, pg_temp"],
        "190's path, pg_temp last"
    );
}

/// 252 re-states only over 112's exact body: over any other it raises
/// 55000 and changes nothing.
#[sqlx::test(migrations = false)]
async fn migration_252_refuses_over_another_body(pool: PgPool) {
    migrate(&pool, &up_to(251)).await.expect("migrate to 251");
    assert_eq!(body_md5(&pool).await, BODY_112_MD5, "112's body below 252");

    // Another migration's re-statement: same behaviour, different body.
    let def: String = sqlx::query_scalar("SELECT pg_get_functiondef(to_regprocedure($1))")
        .bind(SIGNATURE)
        .fetch_one(&pool)
        .await
        .expect("functiondef");
    let rebodied = def.replacen("BEGIN", "BEGIN\n    -- re-bodied elsewhere", 1);
    sqlx::raw_sql(&rebodied)
        .execute(&pool)
        .await
        .expect("re-body the definer");
    let other = body_md5(&pool).await;
    assert_ne!(other, BODY_112_MD5);

    let err = migrate(&pool, &MIGRATOR)
        .await
        .expect_err("252 must refuse over another body");
    assert!(err.contains("252"), "{err}");
    assert_eq!(body_md5(&pool).await, other, "nothing was changed");
}

/// `docs/runbooks/252-undo.sql`: restores 112's body on 190's path, so the
/// agent-key events are ADM03 again and the workflow event still writes; a
/// second run changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_252_undo_restores_112s_body(pool: PgPool) {
    assert_ne!(
        body_md5(&pool).await,
        BODY_112_MD5,
        "252 is applied at head"
    );
    let (admin, client) = seed_client(&pool, true).await;

    for run in ["first", "second"] {
        sqlx::raw_sql(UNDO_252)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("undo, {run} run: {e}"));
        assert_eq!(body_md5(&pool).await, BODY_112_MD5, "{run} run: 112's body");
        assert_eq!(
            proconfig(&pool).await,
            ["search_path=pg_catalog, public, pg_temp"],
            "{run} run: 190's path"
        );
        let jti = Uuid::new_v4();
        assert_eq!(
            audit(&pool, client, jti, admin, "agent_keys.admin_rotate").await,
            Err("22023".to_string()),
            "{run} run: the agent-key event is ADM03 again"
        );
        audit(&pool, client, jti, admin, "workflows.admin_write")
            .await
            .unwrap_or_else(|e| panic!("{run} run: the workflow event must still write: {e}"));
    }
}
