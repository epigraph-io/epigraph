//! Migration 111's audited admin path, measured as the real least-privilege
//! role (batch H-b, D2).
//!
//! # Why these arms run as `epigraph_app`
//!
//! `#[sqlx::test]` connects as a BYPASSRLS superuser that owns every table, so
//! on its pool the ordinary cross-group UPDATE succeeds and the admin path is
//! indistinguishable from it. `fixture::as_role` reaches a genuinely
//! non-bypassing session (`SET SESSION AUTHORIZATION epigraph_app`), stamped
//! with the ADMIN's own GUCs the way `ScopedPool::begin_as` stamps them. This
//! database is migrated 001 -> head with NO orphan `*_privacy` policy, i.e.
//! config A, which is what production becomes after R3: the arm that passes
//! here passes because the definer frame bypasses (its owner is a member of
//! `epigraph_maintenance`), not because any permissive policy admits it.
//!
//! Load-bearing, verified by reverting: with the function's `oauth_clients`
//! re-check removed, `a_token_whose_client_lost_claims_admin_is_refused` and
//! `the_admin_is_the_session_principal_never_a_parameter` fail.
//!
//! NOT load-bearing here, measured: removing the `OWNER TO epigraph_maintenance`
//! leaves every arm green, because this harness migrates as a superuser and a
//! superuser-owned definer bypasses RLS outright. The owner is therefore pinned
//! by catalog assertion instead
//! (`schema_contract.rs::migration_111_admin_write_definer_is_owned_and_granted`,
//! and `tenancy_backfill verify` at deploy).

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;

struct Fixture {
    admin: Uuid,
    admin_group: Uuid,
    client: Uuid,
    claim: Uuid,
    foreign_group: Uuid,
}

/// An admin agent with its own personal group and an ACTIVE `oauth_clients`
/// row granting `claims:admin`, and a claim owned by another agent's personal
/// group the admin is NOT a member of.
async fn seed(pool: &PgPool, client_status: &str, scopes: &[&str]) -> Fixture {
    let (admin, admin_group) = fixture::seed_agent_with_group(pool, "admin").await;
    // The claim is owned by its AUTHOR's personal group, which the admin is not
    // a member of: the shape of retiring another agent's backlog item.
    let (author, foreign_group) = fixture::seed_agent_with_group(pool, "author").await;
    let claim =
        fixture::seed_group_claim(pool, author, foreign_group, "a team's backlog item").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['backlog'] WHERE id = $1")
        .bind(claim)
        .execute(pool)
        .await
        .expect("label the fixture");
    let client = Uuid::new_v4();
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id) \
         VALUES ($1, $2, 'admin client', 'human', $3, $3, $4, $5)",
    )
    .bind(client)
    .bind(format!("admin-{client}"))
    .bind(&scopes)
    .bind(client_status)
    .bind(admin)
    .execute(pool)
    .await
    .expect("seed the admin's oauth client");
    Fixture {
        admin,
        admin_group,
        client,
        claim,
        foreign_group,
    }
}

/// Stamp the session as `principal` with `groups` readable and writable,
/// exactly the three GUCs `ScopedPool::begin_as` sets.
async fn stamp(conn: &mut sqlx::PgConnection, principal: Uuid, groups: &[Uuid]) {
    let list = groups
        .iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, true), \
                set_config('epigraph.writable_group_ids', $1, true), \
                set_config('epigraph.principal_id', $2, true)",
    )
    .bind(list)
    .bind(principal.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp");
}

/// Call the admin function on `conn`; `Err(sqlstate)` on a refusal.
async fn admin_write(
    conn: &mut sqlx::PgConnection,
    client: Uuid,
    claim: Uuid,
) -> Result<serde_json::Value, String> {
    sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT public.epigraph_admin_patch_claim($1, $2, $3, 'update_labels', \
                ARRAY['resolved'], ARRAY[]::text[], NULL, NULL)",
    )
    .bind(client)
    .bind(Uuid::new_v4())
    .bind(claim)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        e.as_database_error()
            .and_then(|d| d.code().map(|c| c.to_string()))
            .unwrap_or_else(|| e.to_string())
    })
}

async fn labels_of(pool: &PgPool, claim: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("labels")
}

async fn audit_rows(pool: &PgPool, admin: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'claims.admin_write' AND agent_id = $1 ORDER BY created_at",
    )
    .bind(admin)
    .fetch_all(pool)
    .await
    .expect("audit rows")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_path_writes_across_the_group_boundary_as_the_app_role(pool: PgPool) {
    let f = seed(&pool, "active", &["claims:read", "claims:admin"]).await;
    let (admin, admin_group, client, claim) = (f.admin, f.admin_group, f.client, f.claim);

    let (plain, admin_path) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        use sqlx::Connection;
        // CALIBRATION: the ordinary UPDATE, stamped from the admin's own
        // viewer, is refused — the admin is not a writer of the owning group.
        let plain = {
            let mut tx = conn.begin().await.expect("begin");
            stamp(&mut tx, admin, &[admin_group]).await;
            let r = sqlx::query(
                "UPDATE claims SET labels = array_append(labels, 'resolved') WHERE id = $1",
            )
            .bind(claim)
            .execute(&mut *tx)
            .await;
            let _ = tx.rollback().await;
            r.map(|done| done.rows_affected())
        };
        // The audited path, on the same kind of stamp.
        let admin_path = {
            let mut tx = conn.begin().await.expect("begin");
            stamp(&mut tx, admin, &[admin_group]).await;
            let r = admin_write(&mut tx, client, claim).await;
            tx.commit().await.expect("commit");
            r
        };
        (conn, (plain, admin_path))
    })
    .await;

    // A clean schema filters the row out of the UPDATE (0 rows) or refuses it.
    assert!(
        matches!(plain, Ok(0) | Err(_)),
        "CALIBRATION: the plain cross-group UPDATE must not land as epigraph_app: {plain:?}"
    );
    let out = admin_path.expect("the admin path must write across the group boundary");
    assert!(
        out["labels"]
            .as_array()
            .expect("labels")
            .iter()
            .any(|l| l == "resolved"),
        "{out}"
    );
    assert!(labels_of(&pool, claim)
        .await
        .contains(&"resolved".to_string()));

    let audit = audit_rows(&pool, admin).await;
    assert_eq!(audit.len(), 1, "exactly one audit row: {audit:?}");
    let a = &audit[0];
    assert_eq!(a["action"], "update_labels");
    assert_eq!(
        a["admin_agent_id"],
        admin.to_string(),
        "the ADMIN is the principal"
    );
    assert_eq!(a["client_id"], client.to_string());
    assert_eq!(a["claim_id"], claim.to_string());
    assert_eq!(a["owner_group_id"], f.foreign_group.to_string());
    assert_ne!(
        a["claim_author"], a["admin_agent_id"],
        "the author is recorded as the target, never as the actor"
    );
    assert_eq!(a["before"]["labels"], serde_json::json!(["backlog"]));
    assert_eq!(
        a["after"]["labels"],
        serde_json::json!(["backlog", "resolved"])
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_whose_client_lost_claims_admin_is_refused(pool: PgPool) {
    for (status, scopes) in [
        ("active", vec!["claims:read", "claims:write"]),
        ("suspended", vec!["claims:read", "claims:admin"]),
    ] {
        let f = seed(&pool, status, &scopes).await;
        let (admin, admin_group, client, claim) = (f.admin, f.admin_group, f.client, f.claim);
        let refused = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            use sqlx::Connection;
            let mut tx = conn.begin().await.expect("begin");
            stamp(&mut tx, admin, &[admin_group]).await;
            let r = admin_write(&mut tx, client, claim).await;
            let _ = tx.rollback().await;
            (conn, r)
        })
        .await;
        assert_eq!(
            refused.as_ref().err().map(String::as_str),
            Some("42501"),
            "a {status} client with {scopes:?} must be refused (ADM02): {refused:?}"
        );
        assert!(!labels_of(&pool, claim)
            .await
            .contains(&"resolved".to_string()));
        assert!(
            audit_rows(&pool, admin).await.is_empty(),
            "no audit row for a refusal"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_is_the_session_principal_never_a_parameter(pool: PgPool) {
    let f = seed(&pool, "active", &["claims:admin"]).await;
    let (stranger, stranger_group) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (client, claim, admin_group) = (f.client, f.claim, f.admin_group);
    let _ = admin_group;

    let (no_principal, someone_else) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            use sqlx::Connection;
            // No principal at all.
            let a = {
                let mut tx = conn.begin().await.expect("begin");
                let r = admin_write(&mut tx, client, claim).await;
                let _ = tx.rollback().await;
                r
            };
            // A session stamped as SOMEONE ELSE presenting the admin's client:
            // the client is bound to the admin agent, not to this principal.
            let b = {
                let mut tx = conn.begin().await.expect("begin");
                stamp(&mut tx, stranger, &[stranger_group]).await;
                let r = admin_write(&mut tx, client, claim).await;
                let _ = tx.rollback().await;
                r
            };
            (conn, (a, b))
        })
        .await;
    assert_eq!(no_principal.err().as_deref(), Some("42501"), "ADM01");
    assert_eq!(someone_else.err().as_deref(), Some("42501"), "ADM02");
    assert!(!labels_of(&pool, claim)
        .await
        .contains(&"resolved".to_string()));
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_the_app_and_maintenance_roles_may_execute_it(pool: PgPool) {
    let sig =
        "public.epigraph_admin_patch_claim(uuid, uuid, uuid, text, text[], text[], jsonb, uuid)";
    for (role, expected) in [("public", false), ("epigraph_app", true)] {
        let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
            .bind(role)
            .bind(sig)
            .fetch_one(&pool)
            .await
            .expect("privilege");
        assert_eq!(can, expected, "{role} EXECUTE on the admin definer");
    }
}
