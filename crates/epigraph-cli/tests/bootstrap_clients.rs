//! Integration tests for canonical-client bootstrap.
//!
//! Verifies:
//! 1. Initial run creates the three named clients with correct scopes.
//! 2. Re-running is a no-op for the existing rows (idempotent).
//! 3. The scope-set invariants hold in the database (admin ⊇ wo ⊃ ro).

use std::collections::HashSet;

use sqlx::PgPool;

use epigraph_cli::bootstrap::{bootstrap_canonical_clients, ClientOutcome};

const LEGAL_NAME: &str = "Bootstrap Test Co.";
const LEGAL_EMAIL: &str = "ops@bootstrap-test.example";

#[sqlx::test(migrations = "../../migrations")]
async fn first_run_creates_three_clients(pool: PgPool) {
    let outcomes = bootstrap_canonical_clients(&pool, LEGAL_NAME, LEGAL_EMAIL, None)
        .await
        .expect("bootstrap");

    assert_eq!(outcomes.len(), 3);
    for o in &outcomes {
        match o {
            ClientOutcome::Created { name, .. } => {
                assert!(
                    matches!(*name, "epigraph-admin" | "epigraph-ro" | "epigraph-wo"),
                    "unexpected created name {name}"
                );
            }
            ClientOutcome::Existing { name, .. } => {
                panic!("first run should not see existing client {name}");
            }
        }
    }

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_clients WHERE client_name IN ('epigraph-admin','epigraph-ro','epigraph-wo')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn second_run_is_idempotent(pool: PgPool) {
    bootstrap_canonical_clients(&pool, LEGAL_NAME, LEGAL_EMAIL, None)
        .await
        .expect("bootstrap 1");

    let outcomes = bootstrap_canonical_clients(&pool, "Other Org", "other@example.com", None)
        .await
        .expect("bootstrap 2");

    assert_eq!(outcomes.len(), 3);
    for o in &outcomes {
        assert!(
            matches!(o, ClientOutcome::Existing { .. }),
            "second run must report Existing, got {o:?}"
        );
        // Nothing drifted, so nothing was rewritten — the reconcile is a no-op
        // on an already-current row and must not churn `updated_at`.
        assert!(
            matches!(
                o,
                ClientOutcome::Existing {
                    scopes_reconciled: false,
                    ..
                }
            ),
            "an unchanged row must not report a reconcile, got {o:?}"
        );
    }

    // Still exactly three rows.
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM oauth_clients WHERE client_name IN ('epigraph-admin','epigraph-ro','epigraph-wo')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn scope_invariants_hold_in_db(pool: PgPool) {
    bootstrap_canonical_clients(&pool, LEGAL_NAME, LEGAL_EMAIL, None)
        .await
        .expect("bootstrap");

    let scopes_for_name = |name: &'static str| {
        let pool = pool.clone();
        async move {
            let row: (Vec<String>,) =
                sqlx::query_as("SELECT granted_scopes FROM oauth_clients WHERE client_name = $1")
                    .bind(name)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            row.0.into_iter().collect::<HashSet<String>>()
        }
    };

    let admin = scopes_for_name("epigraph-admin").await;
    let wo = scopes_for_name("epigraph-wo").await;
    let ro = scopes_for_name("epigraph-ro").await;

    assert!(ro.is_subset(&wo), "ro must be subset of wo");
    assert!(wo.is_subset(&admin), "wo must be subset of admin");
    assert!(
        admin.contains("claims:admin"),
        "admin must include claims:admin"
    );
    assert!(
        !wo.contains("claims:admin"),
        "wo must NOT include claims:admin"
    );
    assert!(
        !ro.contains("claims:write"),
        "ro must NOT include claims:write"
    );
}

/// Bootstrap must be CONVERGENT, not merely idempotent.
///
/// It used to look a canonical client up by name and `continue` on a hit,
/// never touching scopes. PR-02 adds `groups:write` to the write roles and
/// `groups:admin` to admin, and `POST /api/v1/groups` and both member routes now
/// REQUIRE them — so on any already-bootstrapped instance the canonical clients
/// keep their old arrays and 403, including `epigraph-admin`, with no migration
/// or backfill in the release able to fix it. Re-running this binary is the
/// operator-facing repair, so it has to converge.
#[sqlx::test(migrations = "../../migrations")]
async fn a_drifted_canonical_client_is_reconciled(pool: PgPool) {
    bootstrap_canonical_clients(&pool, LEGAL_NAME, LEGAL_EMAIL, None)
        .await
        .expect("bootstrap 1");

    // Simulate the pre-PR-02 instance: the row exists, but without the scopes
    // this release started requiring.
    let narrowed = vec!["claims:read".to_string()];
    sqlx::query(
        "UPDATE oauth_clients SET allowed_scopes = $1, granted_scopes = $1 \
         WHERE client_name = 'epigraph-admin'",
    )
    .bind(&narrowed)
    .execute(&pool)
    .await
    .expect("narrow scopes");

    let outcomes = bootstrap_canonical_clients(&pool, LEGAL_NAME, LEGAL_EMAIL, None)
        .await
        .expect("bootstrap 2");

    let admin = outcomes
        .iter()
        .find(|o| match o {
            ClientOutcome::Existing { name, .. } | ClientOutcome::Created { name, .. } => {
                *name == "epigraph-admin"
            }
        })
        .expect("epigraph-admin in outcomes");
    assert!(
        matches!(
            admin,
            ClientOutcome::Existing {
                scopes_reconciled: true,
                ..
            }
        ),
        "the drifted row must report a reconcile, got {admin:?}"
    );

    let (allowed, granted): (Vec<String>, Vec<String>) = sqlx::query_as(
        "SELECT allowed_scopes, granted_scopes FROM oauth_clients \
         WHERE client_name = 'epigraph-admin'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let canonical = epigraph_core::canonical_scopes::scopes_for("epigraph-admin")
        .expect("canonical name resolves");
    let expected: HashSet<&str> = canonical.iter().map(String::as_str).collect();
    assert_eq!(
        allowed.iter().map(String::as_str).collect::<HashSet<_>>(),
        expected
    );
    assert_eq!(
        granted.iter().map(String::as_str).collect::<HashSet<_>>(),
        expected
    );

    // The routes PR-02 gated are specifically reachable again.
    assert!(granted.iter().any(|s| s == "groups:write"));
    assert!(granted.iter().any(|s| s == "groups:admin"));
}
