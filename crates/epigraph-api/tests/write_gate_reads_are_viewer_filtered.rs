#![cfg(feature = "db")]
//! The HTTP write paths' authorization reads go through the CALLER's viewer
//! (`F-write-authz-reads-unfiltered`, backlog 30c29c52).
//!
//! `POST /claims/:id/supersede` and `DELETE /workflows/:id` each decided whether
//! to act with an UNFILTERED read (`SELECT agent_id FROM claims WHERE id = $1`,
//! or an existence probe on `labels`) while the handler held a `Viewer`. A
//! `claims:admin` principal could therefore mutate a claim it cannot read: the
//! gate asked only whose the claim was, or whether it existed. The reads now run
//! through the caller's viewer, so an invisible claim is 404, exactly like a
//! missing one, and nothing is written.
//!
//! `PATCH /claims/:id` has the same unfiltered owner read, and it is kept here as
//! a regression arm, NOT because it was a live defect. MEASURED: with its read
//! left unfiltered the arm still passes. The handler re-fetches the patched claim
//! through the viewer on the SAME transaction before COMMIT, so an invisible
//! claim 404s there and the whole patch rolls back. The arm pins that the
//! rollback keeps happening.
//!
//! # Why this discriminates even though the test database connects as a superuser
//!
//! A superuser bypasses RLS, so the database would admit every one of these
//! writes. The filter this pins is the viewer's IN-QUERY predicate
//! (`{VISIBILITY:c}`, spliced by `ClaimRepository::get_by_id`), which applies
//! whatever the connection's role. The unfiltered read had no predicate at all,
//! and on this database it let the mutation through. MEASURED: with
//! `versioning.rs`'s change reverted the test fails on the supersede arm (201
//! Created), and with `workflows.rs`'s change alone reverted it fails on the
//! deprecate arm (200 OK).
//!
//! Each arm is calibrated by the same call on a PUBLIC claim, which must
//! succeed. Without that, a 404 could come from a broken fixture rather than
//! from the filter.
mod common;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

/// A team group the caller is not a member of, and a claim owned by it with
/// `visibility = 'group'`.
async fn seed_private_claim(pool: &PgPool, content: &str, labels: &[&str]) -> Uuid {
    let owner_agent = Uuid::new_v4();
    let claim = common::seed_claim_with_agent(pool, content, owner_agent).await;
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind) \
         VALUES ('write-gate read test', 'did:test:wgr:' || gen_random_uuid(), \
                 decode(repeat('ab', 32), 'hex'), 'team') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed group");
    let labels: Vec<String> = labels.iter().map(|l| (*l).to_string()).collect();
    sqlx::query(
        "UPDATE claims SET visibility = 'group', owner_group_id = $2, labels = $3 WHERE id = $1",
    )
    .bind(claim)
    .bind(group)
    .bind(&labels)
    .execute(pool)
    .await
    .expect("privatize the claim");
    claim
}

async fn seed_public_claim(pool: &PgPool, content: &str, labels: &[&str]) -> Uuid {
    let claim = common::seed_claim_with_agent(pool, content, Uuid::new_v4()).await;
    let labels: Vec<String> = labels.iter().map(|l| (*l).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $2 WHERE id = $1")
        .bind(claim)
        .bind(&labels)
        .execute(pool)
        .await
        .expect("label the claim");
    claim
}

/// (is_current, truth_value, has the `wgr` property, superseded-by count)
async fn state_of(pool: &PgPool, id: Uuid) -> (bool, f64, bool, i64) {
    sqlx::query_as(
        "SELECT COALESCE(c.is_current, true), c.truth_value, \
                COALESCE(c.properties ? 'wgr', false), \
                (SELECT count(*) FROM claims s WHERE s.supersedes = c.id) \
           FROM claims c WHERE c.id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read claim state")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_principal_cannot_act_on_a_claim_it_cannot_read() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;
    // An ADMIN caller: the ownership gate would admit it for any claim, so only
    // the read's filter can refuse it.
    let (token, _) = common::test_bearer_token_with_seeded_client(
        &pool,
        &["claims:read", "claims:write", "claims:admin"],
    )
    .await;
    let http = reqwest::Client::new();

    for (visibility, expect_ok) in [("public", true), ("private", false)] {
        let seed = |content: &'static str, labels: &'static [&'static str]| {
            let pool = pool.clone();
            async move {
                if expect_ok {
                    seed_public_claim(&pool, content, labels).await
                } else {
                    seed_private_claim(&pool, content, labels).await
                }
            }
        };

        // ── supersede ──
        let c = seed("wgr supersede target", &[]).await;
        let before = state_of(&pool, c).await;
        let resp = http
            .post(format!("http://{addr}/api/v1/claims/{c}/supersede"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"content": format!("wgr replacement {c}"), "truth_value": 0.7, "reason": "wgr"}))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let after = state_of(&pool, c).await;
        if expect_ok {
            assert!(
                status == 200 || status == 201,
                "calibration ({visibility}): supersede must succeed, got {status}"
            );
            assert_eq!(after.3, 1, "calibration: one replacement must supersede it");
        } else {
            assert_eq!(
                status, 404,
                "supersede of a claim the caller cannot read must be 404, got {status}"
            );
            assert_eq!(after, before, "a refused supersede must write nothing");
        }

        // ── PATCH ──
        let c = seed("wgr patch target", &[]).await;
        let before = state_of(&pool, c).await;
        let resp = http
            .patch(format!("http://{addr}/api/v1/claims/{c}"))
            .bearer_auth(&token)
            .json(&serde_json::json!({"properties": {"wgr": true}}))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let after = state_of(&pool, c).await;
        if expect_ok {
            assert_eq!(status, 200, "calibration ({visibility}): PATCH must succeed");
            assert!(after.2, "calibration: the property must land");
        } else {
            assert_eq!(
                status, 404,
                "PATCH of a claim the caller cannot read must be 404, got {status}"
            );
            assert_eq!(after, before, "a refused PATCH must write nothing");
        }

        // ── deprecate_workflow ──
        let c = seed("wgr workflow target", &["workflow"]).await;
        let before = state_of(&pool, c).await;
        let resp = http
            .delete(format!("http://{addr}/api/v1/workflows/{c}?reason=wgr"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let after = state_of(&pool, c).await;
        if expect_ok {
            assert_eq!(
                status, 200,
                "calibration ({visibility}): deprecate must succeed"
            );
            assert!(!after.0, "calibration: the workflow claim must be deprecated");
        } else {
            assert_eq!(
                status, 404,
                "deprecating a workflow the caller cannot read must be 404, got {status}"
            );
            assert_eq!(after, before, "a refused deprecate must write nothing");
        }
    }
}
