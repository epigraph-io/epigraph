//! Migration 149's link guard, through the stdio self-link's error mapping.
//!
//! A stdio process started with `--operator-id` on a signer that is the agent
//! of an allowlisted OAuth client dies at `self_link`: the link guard refuses
//! (a link would make the agent stdio-only, ending the client's HTTP access).
//! `operator::link_refusal_text` recognises that refusal by the guard
//! message's stable fragment, because its SQLSTATE (55000) is shared with
//! other link refusals, and prints the allowlist remedy instead of the
//! EXECUTE-grant hint.
//!
//! The unit test in `src/operator.rs` feeds the mapping a hand-written
//! message. This test feeds it the REAL database refusal, so a reworded guard
//! message that no longer carries the fragment fails here, instead of
//! silently falling through to the wrong remedy at a production startup.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::AgentRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// Verified to fail: the migration's guard message reworded so it no longer
/// carries the fragment (the mapping falls through to the EXECUTE-grant hint).
#[sqlx::test(migrations = "../../migrations")]
async fn a_real_allowlist_link_refusal_names_the_allowlist_remedy(pool: PgPool) {
    let (operator, _) = fixture::seed_human_operator(&pool, "operator").await;
    let (signer, _) = fixture::seed_agent_with_group(&pool, "signer").await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'host writer', 'service', ARRAY['claims:write'], 'active', $2, \
                 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("host-writer-{}", Uuid::new_v4()))
    .bind(signer)
    .fetch_one(&pool)
    .await
    .expect("the signer's service client");
    let binding: Option<String> =
        fixture::as_role(&pool, "epigraph_maintenance", |mut c| async move {
            let b = sqlx::query_scalar(
                "SELECT effective_binding \
                   FROM public.epigraph_allow_author_binding_client($1, $2, 'test')",
            )
            .bind(client)
            .bind(operator)
            .fetch_one(&mut *c)
            .await
            .expect("allow the signer's client");
            (c, b)
        })
        .await;
    assert_eq!(
        binding.as_deref(),
        Some(epigraph_db::CLIENT_ALLOWLIST_BINDING),
        "CALIBRATION: the signer is allowlisted"
    );

    // The link a stdio `self_link` would record, on the maintenance role that
    // may EXECUTE the definer (so the refusal is the guard's, not a grant's).
    let refused = fixture::as_role(&pool, "epigraph_maintenance", |mut c| async move {
        let r = AgentRepository::link_operator(&mut c, signer, operator).await;
        (c, r)
    })
    .await
    .expect_err("the link guard refuses an allowlisted signer");
    let text = epigraph_mcp::operator::link_refusal_text(signer, operator, &refused);
    assert!(
        text.contains("revoke-author-binding-client")
            && text.contains("author-binding allowlist")
            && !text.contains("EXECUTE-able"),
        "the real refusal maps to the allowlist remedy, not the grant hint: {text}"
    );
    let links: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_links WHERE agent_id = $1")
        .bind(signer)
        .fetch_one(&pool)
        .await
        .expect("links");
    assert_eq!(links, 0, "nothing was linked");
}
