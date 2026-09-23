#![cfg(feature = "db")]
//! PR-16 — the two handler-level preconditions `create_claim`'s tenancy
//! declaration rests on.
//!
//! # Why this file exists
//!
//! Review raised this as a blocker: in `create_claim`, `create_or_get` can
//! return an EXISTING row (`was_created = false`) whose tenancy an earlier,
//! different request decided, while the `if privacy_tier != "public"` block
//! further down — which writes `claim_encryption` — is NOT gated on
//! `was_created`. If both could happen in one request, the handler would seal a
//! pre-existing `visibility = 'public'` row: a state the handler's own comment
//! calls unrepairable, because `claims_block_widening` is `BEFORE UPDATE` and
//! cannot see an INSERT that started out public.
//!
//! They cannot both happen. `was_created = false` is reachable ONLY through the
//! `if request.if_not_exists` branch (the `else` branch hardcodes `true` on the
//! success arm and returns 409 otherwise), and `if_not_exists = true` is
//! rejected with a 400 for every non-public tier, before any database work.
//!
//! That is an argument. This file makes it a pinned invariant, so a later
//! change that relaxes the `if_not_exists` guard fails here instead of silently
//! opening the path.

use sqlx::postgres::PgPoolOptions;
mod common;

/// `if_not_exists = true` is refused for every non-public privacy tier.
///
/// The guard runs BEFORE the group-membership check and before the
/// transaction, so no group needs to exist for this to be observable — which is
/// itself part of the property: nothing has been written by the time it
/// refuses.
#[tokio::test(flavor = "multi_thread")]
async fn if_not_exists_is_refused_for_every_non_public_privacy_tier() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    let agent = common::seed_system_agent(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], agent)
            .await;

    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/claims");

    // `fully_private` is the only non-public tier `validate_privacy_fields`
    // accepts (migration 060's `claim_encryption_privacy_tier_check`), so it is
    // the only tier that can reach the `if_not_exists` guard at all. Every
    // other value is refused one step earlier, naming `privacy_tier`.
    //
    // The request is otherwise WELL FORMED — `encrypted_content` and
    // `encryption_epoch` are present — precisely so that `if_not_exists` is
    // what refuses it, and not a missing field.
    let body = serde_json::json!({
        "content": format!("pr16 boundary {}", uuid::Uuid::new_v4()),
        "agent_id": agent,
        "privacy_tier": "fully_private",
        // A syntactically valid group that does not exist: part of the property
        // is that the refusal lands before anything looks it up.
        "group_id": uuid::Uuid::new_v4(),
        "encrypted_content": "AAAA",
        "encryption_epoch": 0,
        "if_not_exists": true,
    });

    let r = client
        .post(&endpoint)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = r.status();
    let text = r.text().await.unwrap_or_default();

    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "if_not_exists=true with privacy_tier=fully_private must be refused with \
         400. If this now succeeds, `create_or_get` can return an EXISTING public \
         row while the encryption block below writes ciphertext for it — a \
         sealed claim with visibility='public', which cannot be repaired in \
         place. Gate the encryption block on `was_created` before relaxing \
         this. Got {status}: {text}"
    );
    assert!(
        text.contains("if_not_exists"),
        "the 400 must name the field the caller has to change, not an earlier \
         validation it happened to trip on the way: {text}"
    );
}

/// A public claim's `owner_group_id` follows the AUTHENTICATED PRINCIPAL, not
/// the request body's `agent_id`.
///
/// # The request is deliberately DELEGATED, and that is the whole point
///
/// The body names a DIFFERENT agent than the token. A request where the two
/// agree cannot distinguish the two derivations — both produce the same group —
/// so it would pass equally on the code this test exists to pin and on the code
/// it replaced. `epigraph-cli/src/bin/decompose_claims.rs` issues exactly this
/// shape in production: it posts atoms with `agent_id` = the PARENT claim's
/// author, holding an opaque token from which it cannot learn its own agent id.
///
/// Three assertions, and the third is the security one:
///   1. `claims.agent_id` is still the BODY's agent — authorship is unchanged.
///   2. `claims.owner_group_id` is the PRINCIPAL's personal group — ownership
///      is not decided by an unauthenticated body field, and `owner_group_id`
///      is the column PR-17's RLS predicate keys on.
///   3. NO personal group was minted for the body's agent. Deriving from the
///      body called `personal_group_of`, which MINTS a `groups` row plus an
///      `admin` `group_memberships` row when none exists — so a third party
///      could be provisioned as a side effect of an unrelated claim write.
///
/// It also pins §8.2 A4 on the live write path: the row must NOT land on the
/// world group.
#[tokio::test(flavor = "multi_thread")]
async fn a_public_claims_owner_follows_the_principal_not_the_body_agent() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();

    // The token's principal.
    let principal = common::seed_system_agent(&pool).await;
    // A DIFFERENT agent, named only in the request body.
    let body_agent = common::seed_system_agent(&pool).await;
    assert_ne!(principal, body_agent);

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, &["claims:write"], principal)
            .await;

    let personal_group_of = |agent: uuid::Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, uuid::Uuid>(
                "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
            )
            .bind(agent)
            .fetch_optional(&pool)
            .await
            .expect("personal-group probe")
        }
    };

    let content = format!("pr16 owner probe {}", uuid::Uuid::new_v4());
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "content": content, "agent_id": body_agent }))
        .send()
        .await
        .unwrap();
    let status = r.status();
    let body: serde_json::Value = r.json().await.expect("json body");
    assert!(status.is_success(), "create failed: {status} {body}");
    let claim_id: uuid::Uuid = body["id"]
        .as_str()
        .expect("response carries an id")
        .parse()
        .expect("id is a uuid");

    let (visibility, owner, author): (String, uuid::Uuid, uuid::Uuid) =
        sqlx::query_as("SELECT visibility, owner_group_id, agent_id FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("read the row back");

    assert_eq!(visibility, "public");
    assert_eq!(
        author, body_agent,
        "authorship is unchanged: claims.agent_id still records the body's agent"
    );
    assert_ne!(
        owner,
        uuid::Uuid::nil(),
        "§8.2 A4: no claim may be owned by the world group. Migration 074 \
         dropped the DEFAULT that used to put it there; a row landing here \
         again means a write path lost its declaration."
    );

    let principal_group = personal_group_of(principal)
        .await
        .expect("the authenticated principal has a personal group");
    assert_eq!(
        owner, principal_group,
        "owner_group_id must resolve the AUTHENTICATED principal's personal \
         group. If this is the BODY agent's group instead, an unauthenticated \
         request field is deciding the column PR-17's RLS predicate keys on, \
         and a caller can place rows into a group it is not a member of."
    );

    assert!(
        personal_group_of(body_agent).await.is_none(),
        "no personal group may be minted for an agent merely NAMED in a request \
         body. `personal_group_of` mints a groups row AND an admin membership \
         when none exists, so deriving the declaration from the body \
         provisions a third party as a side effect of an unrelated write."
    );
}
