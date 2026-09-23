//! `AgentRepository::get_public_profile` — the Tier-B projection (plan §4.4).
//!
//! # Why this file exists
//!
//! `get_public_profile` lands **caller-less**. `grep -rn get_public_profile
//! crates/` finds nothing outside `repos/agent.rs`, and `routes/agents.rs`
//! registers no public-profile route until PR-07 threads `ViewerExtractor` into
//! handlers. Carried out of PR-02 by the plan ("both its prerequisites are PR-04
//! deliverables"), it would otherwise be compiled-but-never-executed code — and
//! its query is a runtime `sqlx::query_as`, so `SQLX_OFFLINE=true cargo check`
//! does not even validate the column names.
//!
//! # What it pins
//!
//! `agents` is deliberately NOT tenancy-partitioned: authorship must render on a
//! public claim, so migration 077's row policy on it is `USING (true)` with an
//! explicit `-- VISIBILITY-EXEMPT:` marker. The PII narrowing is therefore a
//! **repo-layer column projection**, because PostgreSQL has no column-level RLS —
//! which means nothing but this test stands between `agents.properties`
//! (`full_name`, `email`, `affiliations`, migration 001) and any viewer.
//!
//! The four entitlement paths, each asserted separately so a failure says which
//! one broke:
//!
//! 1. `profile_visibility = 'public'` → details visible to anyone;
//! 2. the viewer IS the agent → visible even when the profile is `group`;
//! 3. the viewer shares a LIVE group with the agent → visible;
//! 4. none of the above → `properties`, `orcid`, `ror_id` are all `None`.
//!
//! Plus: a bypass viewer sees everything, a revoked membership does not count,
//! and the always-present fields are always present.

use epigraph_db::{repos::AgentRepository, ScopedPool, SessionGucMode, SystemReason, Viewer};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// A unique, `orcid_format`-valid ORCID derived from an agent id.
fn orcid_for(id: Uuid) -> String {
    let d = format!("{:016}", (id.as_u128() % 10_u128.pow(16)) as u64);
    format!("{}-{}-{}-{}", &d[0..4], &d[4..8], &d[8..12], &d[12..16])
}

/// A unique, `ror_format`-valid ROR id derived from an agent id: `0`, six
/// lowercase base-36 characters, two digits — exactly 9 characters.
fn ror_for(id: Uuid) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let n = id.as_u128();
    let mut v = (n >> 16) as u64;
    let mut mid = String::with_capacity(6);
    for _ in 0..6 {
        mid.push(ALPHABET[(v % 36) as usize] as char);
        v /= 36;
    }
    format!("0{mid}{:02}", (n % 100) as u8)
}

async fn seed_agent(pool: &PgPool, profile_visibility: &str) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, display_name, properties, \
                             orcid, ror_id, profile_visibility) \
         VALUES ($1, $2, 'system', $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(&pk)
    .bind(format!("agent-{id}"))
    .bind(json!({ "full_name": "Ada Lovelace", "email": "ada@example.test" }))
    // Both identifiers are UNIQUE *and* CHECK-constrained by migration 001, so
    // they are derived from the agent's uuid rather than hard-coded:
    //   orcid_format ~ ^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$   (varchar(19), UNIQUE)
    //   ror_format   ~ ^0[a-z0-9]{6}\d{2}$              (varchar(9),  UNIQUE)
    .bind(orcid_for(id))
    .bind(ror_for(id))
    .bind(profile_visibility)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

async fn seed_group(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, did_key, public_key, kind, display_name) \
         VALUES ($1, $2, $3, 'team', 'profile-test')",
    )
    .bind(id)
    .bind(format!("did:key:profile-{id}"))
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed group");
    id
}

async fn seed_membership(pool: &PgPool, group_id: Uuid, agent_id: Uuid, revoked: bool) {
    sqlx::query(
        "INSERT INTO group_memberships \
             (group_id, agent_id, wrapped_key_share, epoch, role, revoked_at) \
         VALUES ($1, $2, $3, 0, 'writer', CASE WHEN $4 THEN now() ELSE NULL END)",
    )
    .bind(group_id)
    .bind(agent_id)
    .bind(vec![0u8; 48])
    .bind(revoked)
    .execute(pool)
    .await
    .expect("seed membership");
}

// ---------------------------------------------------------------------------
// the four entitlement paths
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_public_profile_is_visible_to_a_stranger(pool: PgPool) {
    let subject = seed_agent(&pool, "public").await;
    let stranger = seed_agent(&pool, "public").await;

    let viewer = Viewer::resolve(&pool, stranger).await.expect("resolve");
    let profile = AgentRepository::get_public_profile(&pool, &viewer, subject)
        .await
        .expect("get_public_profile")
        .expect("the agent exists");

    assert_eq!(profile.id, subject);
    assert_eq!(profile.profile_visibility, "public");
    assert!(profile.properties.is_some(), "public means public");
    assert!(profile.orcid.is_some());
    assert!(profile.ror_id.is_some());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_profile_is_opaque_to_a_stranger(pool: PgPool) {
    let subject = seed_agent(&pool, "group").await;
    let stranger = seed_agent(&pool, "public").await;

    let viewer = Viewer::resolve(&pool, stranger).await.expect("resolve");
    let profile = AgentRepository::get_public_profile(&pool, &viewer, subject)
        .await
        .expect("get_public_profile")
        .expect("the agent exists");

    // The four always-present fields. `agents` is Tier-B: the ROW stays
    // readable so authorship renders on a public claim.
    assert_eq!(profile.id, subject);
    assert!(
        profile.display_name.is_some(),
        "display_name is always returned — it is what renders as authorship"
    );
    assert_eq!(profile.public_key.len(), 32);
    assert_eq!(profile.key_kind, "ed25519");
    assert_eq!(profile.profile_visibility, "group");

    // And the three that are not.
    assert!(
        profile.properties.is_none(),
        "agents.properties holds full_name / email / affiliations (migration 001)"
    );
    assert!(profile.orcid.is_none());
    assert!(profile.ror_id.is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_can_always_see_its_own_profile(pool: PgPool) {
    let subject = seed_agent(&pool, "group").await;

    let viewer = Viewer::resolve(&pool, subject).await.expect("resolve");
    let profile = AgentRepository::get_public_profile(&pool, &viewer, subject)
        .await
        .expect("get_public_profile")
        .expect("the agent exists");

    assert!(
        profile.properties.is_some(),
        "an agent is entitled to its own PII regardless of profile_visibility"
    );
    assert!(profile.orcid.is_some());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_shared_live_group_reveals_the_profile(pool: PgPool) {
    let subject = seed_agent(&pool, "group").await;
    let colleague = seed_agent(&pool, "public").await;
    let shared = seed_group(&pool).await;
    seed_membership(&pool, shared, subject, false).await;
    seed_membership(&pool, shared, colleague, false).await;

    let viewer = Viewer::resolve(&pool, colleague).await.expect("resolve");
    let profile = AgentRepository::get_public_profile(&pool, &viewer, subject)
        .await
        .expect("get_public_profile")
        .expect("the agent exists");

    assert!(
        profile.properties.is_some(),
        "sharing a live group is the third entitlement path"
    );
}

/// The membership predicate is `revoked_at IS NULL`, not "a row exists". A
/// revoked colleague keeps a `group_memberships` row forever — that is the audit
/// trail — and must lose the entitlement the moment it is revoked.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_membership_does_not_reveal_the_profile(pool: PgPool) {
    let subject = seed_agent(&pool, "group").await;
    let former = seed_agent(&pool, "public").await;
    let shared = seed_group(&pool).await;
    seed_membership(&pool, shared, subject, false).await;
    seed_membership(&pool, shared, former, true).await;

    let viewer = Viewer::resolve(&pool, former).await.expect("resolve");
    assert_eq!(
        viewer.group_bind(),
        Some(&[][..]),
        "precondition: the revoked membership is not in the viewer's group set"
    );

    let profile = AgentRepository::get_public_profile(&pool, &viewer, subject)
        .await
        .expect("get_public_profile")
        .expect("the agent exists");
    assert!(
        profile.properties.is_none(),
        "a revoked membership must not carry the entitlement with it"
    );
}

/// The subject's OWN membership must be live too. A viewer who is still in the
/// group but whose subject has left it shares nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_subjects_membership_must_also_be_live(pool: PgPool) {
    let subject = seed_agent(&pool, "group").await;
    let colleague = seed_agent(&pool, "public").await;
    let shared = seed_group(&pool).await;
    seed_membership(&pool, shared, subject, true).await; // subject has left
    seed_membership(&pool, shared, colleague, false).await;

    let viewer = Viewer::resolve(&pool, colleague).await.expect("resolve");
    assert_eq!(viewer.group_bind(), Some(&[shared][..]));

    let profile = AgentRepository::get_public_profile(&pool, &viewer, subject)
        .await
        .expect("get_public_profile")
        .expect("the agent exists");
    assert!(
        profile.properties.is_none(),
        "the EXISTS clause filters gm.revoked_at IS NULL on the SUBJECT's row"
    );
}

// ---------------------------------------------------------------------------
// bypass, and the not-found case
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_bypass_viewer_sees_everything(pool_opts: PgPoolOptions, conn_opts: PgConnectOptions) {
    let pool = pool_opts
        .connect_with(conn_opts.clone())
        .await
        .expect("seeding pool");

    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let db = conn_opts.get_database().expect("test database name");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    let scoped = ScopedPool::connect(&format!("{prefix}/{db}"), SessionGucMode::Session)
        .await
        .expect("ScopedPool::connect");

    let subject = seed_agent(&pool, "group").await;

    let (_conn, lease) = scoped
        .unscoped_for_maintenance(SystemReason::SchemaContractTest)
        .await
        .expect("unscoped_for_maintenance");
    let bypass = Viewer::system(&lease, SystemReason::SchemaContractTest);

    let profile = AgentRepository::get_public_profile(&pool, &bypass, subject)
        .await
        .expect("get_public_profile")
        .expect("the agent exists");

    assert!(
        profile.properties.is_some(),
        "a bypass viewer is unrestricted here as everywhere else"
    );
    assert!(profile.orcid.is_some());
    assert!(profile.ror_id.is_some());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_agent_is_none_not_an_error(pool: PgPool) {
    let caller = seed_agent(&pool, "public").await;
    let viewer = Viewer::resolve(&pool, caller).await.expect("resolve");

    let profile = AgentRepository::get_public_profile(&pool, &viewer, Uuid::new_v4())
        .await
        .expect("an unknown id is not an error");
    assert!(profile.is_none());
}

/// `key_kind` is always returned, and it must be the real value: a caller that
/// cannot tell `ed25519` from the BLAKE3 `derived` placeholder will feed the
/// placeholder to a signature verifier.
#[sqlx::test(migrations = "../../migrations")]
async fn key_kind_is_projected_verbatim(pool: PgPool) {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, key_kind, profile_visibility) \
         VALUES ($1, $2, 'system', 'derived', 'group')",
    )
    .bind(id)
    .bind(&pk)
    .execute(&pool)
    .await
    .expect("seed derived agent");

    let stranger = seed_agent(&pool, "public").await;
    let viewer = Viewer::resolve(&pool, stranger).await.expect("resolve");

    let profile = AgentRepository::get_public_profile(&pool, &viewer, id)
        .await
        .expect("get_public_profile")
        .expect("the agent exists");

    assert_eq!(
        profile.key_kind, "derived",
        "key_kind must survive the projection even when the profile is opaque"
    );
    assert!(profile.properties.is_none());
}
