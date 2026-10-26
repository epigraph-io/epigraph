//! Migration 180: a legacy fleet identity is an acceptable parent (AID03), and
//! a child that registered parentless because it was not can have its
//! succession recorded after the fact.
//!
//! # What went wrong
//!
//! Before host-attested registration (161), epigraph-mcp created each fleet
//! identity through `AgentRepository::create`, which never names
//! `agent_type`, so the row took the column default `'human'`, and then
//! recorded `llm_model` with `set_llm_properties`. 161's AID03 refuses an
//! `agent_type 'human'` parent, so the host's first keyed registration of each
//! group's successor was refused and fell back to registering it with no
//! parent: no succession, no inherited link.
//!
//! 161's own calibration seeded its "legacy" parent as `software_agent`, which
//! is why the suite stayed green. Every legacy parent here is created the way
//! the old path created it: `AgentRepository::create` plus
//! `set_llm_properties`, with its `identity-legacy` key from
//! `epigraph_backfill_legacy_agent_keys()` run as the maintenance role.
//!
//! # What is under test
//!
//! * The legacy fleet parent is accepted, its operator is inherited, and the
//!   succession is recorded.
//! * A REAL human keeps being refused even when it carries the full legacy
//!   shape (`llm_model`, a backfilled legacy key, `agent_type 'human'`): a
//!   registered human operator, a revoked one, a keyless (derived) human, a
//!   human with an OAuth human client of its own (any status), and a row
//!   created after the backfill (no legacy key). Each case adds exactly
//!   one marker to the accepted shape, so the marker is what refuses it.
//! * `epigraph_record_legacy_succession` records the succession of a
//!   parentless child (the row, the display parent, one audit row), moves no
//!   link, is idempotent, is maintenance-only, and refuses every case outside
//!   its rule without changing anything.
//! * 180 refuses to re-state a registration body it was not written from, and
//!   `docs/runbooks/180-undo.sql` returns the catalog to 166's.

#[path = "viewer_fixture.rs"]
mod fixture;

mod helpers;

use epigraph_db::AgentRepository;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const ATTESTOR: &str = "epigraph_identity_attestor";
const MAINTENANCE: &str = "epigraph_maintenance";
const MODEL: &str = "test-model-180";
const GROUP: &str = "g-main";

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn random32() -> Vec<u8> {
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    [a.as_bytes().as_slice(), b.as_bytes().as_slice()].concat()
}

/// A synthetic host identity: identity key, prompt hash, signing key.
struct Identity {
    pubkey: Vec<u8>,
    prompt_hash: String,
    signing: Vec<u8>,
}

fn new_identity() -> Identity {
    let pubkey = random32();
    let prompt_hash = blake3::hash(&pubkey).to_hex().to_string();
    let signing = blake3::hash(&[b"signing:".as_slice(), &pubkey].concat())
        .as_bytes()
        .to_vec();
    Identity {
        pubkey,
        prompt_hash,
        signing,
    }
}

fn blob_json(raw: &[u8]) -> Value {
    let compressed = zstd::bulk::compress(raw, 19).expect("zstd compress");
    json!({
        "blob_hash": blake3::hash(raw).to_hex().to_string(),
        "raw_size": raw.len(),
        "codec": "zstd",
        "content": hex::encode(compressed),
    })
}

fn snapshot(learned: &str) -> Value {
    json!({
        "identity_md": null,
        "global_claude_md": null,
        "group_claude_md": blob_json(b"group claude"),
        "learned_md": blob_json(learned.as_bytes()),
        "in_prompt": {
            "identity_md": false,
            "global_claude_md": false,
            "group_claude_md": true,
            "learned_md": true
        },
        "runner_version": "runner-test",
        "host_sha": "0000000"
    })
}

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct Registered {
    agent_id: Uuid,
    agent_created: bool,
    succession_created: bool,
    snapshot_id: Uuid,
    snapshot_created: bool,
    signing_key_registered: bool,
    operator_id: Option<Uuid>,
    inherited: bool,
    link_live: bool,
    inherit_reason: Option<String>,
}

/// Register `id` as the host does: on the attestor's connection.
async fn try_register(
    pool: &PgPool,
    id: &Identity,
    parent: Option<Uuid>,
    group: &str,
) -> Result<Registered, sqlx::Error> {
    let pubkey = id.pubkey.clone();
    let hash = id.prompt_hash.clone();
    let signing = id.signing.clone();
    let group = group.to_string();
    let snap = snapshot(&format!("learned {}", id.prompt_hash));
    fixture::as_role(pool, ATTESTOR, |mut conn| async move {
        let r = sqlx::query_as::<_, Registered>(
            "SELECT * FROM public.epigraph_register_agent_identity($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&pubkey)
        .bind(parent)
        .bind(MODEL)
        .bind(&hash)
        .bind(&group)
        .bind(&signing)
        .bind(&snap)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

/// A registered human operator (the shape 122 recognises).
async fn human_operator(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(random32())
        .execute(pool)
        .await
        .expect("seed operator agent");
    fixture::make_human_operator(pool, agent).await;
    agent
}

/// A fleet identity created the way epigraph-mcp's pre-161 path created it:
/// `AgentRepository::create` (no `agent_type`, so the column default
/// `'human'`; no `key_kind`, so `'ed25519'`) and then `set_llm_properties`.
async fn legacy_fleet_row(pool: &PgPool) -> Uuid {
    let agent = helpers::make_agent(Some("mcp-agent"));
    let created = AgentRepository::create(pool, &agent)
        .await
        .expect("create the legacy row");
    let id: Uuid = created.id.into();
    AgentRepository::set_llm_properties(pool, id, "old-model", "old-prompt-hash")
        .await
        .expect("record the legacy llm properties");
    let (agent_type, key_kind): (Option<String>, String) =
        sqlx::query_as("SELECT agent_type, key_kind FROM agents WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read the legacy row");
    assert_eq!(
        (agent_type.as_deref(), key_kind.as_str()),
        (Some("human"), "ed25519"),
        "CALIBRATION: the old create path leaves agent_type at its 'human' default"
    );
    id
}

/// The cut-over backfill, as the maintenance role runs it. Every agent that
/// exists at that moment (humans included) gets its `identity-legacy` key.
async fn backfill_legacy_keys(pool: &PgPool) -> i32 {
    fixture::as_role(pool, MAINTENANCE, |mut conn| async move {
        let n: i32 = sqlx::query_scalar("SELECT public.epigraph_backfill_legacy_agent_keys()")
            .fetch_one(&mut *conn)
            .await
            .expect("the maintenance role runs the backfill");
        (conn, n)
    })
    .await
}

async fn has_legacy_key(pool: &PgPool, agent: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM agent_keys k JOIN agents a ON a.id = k.agent_id \
                         WHERE k.agent_id = $1 AND k.key_type = 'identity-legacy' \
                           AND k.public_key = a.public_key)",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("legacy key")
}

/// A manual (maintenance) link, as `epigraph-operator link` makes it.
async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let out = fixture::as_role(pool, MAINTENANCE, |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("the maintenance role links the agent");
    assert!(out.link_live, "the manual link must be live");
}

async fn retire_link(pool: &PgPool, agent: Uuid) {
    sqlx::query("UPDATE operator_links SET retired = true WHERE agent_id = $1")
        .bind(agent)
        .execute(pool)
        .await
        .expect("retire the link");
}

/// Row counts of every table either path can touch, so "nothing changed" is
/// measured rather than inferred.
async fn footprint(pool: &PgPool) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for t in [
        "agents",
        "agent_succession",
        "agent_prompt_snapshots",
        "agent_prompt_blobs",
        "agent_keys",
        "operator_links",
        "group_memberships",
        "groups",
        "edges",
        "role_agents",
        "security_events",
    ] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{t}"))
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("count {t}: {e}"));
        out.push((t.to_string(), n));
    }
    let parents: Vec<(Uuid, Option<Uuid>)> =
        sqlx::query_as("SELECT id, parent_agent_id FROM agents ORDER BY id")
            .fetch_all(pool)
            .await
            .expect("display parents");
    out.push((format!("display parents {parents:?}"), parents.len() as i64));
    out
}

async fn human_of(pool: &PgPool, agent: Uuid, live_only: bool) -> Option<Uuid> {
    sqlx::query_scalar("SELECT public.epigraph_human_of($1, $2)")
        .bind(agent)
        .bind(live_only)
        .fetch_one(pool)
        .await
        .expect("human_of")
}

#[derive(Debug, sqlx::FromRow, PartialEq)]
struct Recorded {
    recorded: bool,
    snapshot_id: Uuid,
    /// NULL is possible on the repeat branch (it reports `human_of(child,
    /// false)`, which an unlinked child would answer NULL).
    operator_id: Option<Uuid>,
}

async fn try_record_as(
    pool: &PgPool,
    role: &str,
    child: Uuid,
    parent: Uuid,
    group: &str,
) -> Result<Recorded, sqlx::Error> {
    let group = group.to_string();
    fixture::as_role(pool, role, |mut conn| async move {
        let r = sqlx::query_as::<_, Recorded>(
            "SELECT * FROM public.epigraph_record_legacy_succession($1, $2, $3, $4)",
        )
        .bind(child)
        .bind(parent)
        .bind(&group)
        .bind("registered parentless after the AID03 legacy-parent refusal")
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

async fn try_record(
    pool: &PgPool,
    child: Uuid,
    parent: Uuid,
    group: &str,
) -> Result<Recorded, sqlx::Error> {
    try_record_as(pool, MAINTENANCE, child, parent, group).await
}

/// The incident's shape: an operator, a legacy fleet parent live-linked to
/// it, and a keyed successor the host registered with NO parent (the refusal
/// fallback) in `GROUP`, then linked to the operator by hand.
struct Incident {
    operator: Uuid,
    parent: Uuid,
    child: Uuid,
}

async fn incident(pool: &PgPool) -> Incident {
    let operator = human_operator(pool).await;
    let parent = legacy_fleet_row(pool).await;
    backfill_legacy_keys(pool).await;
    link(pool, parent, operator).await;
    let child = try_register(pool, &new_identity(), None, GROUP)
        .await
        .expect("the host registers the successor parentless");
    assert_eq!(child.inherit_reason.as_deref(), Some("no_parent"));
    link(pool, child.agent_id, operator).await;
    Incident {
        operator,
        parent,
        child: child.agent_id,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AID03, accept side
// ─────────────────────────────────────────────────────────────────────────────

/// The incident, reproduced: a legacy fleet parent (`agent_type 'human'` by
/// the old path's default, `llm_model` set, a backfilled legacy key) that is
/// live-linked to an operator is accepted. The successor records its
/// succession and display parent and inherits the operator's link, exactly as
/// a registered parent passes it on.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_human_typed_fleet_parent_with_a_legacy_key_is_accepted(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let parent = legacy_fleet_row(&pool).await;
    assert!(backfill_legacy_keys(&pool).await > 0);
    assert!(
        has_legacy_key(&pool, parent).await,
        "CALIBRATION: the backfill gave the legacy row its key"
    );
    link(&pool, parent, operator).await;

    let child = try_register(&pool, &new_identity(), Some(parent), GROUP)
        .await
        .expect("a legacy fleet parent is accepted (no AID03)");
    assert!(child.agent_created && child.succession_created);
    assert!(
        child.inherited && child.link_live,
        "the child inherits the legacy parent's live operator link: {child:?}"
    );
    assert_eq!(child.operator_id, Some(operator));
    let succ: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent_succession \
          WHERE child_agent_id = $1 AND parent_agent_id = $2 AND group_folder = $3",
    )
    .bind(child.agent_id)
    .bind(parent)
    .bind(GROUP)
    .fetch_one(&pool)
    .await
    .expect("succession");
    assert_eq!(succ, 1, "the succession is recorded");
    let display: Option<Uuid> =
        sqlx::query_scalar("SELECT parent_agent_id FROM agents WHERE id = $1")
            .bind(child.agent_id)
            .fetch_one(&pool)
            .await
            .expect("display parent");
    assert_eq!(display, Some(parent));
}

/// The old create path records `llm_model` best-effort only (a failed
/// `set_llm_properties` leaves the row without it), so the operator link is
/// the other LLM evidence: a legacy `'human'` row with a backfilled key and NO
/// `llm_model`, which an operator linked as one of its agents, is accepted and
/// passes the link on.
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_legacy_parent_without_llm_model_is_accepted(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let agent = helpers::make_agent(Some("mcp-agent"));
    let parent: Uuid = AgentRepository::create(&pool, &agent)
        .await
        .expect("create the legacy row")
        .id
        .into();
    backfill_legacy_keys(&pool).await;
    let has_model: bool =
        sqlx::query_scalar("SELECT properties ? 'llm_model' FROM agents WHERE id = $1")
            .bind(parent)
            .fetch_one(&pool)
            .await
            .expect("properties");
    assert!(!has_model, "CALIBRATION: no llm_model on this legacy row");
    assert!(has_legacy_key(&pool, parent).await, "CALIBRATION: keyed");

    // Unlinked, it has no LLM evidence at all: still refused.
    let err = try_register(&pool, &new_identity(), Some(parent), GROUP)
        .await
        .expect_err("an unlinked legacy row with no llm_model is not an LLM agent");
    assert_eq!(sqlstate(&err).as_deref(), Some("AID03"), "{err}");

    link(&pool, parent, operator).await;
    let child = try_register(&pool, &new_identity(), Some(parent), GROUP)
        .await
        .expect("a linked legacy row is accepted");
    assert!(
        child.succession_created && child.inherited && child.link_live,
        "{child:?}"
    );
    assert_eq!(child.operator_id, Some(operator));
}

/// The legacy arm repairs exactly the `'human'`-typed default. A `system` row
/// with a backfilled key and an operator link, but no `llm_model`, is refused
/// by 161's test as before (it is not an LLM agent), and 180 does not widen
/// that: its arm is scoped to `agent_type 'human'`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_keyed_non_human_typed_row_stays_on_161s_test(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let mut ids = Vec::new();
    for agent_type in ["system", "software_agent"] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(random32())
            .bind(agent_type)
            .execute(&pool)
            .await
            .expect("seed a non-human row");
        ids.push((id, agent_type));
    }
    backfill_legacy_keys(&pool).await;
    for (id, agent_type) in ids {
        assert!(has_legacy_key(&pool, id).await, "CALIBRATION: keyed");
        link(&pool, id, operator).await;
        let before = footprint(&pool).await;
        let err = try_register(&pool, &new_identity(), Some(id), GROUP)
            .await
            .expect_err(agent_type);
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some("AID03"),
            "{agent_type}: {err}"
        );
        assert_eq!(
            footprint(&pool).await,
            before,
            "{agent_type}: nothing changes"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AID03, refuse side: a REAL human is still refused
// ─────────────────────────────────────────────────────────────────────────────

/// Each case is the accepted legacy shape (`create` + `set_llm_properties`,
/// a backfilled legacy key) plus EXACTLY ONE human marker, so the marker is
/// what refuses it. Each refusal is AID03 and changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_real_human_with_the_legacy_shape_is_still_refused_aid03(pool: PgPool) {
    // A registered human operator (122's shape, on the legacy row).
    let operator = legacy_fleet_row(&pool).await;
    fixture::make_human_operator(&pool, operator).await;

    // A human operator whose registration was REVOKED: still a human.
    let revoked = legacy_fleet_row(&pool).await;
    fixture::make_human_operator(&pool, revoked).await;
    sqlx::query(
        "UPDATE human_operators SET revoked_at = now(), revoked_by = 'test', \
                revoked_reason = 'test' WHERE agent_id = $1",
    )
    .bind(revoked)
    .execute(&pool)
    .await
    .expect("revoke the human operator");

    // A revoked human operator whose recorded client no longer names it (its
    // `agent_id` re-pointed away out of band): only the `human_operators`
    // row still says it is a person, so that row alone must refuse it.
    let registry_only = legacy_fleet_row(&pool).await;
    fixture::make_human_operator(&pool, registry_only).await;
    sqlx::query(
        "UPDATE human_operators SET revoked_at = now(), revoked_by = 'test', \
                revoked_reason = 'test' WHERE agent_id = $1",
    )
    .bind(registry_only)
    .execute(&pool)
    .await
    .expect("revoke the human operator");
    sqlx::query("UPDATE oauth_clients SET agent_id = NULL WHERE agent_id = $1")
        .bind(registry_only)
        .execute(&pool)
        .await
        .expect("re-point its client");

    // A keyless human: the OAuth placeholder's `derived` key.
    let keyless = legacy_fleet_row(&pool).await;
    sqlx::query("UPDATE agents SET key_kind = 'derived' WHERE id = $1")
        .bind(keyless)
        .execute(&pool)
        .await
        .expect("make it keyless");

    // A keyless human the OAuth mint labelled, key kind left alone.
    let labelled = legacy_fleet_row(&pool).await;
    sqlx::query("UPDATE agents SET labels = array_append(labels, 'oauth-principal') WHERE id = $1")
        .bind(labelled)
        .execute(&pool)
        .await
        .expect("label it an OAuth principal");

    // A human with an OAuth human client of its own (pending, so it is NOT a
    // registered human operator).
    let oauth_human = legacy_fleet_row(&pool).await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, 'a person', 'human', ARRAY['claims:read'], 'pending', $2)",
    )
    .bind(format!("human-{oauth_human}"))
    .bind(oauth_human)
    .execute(&pool)
    .await
    .expect("human oauth client");

    // The legacy shape without `llm_model` (an ed25519 'human' row with no
    // other marker): the LLM evidence 161 already requires.
    let no_llm = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'a person')")
        .bind(no_llm)
        .bind(random32())
        .execute(&pool)
        .await
        .expect("seed a keyed human");

    backfill_legacy_keys(&pool).await;

    // Created AFTER the (last) backfill: no legacy key, so not a pre-cut-over
    // row.
    let unkeyed = legacy_fleet_row(&pool).await;
    assert!(!has_legacy_key(&pool, unkeyed).await, "CALIBRATION: no key");

    for (parent, what) in [
        (operator, "a registered human operator"),
        (revoked, "a revoked human operator"),
        (
            registry_only,
            "a revoked human operator whose client no longer names it",
        ),
        (keyless, "a keyless (derived) human"),
        (labelled, "an OAuth-principal-labelled human"),
        (oauth_human, "a human with an OAuth human client"),
        (unkeyed, "a 'human' row with no legacy key"),
        (no_llm, "a keyed 'human' row with no llm_model"),
    ] {
        if parent != unkeyed {
            assert!(
                has_legacy_key(&pool, parent).await,
                "CALIBRATION: {what} carries a legacy key, so the marker refuses it"
            );
        }
        let before = footprint(&pool).await;
        let err = try_register(&pool, &new_identity(), Some(parent), GROUP)
            .await
            .expect_err(what);
        assert_eq!(sqlstate(&err).as_deref(), Some("AID03"), "{what}: {err}");
        assert_eq!(
            footprint(&pool).await,
            before,
            "{what}: AID03 changes nothing"
        );
    }

    // POSITIVE CONTROL: the same shape with no marker is accepted (the
    // backfill now keys `unkeyed` too, which no longer matters: it was tested).
    let clean = legacy_fleet_row(&pool).await;
    backfill_legacy_keys(&pool).await;
    try_register(&pool, &new_identity(), Some(clean), GROUP)
        .await
        .expect("the unmarked legacy shape is accepted");
}

// ─────────────────────────────────────────────────────────────────────────────
// The after-the-fact succession record
// ─────────────────────────────────────────────────────────────────────────────

/// The incident repaired: the maintenance role records the succession the
/// refusal skipped. It writes the `agent_succession` row (with the child's
/// snapshot in that group), the display parent and one
/// `agent.identity_succession_recorded` audit row, and moves NO link (no
/// operator_links, membership or edge row). A repeat call records nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_maintenance_role_records_a_skipped_legacy_succession(pool: PgPool) {
    let inc = incident(&pool).await;
    let child_snapshot: Uuid = sqlx::query_scalar(
        "SELECT id FROM agent_prompt_snapshots WHERE agent_id = $1 AND group_folder = $2",
    )
    .bind(inc.child)
    .bind(GROUP)
    .fetch_one(&pool)
    .await
    .expect("the child's snapshot");
    let links_before: Vec<(Uuid, Uuid, bool)> = sqlx::query_as(
        "SELECT agent_id, operator_id, retired FROM operator_links ORDER BY agent_id",
    )
    .fetch_all(&pool)
    .await
    .expect("links");
    let before = footprint(&pool).await;

    let r = try_record(&pool, inc.child, inc.parent, GROUP)
        .await
        .expect("the maintenance role records the succession");
    assert_eq!(
        r,
        Recorded {
            recorded: true,
            snapshot_id: child_snapshot,
            operator_id: Some(inc.operator),
        }
    );

    let (attested_by,): (String,) = sqlx::query_as(
        "SELECT attested_by FROM agent_succession \
          WHERE child_agent_id = $1 AND parent_agent_id = $2 AND group_folder = $3 \
            AND snapshot_id = $4",
    )
    .bind(inc.child)
    .bind(inc.parent)
    .bind(GROUP)
    .bind(child_snapshot)
    .fetch_one(&pool)
    .await
    .expect("the succession row");
    assert_eq!(attested_by, MAINTENANCE);
    let display: Option<Uuid> =
        sqlx::query_scalar("SELECT parent_agent_id FROM agents WHERE id = $1")
            .bind(inc.child)
            .fetch_one(&pool)
            .await
            .expect("display parent");
    assert_eq!(display, Some(inc.parent));
    let audit: Vec<Value> = sqlx::query_scalar(
        "SELECT details FROM security_events \
          WHERE event_type = 'agent.identity_succession_recorded' AND agent_id = $1",
    )
    .bind(inc.child)
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(audit.len(), 1, "one audit row: {audit:?}");
    assert_eq!(audit[0]["parent_agent_id"], json!(inc.parent));
    assert_eq!(audit[0]["group_folder"], json!(GROUP));
    assert_eq!(audit[0]["operator_id"], json!(inc.operator));
    assert_eq!(audit[0]["session_user"], json!(MAINTENANCE));
    assert!(audit[0]["reason"].as_str().is_some_and(|s| !s.is_empty()));

    // Exactly three rows changed: one succession, one audit row, and the
    // display parent; nothing about links.
    let after = footprint(&pool).await;
    let changed: Vec<_> = before
        .iter()
        .zip(after.iter())
        .filter(|(b, a)| b != a)
        .map(|(b, a)| (b.0.clone(), b.1, a.1))
        .collect();
    let names: Vec<&str> = changed
        .iter()
        .map(|c| c.0.split(' ').next().unwrap_or(""))
        .collect();
    assert_eq!(
        names,
        vec!["agent_succession", "security_events", "display"],
        "only the succession, the audit row and the display parent change: {changed:?}"
    );
    let links_after: Vec<(Uuid, Uuid, bool)> = sqlx::query_as(
        "SELECT agent_id, operator_id, retired FROM operator_links ORDER BY agent_id",
    )
    .fetch_all(&pool)
    .await
    .expect("links");
    assert_eq!(links_after, links_before, "no link moves");

    // Idempotent: the same record again writes nothing.
    let again_before = footprint(&pool).await;
    let again = try_record(&pool, inc.child, inc.parent, GROUP)
        .await
        .expect("a repeat is not an error");
    assert!(!again.recorded, "a repeat records nothing: {again:?}");
    assert_eq!(
        footprint(&pool).await,
        again_before,
        "a repeat writes nothing"
    );
}

/// A parent whose link the operator has since RETIRED still names the same
/// operator (122's `human_of(.., false)`), so the record is still accepted:
/// the legacy links are scheduled for retirement.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_legacy_parent_link_still_names_the_operator(pool: PgPool) {
    let inc = incident(&pool).await;
    retire_link(&pool, inc.parent).await;
    assert_eq!(human_of(&pool, inc.parent, true).await, None);
    let r = try_record(&pool, inc.child, inc.parent, GROUP)
        .await
        .expect("a retired parent link still names the operator");
    assert!(r.recorded);
}

/// Only the maintenance role may record: the application role and the
/// attestor are refused EXECUTE (42501) and nothing changes.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_maintenance_role_records_a_succession(pool: PgPool) {
    let inc = incident(&pool).await;
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    for role in ["epigraph_app", ATTESTOR] {
        let before = footprint(&pool).await;
        let err = try_record_as(&pool, role, inc.child, inc.parent, GROUP)
            .await
            .expect_err(role);
        assert_eq!(sqlstate(&err).as_deref(), Some("42501"), "{role}: {err}");
        assert_eq!(footprint(&pool).await, before, "{role}: nothing changes");
    }
    // POSITIVE CONTROL.
    try_record(&pool, inc.child, inc.parent, GROUP)
        .await
        .expect("the maintenance role records it");
}

/// Every case outside the rule is refused AID10 and changes nothing. Each case
/// is the incident with exactly ONE thing changed (every alternative parent
/// is keyed, linked to the same operator and created before the child unless
/// that is the thing changed); the incident itself is the positive control,
/// recorded at the end.
#[sqlx::test(migrations = "../../migrations")]
async fn the_record_refuses_everything_outside_its_rule_aid10(pool: PgPool) {
    let operator = human_operator(&pool).await;
    let other_op = human_operator(&pool).await;
    seed_role(&pool, "role:test-180").await;

    // Parents, all created before any child and all keyed by ONE backfill.
    // A legacy row that is ALSO a registered human operator: the marker is the
    // only difference from `parent`.
    let human_parent = legacy_fleet_row(&pool).await;
    fixture::make_human_operator(&pool, human_parent).await;
    let parent = legacy_fleet_row(&pool).await;
    let alt_parent = legacy_fleet_row(&pool).await;
    let second_parent = legacy_fleet_row(&pool).await;
    let foreign_parent = legacy_fleet_row(&pool).await;
    let late_parent = legacy_fleet_row(&pool).await;
    // A legacy-shaped parent holding a live role attachment. A 'human' agent
    // cannot be attached (ROL02), so attach it as a software agent and then
    // give it the legacy type back, as an out-of-band edit would.
    let attached_parent = legacy_fleet_row(&pool).await;
    sqlx::query("UPDATE agents SET agent_type = 'software_agent' WHERE id = $1")
        .bind(attached_parent)
        .execute(&pool)
        .await
        .expect("retype");
    fixture::as_role(&pool, MAINTENANCE, |mut conn| async move {
        let r: Result<Uuid, _> = sqlx::query_scalar(
            "SELECT public.epigraph_attach_agent_to_role('role:test-180', $1, now(), NULL, \
                                                         'test attach')",
        )
        .bind(attached_parent)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
    .expect("attach");
    sqlx::query("UPDATE agents SET agent_type = 'human' WHERE id = $1")
        .bind(attached_parent)
        .execute(&pool)
        .await
        .expect("retype back");
    // A child the host never registered (no snapshot): a legacy row.
    let unregistered_child = legacy_fleet_row(&pool).await;
    backfill_legacy_keys(&pool).await;
    // A parent with NO legacy key: created after the backfill, then dated
    // before the children so that is the only thing wrong with it.
    let unkeyed_parent = legacy_fleet_row(&pool).await;
    sqlx::query("UPDATE agents SET created_at = created_at - interval '1 day' WHERE id = $1")
        .bind(unkeyed_parent)
        .execute(&pool)
        .await
        .expect("date it earlier");
    assert!(!has_legacy_key(&pool, unkeyed_parent).await, "CALIBRATION");
    for p in [
        parent,
        alt_parent,
        second_parent,
        late_parent,
        attached_parent,
        unkeyed_parent,
        unregistered_child,
    ] {
        link(&pool, p, operator).await;
    }
    link(&pool, foreign_parent, other_op).await;

    // The children, registered by the host with no parent, then linked.
    let child = try_register(&pool, &new_identity(), None, GROUP)
        .await
        .expect("parentless registration")
        .agent_id;
    link(&pool, child, operator).await;
    let unlinked_child = try_register(&pool, &new_identity(), None, GROUP)
        .await
        .expect("parentless registration")
        .agent_id;
    // A child registered WITH a parent already (it inherits the link).
    let parented_child = try_register(&pool, &new_identity(), Some(parent), GROUP)
        .await
        .expect("registered with the legacy parent");
    assert!(parented_child.succession_created && parented_child.link_live);

    // The late parent is dated after every child.
    sqlx::query("UPDATE agents SET created_at = now() + interval '1 hour' WHERE id = $1")
        .bind(late_parent)
        .execute(&pool)
        .await
        .expect("date the parent after the child");

    assert!(
        has_legacy_key(&pool, human_parent).await,
        "CALIBRATION: the human-operator parent carries a legacy key, so the marker refuses it"
    );
    let missing = Uuid::new_v4();
    // (child, parent, group, what, the refusal's distinguishing text)
    let cases: Vec<(Uuid, Uuid, &str, &str, &str)> = vec![
        (
            child,
            human_parent,
            GROUP,
            "a parent that is a registered human operator",
            "is not a legacy fleet parent",
        ),
        (
            child,
            operator,
            GROUP,
            "a parent that is the operator itself",
            "is not a legacy fleet parent",
        ),
        (
            child,
            unkeyed_parent,
            GROUP,
            "a parent with no legacy key",
            "is not a legacy fleet parent",
        ),
        (
            child,
            foreign_parent,
            GROUP,
            "a parent of another operator",
            "is linked to operator",
        ),
        (
            child,
            parent,
            "g-elsewhere",
            "a group the child never ran in",
            "was never registered in group",
        ),
        (
            unlinked_child,
            parent,
            GROUP,
            "an unlinked child",
            "has no live operator link",
        ),
        (
            parented_child.agent_id,
            alt_parent,
            GROUP,
            "a child that already has a recorded parent",
            "already has a recorded parent",
        ),
        (
            unregistered_child,
            parent,
            GROUP,
            "a child the host never registered",
            "was never registered in group",
        ),
        (
            child,
            late_parent,
            GROUP,
            "a parent created after the child",
            "was created after",
        ),
        (
            child,
            attached_parent,
            GROUP,
            "a parent with a live role attachment",
            "holds a role attachment",
        ),
        (
            child,
            child,
            GROUP,
            "a parent equal to the child",
            "is its own parent",
        ),
        (
            child,
            missing,
            GROUP,
            "a parent that does not exist",
            "does not exist",
        ),
    ];
    for (c, p, group, what, text) in cases {
        let before = footprint(&pool).await;
        let err = try_record(&pool, c, p, group).await.expect_err(what);
        assert_eq!(sqlstate(&err).as_deref(), Some("AID10"), "{what}: {err}");
        assert!(
            err.to_string().contains(text),
            "{what}: the refusal must say {text:?}: {err}"
        );
        assert_eq!(footprint(&pool).await, before, "{what}: nothing changes");
    }

    // POSITIVE CONTROL: the incident itself is recorded. A second parent for
    // the same child is then refused (the first record stands).
    try_record(&pool, child, parent, GROUP)
        .await
        .expect("the incident is recorded");
    let before = footprint(&pool).await;
    let err = try_record(&pool, child, second_parent, GROUP)
        .await
        .expect_err("a second parent");
    assert_eq!(sqlstate(&err).as_deref(), Some("AID10"), "{err}");
    assert!(
        err.to_string().contains("already has a recorded parent"),
        "{err}"
    );
    assert_eq!(footprint(&pool).await, before);
}

/// A SHARED identity: one identity serves every group with the same model and
/// files, so the host may register the same child parentless in two group
/// folders, each time against the same legacy parent. One succession row per
/// (child, parent) is enough: the record in the first folder writes it, the
/// call for the second folder is a repeat (`recorded = false`, nothing
/// written), and a DIFFERENT parent named for the second folder is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_shared_child_gets_one_succession_row_per_parent(pool: PgPool) {
    let inc = incident(&pool).await;
    let other_parent = legacy_fleet_row(&pool).await;
    backfill_legacy_keys(&pool).await;
    link(&pool, other_parent, inc.operator).await;
    sqlx::query("UPDATE agents SET created_at = created_at - interval '1 day' WHERE id = $1")
        .bind(other_parent)
        .execute(&pool)
        .await
        .expect("date it before the child");

    // The same identity registered again, parentless, in a second folder.
    let pubkey: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
        .bind(inc.child)
        .fetch_one(&pool)
        .await
        .expect("child key");
    let (hash, signing): (String, Vec<u8>) = sqlx::query_as(
        "SELECT s.prompt_hash, k.public_key FROM agent_prompt_snapshots s \
           JOIN agent_keys k ON k.agent_id = s.agent_id AND k.key_type = 'signing' \
          WHERE s.agent_id = $1 LIMIT 1",
    )
    .bind(inc.child)
    .fetch_one(&pool)
    .await
    .expect("child registration inputs");
    let shared = Identity {
        pubkey,
        prompt_hash: hash,
        signing,
    };
    let second = try_register(&pool, &shared, None, "g-chat")
        .await
        .expect("the shared identity registers in a second folder");
    assert_eq!(second.agent_id, inc.child, "CALIBRATION: the same identity");
    assert!(
        second.snapshot_created,
        "CALIBRATION: a snapshot in the second folder"
    );

    let first = try_record(&pool, inc.child, inc.parent, GROUP)
        .await
        .expect("the record in the first folder");
    assert!(first.recorded);

    let before = footprint(&pool).await;
    let again = try_record(&pool, inc.child, inc.parent, "g-chat")
        .await
        .expect("the same parent for the second folder is a repeat, not an error");
    assert_eq!(
        again,
        Recorded {
            recorded: false,
            snapshot_id: first.snapshot_id,
            operator_id: Some(inc.operator),
        }
    );
    assert_eq!(footprint(&pool).await, before, "a repeat writes nothing");

    let err = try_record(&pool, inc.child, other_parent, "g-chat")
        .await
        .expect_err("a conflicting parent for the second folder");
    assert_eq!(sqlstate(&err).as_deref(), Some("AID10"), "{err}");
    assert!(
        err.to_string().contains("already has a recorded parent"),
        "{err}"
    );
    assert_eq!(footprint(&pool).await, before, "a refusal writes nothing");

    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM agent_succession WHERE child_agent_id = $1")
            .bind(inc.child)
            .fetch_one(&pool)
            .await
            .expect("succession rows");
    assert_eq!(rows, 1, "one succession row for the shared child");
}

async fn seed_role(pool: &PgPool, key: &str) {
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, role, labels) \
         VALUES ($1, $2, $3, 'role', 'custom', ARRAY['role'])",
    )
    .bind(node)
    .bind(random32())
    .bind(key)
    .execute(pool)
    .await
    .expect("role node");
    sqlx::query(
        "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
         VALUES ($1, false, false, $2, 'test role')",
    )
    .bind(key)
    .bind(node)
    .execute(pool)
    .await
    .expect("platform role");
}

// ─────────────────────────────────────────────────────────────────────────────
// The re-statement guard and the undo
// ─────────────────────────────────────────────────────────────────────────────

fn up_to_below(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < version)
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
    let r = migrator.run(&mut *conn).await.map_err(|e| format!("{e:?}"));
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    r
}

const REGISTER_SIG: &str =
    "public.epigraph_register_agent_identity(bytea, uuid, text, text, text, bytea, jsonb)";

async fn register_src(pool: &PgPool) -> String {
    sqlx::query_scalar(&format!(
        "SELECT p.prosrc FROM pg_proc p WHERE p.oid = to_regprocedure('{REGISTER_SIG}')"
    ))
    .fetch_one(pool)
    .await
    .expect("the registration exists")
}

/// Re-body the registration with `src` (signature, owner and ACL unchanged:
/// CREATE OR REPLACE keeps them).
async fn set_register_src(pool: &PgPool, src: &str) {
    assert!(!src.contains("$body$"));
    let sig_args = "p_identity_pubkey bytea, p_parent_agent uuid, p_model text, \
                    p_prompt_hash text, p_group_folder text, p_signing_pubkey bytea, \
                    p_snapshot jsonb";
    sqlx::raw_sql(&format!(
        "CREATE OR REPLACE FUNCTION public.epigraph_register_agent_identity({sig_args}) \
         RETURNS TABLE (agent_id uuid, agent_created boolean, succession_created boolean, \
                        snapshot_id uuid, snapshot_created boolean, \
                        signing_key_registered boolean, operator_id uuid, \
                        inherited boolean, link_live boolean, inherit_reason text) \
         LANGUAGE plpgsql VOLATILE SECURITY DEFINER \
         SET search_path = public, pg_temp AS $body${src}$body$"
    ))
    .execute(pool)
    .await
    .expect("re-body the registration");
}

/// 180 re-states 166's registration whole, so it first checks the body it
/// replaces. Over any other body (here 166's plus one comment line, standing
/// in for a re-statement applied out of order) it refuses 55000, names the
/// function and applies nothing. POSITIVE CONTROL: with 166's exact body
/// back, it applies.
#[sqlx::test(migrations = false)]
async fn migration_180_refuses_to_restate_a_body_it_was_not_written_from(pool: PgPool) {
    migrate(&pool, &up_to_below(180))
        .await
        .expect("migrate below 180");
    let original = register_src(&pool).await;
    assert!(
        original.contains("-- 5b (166)"),
        "CALIBRATION: below 180 the registration is 166's"
    );
    set_register_src(
        &pool,
        &format!("{original}-- an out-of-order re-statement\n"),
    )
    .await;
    let err = migrate(&pool, &up_to_below(181))
        .await
        .expect_err("180 refuses a body it was not written from");
    assert!(
        err.contains("55000") && err.contains("epigraph_register_agent_identity"),
        "the refusal names the function: {err}"
    );
    let has_record: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('public.epigraph_record_legacy_succession(uuid, uuid, text, text)') \
                IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert!(!has_record, "a refused 180 applies nothing");

    set_register_src(&pool, &original).await;
    migrate(&pool, &up_to_below(181))
        .await
        .expect("over 166's exact body, 180 applies");
}

async fn catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for sql in [
        "SELECT 'function ' || p.oid::regprocedure::text || ' owner ' \
                || p.proowner::regrole::text || ' acl ' || COALESCE(p.proacl::text, '-') \
                || E'\\n' || pg_get_functiondef(p.oid) \
           FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
          WHERE n.nspname = 'public' AND p.prokind IN ('f', 'p')",
        "SELECT 'trigger ' || pg_get_triggerdef(t.oid) || ' enabled ' || t.tgenabled::text \
           FROM pg_trigger t WHERE NOT t.tgisinternal",
        "SELECT 'relation ' || c.relname || ' kind ' || c.relkind::text || ' acl ' \
                || COALESCE(c.relacl::text, '-') \
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'S')",
        "SELECT 'index ' || indexdef FROM pg_indexes WHERE schemaname = 'public'",
        "SELECT 'policy ' || tablename || '.' || policyname || ' ' || cmd || ' ' \
                || roles::text || ' ' || COALESCE(qual, '-') || ' ' || COALESCE(with_check, '-') \
           FROM pg_policies WHERE schemaname = 'public'",
    ] {
        let rows: Vec<String> = sqlx::query_scalar(sql)
            .fetch_all(pool)
            .await
            .unwrap_or_else(|e| panic!("catalog read failed: {e}\n{sql}"));
        out.extend(rows);
    }
    out
}

/// `docs/runbooks/180-undo.sql`, applied twice to a database migrated through
/// 180, returns the catalog to exactly what it was below 180 (166's
/// registration body, owner and ACL; no 180 function left). After the undo the
/// legacy parent is refused again (166's AID03), which proves the body that
/// came back is the one that runs.
#[sqlx::test(migrations = false)]
async fn the_180_undo_restores_the_catalog_below_180(pool: PgPool) {
    migrate(&pool, &up_to_below(180)).await.expect("below 180");
    let before = catalog(&pool).await;
    migrate(&pool, &up_to_below(181))
        .await
        .expect("through 180");
    assert_ne!(
        catalog(&pool).await,
        before,
        "CALIBRATION: 180 changed the catalog"
    );

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/180-undo.sql"),
    )
    .expect("180-undo.sql");

    // Over a body a LATER migration re-stated (here 180's plus one comment
    // line), the undo refuses 55000 and changes nothing: restoring 166's body
    // would silently drop that migration's delta.
    let through_180 = catalog(&pool).await;
    let body_180 = register_src(&pool).await;
    set_register_src(&pool, &format!("{body_180}-- a later re-statement\n")).await;
    let refused = {
        let mut conn = pool.acquire().await.expect("acquire");
        let r = sqlx::raw_sql(&undo).execute(&mut *conn).await;
        // The undo's own BEGIN is left aborted on this connection.
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut *conn)
            .await
            .expect("ROLLBACK");
        r.expect_err("the undo refuses a body it does not know")
    };
    assert!(
        refused.to_string().contains("180-undo"),
        "the refusal names the undo: {refused}"
    );
    assert!(
        register_src(&pool)
            .await
            .ends_with("-- a later re-statement\n"),
        "a refused undo changes nothing"
    );
    set_register_src(&pool, &body_180).await;
    assert_eq!(
        catalog(&pool).await,
        through_180,
        "CALIBRATION: back to 180's catalog"
    );

    for run in 1..=2 {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the undo applies (run {run}): {e}"));
    }
    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&before).collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the undo does not restore the catalog below 180.\nleft: {left:#?}\nlost: {lost:#?}"
    );

    let parent = legacy_fleet_row(&pool).await;
    backfill_legacy_keys(&pool).await;
    let err = try_register(&pool, &new_identity(), Some(parent), GROUP)
        .await
        .expect_err("after the undo the legacy parent is refused again");
    assert_eq!(sqlstate(&err).as_deref(), Some("AID03"), "{err}");
}
