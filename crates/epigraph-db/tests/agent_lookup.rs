//! `AgentLookupRepository` (find_agent / get_agent) and migration 198.
//!
//! # What is under test
//!
//! * Matching: case-insensitive, accent-folded on BOTH sides, ranked
//!   ORCID/ROR > exact > prefix > trigram; filters apply before the limit.
//! * Privacy, measured DIFFERENTIALLY: for each fact a caller may not see (an
//!   operator link, human-operator registration, a group-private claim or
//!   paper edge, a private-profile ORCID or LLM model, an elevating role), two
//!   agents identical but for that fact produce byte-identical cards for an
//!   outsider apart from id, name and timestamps, while a caller entitled to
//!   the fact sees it. A leak in ANY field (kind, kind_evidence, counts,
//!   roles, the match tier) fails the comparison, not just the field a test
//!   happened to target.
//! * Migration 198's catalog: SECURITY DEFINER, owner, search path, grants,
//!   the 200-id cap.
//!
//! # Why the reads run as `epigraph_app`
//!
//! `#[sqlx::test]` connects as a superuser, and a superuser session is
//! privileged (`epigraph_bypass()` reads `session_user`), which every gate
//! here admits. So every read is made on an `epigraph_app` `ScopedPool`
//! connection stamped from the caller's resolved viewer, exactly as
//! `read_as` serves a request. Fixture rows are seeded on the superuser pool.
//!
//! All names are invented.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::pool::{ScopedPool, SessionGucMode};
use epigraph_db::visibility::{SystemReason, Viewer};
use epigraph_db::{AgentCard, AgentKind, AgentLookupRepository, FindAgentQuery, MatchTier};
use sqlx::PgPool;
use uuid::Uuid;

async fn app_pool(pool: &PgPool) -> ScopedPool {
    ScopedPool::connect_downgraded_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool")
}

async fn viewer(pool: &PgPool, who: Uuid) -> Viewer {
    Viewer::resolve(pool, who).await.expect("resolve viewer")
}

/// An agent with a personal group and a display name.
async fn named(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (a, g) = fixture::seed_agent_with_group(pool, name).await;
    sqlx::query("UPDATE agents SET display_name = $2 WHERE id = $1")
        .bind(a)
        .bind(name)
        .execute(pool)
        .await
        .expect("name");
    (a, g)
}

/// A registered human operator with a display name.
async fn named_human(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (a, g) = named(pool, name).await;
    fixture::make_human_operator(pool, a).await;
    (a, g)
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
    assert!(out.link_live, "fixture link must be live");
}

async fn cards_as(pool: &PgPool, who: Uuid, ids: &[Uuid]) -> Vec<AgentCard> {
    let scoped = app_pool(pool).await;
    let v = viewer(pool, who).await;
    let mut read = scoped.read_as(&v).await.expect("read_as");
    let who_am_i: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *read)
        .await
        .expect("session_user");
    assert_eq!(
        who_am_i, "epigraph_app",
        "CALIBRATION: reads run as the app role"
    );
    AgentLookupRepository::cards(&mut read, &v, ids)
        .await
        .expect("cards")
}

async fn card_as(pool: &PgPool, who: Uuid, id: Uuid) -> AgentCard {
    cards_as(pool, who, &[id])
        .await
        .into_iter()
        .next()
        .expect("card for an existing agent")
}

async fn find_as(
    pool: &PgPool,
    who: Uuid,
    name: &str,
    kind: Option<&str>,
    role: Option<&str>,
    limit: Option<i64>,
) -> epigraph_db::FindAgentResult {
    let scoped = app_pool(pool).await;
    let v = viewer(pool, who).await;
    let mut read = scoped.read_as(&v).await.expect("read_as");
    let q = FindAgentQuery::new(name, kind, role, limit).expect("valid query");
    AgentLookupRepository::find(&mut read, &v, &q)
        .await
        .expect("find")
}

/// A card's JSON with the fields that legitimately differ between two
/// fixture agents (identity, name, timestamps) removed.
fn shape(card: &AgentCard) -> serde_json::Value {
    let mut v = serde_json::to_value(card).expect("serialize card");
    let o = v.as_object_mut().expect("object");
    o.remove("id");
    o.remove("display_name");
    o.remove("created_at");
    v
}

fn ids(r: &epigraph_db::FindAgentResult) -> Vec<Uuid> {
    r.results.iter().map(|h| h.card.id).collect()
}

/// A team group with live `writer` members.
async fn team_of(pool: &PgPool, members: &[Uuid]) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, did_key, public_key, kind, display_name) \
         VALUES ($1, $2, $3, 'team', 'lookup-test team')",
    )
    .bind(id)
    .bind(format!("did:key:lookup-team-{id}"))
    .bind(&pk)
    .execute(pool)
    .await
    .expect("team group");
    for m in members {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, $3, 0, 'writer')",
        )
        .bind(id)
        .bind(m)
        .bind(vec![0u8; 48])
        .execute(pool)
        .await
        .expect("team membership");
    }
    id
}

/// A synthetic catalog role with its role node (123 requires one per role).
async fn seed_role(pool: &PgPool, key: &str, elevates: bool) {
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, role, labels) \
         VALUES ($1, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), $2, 'role', \
                 'custom', ARRAY['role'])",
    )
    .bind(node)
    .bind(key)
    .execute(pool)
    .await
    .expect("role node");
    sqlx::query(
        "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
         VALUES ($1, $2, false, $3, 'test role')",
    )
    .bind(key)
    .bind(elevates)
    .bind(node)
    .execute(pool)
    .await
    .expect("platform role");
}

/// `agent`'s (first) human OAuth client.
async fn human_client_of(pool: &PgPool, agent: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human' \
          ORDER BY created_at LIMIT 1",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the human's client")
}

async fn set_client_status(pool: &PgPool, client: Uuid, status: &str) {
    sqlx::query("UPDATE oauth_clients SET status = $2 WHERE id = $1")
        .bind(client)
        .bind(status)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("client status -> {status}: {e}"));
}

/// Revoke `human`'s registration through the real maintenance definer.
async fn revoke_registration(pool: &PgPool, human: Uuid) {
    let revoked: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT revoked_now FROM public.epigraph_revoke_human_operator($1, 'test revoke')",
        )
        .bind(human)
        .fetch_one(&mut *conn)
        .await
        .expect("revoke registration");
        (conn, r)
    })
    .await;
    assert!(revoked, "CALIBRATION: the registration was live");
}

/// A fresh named agent bound to `operator` by a migration-149 client
/// allowance (a service client on the maintenance-only registry). Returns
/// `(agent, client)`.
async fn allowance_bound(pool: &PgPool, operator: Uuid, name: &str) -> (Uuid, Uuid) {
    let (agent, _) = named(pool, name).await;
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'lookup allowance fixture', 'service', ARRAY['claims:write'], \
                 'active', $2, 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("lookup-allowance-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("service client");
    let allowed: bool = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT allowed_now FROM public.epigraph_allow_author_binding_client($1, $2, $3)",
        )
        .bind(client)
        .bind(operator)
        .bind("lookup test")
        .fetch_one(&mut *conn)
        .await
        .expect("allow the client for the operator");
        (conn, r)
    })
    .await;
    assert!(allowed, "CALIBRATION: the allowance is in force");
    (agent, client)
}

/// `epigraph_human_of(agent, false)`, read on the harness connection.
async fn human_of(pool: &PgPool, agent: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT public.epigraph_human_of($1, false)")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("epigraph_human_of")
}

/// Whole card JSON, nothing stripped: for before/after comparisons of the
/// SAME agents.
fn whole(cards: &[AgentCard]) -> serde_json::Value {
    serde_json::to_value(cards).expect("serialize cards")
}

async fn grant(pool: &PgPool, role: &str, holder: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now() - interval '5 seconds', NULL, NULL, \
                'test grant')",
    )
    .bind(role)
    .bind(holder)
    .fetch_one(pool)
    .await
    .expect("grant role")
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn names_fold_case_and_accents_on_both_sides(pool: PgPool) {
    let (asker, _) = named(&pool, "asker").await;
    let (jose, _) = named(&pool, "José Núñez-Strauß").await;
    let (lukasz, _) = named(&pool, "ŁUKASZ Øberg").await;
    let (plain, _) = named(&pool, "Ines Avila").await;

    for (q, want) in [
        ("jose nunez-strauss", jose),
        ("JOSÉ NÚÑEZ-STRAUSS", jose),
        ("  José   Núñez-Strauß ", jose),
        ("lukasz oberg", lukasz),
        ("Łukasz Øberg", lukasz),
        ("Inés Ávila", plain),
    ] {
        let r = find_as(&pool, asker, q, None, None, None).await;
        let top = r
            .results
            .first()
            .unwrap_or_else(|| panic!("{q:?} found nothing"));
        assert_eq!(top.card.id, want, "{q:?}");
        assert_eq!(top.tier, MatchTier::Exact, "{q:?} is a folded exact match");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn ranking_is_exact_then_prefix_then_trigram_and_unrelated_names_never_match(pool: PgPool) {
    let (asker, _) = named(&pool, "asker").await;
    let (trigram, _) = named(&pool, "Wren Hallowey").await;
    let (word_prefix, _) = named(&pool, "Dr Wren Halloway-Oakes").await;
    let (prefix, _) = named(&pool, "Wren Halloway-Oakes").await;
    let (exact, _) = named(&pool, "Wren Halloway").await;
    let (unrelated, _) = named(&pool, "Marguerite Quist").await;

    let r = find_as(&pool, asker, "wren halloway", None, None, Some(25)).await;
    let got = ids(&r);
    assert_eq!(got.first(), Some(&exact), "exact first: {got:?}");
    let pos = |id| got.iter().position(|g| *g == id).expect("present");
    assert!(
        pos(prefix) < pos(trigram) && pos(word_prefix) < pos(trigram),
        "{got:?}"
    );
    assert_eq!(r.results[pos(prefix)].tier, MatchTier::Prefix);
    assert_eq!(r.results[pos(word_prefix)].tier, MatchTier::Prefix);
    assert_eq!(r.results[pos(trigram)].tier, MatchTier::Trigram);
    assert!(!got.contains(&unrelated), "an unrelated name never matches");
    assert!(!r.candidates_truncated);

    // A LIKE metacharacter in the query is a literal, not a wildcard.
    let r = find_as(&pool, asker, "w%n", None, None, None).await;
    assert!(
        ids(&r).is_empty(),
        "'%' must not act as a wildcard: {:?}",
        ids(&r)
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn filters_apply_before_the_limit(pool: PgPool) {
    let (asker, _) = named(&pool, "asker").await;
    // 30 look-alikes with no evidence, created first so they rank first.
    for _ in 0..30 {
        named(&pool, "relay-agent").await;
    }
    let (llm, _) = named(&pool, "relay-agent").await;
    sqlx::query(
        "UPDATE agents SET properties = properties || '{\"llm_model\": \"model-x\"}' WHERE id = $1",
    )
    .bind(llm)
    .execute(&pool)
    .await
    .expect("llm model");

    let r = find_as(&pool, asker, "relay-agent", None, None, Some(5)).await;
    assert_eq!(r.results.len(), 5);
    assert!(
        !ids(&r).contains(&llm),
        "CALIBRATION: unfiltered, the 30 older rank first"
    );

    let r = find_as(
        &pool,
        asker,
        "relay-agent",
        Some("llm_agent"),
        None,
        Some(5),
    )
    .await;
    assert_eq!(
        ids(&r),
        vec![llm],
        "kind filter reaches past the first 5 matches"
    );
    assert_eq!(r.results[0].card.kind, AgentKind::LlmAgent);
}

#[sqlx::test(migrations = "../../migrations")]
async fn more_than_the_candidate_pool_reports_truncation(pool: PgPool) {
    let (asker, _) = named(&pool, "asker").await;
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name) \
         SELECT gen_random_uuid(), uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), \
                'swarm-node' FROM generate_series(1, 201)",
    )
    .execute(&pool)
    .await
    .expect("201 look-alikes");
    let r = find_as(&pool, asker, "swarm-node", None, None, Some(25)).await;
    assert_eq!(r.results.len(), 25);
    assert!(r.candidates_truncated, "201 > 200 matches");
}

// ---------------------------------------------------------------------------
// Kind from evidence
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn kind_is_derived_from_evidence_not_agent_type(pool: PgPool) {
    let (asker, _) = named(&pool, "asker").await;
    // Legacy row: agent_type 'human', no evidence at all.
    let (legacy, _) = named(&pool, "Legacy Person").await;
    sqlx::query("UPDATE agents SET agent_type = 'human' WHERE id = $1")
        .bind(legacy)
        .execute(&pool)
        .await
        .expect("legacy type");
    // The document ingest's author node: the deterministic name-derived key.
    let (_, key) = epigraph_crypto::did_key::did_key_for_author(None, "Corin Vale");
    let author = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'Corin Vale')")
        .bind(author)
        .bind(key.as_slice())
        .execute(&pool)
        .await
        .expect("ingest author");
    // A system identity.
    let (system, _) = named(&pool, "pipeline-runner").await;
    assert!(fixture::register_system_agent(&pool, system).await);
    // A role node.
    seed_role(&pool, "role:test-stewards", false).await;
    let role_node: Uuid = sqlx::query_scalar(
        "SELECT role_node_id FROM platform_roles WHERE key = 'role:test-stewards'",
    )
    .fetch_one(&pool)
    .await
    .expect("node");

    let cards = cards_as(&pool, asker, &[legacy, author, system, role_node]).await;
    let kinds: Vec<AgentKind> = cards.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        vec![
            AgentKind::Unknown,
            AgentKind::IngestAuthor,
            AgentKind::System,
            AgentKind::Role
        ]
    );
    assert_eq!(cards[1].kind_evidence, vec!["name_derived_key"]);
}

// ---------------------------------------------------------------------------
// Privacy: differential pairs
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_human_is_shown_to_every_reader(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (human, _) = named_human(&pool, "Talia Brennick").await;
    let (linked, _) = named(&pool, "helper-bot").await;
    let (unlinked, _) = named(&pool, "helper-bot").await;
    link(&pool, linked, human).await;
    assert_eq!(
        human_of(&pool, linked).await,
        Some(human),
        "CALIBRATION: the card names the binding epigraph_human_of names"
    );

    // Every reader: an outsider, the agent itself, the human.
    for who in [outsider, linked, human] {
        let c = card_as(&pool, who, linked).await;
        let h = c.operator_human.as_ref().expect("operator_human shown");
        assert_eq!(h.id, human);
        assert_eq!(h.display_name.as_deref(), Some("Talia Brennick"));
        assert_eq!(c.kind, AgentKind::LlmAgent);
        assert!(c.kind_evidence.contains(&"bound_to_visible_human"));
    }
    // An unbound look-alike shows none; a human is never its own operator.
    assert!(card_as(&pool, outsider, unlinked)
        .await
        .operator_human
        .is_none());
    assert!(card_as(&pool, outsider, human)
        .await
        .operator_human
        .is_none());

    // find_agent: the same field through the search path.
    let r = find_as(&pool, outsider, "helper-bot", None, None, None).await;
    let hit = r
        .results
        .iter()
        .find(|h| h.card.id == linked)
        .expect("listed");
    assert_eq!(hit.card.operator_human.as_ref().map(|h| h.id), Some(human));
}

/// The operator human is read from the binding RECORD, so no client or
/// registration event moves it: an outsider's whole card for each agent is
/// byte-identical before and after every event, while each event is shown
/// (CALIBRATION) to move `epigraph_human_of`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_human_does_not_move_with_client_or_registration_status(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (h1, _) = named_human(&pool, "Ren Okafor").await;
    let (linked, _) = named(&pool, "relay-bot").await;
    link(&pool, linked, h1).await;
    let (h2, _) = named_human(&pool, "Ilse Marrow").await;
    let (allowed, allowed_client) = allowance_bound(&pool, h2, "scribe-service").await;
    // A registered human that is also linked as an agent (123 calls it an
    // operated agent): link first, then register.
    let (o3, _) = named_human(&pool, "Bram Tolliver").await;
    let (dual, _) = named(&pool, "dual-principal").await;
    link(&pool, dual, o3).await;
    fixture::make_human_operator(&pool, dual).await;

    // Where both agree, the card equals epigraph_human_of.
    assert_eq!(human_of(&pool, linked).await, Some(h1));
    assert_eq!(human_of(&pool, allowed).await, Some(h2));

    let ids = [linked, allowed, dual, h1, h2, o3];
    let before = whole(&cards_as(&pool, outsider, &ids).await);
    let shown = |v: &serde_json::Value, i: usize| v[i]["operator_human"]["id"].clone();
    assert_eq!(shown(&before, 0), serde_json::json!(h1.to_string()));
    assert_eq!(shown(&before, 1), serde_json::json!(h2.to_string()));
    assert_eq!(shown(&before, 2), serde_json::json!(o3.to_string()));

    let check = |label: &'static str| {
        let pool = pool.clone();
        let before = before.clone();
        async move {
            let now = whole(&cards_as(&pool, outsider, &ids).await);
            assert_eq!(now, before, "{label}: the outsider's cards moved");
        }
    };

    // 1. The allowlisted agent's own client suspended.
    set_client_status(&pool, allowed_client, "suspended").await;
    assert_eq!(human_of(&pool, allowed).await, None, "CALIBRATION 1");
    check("allowlisted client suspended").await;
    set_client_status(&pool, allowed_client, "active").await;

    // 2. The allowlist operator's human client suspended.
    let h2_client = human_client_of(&pool, h2).await;
    set_client_status(&pool, h2_client, "suspended").await;
    assert_eq!(human_of(&pool, allowed).await, None, "CALIBRATION 2");
    check("operator's human client suspended").await;
    set_client_status(&pool, h2_client, "active").await;

    // 3. The registered-and-linked principal's own human client suspended.
    assert_eq!(human_of(&pool, dual).await, Some(dual), "CALIBRATION 3a");
    let dual_client = human_client_of(&pool, dual).await;
    set_client_status(&pool, dual_client, "suspended").await;
    assert_eq!(human_of(&pool, dual).await, Some(o3), "CALIBRATION 3b");
    check("linked human's client suspended").await;
    set_client_status(&pool, dual_client, "active").await;

    // 4. A second live client added to the allowlisted agent.
    let second: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'second client', 'service', ARRAY['claims:read'], 'active', $2, \
                 'Fixture Org', 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("lookup-second-{}", Uuid::new_v4()))
    .bind(allowed)
    .fetch_one(&pool)
    .await
    .expect("second client");
    assert_eq!(human_of(&pool, allowed).await, None, "CALIBRATION 4");
    check("second client added").await;
    set_client_status(&pool, second, "revoked").await;

    // 5. Both operators' registrations revoked.
    revoke_registration(&pool, h1).await;
    revoke_registration(&pool, h2).await;
    assert_eq!(human_of(&pool, allowed).await, None, "CALIBRATION 5");
    check("operators' registrations revoked").await;

    // 6. The allowlisted client revoked.
    set_client_status(&pool, allowed_client, "revoked").await;
    check("allowlisted client revoked").await;
}

/// An operated agent learns nothing about its human that an outsider does
/// not: its human is on every reader's card of the agent, and the human's
/// own card reads to the agent exactly as it reads to an outsider (no
/// registration status, so `kind=human` finds nobody for either).
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_sees_its_human_exactly_as_an_outsider_does(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (h1, _) = named_human(&pool, "Sable Voss").await;
    let (h2, _) = named_human(&pool, "Sable Voss").await;
    let (bot, _) = named(&pool, "voss-bot").await;
    link(&pool, bot, h1).await;

    for q in ["sable voss", "sa"] {
        let as_bot = find_as(&pool, bot, q, Some("human"), None, Some(25)).await;
        let as_out = find_as(&pool, outsider, q, Some("human"), None, Some(25)).await;
        assert_eq!(ids(&as_bot), ids(&as_out), "{q}");
        assert!(ids(&as_bot).is_empty(), "{q}: {:?}", ids(&as_bot));
    }
    assert_eq!(
        whole(&cards_as(&pool, bot, &[h1, h2]).await),
        whole(&cards_as(&pool, outsider, &[h1, h2]).await),
        "the agent's view of the humans is the outsider's"
    );
    // What it may know, it reads on its own card, as everyone does.
    let own = card_as(&pool, bot, bot).await;
    assert_eq!(own.operator_human.map(|h| h.id), Some(h1));
    // The human itself still sees its own registration.
    assert_eq!(card_as(&pool, h1, h1).await.kind, AgentKind::Human);
}

/// A document-ingest author node that is linked to its human (a legacy
/// author, migration 122) is an ingest author, not an LLM agent, for every
/// reader, now that every reader sees the binding.
#[sqlx::test(migrations = "../../migrations")]
async fn a_linked_ingest_author_node_reads_as_an_ingest_author(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (human, _) = named_human(&pool, "Corin Vale").await;
    let (_, key) = epigraph_crypto::did_key::did_key_for_author(None, "Corin Vale");
    let author = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'Corin Vale')")
        .bind(author)
        .bind(key.as_slice())
        .execute(&pool)
        .await
        .expect("ingest author");
    link(&pool, author, human).await;

    for who in [outsider, human] {
        let c = card_as(&pool, who, author).await;
        assert_eq!(c.kind, AgentKind::IngestAuthor, "{c:?}");
        assert!(c.kind_evidence.contains(&"name_derived_key"));
        assert!(c.kind_evidence.contains(&"bound_to_visible_human"));
        assert_eq!(c.operator_human.map(|h| h.id), Some(human));
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_admin_sees_the_operator_human(pool: PgPool) {
    let (human, _) = named_human(&pool, "Talia Brennick").await;
    let (linked, _) = named(&pool, "helper-bot").await;
    link(&pool, linked, human).await;
    let (scoped, admin) = fixture::bypass(&pool).await;
    let (mut conn, _lease) = scoped
        .unscoped_for_maintenance(SystemReason::SchemaContractTest)
        .await
        .expect("maintenance connection");
    let card = AgentLookupRepository::card(&mut conn, &admin, linked)
        .await
        .expect("card")
        .expect("exists");
    assert_eq!(card.operator_human.map(|h| h.id), Some(human));
}

#[sqlx::test(migrations = "../../migrations")]
async fn human_operator_status_is_shown_only_to_those_who_may_know_it(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (human, _) = named_human(&pool, "Oren Lisle").await;
    let (plain, _) = named(&pool, "Oren Lisle").await;
    let (agent_of_human, _) = named(&pool, "oren-assistant").await;
    link(&pool, agent_of_human, human).await;

    let out = cards_as(&pool, outsider, &[human, plain]).await;
    assert_eq!(
        shape(&out[0]),
        shape(&out[1]),
        "registration is hidden from an outsider"
    );
    assert_eq!(out[0].kind, AgentKind::Unknown);

    assert_eq!(
        card_as(&pool, human, human).await.kind,
        AgentKind::Human,
        "itself"
    );
    // Its own agent reads the human's card exactly as an outsider does: the
    // agent learns its human from its OWN card's operator_human (shown to
    // every reader), never registration status from the human's.
    let via_agent = card_as(&pool, agent_of_human, human).await;
    assert_eq!(shape(&via_agent), shape(&out[0]));
    assert_eq!(via_agent.kind, AgentKind::Unknown);
}

#[sqlx::test(migrations = "../../migrations")]
async fn counts_are_computed_under_the_callers_viewer(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (member, _) = named(&pool, "member").await;
    let (with_private, _) = named(&pool, "Ada Fenwright").await;
    let (without, _) = named(&pool, "Ada Fenwright").await;
    let team = team_of(&pool, &[member, with_private]).await;
    let claim = fixture::seed_group_claim(&pool, with_private, team, "a private finding").await;
    // A private paper edge and a private asserts edge too.
    let paper = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, '10.9999/fixture.1', 'A Paper')")
        .bind(paper)
        .execute(&pool)
        .await
        .expect("paper");
    for (target, ttype, rel) in [(paper, "paper", "authored"), (claim, "claim", "asserts")] {
        // Inserted, then its tenancy FORCED (migration 070's trigger stamps an
        // INSERT from its endpoints; see `fixture::seed_edge_owned_by`).
        let edge: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'agent', $2, $3, $4) RETURNING id",
        )
        .bind(with_private)
        .bind(target)
        .bind(ttype)
        .bind(rel)
        .fetch_one(&pool)
        .await
        .expect("edge");
        sqlx::query(
            "UPDATE edges SET visibility = 'group', owner_group_id = $2, \
                              co_owner_group_id = NULL WHERE id = $1",
        )
        .bind(edge)
        .bind(team)
        .execute(&pool)
        .await
        .expect("force the edge private");
    }

    let out = cards_as(&pool, outsider, &[with_private, without]).await;
    assert_eq!(
        shape(&out[0]),
        shape(&out[1]),
        "private rows move no outsider count"
    );
    assert_eq!(out[0].counts.asserted_claims, 0);
    assert_eq!(out[0].counts.authored_papers, 0);

    let inside = card_as(&pool, member, with_private).await;
    assert_eq!(
        inside.counts.authored_papers, 1,
        "a member sees the paper edge"
    );
    assert_eq!(
        inside.counts.asserted_claims, 1,
        "authored AND asserted, the same claim counted once"
    );

    // find_agent returns the same counts (computed for its results only).
    let r = find_as(&pool, member, "ada fenwright", None, None, None).await;
    let hit = r
        .results
        .iter()
        .find(|h| h.card.id == with_private)
        .expect("listed");
    assert_eq!(hit.card.counts.asserted_claims, 1);
    assert_eq!(hit.card.counts.authored_papers, 1);

    // Public claims count for everyone.
    fixture::seed_public_claim(&pool, without, "a public finding").await;
    assert_eq!(
        card_as(&pool, outsider, without)
            .await
            .counts
            .asserted_claims,
        1
    );
}

/// The counts' in-query predicate holds on its own: on a session row security
/// does not filter (the superuser harness connection, stamped from the
/// outsider's viewer), a group-private claim and edge still move no outsider
/// count. On the application role, FORCEd row security filters the same rows
/// a second time, so this is the test that pins the splice itself.
#[sqlx::test(migrations = "../../migrations")]
async fn counts_filter_in_query_even_where_row_security_does_not(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (author, _) = named(&pool, "Ada Fenwright").await;
    let team = team_of(&pool, &[author]).await;
    let claim = fixture::seed_group_claim(&pool, author, team, "a private finding").await;
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'agent', $2, 'claim', 'asserts') RETURNING id",
    )
    .bind(author)
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("edge");
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(edge)
    .bind(team)
    .execute(&pool)
    .await
    .expect("force the edge private");

    let superuser = fixture::scoped_pool(&pool).await;
    let v = viewer(&pool, outsider).await;
    let mut read = superuser.read_as(&v).await.expect("read_as");
    let rls_bypassed: bool = sqlx::query_scalar(
        "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&mut *read)
    .await
    .expect("role");
    assert!(
        rls_bypassed,
        "CALIBRATION: row security does not filter this session"
    );
    let card = AgentLookupRepository::card(&mut read, &v, author)
        .await
        .expect("card")
        .expect("exists");
    assert_eq!(card.counts.asserted_claims, 0, "{card:?}");

    let member = viewer(&pool, author).await;
    let mut read = superuser.read_as(&member).await.expect("read_as");
    let card = AgentLookupRepository::card(&mut read, &member, author)
        .await
        .expect("card")
        .expect("exists");
    assert_eq!(
        card.counts.asserted_claims, 1,
        "CALIBRATION: the member counts it"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn counts_are_capped(pool: PgPool) {
    let (asker, _) = named(&pool, "asker").await;
    let (prolific, _) = named(&pool, "prolific").await;
    let world = fixture::world_group(&pool).await;
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         SELECT gen_random_uuid(), 'bulk ' || g, sha256(('bulk ' || g)::bytea), 0.5, $1, true, \
                'public', $2 \
           FROM generate_series(1, 10001) g",
    )
    .bind(prolific)
    .bind(world)
    .execute(&pool)
    .await
    .expect("bulk claims");
    let c = card_as(&pool, asker, prolific).await;
    assert_eq!(
        c.counts.asserted_claims,
        epigraph_db::agent_lookup::COUNT_CAP
    );
    assert!(c.counts.capped);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_orcid_never_matches_and_is_never_shown(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (colleague, _) = named(&pool, "colleague").await;
    let (private_p, _) = named(&pool, "Bex Thornaby").await;
    let (no_orcid, _) = named(&pool, "Bex Thornaby").await;
    let (public_p, _) = named(&pool, "Pell Ardow").await;
    sqlx::query(
        "UPDATE agents SET orcid = '0000-0002-0000-0001', profile_visibility = 'group', \
                properties = properties || '{\"llm_model\": \"model-y\"}' WHERE id = $1",
    )
    .bind(private_p)
    .execute(&pool)
    .await
    .expect("private profile");
    sqlx::query("UPDATE agents SET profile_visibility = 'group' WHERE id = $1")
        .bind(no_orcid)
        .execute(&pool)
        .await
        .expect("private, no orcid");
    sqlx::query("UPDATE agents SET orcid = '0000-0002-0000-0002' WHERE id = $1")
        .bind(public_p)
        .execute(&pool)
        .await
        .expect("public orcid");
    team_of(&pool, &[colleague, private_p]).await;

    // Outsider: the private ORCID matches nothing; the cards are identical.
    let r = find_as(&pool, outsider, "0000-0002-0000-0001", None, None, None).await;
    assert!(ids(&r).is_empty(), "a private ORCID is no oracle");
    let out = cards_as(&pool, outsider, &[private_p, no_orcid]).await;
    assert_eq!(
        shape(&out[0]),
        shape(&out[1]),
        "nor do its ORCID or model show"
    );

    // A group co-member sees it, and the ORCID matches.
    let r = find_as(&pool, colleague, "0000-0002-0000-0001", None, None, None).await;
    assert_eq!(ids(&r), vec![private_p]);
    assert_eq!(r.results[0].tier, MatchTier::Orcid);
    assert_eq!(r.results[0].card.kind, AgentKind::LlmAgent);

    // A public ORCID matches for anyone, with or without the resolver prefix.
    for q in [
        "0000-0002-0000-0002",
        "https://orcid.org/0000-0002-0000-0002",
    ] {
        let r = find_as(&pool, outsider, q, None, None, None).await;
        assert_eq!(ids(&r), vec![public_p], "{q}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn roles_show_disclosed_assignments_and_never_the_admin_roster(pool: PgPool) {
    seed_role(&pool, "role:test-members", false).await;
    let (outsider, _) = named(&pool, "outsider").await;
    let (member, _) = named_human(&pool, "Juno Marsh").await;
    let (non_member, _) = named_human(&pool, "Juno Marsh").await;
    grant(&pool, "role:test-members", member).await;
    // Custodian after the member grant: a live custodian makes every later
    // grant name a grantor (CUS03).
    let (custodian, _) = named_human(&pool, "Kit Arlow").await;
    let (plain, _) = named_human(&pool, "Kit Arlow").await;
    fixture::make_custodian(&pool, custodian).await;

    let out = cards_as(&pool, outsider, &[member, non_member, custodian, plain]).await;
    assert_eq!(
        out[0]
            .roles
            .iter()
            .map(|r| r.role.as_str())
            .collect::<Vec<_>>(),
        vec!["role:test-members"],
        "a disclosed role is shown to anyone"
    );
    assert_eq!(
        out[0].kind,
        AgentKind::Human,
        "holding a role discloses a human"
    );
    assert!(out[1].roles.is_empty());
    assert_eq!(out[1].kind, AgentKind::Unknown);
    assert_eq!(
        shape(&out[2]),
        shape(&out[3]),
        "the custodian roster is not disclosed to an outsider"
    );

    // The holder of an elevating role sees its own.
    let own = card_as(&pool, custodian, custodian).await;
    assert!(own
        .roles
        .iter()
        .any(|r| r.role == "role:platform-custodian"));

    // find_agent's role filter, with or without the prefix.
    for role in ["role:test-members", "test-members"] {
        let r = find_as(&pool, outsider, "juno marsh", None, Some(role), None).await;
        assert_eq!(ids(&r), vec![member], "{role}");
    }
    let r = find_as(
        &pool,
        outsider,
        "kit arlow",
        None,
        Some("platform-custodian"),
        None,
    )
    .await;
    assert!(
        ids(&r).is_empty(),
        "the role filter is no roster oracle either"
    );
}

/// The auditor roster (`role:auditor`: elevates = false, reads_audit = true)
/// is not disclosed: the reads-audit half of 198's filter, on its own.
#[sqlx::test(migrations = "../../migrations")]
async fn the_auditor_roster_is_not_disclosed(pool: PgPool) {
    let (elevates, reads_audit): (bool, bool) = sqlx::query_as(
        "SELECT elevates, reads_audit FROM platform_roles WHERE key = 'role:auditor'",
    )
    .fetch_one(&pool)
    .await
    .expect("123 seeds role:auditor");
    assert!(
        !elevates && reads_audit,
        "CALIBRATION: only the reads_audit half of the filter covers this role"
    );
    let (outsider, _) = named(&pool, "outsider").await;
    let (auditor, _) = named_human(&pool, "Noor Castell").await;
    let (plain, _) = named_human(&pool, "Noor Castell").await;
    grant(&pool, "role:auditor", auditor).await;

    let out = cards_as(&pool, outsider, &[auditor, plain]).await;
    assert_eq!(
        shape(&out[0]),
        shape(&out[1]),
        "an outsider cannot tell the auditor"
    );
    assert!(out[0].roles.is_empty());
    let r = find_as(&pool, outsider, "noor castell", None, Some("auditor"), None).await;
    assert!(ids(&r).is_empty(), "the role filter is no auditor oracle");

    // The holder sees its own.
    let own = card_as(&pool, auditor, auditor).await;
    assert!(
        own.roles.iter().any(|r| r.role == "role:auditor"),
        "{own:?}"
    );
}

/// A disclosed role is decided by the assignment window alone, as the public
/// projection shows it, so no client or registration event moves an
/// outsider's card (`kind` included).
#[sqlx::test(migrations = "../../migrations")]
async fn a_disclosed_role_does_not_move_with_client_or_registration_status(pool: PgPool) {
    seed_role(&pool, "role:test-members", false).await;
    let (outsider, _) = named(&pool, "outsider").await;
    let (member, _) = named_human(&pool, "Juno Marsh").await;
    grant(&pool, "role:test-members", member).await;

    let before = whole(&cards_as(&pool, outsider, &[member]).await);
    assert_eq!(before[0]["kind"], "human");
    assert_eq!(before[0]["roles"][0]["role"], "role:test-members");

    let is_human = |pool: PgPool| async move {
        sqlx::query_scalar::<_, bool>("SELECT public.epigraph_is_human_operator($1)")
            .bind(member)
            .fetch_one(&pool)
            .await
            .expect("is_human_operator")
    };
    let client = human_client_of(&pool, member).await;
    set_client_status(&pool, client, "suspended").await;
    assert!(!is_human(pool.clone()).await, "CALIBRATION: suspended");
    assert_eq!(
        whole(&cards_as(&pool, outsider, &[member]).await),
        before,
        "client suspended"
    );
    set_client_status(&pool, client, "active").await;

    revoke_registration(&pool, member).await;
    assert!(!is_human(pool.clone()).await, "CALIBRATION: deregistered");
    assert_eq!(
        whole(&cards_as(&pool, outsider, &[member]).await),
        before,
        "registration revoked"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn punctuation_and_identifier_spelling_fold(pool: PgPool) {
    let (asker, _) = named(&pool, "asker").await;
    let (jp, _) = named(&pool, "Jean-Pierre Dubois").await;
    let (ob, _) = named(&pool, "Aine O'Brien").await;
    let (orc, _) = named(&pool, "Hale Mercer").await;
    sqlx::query("UPDATE agents SET orcid = '0000-0002-0000-000X' WHERE id = $1")
        .bind(orc)
        .execute(&pool)
        .await
        .expect("public orcid");

    for (q, want, tier) in [
        ("jean pierre dubois", jp, MatchTier::Exact),
        ("Jean–Pierre Dubois", jp, MatchTier::Exact),
        ("pierre", jp, MatchTier::Prefix),
        ("Aine O’Brien", ob, MatchTier::Exact),
        ("aine obrien", ob, MatchTier::Exact),
        ("000000020000000x", orc, MatchTier::Orcid),
        ("0000-0002-0000-000x", orc, MatchTier::Orcid),
        ("orcid.org/0000-0002-0000-000X", orc, MatchTier::Orcid),
    ] {
        let r = find_as(&pool, asker, q, None, None, None).await;
        let top = r
            .results
            .first()
            .unwrap_or_else(|| panic!("{q:?} found nothing"));
        assert_eq!((top.card.id, top.tier), (want, tier), "{q:?}");
    }
}

// ---------------------------------------------------------------------------
// Migration 198
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn migration_198_is_a_pinned_owned_and_granted_definer(pool: PgPool) {
    let row: (bool, String, Option<Vec<String>>, bool, bool) = sqlx::query_as(
        "SELECT p.prosecdef, r.rolname::text, p.proconfig, \
                has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                has_function_privilege('public', p.oid, 'EXECUTE') \
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
          WHERE p.oid = to_regprocedure('public.epigraph_disclosed_role_assignments(uuid[])')",
    )
    .fetch_one(&pool)
    .await
    .expect("198's function exists");
    assert!(row.0, "SECURITY DEFINER");
    assert_eq!(row.1, "epigraph_maintenance");
    assert_eq!(
        row.2,
        Some(vec!["search_path=pg_catalog, pg_temp".to_string()])
    );
    assert!(row.3, "the app role executes it");
    assert!(!row.4, "PUBLIC does not");
}

#[sqlx::test(migrations = "../../migrations")]
async fn migration_198_refuses_more_than_200_agents(pool: PgPool) {
    let scoped = app_pool(&pool).await;
    let (asker, _) = named(&pool, "asker").await;
    let v = viewer(&pool, asker).await;
    let mut read = scoped.read_as(&v).await.expect("read_as");
    let many: Vec<Uuid> = (0..201).map(|_| Uuid::new_v4()).collect();
    let err = sqlx::query("SELECT * FROM public.epigraph_disclosed_role_assignments($1)")
        .bind(&many)
        .fetch_all(&mut *read)
        .await
        .expect_err("201 ids refused");
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("22023")
    );
    let ok = sqlx::query("SELECT * FROM public.epigraph_disclosed_role_assignments($1)")
        .bind(&many[..200])
        .fetch_all(&mut *read)
        .await
        .expect("200 ids accepted");
    assert!(ok.is_empty());
}

// ---------------------------------------------------------------------------
// The agent's human is its CURRENT live binding only
// ---------------------------------------------------------------------------

/// Retire `agent`'s live link through 191's maintenance verb, revoking its
/// writer row in the same call (the verb's zero-authority precondition).
async fn retire_link(pool: &PgPool, agent: Uuid) {
    let outcome: String = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let r: String = sqlx::query_scalar(
            "SELECT outcome FROM public.epigraph_retire_operator_link($1, 'lookup test retire', \
                                                                     true)",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("retire the link");
        (conn, r)
    })
    .await;
    assert_eq!(outcome, "retired", "CALIBRATION: the link was live");
}

/// `epigraph_human_of(agent, true)`: the binding in force, links' retired bit
/// honoured. Read on the harness connection.
async fn live_human_of(pool: &PgPool, agent: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT public.epigraph_human_of($1, true)")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("epigraph_human_of live")
}

/// A retired operator link is no longer the agent's human: the operator owns
/// the agent's past claims, but the agent never acts for it again (107
/// section 7), so the card must not present that human as the current one.
/// Every reader's card of the retired agent then reads exactly like an
/// unbound look-alike's, while the binding RECORD still names the operator
/// (CALIBRATION: the retire is the only thing that changed).
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_link_is_not_shown_as_the_agents_human(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (human, _) = named_human(&pool, "Maren Quillfeather").await;
    let (bot, _) = named(&pool, "quill-bot").await;
    let (lookalike, _) = named(&pool, "quill-bot").await;
    link(&pool, bot, human).await;
    for who in [outsider, bot, human] {
        assert_eq!(
            card_as(&pool, who, bot).await.operator_human.map(|h| h.id),
            Some(human),
            "CALIBRATION: a live link is shown"
        );
    }

    retire_link(&pool, bot).await;
    assert_eq!(
        human_of(&pool, bot).await,
        Some(human),
        "CALIBRATION: the link record still names the operator"
    );
    assert_eq!(
        live_human_of(&pool, bot).await,
        None,
        "CALIBRATION: no binding is in force"
    );

    for who in [outsider, bot, human] {
        let c = card_as(&pool, who, bot).await;
        assert!(
            c.operator_human.is_none(),
            "a retired link is shown as the current human to {who}: {c:?}"
        );
        assert!(
            !c.kind_evidence.contains(&"bound_to_visible_human"),
            "{c:?}"
        );
    }
    let out = cards_as(&pool, outsider, &[bot, lookalike]).await;
    assert_eq!(
        shape(&out[0]),
        shape(&out[1]),
        "a retired agent reads as an unbound one"
    );

    // A link RECORDED retired (107's link-retired path) is never shown either.
    let (old_bot, _) = named(&pool, "quill-bot-legacy").await;
    let mut conn = pool.acquire().await.expect("acquire");
    let rl = epigraph_db::AgentRepository::link_retired_agent(&mut conn, old_bot, human)
        .await
        .expect("record a retired link");
    assert!(rl.link_retired, "CALIBRATION: recorded retired");
    drop(conn);
    assert_eq!(human_of(&pool, old_bot).await, Some(human), "CALIBRATION");
    assert!(card_as(&pool, outsider, old_bot)
        .await
        .operator_human
        .is_none());

    // find_agent goes through the same card.
    let r = find_as(&pool, outsider, "quill-bot", None, None, Some(25)).await;
    for hit in &r.results {
        assert!(hit.card.operator_human.is_none(), "{:?}", hit.card);
    }
}

/// A revoked binding is no binding: a revoked client allowance names nobody,
/// and an agent whose (retired) link record exists never falls back to an
/// allowance row, exactly as `epigraph_human_of` never consults the
/// allowance for a linked agent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_binding_is_not_shown_and_a_retired_link_never_falls_back(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (h_allow, _) = named_human(&pool, "Ottoline Fairweather").await;
    let (h_link, _) = named_human(&pool, "Caspian Thornbury").await;

    // 1. An allowance revoked through 149's maintenance verb.
    let (revoked_agent, revoked_client) = allowance_bound(&pool, h_allow, "ledger-service").await;
    assert_eq!(
        card_as(&pool, outsider, revoked_agent)
            .await
            .operator_human
            .map(|h| h.id),
        Some(h_allow),
        "CALIBRATION: an allowance in force is shown"
    );
    let revoked: bool = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, \
                                                                              'lookup test')",
        )
        .bind(revoked_client)
        .fetch_one(&mut *conn)
        .await
        .expect("revoke the allowance");
        (conn, r)
    })
    .await;
    assert!(revoked, "CALIBRATION: the allowance was live");
    assert!(card_as(&pool, outsider, revoked_agent)
        .await
        .operator_human
        .is_none());

    // 2. An allowance whose agent was later linked (its client revoked first,
    //    which 149 requires), and then that link retired: the allowance row
    //    is still unrevoked, but a linked agent is bound by its link alone.
    let (agent, client) = allowance_bound(&pool, h_allow, "archive-service").await;
    set_client_status(&pool, client, "revoked").await;
    link(&pool, agent, h_link).await;
    assert_eq!(
        card_as(&pool, outsider, agent)
            .await
            .operator_human
            .map(|h| h.id),
        Some(h_link),
        "CALIBRATION: the link, not the allowance, binds a linked agent"
    );
    let unrevoked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM author_binding_clients WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("allowance rows");
    assert_eq!(unrevoked, 1, "CALIBRATION: the allowance row is unrevoked");
    retire_link(&pool, agent).await;
    assert_eq!(live_human_of(&pool, agent).await, None, "CALIBRATION");
    assert!(
        card_as(&pool, outsider, agent)
            .await
            .operator_human
            .is_none(),
        "a retired link fell back to the allowance"
    );
}

// ---------------------------------------------------------------------------
// Counts trust only attributions the ingest path wrote
// ---------------------------------------------------------------------------

/// A paper row, as the document ingest creates one.
async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, 'A Fixture Paper')")
        .bind(id)
        .bind(doi)
        .execute(pool)
        .await
        .expect("paper");
    id
}

/// An edge written by `writer` on an `epigraph_app` transaction stamped with
/// `writer`'s viewer: the repository call both the document ingest's walk and
/// `POST /api/v1/edges` make. Agent and paper endpoints land
/// `('public', world)` (migration 120), readable by everyone.
async fn edge_as(
    pool: &PgPool,
    writer: Uuid,
    src: (Uuid, &str),
    tgt: (Uuid, &str),
    rel: &str,
    props: Option<serde_json::Value>,
) -> Uuid {
    let scoped = app_pool(pool).await;
    let v = viewer(pool, writer).await;
    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    let id = epigraph_db::EdgeRepository::create(
        &mut *tx, src.0, src.1, tgt.0, tgt.1, rel, props, None, None,
    )
    .await
    .unwrap_or_else(|e| panic!("{rel} edge as {writer}: {e}"));
    tx.commit().await.expect("commit");
    let vis: (String, Uuid) =
        sqlx::query_as("SELECT visibility::text, owner_group_id FROM edges WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("edge row");
    assert_eq!(vis.0, "public", "CALIBRATION: the edge is world-readable");
    id
}

/// What one document ingest writes for one author and one claim: the
/// author's `authored -> paper`, the paper's `asserts -> claim`, and the
/// author's `asserts -> claim`.
async fn ingest_attribution(
    pool: &PgPool,
    ingester: Uuid,
    author: Uuid,
    paper_id: Uuid,
    claim: Uuid,
    authored_props: serde_json::Value,
) {
    edge_as(
        pool,
        ingester,
        (author, "agent"),
        (paper_id, "paper"),
        "authored",
        Some(authored_props),
    )
    .await;
    edge_as(
        pool,
        ingester,
        (paper_id, "paper"),
        (claim, "claim"),
        "asserts",
        None,
    )
    .await;
    edge_as(
        pool,
        ingester,
        (author, "agent"),
        (claim, "claim"),
        "asserts",
        Some(serde_json::json!({"role": "author", "source": "document_attribution"})),
    )
    .await;
}

fn counts_json(card: &AgentCard) -> serde_json::Value {
    serde_json::to_value(card.counts).expect("serialize counts")
}

/// The control: a document ingest's attribution counts, for every reader.
/// And the forgery: a stranger's own `agent -asserts-> claim` edge naming a
/// registered human, onto a claim it can read (its own, or one a paper
/// asserts that the human never authored), moves no reader's count of that
/// human. Only an attribution backed by a countersigned, in-force authorship
/// of a paper asserting the claim is the agent's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_strangers_asserts_edge_moves_no_count(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (ingester, _) = named(&pool, "ingest-runner").await;
    let (stranger, _) = named(&pool, "stranger").await;
    let (human, _) = named_human(&pool, "Perrin Galloway").await;
    let (lookalike, _) = named(&pool, "Perrin Galloway").await;
    let (author, _) = named(&pool, "Wilhelmina Strand").await;

    // Control: an ingested paper's author.
    let p = paper(&pool, "10.9999/lookup.trust.1").await;
    let c = fixture::seed_public_claim(&pool, ingester, "an ingested finding").await;
    ingest_attribution(
        &pool,
        ingester,
        author,
        p,
        c,
        serde_json::json!({"position": 0, "role": "author"}),
    )
    .await;
    for who in [outsider, author, human] {
        let k = card_as(&pool, who, author).await.counts;
        assert_eq!(
            (k.authored_papers, k.asserted_claims),
            (1, 1),
            "CALIBRATION: an ingest attribution counts for {who}"
        );
    }

    // Forgery 1: onto the stranger's own claim (no paper at all).
    let own = fixture::seed_public_claim(&pool, stranger, "a stranger's finding").await;
    edge_as(
        &pool,
        stranger,
        (human, "agent"),
        (own, "claim"),
        "asserts",
        Some(serde_json::json!({"role": "author", "source": "document_attribution"})),
    )
    .await;
    // Forgery 2: onto a claim a real paper asserts, which the human did not
    // author.
    edge_as(
        &pool,
        stranger,
        (human, "agent"),
        (c, "claim"),
        "asserts",
        Some(serde_json::json!({"role": "author", "source": "document_attribution"})),
    )
    .await;
    let forged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'asserts'",
    )
    .bind(human)
    .fetch_one(&pool)
    .await
    .expect("forged edges");
    assert_eq!(forged, 2, "CALIBRATION: both forged edges were written");

    for who in [outsider, human, stranger] {
        let out = cards_as(&pool, who, &[human, lookalike]).await;
        assert_eq!(
            counts_json(&out[0]),
            counts_json(&out[1]),
            "a stranger's asserts edge moved {who}'s count of the human"
        );
        assert_eq!(out[0].counts.asserted_claims, 0, "{:?}", out[0]);
    }
}

/// An `authored` edge an ingester wrote naming someone it neither is nor
/// operates (the pending-countersign mark) is the ingester's word, not the
/// person's: it is reported apart as `pending_authored_papers`, never in
/// `authored_papers`, and it backs no `asserted_claims` (a stranger who
/// names a human on a paper and then writes the human's `asserts` onto that
/// paper's claim moves nothing).
#[sqlx::test(migrations = "../../migrations")]
async fn a_pending_authorship_is_reported_apart_and_backs_no_claim(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (stranger, _) = named(&pool, "stranger").await;
    let (human, _) = named_human(&pool, "Isolde Varrick").await;

    let p = paper(&pool, "10.9999/lookup.pending.1").await;
    let c = fixture::seed_public_claim(&pool, stranger, "a named-author finding").await;
    ingest_attribution(
        &pool,
        stranger,
        human,
        p,
        c,
        serde_json::json!({
            "position": 0,
            "role": "author",
            "explicit_agent_id": true,
            "author_name": "Isolde Varrick",
            "pending_countersign": true,
            "ingested_by": stranger.to_string(),
        }),
    )
    .await;

    for who in [outsider, human, stranger] {
        let card = card_as(&pool, who, human).await;
        let k = counts_json(&card);
        assert_eq!(k["authored_papers"], 0, "{who}: {k}");
        assert_eq!(k["pending_authored_papers"], 1, "{who}: {k}");
        assert_eq!(k["asserted_claims"], 0, "{who}: {k}");
    }

    // A countersigned authorship of the same shape counts (the control).
    let (author, _) = named(&pool, "Isolde Varrick").await;
    let p2 = paper(&pool, "10.9999/lookup.pending.2").await;
    let c2 = fixture::seed_public_claim(&pool, stranger, "a name-derived finding").await;
    ingest_attribution(
        &pool,
        stranger,
        author,
        p2,
        c2,
        serde_json::json!({"position": 0, "role": "author", "pending_countersign": false}),
    )
    .await;
    let k = counts_json(&card_as(&pool, outsider, author).await);
    assert_eq!(k["authored_papers"], 1, "{k}");
    assert_eq!(k["pending_authored_papers"], 0, "{k}");
    assert_eq!(k["asserted_claims"], 1, "{k}");
}

/// A retracted edge (an in-force window that has closed: the operator
/// ingest's replacement, or any retract) counts nowhere: neither the
/// authorship nor an attribution that only the retracted authorship backs.
#[sqlx::test(migrations = "../../migrations")]
async fn retracted_authorships_and_attributions_do_not_count(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (ingester, _) = named(&pool, "ingest-runner").await;
    let (author, _) = named(&pool, "Ambrose Kettering").await;
    let kept = paper(&pool, "10.9999/lookup.retract.1").await;
    let gone = paper(&pool, "10.9999/lookup.retract.2").await;
    let c_kept = fixture::seed_public_claim(&pool, ingester, "a kept finding").await;
    let c_gone = fixture::seed_public_claim(&pool, ingester, "a retracted finding").await;
    let props = serde_json::json!({"position": 0, "role": "author"});
    ingest_attribution(&pool, ingester, author, kept, c_kept, props.clone()).await;
    ingest_attribution(&pool, ingester, author, gone, c_gone, props).await;
    let k = card_as(&pool, outsider, author).await.counts;
    assert_eq!(
        (k.authored_papers, k.asserted_claims),
        (2, 2),
        "CALIBRATION"
    );

    // Retract the second paper's authorship only (the privileged replacement
    // closes edges by valid_to; no application session can).
    sqlx::query(
        "UPDATE edges SET valid_to = now() - interval '1 second' \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'authored'",
    )
    .bind(author)
    .bind(gone)
    .execute(&pool)
    .await
    .expect("retract the authorship");
    let k = card_as(&pool, outsider, author).await.counts;
    assert_eq!(
        (k.authored_papers, k.asserted_claims),
        (1, 1),
        "a retracted authorship still counts: {k:?}"
    );

    // And a retracted attribution edge, its authorship in force.
    sqlx::query(
        "UPDATE edges SET valid_to = now() - interval '1 second' \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'asserts'",
    )
    .bind(author)
    .bind(c_kept)
    .execute(&pool)
    .await
    .expect("retract the attribution");
    let k = card_as(&pool, outsider, author).await.counts;
    assert_eq!(
        (k.authored_papers, k.asserted_claims),
        (1, 0),
        "a retracted attribution still counts: {k:?}"
    );
}
