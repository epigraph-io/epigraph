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

/// A registered human operator with a display name, its profile `'group'` as
/// provisioning writes it since migration 274: a fixture left at the column
/// default `'public'` would count as the person's opt-in, and every
/// name-visibility assertion below would pass by consent instead of by the
/// rule under test.
async fn named_human(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let (a, g) = named(pool, name).await;
    fixture::make_human_operator(pool, a).await;
    set_profile(pool, a, "group").await;
    (a, g)
}

async fn set_profile(pool: &PgPool, agent: Uuid, profile: &str) {
    sqlx::query("UPDATE agents SET profile_visibility = $2 WHERE id = $1")
        .bind(agent)
        .bind(profile)
        .execute(pool)
        .await
        .expect("profile");
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

/// The operator human's ID is on every reader's card of the bound agent
/// (who an agent acts for is public); its NAME follows the disclosure rule
/// (migration 272): an outsider gets `display_name: null`; the human itself,
/// a teammate, and the bound agent (which reads its operator's teams through
/// migration 234, so the team arm holds) get the name. Was
/// `the_operator_human_is_shown_to_every_reader`, which pinned the name to
/// every reader before the operator's ruling that a human is named only to
/// those the rule admits.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_humans_id_is_shown_to_every_reader_and_its_name_by_the_rule(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (human, _) = named_human(&pool, "Talia Brennick").await;
    let (teammate, _) = named(&pool, "brennick-teammate").await;
    team_of(&pool, &[human, teammate]).await;
    let (linked, _) = named(&pool, "helper-bot").await;
    let (unlinked, _) = named(&pool, "helper-bot").await;
    link(&pool, linked, human).await;
    assert_eq!(
        human_of(&pool, linked).await,
        Some(human),
        "CALIBRATION: the card names the binding epigraph_human_of names"
    );

    for (who, name) in [
        (outsider, None),
        // The bound agent reads its operator's teams (migration 234), so the
        // team arm names the human to it once the human has a team.
        (linked, Some("Talia Brennick")),
        (human, Some("Talia Brennick")),
        (teammate, Some("Talia Brennick")),
    ] {
        let c = card_as(&pool, who, linked).await;
        let h = c.operator_human.as_ref().expect("operator_human shown");
        assert_eq!(h.id, human, "{who}: the id is never withheld");
        assert_eq!(h.display_name.as_deref(), name, "{who}");
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
    // The operators opted in, so the outsider's cards carry their names and
    // the reverse evidence at all (an unnamed human shows neither); the
    // opt-in arm reads no status, so the property under test is unchanged.
    for h in [h1, h2, o3] {
        set_profile(&pool, h, "public").await;
    }

    // Where both agree, the card equals epigraph_human_of.
    assert_eq!(human_of(&pool, linked).await, Some(h1));
    assert_eq!(human_of(&pool, allowed).await, Some(h2));

    let ids = [linked, allowed, dual, h1, h2, o3];
    let before = whole(&cards_as(&pool, outsider, &ids).await);
    let shown = |v: &serde_json::Value, i: usize| v[i]["operator_human"]["id"].clone();
    assert_eq!(shown(&before, 0), serde_json::json!(h1.to_string()));
    assert_eq!(shown(&before, 1), serde_json::json!(h2.to_string()));
    assert_eq!(shown(&before, 2), serde_json::json!(o3.to_string()));
    // Each operator reads as human through the binding, so the events below
    // also prove that evidence reads no client or registration status.
    for i in 3..6 {
        assert_eq!(before[i]["kind"], "human", "{}", before[i]);
        assert_eq!(
            before[i]["kind_evidence"],
            serde_json::json!(["operator_of_bound_agent"])
        );
    }

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
/// registration status: `kind=human` finds, for both, only the human some
/// agent is bound to, which every reader already sees on that agent's card).
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_sees_its_human_exactly_as_an_outsider_does(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (h1, _) = named_human(&pool, "Sable Voss").await;
    let (h2, _) = named_human(&pool, "Sable Voss").await;
    let (bot, _) = named(&pool, "voss-bot").await;
    link(&pool, bot, h1).await;

    // Neither finds an unnamed human by its name (both humans keep the
    // 'group' profile and share no team with either reader); the human
    // itself does (CALIBRATION: the rule's self arm).
    for q in ["sable voss", "sa"] {
        let as_bot = find_as(&pool, bot, q, Some("human"), None, Some(25)).await;
        let as_out = find_as(&pool, outsider, q, Some("human"), None, Some(25)).await;
        assert_eq!(ids(&as_bot), ids(&as_out), "{q}");
        assert_eq!(
            ids(&as_bot),
            Vec::<Uuid>::new(),
            "{q}: no unnamed human is found"
        );
        let as_self = find_as(&pool, h1, q, Some("human"), None, Some(25)).await;
        assert_eq!(ids(&as_self), vec![h1], "{q}: CALIBRATION");
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
    // A registered human no agent is bound to: only registration says human.
    let (lone, _) = named_human(&pool, "Oren Lisle").await;
    let (plain, _) = named(&pool, "Oren Lisle").await;
    // A registered human its agent is bound to: the binding says human, to
    // every reader, and registration still to nobody else.
    let (human, _) = named_human(&pool, "Oren Lisle").await;
    let (agent_of_human, _) = named(&pool, "oren-assistant").await;
    link(&pool, agent_of_human, human).await;

    let out = cards_as(&pool, outsider, &[lone, plain, human]).await;
    assert_eq!(
        shape(&out[0]),
        shape(&out[1]),
        "registration is hidden from an outsider"
    );
    assert_eq!(out[0].kind, AgentKind::Unknown);
    // The bound human is UNNAMED to an outsider (no arm of migration 272
    // holds), so the binding's reverse evidence is withheld with its name:
    // it reads as the unregistered look-alike. Before the human-identity
    // rule this asserted `human` via `operator_of_bound_agent`.
    assert_eq!(out[2].kind, AgentKind::Unknown);
    assert_eq!(shape(&out[2]), shape(&out[1]));
    // CALIBRATION: once the human opts in, the binding says human to anyone.
    set_profile(&pool, human, "public").await;
    let opted = card_as(&pool, outsider, human).await;
    assert_eq!(opted.kind, AgentKind::Human);
    assert_eq!(opted.kind_evidence, vec!["operator_of_bound_agent"]);
    set_profile(&pool, human, "group").await;

    for h in [lone, human] {
        let own = card_as(&pool, h, h).await;
        assert_eq!(own.kind, AgentKind::Human, "itself");
        assert!(own.kind_evidence.contains(&"registered_human_operator"));
    }
    // Its own agent reads the human's card exactly as an outsider does: the
    // agent learns its human from its OWN card's operator_human (shown to
    // every reader), never registration status from the human's.
    let via_agent = card_as(&pool, agent_of_human, human).await;
    assert_eq!(shape(&via_agent), shape(&out[2]));
    assert!(!via_agent
        .kind_evidence
        .contains(&"registered_human_operator"));
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
        // Inserted as the ingest writes it (declared and marked), then its
        // tenancy FORCED (migration 070's trigger stamps an INSERT from its
        // endpoints; see `fixture::seed_edge_owned_by`).
        let mut tx = pool.begin().await.expect("tx");
        sqlx::query("SELECT pg_catalog.set_config($1, 'on', true)")
            .bind(epigraph_db::INGEST_WRITTEN_SETTING)
            .execute(&mut *tx)
            .await
            .expect("declare the walk");
        let edge: Uuid = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                properties) \
             VALUES ($1, 'agent', $2, $3, $4, \
                     jsonb_build_object($5::text, \
                                        jsonb_build_object('tool', 'ingest_document', \
                                                           'by', $1::text))) \
             RETURNING id",
        )
        .bind(with_private)
        .bind(target)
        .bind(ttype)
        .bind(rel)
        .bind(epigraph_db::INGEST_WRITTEN_PROPERTY)
        .fetch_one(&mut *tx)
        .await
        .expect("edge");
        tx.commit().await.expect("commit");
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
    // The roster is read from a NAMED holder (it opted in): an unnamed
    // holder's roles are withheld with its name (asserted below).
    set_profile(&pool, member, "public").await;
    let (hidden_member, _) = named_human(&pool, "Juno Marsh").await;
    grant(&pool, "role:test-members", hidden_member).await;
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
    // An UNNAMED holder of the same disclosed role reads to an outsider as
    // the non-member does: roles are human evidence (only registered people
    // hold them), so they go with the name (spec 5).
    let hidden = card_as(&pool, outsider, hidden_member).await;
    assert!(hidden.roles.is_empty(), "{hidden:?}");
    assert_eq!(shape(&hidden), shape(&out[1]));
    assert_eq!(
        card_as(&pool, hidden_member, hidden_member)
            .await
            .roles
            .len(),
        1,
        "CALIBRATION: the holder sees its own"
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
    // Opted in, so the outsider sees the role at all (an unnamed holder's
    // roles are withheld); the opt-in arm reads no status either.
    set_profile(&pool, member, "public").await;

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
/// `writer`'s viewer: the repository call `POST /api/v1/edges` makes (the
/// ingest walk writes these shapes through [`ingest_edge_as`]'s marked
/// writer instead). Agent and paper endpoints land
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

/// One edge as the document ingest walk writes it: through
/// `create_ingest_written_edge_if_absent_conn` (the walk's only writer of
/// these shapes, which declares the walk and marks the edge) on an
/// `epigraph_app` transaction stamped as `writer`.
async fn ingest_edge_as(
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
    let (row, created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut tx,
        None,
        "ingest_document",
        writer,
        src.0,
        src.1,
        tgt.0,
        tgt.1,
        rel,
        props,
    )
    .await
    .unwrap_or_else(|e| panic!("ingest {rel} edge as {writer}: {e}"));
    tx.commit().await.expect("commit");
    assert!(created, "CALIBRATION: the ingest wrote a new {rel} edge");
    row.id
}

/// What one document ingest writes for one author and one claim: the
/// author's `authored -> paper`, the paper's `asserts -> claim`, and the
/// author's `asserts -> claim`, each marked ingest-written.
async fn ingest_attribution(
    pool: &PgPool,
    ingester: Uuid,
    author: Uuid,
    paper_id: Uuid,
    claim: Uuid,
    authored_props: serde_json::Value,
) {
    ingest_edge_as(
        pool,
        ingester,
        (author, "agent"),
        (paper_id, "paper"),
        "authored",
        Some(authored_props),
    )
    .await;
    ingest_edge_as(
        pool,
        ingester,
        (paper_id, "paper"),
        (claim, "claim"),
        "asserts",
        None,
    )
    .await;
    ingest_edge_as(
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

/// The whole backing chain forged, not just the agent's own edge. A stranger
/// writes BOTH `paper -asserts-> X`, onto a paper the agent really authored,
/// and `agent -asserts-> X`: the two shapes an edges:write caller could post.
/// The agent's in-force, countersigned `authored` edge is real, so a read that
/// trusted edges by their shape would credit the agent with X. Neither the
/// name-derived author nor a registered human that ingested its own paper may
/// move, for any reader.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_paper_assertion_backs_no_attribution(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (ingester, _) = named(&pool, "ingest-runner").await;
    let (stranger, _) = named(&pool, "stranger").await;
    let (author, _) = named(&pool, "Leocadia Brennt").await;
    let (human, _) = named_human(&pool, "Ferdinand Holloway").await;

    let p = paper(&pool, "10.9999/lookup.forged-paper.1").await;
    let c = fixture::seed_public_claim(&pool, ingester, "a real finding").await;
    ingest_attribution(
        &pool,
        ingester,
        author,
        p,
        c,
        serde_json::json!({"position": 0, "role": "author"}),
    )
    .await;
    // A registered human's own ingest of its own paper: not pending.
    let ph = paper(&pool, "10.9999/lookup.forged-paper.2").await;
    let ch = fixture::seed_public_claim(&pool, human, "the human's own finding").await;
    ingest_attribution(
        &pool,
        human,
        human,
        ph,
        ch,
        serde_json::json!({"position": 0, "role": "author"}),
    )
    .await;
    for who in [author, human] {
        let k = card_as(&pool, outsider, who).await.counts;
        assert_eq!(
            (k.authored_papers, k.asserted_claims),
            (1, 1),
            "CALIBRATION: the real ingest counts for {who}"
        );
    }

    // The forgery, onto three of the stranger's own public claims. Written
    // through the application repository call, as POST /api/v1/edges would.
    for i in 0..3 {
        let x = fixture::seed_public_claim(&pool, stranger, &format!("stranger text {i}")).await;
        for (who, pp) in [(author, p), (human, ph)] {
            edge_as(
                &pool,
                stranger,
                (pp, "paper"),
                (x, "claim"),
                "asserts",
                None,
            )
            .await;
            edge_as(
                &pool,
                stranger,
                (who, "agent"),
                (x, "claim"),
                "asserts",
                Some(serde_json::json!({"role": "author", "source": "document_attribution"})),
            )
            .await;
        }
    }

    for reader in [outsider, author, human, stranger] {
        for who in [author, human] {
            let k = card_as(&pool, reader, who).await.counts;
            assert_eq!(
                (k.authored_papers, k.asserted_claims),
                (1, 1),
                "a forged paper assertion moved {reader}'s count of {who}: {k:?}"
            );
        }
    }
}

/// A second ingest under the same DOI cannot borrow the first one's
/// authorship. A stranger running its OWN (marked) ingest of the paper an
/// author really authored, asserting a claim of its own and attributing it to
/// that author, writes edges that each carry the marker, but they name the
/// stranger, not the ingest that wrote the authorship: the chain does not
/// hold and no reader's count moves. (An ingest that NAMES the author writes
/// an authorship of its own, and its claims are then the author's by that
/// ingest's word: see
/// `each_ingest_that_names_an_author_credits_it_with_that_ingests_claims`.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_ingest_of_the_same_paper_cannot_borrow_its_authorship(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (ingester, _) = named(&pool, "ingest-runner").await;
    let (stranger, _) = named(&pool, "stranger").await;
    let (author, _) = named(&pool, "Leopold Fairweather").await;
    let p = paper(&pool, "10.9999/lookup.second-ingest.1").await;
    let c = fixture::seed_public_claim(&pool, ingester, "the paper's finding").await;
    ingest_attribution(
        &pool,
        ingester,
        author,
        p,
        c,
        serde_json::json!({"position": 0, "role": "author"}),
    )
    .await;
    let k = card_as(&pool, outsider, author).await.counts;
    assert_eq!(
        (k.authored_papers, k.asserted_claims),
        (1, 1),
        "CALIBRATION"
    );

    let x = fixture::seed_public_claim(&pool, stranger, "the stranger's finding").await;
    ingest_edge_as(&pool, stranger, (p, "paper"), (x, "claim"), "asserts", None).await;
    ingest_edge_as(
        &pool,
        stranger,
        (author, "agent"),
        (x, "claim"),
        "asserts",
        Some(serde_json::json!({"role": "author", "source": "document_attribution"})),
    )
    .await;
    let marked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND properties ? 'ingest_written'",
    )
    .bind(x)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        marked, 2,
        "CALIBRATION: both of the stranger's edges are marked"
    );

    for reader in [outsider, author, stranger] {
        let k = card_as(&pool, reader, author).await.counts;
        assert_eq!(
            (k.authored_papers, k.asserted_claims),
            (1, 1),
            "a second ingest borrowed the first one's authorship for {reader}: {k:?}"
        );
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

    // Every reader sees the pending naming, the person unnamed to it
    // included. A pending authorship is an ingester's word about ANY agent
    // (`check_explicit_author_ids` has no human gate), so it is not human
    // evidence; withholding it from an unnamed person only (the branch's
    // first cut, `hide_pending`) made `0` a hidden-human marker (review
    // findings leaks#2 / correctness#2). The H-vs-N comparison is
    // `human_identity_visibility.rs::a_pending_naming_reads_the_same_on_an_unnamed_human_and_a_nameless_agent`.
    for (who, pending) in [(human, 1), (outsider, 1), (stranger, 1)] {
        let card = card_as(&pool, who, human).await;
        let k = counts_json(&card);
        assert_eq!(k["authored_papers"], 0, "{who}: {k}");
        assert_eq!(k["pending_authored_papers"], pending, "{who}: {k}");
        assert_eq!(k["asserted_claims"], 0, "{who}: {k}");
    }

    // An authorship of the same shape not awaiting countersignature counts
    // (the control).
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

/// [`ingest_edge_as`] without its calibration that the write was new:
/// returns whether the writer inserted a row (a deduplicated write returns
/// the existing one).
async fn ingest_edge_as_any(
    pool: &PgPool,
    writer: Uuid,
    src: (Uuid, &str),
    tgt: (Uuid, &str),
    rel: &str,
    props: Option<serde_json::Value>,
) -> bool {
    let scoped = app_pool(pool).await;
    let v = viewer(pool, writer).await;
    let mut tx = scoped.begin_as(&v).await.expect("stamped tx");
    let (_row, created) = epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut tx,
        None,
        "ingest_document",
        writer,
        src.0,
        src.1,
        tgt.0,
        tgt.1,
        rel,
        props,
    )
    .await
    .unwrap_or_else(|e| panic!("ingest {rel} edge as {writer}: {e}"));
    tx.commit().await.expect("commit");
    created
}

/// Two principals' ingests of the same paper both name an author, each
/// asserting a claim of its own. Each ingest's attribution is backed by that
/// SAME ingest's authorship and paper assertion, so the author is credited
/// with both claims, and the paper once. A deduplicated authorship that
/// recorded only its first writer left the second ingest with no authorship
/// of its own, so its claim was never credited.
#[sqlx::test(migrations = "../../migrations")]
async fn each_ingest_that_names_an_author_credits_it_with_that_ingests_claims(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (first, _) = named(&pool, "ingest-runner-one").await;
    let (second, _) = named(&pool, "ingest-runner-two").await;
    let (author, _) = named(&pool, "Rosalind Ebberly").await;
    let p = paper(&pool, "10.9999/lookup.per-ingest.1").await;
    let c1 = fixture::seed_public_claim(&pool, first, "the first ingest's finding").await;
    let c2 = fixture::seed_public_claim(&pool, second, "the second ingest's finding").await;
    let authored = serde_json::json!({"position": 0, "role": "author"});
    let attribution = serde_json::json!({"role": "author", "source": "document_attribution"});
    for (by, c) in [(first, c1), (second, c2)] {
        ingest_edge_as_any(
            &pool,
            by,
            (author, "agent"),
            (p, "paper"),
            "authored",
            Some(authored.clone()),
        )
        .await;
        ingest_edge_as_any(&pool, by, (p, "paper"), (c, "claim"), "asserts", None).await;
        ingest_edge_as_any(
            &pool,
            by,
            (author, "agent"),
            (c, "claim"),
            "asserts",
            Some(attribution.clone()),
        )
        .await;
    }
    for reader in [outsider, author, first, second] {
        let k = card_as(&pool, reader, author).await.counts;
        assert_eq!(
            (
                k.authored_papers,
                k.pending_authored_papers,
                k.asserted_claims
            ),
            (1, 0, 2),
            "the second ingest's claim is not credited to the author it named, for {reader}: {k:?}"
        );
    }
    let authorships: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'authored'",
    )
    .bind(author)
    .bind(p)
    .fetch_one(&pool)
    .await
    .expect("authorships");
    assert_eq!(authorships, 2, "CALIBRATION: one authorship per ingest");
}

/// The attribution must come from the ingest that wrote the authorship, not
/// only the paper assertion. Here one principal's ingest wrote the author's
/// authorship and the paper's assertion of X, and ANOTHER principal wrote the
/// author's attribution of X: no single ingest said the author asserts X, so
/// X is not counted. The control, Y, has all three edges from one ingest.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attribution_from_another_ingest_than_the_authorship_is_not_counted(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (ingester, _) = named(&pool, "ingest-runner").await;
    let (stranger, _) = named(&pool, "stranger").await;
    let (author, _) = named(&pool, "Cosima Wetherell").await;
    let p = paper(&pool, "10.9999/lookup.attribution-tie.1").await;
    let x = fixture::seed_public_claim(&pool, ingester, "a finding the author never stated").await;
    let y = fixture::seed_public_claim(&pool, ingester, "the author's finding").await;
    ingest_attribution(
        &pool,
        ingester,
        author,
        p,
        y,
        serde_json::json!({"position": 0, "role": "author"}),
    )
    .await;
    ingest_edge_as(&pool, ingester, (p, "paper"), (x, "claim"), "asserts", None).await;
    ingest_edge_as(
        &pool,
        stranger,
        (author, "agent"),
        (x, "claim"),
        "asserts",
        Some(serde_json::json!({"role": "author", "source": "document_attribution"})),
    )
    .await;
    for reader in [outsider, author, stranger] {
        let k = card_as(&pool, reader, author).await.counts;
        assert_eq!(
            (k.authored_papers, k.asserted_claims),
            (1, 1),
            "an attribution another ingest wrote was counted for {reader}: {k:?}"
        );
    }
}

/// A person's own, not-pending authorship of a paper outranks a stranger's
/// pending naming of the same person on the same paper: the paper is the
/// person's authored paper, not a pending one, and the person's own ingest's
/// claims are credited. (A stranger who names someone writes its own pending
/// authorship; it neither blocks nor replaces the person's own.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_persons_own_authorship_outranks_a_strangers_pending_naming(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (stranger, _) = named(&pool, "stranger").await;
    let (human, _) = named_human(&pool, "Aurelio Dunmore").await;
    let p = paper(&pool, "10.9999/lookup.own-over-pending.1").await;
    ingest_edge_as_any(
        &pool,
        stranger,
        (human, "agent"),
        (p, "paper"),
        "authored",
        Some(serde_json::json!({
            "position": 0,
            "role": "author",
            "explicit_agent_id": true,
            "pending_countersign": true,
            "ingested_by": stranger.to_string(),
        })),
    )
    .await;
    // Read by an outsider the person is not named to: the pending count is
    // the ingester's word and is shown to every reader (no hidden-human
    // marker; review findings leaks#2 / correctness#2).
    let k = card_as(&pool, outsider, human).await.counts;
    assert_eq!(
        (k.authored_papers, k.pending_authored_papers),
        (0, 1),
        "CALIBRATION: the stranger's naming is pending"
    );

    // The person's own ingest of the same paper.
    let c = fixture::seed_public_claim(&pool, human, "the person's own finding").await;
    ingest_edge_as_any(
        &pool,
        human,
        (human, "agent"),
        (p, "paper"),
        "authored",
        Some(serde_json::json!({"position": 0, "role": "author"})),
    )
    .await;
    ingest_edge_as_any(&pool, human, (p, "paper"), (c, "claim"), "asserts", None).await;
    ingest_edge_as_any(
        &pool,
        human,
        (human, "agent"),
        (c, "claim"),
        "asserts",
        Some(serde_json::json!({"role": "author", "source": "document_attribution"})),
    )
    .await;
    for reader in [outsider, human, stranger] {
        let k = card_as(&pool, reader, human).await.counts;
        assert_eq!(
            (
                k.authored_papers,
                k.pending_authored_papers,
                k.asserted_claims
            ),
            (1, 0, 1),
            "the person's own authorship did not outrank a stranger's pending naming, \
             for {reader}: {k:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The three copies of the public-profile rule decide alike (backlog 0e419970)
// ---------------------------------------------------------------------------

/// Whether `viewer` may see `subject`'s profile details, as each copy of the
/// rule decides it, on ONE connection: `get_public_profile` (its `orcid`),
/// the card (`cards_inner`: its `orcid`) and the matcher (`match_ranked`:
/// the ORCID tier).
async fn profile_decisions(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    subject: Uuid,
    orcid: &str,
) -> [bool; 3] {
    let profile = epigraph_db::AgentRepository::get_public_profile(&mut *conn, subject)
        .await
        .expect("get_public_profile")
        .expect("subject exists");
    let card = AgentLookupRepository::card(&mut *conn, viewer, subject)
        .await
        .expect("card")
        .expect("subject exists");
    let matched = AgentLookupRepository::match_by_name(&mut *conn, orcid, 25)
        .await
        .expect("match_by_name")
        .iter()
        .any(|m| m.agent_id == subject && m.tier == MatchTier::Orcid);
    [profile.orcid.is_some(), card.orcid.is_some(), matched]
}

/// The agent public-profile rule is spelled in three statements
/// (`get_public_profile`, the card, the matcher); `visibility_lint.rs` pins
/// their TEXT. This pins their DECISIONS: for every arm of the rule (public
/// profile; the agent itself; a live co-member; a co-member whose subject's
/// membership is revoked; an outsider; an admin) the three agree, and agree
/// with the expected truth table, so a copy whose binds or arms drift is seen
/// at run time as well.
#[sqlx::test(migrations = "../../migrations")]
async fn the_three_copies_of_the_profile_rule_decide_alike(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (colleague, _) = named(&pool, "colleague").await;
    let (former, _) = named(&pool, "former colleague").await;
    let (private_p, _) = named(&pool, "Ivo Pellar").await;
    let (public_p, _) = named(&pool, "Ama Quist").await;
    let private_orcid = "0000-0002-0000-0011";
    let public_orcid = "0000-0002-0000-0012";
    sqlx::query("UPDATE agents SET orcid = $2, profile_visibility = 'group' WHERE id = $1")
        .bind(private_p)
        .bind(private_orcid)
        .execute(&pool)
        .await
        .expect("private profile");
    sqlx::query("UPDATE agents SET orcid = $2 WHERE id = $1")
        .bind(public_p)
        .bind(public_orcid)
        .execute(&pool)
        .await
        .expect("public profile");
    team_of(&pool, &[colleague, private_p]).await;
    // A team the former colleague still holds, whose membership of the
    // SUBJECT is revoked: the rule's `gm.revoked_at IS NULL` arm.
    let old_team = team_of(&pool, &[former, private_p]).await;
    sqlx::query(
        "UPDATE group_memberships SET revoked_at = now() WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(old_team)
    .bind(private_p)
    .execute(&pool)
    .await
    .expect("revoke the subject's membership");

    let scoped = app_pool(&pool).await;
    for (who, private_visible) in [
        (outsider, false),
        (former, false),
        (colleague, true),
        (private_p, true),
    ] {
        let v = viewer(&pool, who).await;
        let mut read = scoped.read_as(&v).await.expect("read_as");
        let got = profile_decisions(&mut read, &v, private_p, private_orcid).await;
        assert_eq!(got, [private_visible; 3], "private profile, viewer {who}");
        let got = profile_decisions(&mut read, &v, public_p, public_orcid).await;
        assert_eq!(got, [true; 3], "public profile, viewer {who}");
    }

    // An admin (a bypass viewer) sees both.
    let (bypass_pool, admin) = fixture::bypass(&pool).await;
    let (mut conn, _lease) = bypass_pool
        .unscoped_for_maintenance(SystemReason::SchemaContractTest)
        .await
        .expect("maintenance connection");
    assert_eq!(
        profile_decisions(&mut conn, &admin, private_p, private_orcid).await,
        [true; 3],
        "admin, private profile"
    );
}

// ---------------------------------------------------------------------------
// A human some agent is bound to reads as a human (backlog 0e419970)
// ---------------------------------------------------------------------------

/// `operator_human` is shown to every reader, so "X is the human some agent
/// is bound to" is public; the card used to show it only on the AGENT's card,
/// and X itself read `unknown` to outsiders unless it held a disclosed role.
/// Now X's own card says `human` (evidence `operator_of_bound_agent`) exactly
/// when some agent's card names X as its `operator_human`: the reverse is
/// derived from the forward binding rule, never from registration or client
/// status, so a retired link, a revoked allowance and an allowance on an
/// agent that also has a link name nobody, in either direction.
#[sqlx::test(migrations = "../../migrations")]
async fn a_human_some_agent_is_bound_to_reads_as_human_to_every_reader_it_is_named_to(
    pool: PgPool,
) {
    let (outsider, _) = named(&pool, "outsider").await;
    // Bound by a live link.
    let (h_link, _) = named_human(&pool, "Wenna Calloway").await;
    let (bot, _) = named(&pool, "calloway-bot").await;
    link(&pool, bot, h_link).await;
    // Bound by a client allowance in force.
    let (h_allow, _) = named_human(&pool, "Ruan Esterly").await;
    let (svc, _) = allowance_bound(&pool, h_allow, "esterly-service").await;
    // Named only by a retired link.
    let (h_retired, _) = named_human(&pool, "Odile Varga").await;
    let (old_bot, _) = named(&pool, "varga-bot").await;
    link(&pool, old_bot, h_retired).await;
    retire_link(&pool, old_bot).await;
    // Named only by a revoked allowance.
    let (h_revoked, _) = named_human(&pool, "Piet Lambrecht").await;
    let (gone_svc, gone_client) = allowance_bound(&pool, h_revoked, "lambrecht-service").await;
    let revoked: bool = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r: bool = sqlx::query_scalar(
            "SELECT revoked_now FROM public.epigraph_revoke_author_binding_client($1, \
                                                                              'lookup test')",
        )
        .bind(gone_client)
        .fetch_one(&mut *conn)
        .await
        .expect("revoke the allowance");
        (conn, r)
    })
    .await;
    assert!(revoked, "CALIBRATION: the allowance was live");
    // Named only by an unrevoked allowance on an agent that is now linked to
    // someone else (a linked agent is bound by its link alone).
    let (h_shadowed, _) = named_human(&pool, "Cleo Brandt").await;
    let (h_other, _) = named_human(&pool, "Tamsin Holt").await;
    let (moved_svc, moved_client) = allowance_bound(&pool, h_shadowed, "brandt-service").await;
    set_client_status(&pool, moved_client, "revoked").await;
    link(&pool, moved_svc, h_other).await;
    // A registered human no agent is bound to.
    let (h_lone, _) = named_human(&pool, "Ilka Dorne").await;
    let (plain, _) = named(&pool, "Ilka Dorne").await;
    // Every human above opted in: this test pins the binding's reverse
    // evidence to readers the human is NAMED to. An unnamed human shows no
    // human evidence at all (asserted at the end).
    for h in [
        h_link, h_allow, h_retired, h_revoked, h_shadowed, h_other, h_lone,
    ] {
        set_profile(&pool, h, "public").await;
    }

    let everyone = [
        outsider, h_link, bot, h_allow, svc, h_retired, old_bot, h_revoked, gone_svc, h_shadowed,
        h_other, moved_svc, h_lone, plain,
    ];
    let cards = cards_as(&pool, outsider, &everyone).await;
    let card = |id: Uuid| cards.iter().find(|c| c.id == id).expect("carded");

    for h in [h_link, h_allow, h_other] {
        let c = card(h);
        assert_eq!(c.kind, AgentKind::Human, "{c:?}");
        assert_eq!(c.kind_evidence, vec!["operator_of_bound_agent"], "{c:?}");
    }
    for h in [h_retired, h_revoked, h_shadowed, h_lone] {
        let c = card(h);
        assert_eq!(c.kind, AgentKind::Unknown, "{c:?}");
        assert_eq!(
            shape(c),
            shape(card(plain)),
            "an unbound human reads as an unregistered look-alike"
        );
    }

    // The reverse IS the forward rule: over every fixture agent, the agents
    // carrying the evidence are exactly the humans some card names.
    let mut reverse: Vec<Uuid> = cards
        .iter()
        .filter(|c| c.kind_evidence.contains(&"operator_of_bound_agent"))
        .map(|c| c.id)
        .collect();
    let mut forward: Vec<Uuid> = cards
        .iter()
        .filter_map(|c| c.operator_human.as_ref().map(|h| h.id))
        .collect();
    reverse.sort();
    forward.sort();
    forward.dedup();
    assert_eq!(reverse, forward);
    assert_eq!(forward.len(), 3, "CALIBRATION: h_link, h_allow, h_other");

    // Every reader sees it alike: the bound agent, another human.
    for who in [bot, h_allow] {
        let mut c = card_as(&pool, who, h_link).await;
        c.kind_evidence
            .retain(|e| *e != "registered_human_operator");
        assert_eq!(c.kind, AgentKind::Human);
        assert_eq!(c.kind_evidence, vec!["operator_of_bound_agent"]);
    }

    // And find_agent's kind filter finds the bound humans, never the others.
    let r = find_as(&pool, outsider, "wenna calloway", Some("human"), None, None).await;
    assert_eq!(ids(&r), vec![h_link]);
    let r = find_as(&pool, outsider, "odile varga", Some("human"), None, None).await;
    assert!(ids(&r).is_empty(), "a retired link's operator is no human");

    // A bound human that did NOT opt in: to an outsider its card reads as the
    // unregistered look-alike's, though its bot's card shows its id.
    let (h_hidden, _) = named_human(&pool, "Ilka Dorne").await;
    let (hidden_bot, _) = named(&pool, "dorne-bot").await;
    link(&pool, hidden_bot, h_hidden).await;
    let c = card_as(&pool, outsider, h_hidden).await;
    assert_eq!(c.kind, AgentKind::Unknown, "{c:?}");
    assert_eq!(shape(&c), shape(card(plain)));
    assert_eq!(
        card_as(&pool, outsider, hidden_bot)
            .await
            .operator_human
            .map(|h| (h.id, h.display_name)),
        Some((h_hidden, None)),
        "the id, never the name"
    );
}

/// Migration 269's definers: SECURITY DEFINER, maintenance-owned, on 172's
/// path, executable by the app role and not by PUBLIC.
#[sqlx::test(migrations = "../../migrations")]
async fn migration_269_definers_are_pinned_owned_and_granted(pool: PgPool) {
    for sig in [
        "public.epigraph_agents_linked_to_operator(uuid)",
        "public.epigraph_disclosed_role_attachments(uuid[])",
    ] {
        let row: (bool, String, Option<Vec<String>>, bool, bool) = sqlx::query_as(
            "SELECT p.prosecdef, r.rolname::text, p.proconfig, \
                    has_function_privilege('epigraph_app', p.oid, 'EXECUTE'), \
                    has_function_privilege('public', p.oid, 'EXECUTE') \
               FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
              WHERE p.oid = to_regprocedure($1)",
        )
        .bind(sig)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{sig} exists: {e}"));
        assert!(row.0, "{sig}: SECURITY DEFINER");
        assert_eq!(row.1, "epigraph_maintenance", "{sig}");
        assert_eq!(
            row.2,
            Some(vec!["search_path=pg_catalog, pg_temp".to_string()]),
            "{sig}"
        );
        assert!(row.3, "{sig}: the app role executes it");
        assert!(!row.4, "{sig}: PUBLIC does not");
    }
}

// ---------------------------------------------------------------------------
// Role attachments (166 `role_agents`) on the card (backlog 0e419970)
// ---------------------------------------------------------------------------

/// Attach `agent` to `role` through 166's maintenance verb.
async fn attach_to_role(pool: &PgPool, role: &str, agent: Uuid) {
    let role = role.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let _: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_attach_agent_to_role($1, $2, now() - interval '5 seconds', \
                                                         NULL, 'lookup test attach')",
        )
        .bind(&role)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("the maintenance role attaches");
        (conn, ())
    })
    .await;
}

/// The roles a card's `role_attachments` names, read from its JSON so the
/// test fails at RUN time on a card without the field.
fn attached_roles(card: &AgentCard) -> serde_json::Value {
    let v = serde_json::to_value(card).expect("serialize card");
    match v.get("role_attachments") {
        Some(serde_json::Value::Array(a)) => serde_json::Value::Array(
            a.iter()
                .map(|r| r.get("role").cloned().unwrap_or_default())
                .collect(),
        ),
        other => other.cloned().unwrap_or_default(),
    }
}

/// An LLM agent's role attachments (166 `role_agents`, which the application
/// role cannot read) are on its card for the agent itself, its LIVE human and
/// a privileged maintenance session (`epigraph_bypass()`), through migration
/// 269's `epigraph_disclosed_role_attachments`; undetached rows inside their
/// window only. Everyone else reads the card exactly as an unattached
/// look-alike's: attachments are shown to no outsider, of any role, until a
/// ruling says which may be (the elevating roles' never). Once the agent's
/// link is retired its former operator is no longer its human and sees none,
/// not even an attachment made after the retire.
#[sqlx::test(migrations = "../../migrations")]
async fn role_attachments_are_shown_to_the_agent_its_live_human_and_maintenance_sessions_only(
    pool: PgPool,
) {
    seed_role(&pool, "role:test-stewards", false).await;
    let (outsider, _) = named(&pool, "outsider").await;
    let (human, _) = named_human(&pool, "Hesper Lunde").await;
    let (other_human, _) = named_human(&pool, "Bryn Asker").await;
    let (bot, _) = named(&pool, "steward-bot").await;
    let (lookalike, _) = named(&pool, "steward-bot").await;
    link(&pool, bot, human).await;
    link(&pool, lookalike, human).await;
    attach_to_role(&pool, "role:test-stewards", bot).await;
    // An elevating role too (123's custodian role).
    attach_to_role(&pool, "role:platform-custodian", bot).await;

    let both = serde_json::json!(["role:platform-custodian", "role:test-stewards"]);
    for who in [bot, human] {
        let c = card_as(&pool, who, bot).await;
        assert_eq!(attached_roles(&c), both, "viewer {who}: {c:?}");
    }
    let (bypass_pool, admin) = fixture::bypass(&pool).await;
    {
        let (mut conn, _lease) = bypass_pool
            .unscoped_for_maintenance(SystemReason::SchemaContractTest)
            .await
            .expect("maintenance connection");
        let c = AgentLookupRepository::card(&mut conn, &admin, bot)
            .await
            .expect("card")
            .expect("exists");
        assert_eq!(attached_roles(&c), both, "admin");
    }

    // Nobody else: an outsider, another human, the human's other agent.
    for who in [outsider, other_human, lookalike] {
        let out = cards_as(&pool, who, &[bot, lookalike]).await;
        assert_eq!(
            attached_roles(&out[0]),
            serde_json::json!([]),
            "viewer {who}"
        );
        assert_eq!(
            shape(&out[0]),
            shape(&out[1]),
            "viewer {who} can tell the attached agent from its look-alike"
        );
    }

    // A detached attachment is not shown to anyone.
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let n: i32 = sqlx::query_scalar(
            "SELECT public.epigraph_detach_agent_from_role('role:platform-custodian', $1, 'done')",
        )
        .bind(bot)
        .fetch_one(&mut *conn)
        .await
        .expect("detach");
        assert_eq!(n, 1, "CALIBRATION: one attachment detached");
        (conn, ())
    })
    .await;
    assert_eq!(
        attached_roles(&card_as(&pool, bot, bot).await),
        serde_json::json!(["role:test-stewards"])
    );

    // A RETIRED link's former operator is no longer the agent's human: it
    // sees none of the agent's attachments, including one made after the
    // retire (166's attach does not need a live link). The agent itself and
    // a maintenance session still see both.
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
    seed_role(&pool, "role:test-archivists", false).await;
    attach_to_role(&pool, "role:test-archivists", bot).await;
    let after = serde_json::json!(["role:test-archivists", "role:test-stewards"]);
    assert_eq!(
        attached_roles(&card_as(&pool, bot, bot).await),
        after,
        "the agent itself"
    );
    {
        let (mut conn, _lease) = bypass_pool
            .unscoped_for_maintenance(SystemReason::SchemaContractTest)
            .await
            .expect("maintenance connection");
        let c = AgentLookupRepository::card(&mut conn, &admin, bot)
            .await
            .expect("card")
            .expect("exists");
        assert_eq!(attached_roles(&c), after, "maintenance session");
    }
    assert_eq!(
        attached_roles(&card_as(&pool, human, bot).await),
        serde_json::json!([]),
        "a retired link's former operator still reads the agent's attachments"
    );
    // The look-alike's link is still live: its human still reads it.
    attach_to_role(&pool, "role:test-archivists", lookalike).await;
    assert_eq!(
        attached_roles(&card_as(&pool, human, lookalike).await),
        serde_json::json!(["role:test-archivists"]),
        "CALIBRATION: a live human reads its agent's attachments"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn migration_269_attachments_refuse_more_than_200_agents(pool: PgPool) {
    let ids: Vec<Uuid> = (0..201).map(|_| Uuid::new_v4()).collect();
    let err = sqlx::query("SELECT * FROM public.epigraph_disclosed_role_attachments($1)")
        .bind(&ids)
        .fetch_all(&pool)
        .await
        .expect_err("201 ids refused");
    assert!(err.to_string().contains("at most 200"), "{err}");
    let ok = sqlx::query("SELECT * FROM public.epigraph_disclosed_role_attachments($1)")
        .bind(&ids[..200])
        .fetch_all(&pool)
        .await
        .expect("200 ids accepted");
    assert!(ok.is_empty());
}

// ---------------------------------------------------------------------------
// Paper author listings (spec 2026-11-24 human identity, row E1)
// ---------------------------------------------------------------------------

/// `PaperRepository::list_authors_by` (MCP `query_paper`, REST papers, the
/// `authored_by` literature block, the sources paper kind) lists a human
/// author a stranger's ingest named with NO name to an outsider, exactly as
/// it lists a nameless author node, and with its name to a teammate
/// (CALIBRATION); position and role are the ingester's edge data and show
/// alike.
#[sqlx::test(migrations = "../../migrations")]
async fn a_paper_lists_an_unnamed_human_author_without_its_name(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (stranger, _) = named(&pool, "stranger").await;
    let (human, _) = named_human(&pool, "Ysolde Authored").await;
    let (mate, _) = named(&pool, "ysolde-teammate").await;
    team_of(&pool, &[human, mate]).await;
    // A nameless author node at the next position, for the comparison.
    let (nameless, _) = named(&pool, "placeholder").await;
    sqlx::query("UPDATE agents SET display_name = NULL WHERE id = $1")
        .bind(nameless)
        .execute(&pool)
        .await
        .expect("nameless");
    let p = paper(&pool, "10.9999/lookup.unnamed-author.1").await;
    for (who, pos) in [(human, 0), (nameless, 1)] {
        assert!(
            ingest_edge_as_any(
                &pool,
                stranger,
                (who, "agent"),
                (p, "paper"),
                "authored",
                Some(serde_json::json!({"position": pos, "role": "author"})),
            )
            .await
        );
    }
    let list = |who: Uuid| {
        let pool = pool.clone();
        async move {
            let scoped = app_pool(&pool).await;
            let v = viewer(&pool, who).await;
            let mut read = scoped.read_as(&v).await.expect("read_as");
            epigraph_db::PaperRepository::list_authors_by(&mut *read, &v, p, stranger, 10)
                .await
                .expect("list_authors_by")
        }
    };
    let rows = list(outsider).await;
    assert_eq!(rows.len(), 2, "both authorships listed: {rows:?}");
    let h = rows.iter().find(|r| r.agent_id == human).expect("H listed");
    let n = rows
        .iter()
        .find(|r| r.agent_id == nameless)
        .expect("N listed");
    assert_eq!(h.display_name, None, "an outsider gets no name");
    assert_eq!(
        (
            h.display_name.clone(),
            h.role.clone(),
            h.affiliations.clone()
        ),
        (
            n.display_name.clone(),
            n.role.clone(),
            n.affiliations.clone()
        )
    );
    let rows = list(mate).await;
    let h = rows.iter().find(|r| r.agent_id == human).expect("H listed");
    assert_eq!(
        h.display_name.as_deref(),
        Some("Ysolde Authored"),
        "CALIBRATION"
    );
}
