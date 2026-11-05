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
async fn a_hidden_operator_link_is_indistinguishable_from_none(pool: PgPool) {
    let (outsider, _) = named(&pool, "outsider").await;
    let (human, _) = named_human(&pool, "Talia Brennick").await;
    let (linked, _) = named(&pool, "helper-bot").await;
    let (unlinked, _) = named(&pool, "helper-bot").await;
    link(&pool, linked, human).await;

    let out = cards_as(&pool, outsider, &[linked, unlinked]).await;
    assert_eq!(
        shape(&out[0]),
        shape(&out[1]),
        "an outsider cannot tell the link"
    );
    assert!(out[0].operator_human.is_none());
    assert_eq!(out[0].kind, AgentKind::Unknown);

    // The linked human passes the D4 gate: it sees itself named, and the kind.
    let mine = card_as(&pool, human, linked).await;
    assert_eq!(mine.operator_human.as_ref().map(|h| h.id), Some(human));
    assert_eq!(
        mine.operator_human
            .as_ref()
            .and_then(|h| h.display_name.as_deref()),
        Some("Talia Brennick")
    );
    assert_eq!(mine.kind, AgentKind::LlmAgent);
    assert!(mine.kind_evidence.contains(&"bound_to_visible_human"));

    // The agent itself is not its human: D4 does not admit it.
    let itself = card_as(&pool, linked, linked).await;
    assert!(itself.operator_human.is_none());

    // find_agent: same differential, through the search path.
    let r = find_as(&pool, outsider, "helper-bot", None, None, None).await;
    assert_eq!(r.results.len(), 2);
    let a = serde_json::to_value(&r.results[0]).unwrap();
    let b = serde_json::to_value(&r.results[1]).unwrap();
    let strip = |mut v: serde_json::Value| {
        let o = v.as_object_mut().unwrap();
        o.remove("id");
        o.remove("display_name");
        o.remove("created_at");
        v
    };
    assert_eq!(strip(a), strip(b));
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
    let via_agent = card_as(&pool, agent_of_human, human).await;
    assert_eq!(
        via_agent.kind,
        AgentKind::Human,
        "its own agent knows its human"
    );
    assert!(via_agent
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
