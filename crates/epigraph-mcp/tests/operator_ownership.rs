//! `require_owner_or_admin`'s operator arm (migration 102), driven through the
//! REAL ownership-gated tools so the actual gate runs.
//!
//! # What is under test, and what is not
//!
//! The gate's decision depends on who authored the target claim and on the
//! operator links migration 102 records — never on RLS — so the superuser
//! `#[sqlx::test]` harness observes it faithfully: a refusal here is the gate's
//! refusal, and an admitted call is asserted by its committed effect
//! (`is_current` flipped, `resolved` label present), not by an `Ok` alone. The
//! RLS half of the feature (writer membership, app-role grants) is in
//! `epigraph-db/tests/operator_link.rs`.
//!
//! Stdio `patch_claim` / `update_labels` are ungated by design (issue #374's
//! carve-out), so a stdio "patch" arm would pass with or without this change.
//! Patching is therefore proven on the HTTP retirement-label path, where the
//! gate runs, and retirement on `supersede_claim` / `resolve_backlog_item`.
//!
//! The operator's HTTP principal is a stand-in agent, not the production
//! operator's id: this repository is public.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_crypto::AgentSigner;
use epigraph_db::AgentRepository;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::claims::{patch_claim, resolve_backlog_item, submit_claim};
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::{
    PatchClaimParams, ResolveBacklogItemParams, SubmitClaimParams, SupersedeClaimParams,
};
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

/// A declared-signer server (`--agent-key` / `--agent-model`, rungs 1-3) with a
/// stamped pool, and the agent id it signs as.
async fn server_with_seed(pool: &PgPool, seed: u8) -> (EpiGraphMcpFull, Uuid) {
    let scoped = fixture::scoped_pool(pool).await;
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    let server =
        EpiGraphMcpFull::new(pool.clone(), signer, embedder, false).with_scoped_pool(scoped);
    let id = server.server_agent_id().await.expect("server agent id");
    (server, id)
}

async fn agent(pool: &PgPool, label: &str) -> Uuid {
    fixture::seed_agent_with_group(pool, label).await.0
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link on the privileged harness connection");
    assert!(out.membership_live && out.link_live);
}

async fn link_retired(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_retired_agent(&mut conn, agent, operator)
        .await
        .expect("retired link on the privileged harness connection");
    assert!(out.link_retired && !out.membership_live, "{out:?}");
}

async fn personal_group(pool: &PgPool, agent: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("personal group")
}

/// A `('public', owner)` claim authored by `author`, labelled `backlog`.
async fn claim(pool: &PgPool, author: Uuid, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, ARRAY['backlog'], true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("operator-ownership claim {id}"))
    .bind(hash)
    .bind(author)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// A claim authored by `author` and owned by the author's own personal group.
async fn own_claim(pool: &PgPool, author: Uuid) -> Uuid {
    let g = personal_group(pool, author).await;
    claim(pool, author, g).await
}

fn http_auth(agent_id: Option<Uuid>) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id,
        // The login principal (owner_id) is NOT the graph agent; the existing
        // `principal == target` arm compares this, and must not be what admits.
        owner_id: Some(Uuid::new_v4()),
        client_type: ClientType::Human,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
    }
}

async fn supersede(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    target: Uuid,
    auth: Option<&AuthContext>,
) -> Result<(), String> {
    supersede_claim(
        server,
        &fixture::public_viewer(pool).await,
        SupersedeClaimParams {
            claim_id: target.to_string(),
            content: format!("replacement for {target}"),
            truth_value: 0.7,
            reason: "operator-ownership test".to_string(),
        },
        auth,
    )
    .await
    .map(|_| ())
    .map_err(|e| e.message.to_string())
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

async fn labels(pool: &PgPool, claim: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("labels")
}

// ─────────────────────────────────────────────────────────────────────────────
// ALLOWED
// ─────────────────────────────────────────────────────────────────────────────

/// Two agents under one operator — the model-bump case: the new identity may
/// retire (supersede) and resolve its sibling's claims over stdio, with a
/// DECLARED signer, where the pre-102 gate refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_sibling_agent_under_the_same_operator_may_retire_its_claims(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let (server, me) = server_with_seed(&pool, 0x51).await;
    let sibling = agent(&pool, "sibling").await;
    link(&pool, me, operator).await;
    link(&pool, sibling, operator).await;

    let c1 = own_claim(&pool, sibling).await;
    supersede(&server, &pool, c1, None)
        .await
        .expect("a sibling under the same operator must be able to supersede");
    assert!(!is_current(&pool, c1).await, "the supersede must commit");

    let c2 = own_claim(&pool, sibling).await;
    resolve_backlog_item(
        &server,
        &fixture::public_viewer(&pool).await,
        ResolveBacklogItemParams {
            original_id: c2.to_string(),
            resolution_content: "retired by a sibling agent".to_string(),
            methodology: None,
            basis_claim_ids: Vec::new(),
        },
        None,
    )
    .await
    .expect("a sibling under the same operator must be able to resolve a backlog item");
    assert!(labels(&pool, c2).await.contains(&"resolved".to_string()));
}

/// The operator's own HTTP principal (`auth.agent_id` = the operator; no
/// `claims:admin`; `owner_id` a different login id) may retire AND patch the
/// retirement label on its agents' claims.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operators_http_principal_may_retire_and_patch_its_agents_claims(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let (server, _unlinked_signer) = server_with_seed(&pool, 0x52).await;
    let operated = agent(&pool, "operated").await;
    link(&pool, operated, operator).await;
    let auth = http_auth(Some(operator));

    let c1 = own_claim(&pool, operated).await;
    supersede(&server, &pool, c1, Some(&auth))
        .await
        .expect("the operator's HTTP principal must be able to supersede its agent's claim");
    assert!(!is_current(&pool, c1).await);

    let c2 = own_claim(&pool, operated).await;
    patch_claim(
        &server,
        &fixture::public_viewer(&pool).await,
        PatchClaimParams {
            claim_id: c2.to_string(),
            trace_id: None,
            properties: None,
            add_labels: vec!["resolved".to_string()],
            remove_labels: Vec::new(),
        },
        Some(&auth),
    )
    .await
    .expect("the operator's HTTP principal must pass the retirement-label gate on patch_claim");
    assert!(labels(&pool, c2).await.contains(&"resolved".to_string()));
}

/// Stdio, where the server's own agent IS the operator.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operator_on_stdio_may_retire_its_agents_claims(pool: PgPool) {
    let (server, operator) = server_with_seed(&pool, 0x53).await;
    let operated = agent(&pool, "operated").await;
    link(&pool, operated, operator).await;

    let c = own_claim(&pool, operated).await;
    supersede(&server, &pool, c, None)
        .await
        .expect("the operator must be able to supersede its agent's claim");
    assert!(!is_current(&pool, c).await);
}

/// The ownership rule is exactly two arms (stage-2 brief A1): the operator
/// over its linked agents' claims, and an acting agent over its operator's
/// OTHER linked agents' claims. An operated agent does NOT own a claim its
/// operator authored directly: the operator itself has no link record, so
/// `author_op(operator)` is `None`. (An earlier revision had a third arm,
/// `op(caller) == target`; it was removed to keep the rule to the brief's two.
/// A human's other claims, of course, stay refused too.)
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_does_not_own_its_operators_directly_authored_claims(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let other_human = agent(&pool, "other-human").await;
    let (server, me) = server_with_seed(&pool, 0x54).await;
    link(&pool, me, operator).await;

    for author in [operator, other_human] {
        let c = own_claim(&pool, author).await;
        let err = supersede(&server, &pool, c, None)
            .await
            .expect_err("an operated agent must not own a claim authored by a human directly");
        assert!(err.contains("declared signer identity"), "{err}");
        assert!(is_current(&pool, c).await);
    }
}

/// A2 + A1: a RETIRED agent's claims — world-owned legacy ones and ones owned
/// by its own personal group — belong to its operator. The operator (HTTP,
/// `auth.agent_id` = operator) and an agent ACTING for the operator (stdio)
/// may both retire them. This is the TARGET side reading the author record,
/// retired included.
#[sqlx::test(migrations = "../../migrations")]
async fn the_operator_and_an_actor_sibling_own_a_retired_agents_claims(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let (actor_server, actor) = server_with_seed(&pool, 0x5B).await;
    link(&pool, actor, operator).await;
    let retired = agent(&pool, "retired").await;
    link_retired(&pool, retired, operator).await;
    let world = fixture::world_group(&pool).await;

    let legacy = claim(&pool, retired, world).await;
    supersede(&actor_server, &pool, legacy, None)
        .await
        .expect("an agent acting for the operator must own the retired agent's world-owned claim");
    assert!(!is_current(&pool, legacy).await);

    let own = own_claim(&pool, retired).await;
    let (other_server, _) = server_with_seed(&pool, 0x5C).await;
    supersede(&other_server, &pool, own, Some(&http_auth(Some(operator))))
        .await
        .expect("the operator must own its retired agent's claims");
    assert!(!is_current(&pool, own).await);
}

/// A2: a RETIRED identity can never act for its operator — not over a sibling
/// actor's claims, not over another retired sibling's. Its key may be exposed;
/// the CALLER side reads the actor record, which a retired link never is.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_agent_cannot_act_for_its_operator(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let (retired_server, retired) = server_with_seed(&pool, 0x5D).await;
    link_retired(&pool, retired, operator).await;
    let actor = agent(&pool, "actor").await;
    link(&pool, actor, operator).await;
    let other_retired = agent(&pool, "other-retired").await;
    link_retired(&pool, other_retired, operator).await;

    for author in [actor, other_retired] {
        let c = own_claim(&pool, author).await;
        let err = supersede(&retired_server, &pool, c, None)
            .await
            .expect_err("a retired identity must not act for its operator");
        assert!(err.contains("declared signer identity"), "{err}");
        assert!(is_current(&pool, c).await);
    }
}

/// The authoring half, end to end through `submit_claim`: an operated agent's
/// new claim is owned by the operator's personal group, and the operator's
/// HTTP principal may then retire it.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_from_an_operated_agent_is_owned_by_the_operator(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let (server, me) = server_with_seed(&pool, 0x55).await;
    link(&pool, me, operator).await;

    let out = submit_claim(
        &server,
        &fixture::public_viewer(&pool).await,
        SubmitClaimParams {
            content: format!("operated agent claim {}", Uuid::new_v4()),
            methodology: "direct_observation".to_string(),
            evidence_data: "operator ownership e2e".to_string(),
            evidence_type: "empirical".to_string(),
            confidence: 0.8,
            source_url: None,
            reasoning: Some("operator ownership".to_string()),
            labels: Vec::new(),
            novelty_threshold: Some(0.0),
        },
    )
    .await
    .expect("submit_claim");
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    let body: serde_json::Value = serde_json::from_str(&text).expect("json");
    let claim_id: Uuid = body["claim_id"]
        .as_str()
        .expect("claim_id")
        .parse()
        .expect("uuid");

    let (author, owner): (Uuid, Uuid) =
        sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(author, me, "authorship stays with the agent");
    assert_eq!(
        owner,
        personal_group(&pool, operator).await,
        "an operated agent's claim must be OWNED by the operator's personal group"
    );

    let (other_server, _) = server_with_seed(&pool, 0x56).await;
    supersede(
        &other_server,
        &pool,
        claim_id,
        Some(&http_auth(Some(operator))),
    )
    .await
    .expect("the operator may retire what its agent wrote");
}

// ─────────────────────────────────────────────────────────────────────────────
// STILL REFUSED
// ─────────────────────────────────────────────────────────────────────────────

/// An agent with NO link is refused exactly as before — both against an
/// operated target and against an unlinked one. The second pair is the
/// `None == None` case: two unlinked agents share no operator.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unlinked_agent_is_still_refused(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let (server, _me) = server_with_seed(&pool, 0x57).await;
    let operated = agent(&pool, "operated").await;
    let unlinked = agent(&pool, "unlinked").await;
    link(&pool, operated, operator).await;

    for target_author in [operated, unlinked] {
        let c = own_claim(&pool, target_author).await;
        let err = supersede(&server, &pool, c, None)
            .await
            .expect_err("an unlinked declared signer must still be refused");
        assert!(err.contains("declared signer identity"), "{err}");
        assert!(is_current(&pool, c).await, "a refusal must write nothing");
    }
}

/// An agent (stdio) or HTTP principal under a DIFFERENT operator is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_different_operator_is_refused(pool: PgPool) {
    let op_j = agent(&pool, "operator-j").await;
    let op_k = agent(&pool, "operator-k").await;
    let (server, me) = server_with_seed(&pool, 0x58).await;
    let j_agent = agent(&pool, "j-agent").await;
    let k_http_agent = agent(&pool, "k-http-agent").await;
    link(&pool, me, op_k).await;
    link(&pool, j_agent, op_j).await;
    link(&pool, k_http_agent, op_k).await;

    let c = own_claim(&pool, j_agent).await;
    let err = supersede(&server, &pool, c, None)
        .await
        .expect_err("an agent under operator K must not own operator J's agents' claims");
    assert!(err.contains("declared signer identity"), "{err}");

    for http_caller in [op_k, k_http_agent] {
        let err = supersede(&server, &pool, c, Some(&http_auth(Some(http_caller))))
            .await
            .expect_err("an HTTP caller under a different operator must be refused");
        assert!(err.contains("claims:admin"), "{err}");
    }
    assert!(is_current(&pool, c).await);
}

/// World-owned claims do NOT become ownable. The rule is keyed on AUTHORS, and
/// a world-owned claim by an unlinked author has no operator for anyone to
/// share — not the operator's HTTP principal, not its agents.
#[sqlx::test(migrations = "../../migrations")]
async fn world_owned_claims_do_not_become_ownable(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let (server, me) = server_with_seed(&pool, 0x59).await;
    link(&pool, me, operator).await;
    let legacy_author = agent(&pool, "legacy-author").await;
    let world = fixture::world_group(&pool).await;
    let c = claim(&pool, legacy_author, world).await;

    let err = supersede(&server, &pool, c, None)
        .await
        .expect_err("an operated agent must not own a world-owned claim");
    assert!(err.contains("declared signer identity"), "{err}");
    let err = supersede(&server, &pool, c, Some(&http_auth(Some(operator))))
        .await
        .expect_err("the operator must not own a world-owned claim it did not author");
    assert!(err.contains("claims:admin"), "{err}");
    assert!(is_current(&pool, c).await);
}

/// A revoked link grants nothing: the operator revokes the agent's writer
/// membership and the sibling arm closes with it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_link_grants_nothing(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let (server, me) = server_with_seed(&pool, 0x5A).await;
    let sibling = agent(&pool, "sibling").await;
    link(&pool, me, operator).await;
    link(&pool, sibling, operator).await;
    epigraph_db::GroupMembershipRepository::revoke_member_unless_last_admin(
        &pool,
        personal_group(&pool, operator).await,
        me,
    )
    .await
    .expect("revoke");

    let c = own_claim(&pool, sibling).await;
    let err = supersede(&server, &pool, c, None)
        .await
        .expect_err("a revoked link must not keep granting ownership");
    assert!(err.contains("declared signer identity"), "{err}");

    // ...while the OPERATOR keeps ownership of what the revoked agent wrote:
    // the target side reads the author record, not the membership.
    let mine = claim(&pool, me, fixture::world_group(&pool).await).await;
    let (other_server, _) = server_with_seed(&pool, 0x5E).await;
    supersede(&other_server, &pool, mine, Some(&http_auth(Some(operator))))
        .await
        .expect("revoking an agent must not take its claims away from the operator");
    assert!(!is_current(&pool, mine).await);
}

/// Review finding F12: on stdio the pre-102 undeclared-signer arm (warn and
/// allow) must behave exactly as before 102, including when the operator lookup
/// FAILS. The operator arm therefore runs after it.
///
/// The lookup is made to fail by dropping the author read (the state of a
/// database without migration 102's read).
///
/// * CALIBRATION: a DECLARED stdio signer's cross-agent supersede now surfaces
///   the lookup failure as an error (the gate does not decide ownership on an
///   answer it did not get), so the failure is real.
/// * The same supersede from an UNDECLARED signer is still allowed (its
///   pre-102 warn-and-allow), rather than turned into an internal error.
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_stdio_signer_keeps_its_pre_102_arm_when_the_operator_lookup_fails(
    pool: PgPool,
) {
    let author = agent(&pool, "author").await;
    let (declared, _) = server_with_seed(&pool, 0x5F).await;
    let (undeclared, _) = server_with_seed(&pool, 0x60).await;
    let undeclared = undeclared.with_generated_signer_identity();
    sqlx::query("DROP FUNCTION public.epigraph_operator_of_author(uuid)")
        .execute(&pool)
        .await
        .expect("drop the author read, as on a database without it");

    let c = own_claim(&pool, author).await;
    let err = supersede(&declared, &pool, c, None)
        .await
        .expect_err("CALIBRATION: a declared signer's operator lookup must fail here");
    assert!(
        err.contains("epigraph_operator_of_author"),
        "CALIBRATION: the refusal must be the failed lookup: {err}"
    );
    assert!(is_current(&pool, c).await);

    supersede(&undeclared, &pool, c, None).await.expect(
        "an undeclared stdio signer's cross-agent supersede must keep its pre-102 \
         warn-and-allow even when the operator lookup would fail",
    );
    assert!(!is_current(&pool, c).await);
}

/// Operated agents are stdio-only, and over HTTP that must hold even for a
/// token minted BEFORE the link (stage-2 review: A3 is enforced at mint).
///
/// * the actor arm is stdio-only: an actor's HTTP principal is REFUSED on its
///   sibling's claim, where the same actor over stdio is admitted;
/// * `request_viewer` gives an operated HTTP principal no viewer at all;
/// * CALIBRATION: the operator's own HTTP principal is still admitted on the
///   same claim, and still gets a viewer.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_has_no_operator_authority_over_http(pool: PgPool) {
    let operator = agent(&pool, "operator").await;
    let (actor_server, actor) = server_with_seed(&pool, 0x5E).await;
    let sibling = agent(&pool, "sibling").await;
    link(&pool, actor, operator).await;
    link(&pool, sibling, operator).await;
    let (http_server, _) = server_with_seed(&pool, 0x5F).await;

    let c = own_claim(&pool, sibling).await;
    let err = supersede(&http_server, &pool, c, Some(&http_auth(Some(actor))))
        .await
        .expect_err(
            "an operated agent's HTTP principal was granted the actor arm: a token minted before \
             its link would carry the operator's authority onto HTTP",
        );
    assert!(err.contains("claims:admin"), "{err}");
    assert!(is_current(&pool, c).await, "the refused supersede wrote");

    let refused =
        epigraph_mcp::tools::viewer::request_viewer(&http_server, Some(&http_auth(Some(actor))))
            .await;
    let err = refused.expect_err("an operated HTTP principal was given a viewer");
    assert!(err.message.contains("stdio-only"), "{}", err.message);

    // CALIBRATION: the same actor over stdio is admitted, and the operator's
    // own HTTP principal is admitted and gets a viewer.
    supersede(&actor_server, &pool, c, None)
        .await
        .expect("CALIBRATION: the actor over stdio acts for the operator");
    let c2 = own_claim(&pool, sibling).await;
    supersede(&http_server, &pool, c2, Some(&http_auth(Some(operator))))
        .await
        .expect("CALIBRATION: the operator's own HTTP principal is admitted");
    epigraph_mcp::tools::viewer::request_viewer(&http_server, Some(&http_auth(Some(operator))))
        .await
        .expect("CALIBRATION: the operator's HTTP principal gets a viewer");
}
