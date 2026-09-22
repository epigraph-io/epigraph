//! Behavioural tenancy tests for the MCP read surface (PR-09).
//!
//! The MCP mirror of `epigraph-api/tests/tenant_isolation_http.rs`.
//!
//! # Two things that make a test in this file mean something
//!
//! **1. The fixture must contain a `visibility = 'group'` row.** Migration 062
//! adds `visibility varchar(16) NOT NULL DEFAULT 'public'` and backfills
//! nothing, so on a default fixture *every* spliced viewer predicate matches
//! *every* row and an isolation assertion is vacuously true. Every case below
//! seeds through `fixture::seed_group_claim`, which sets `'group'` explicitly.
//! PR-07 learned this the hard way and had to hand-set the column on
//! `tenant_isolation_http.rs::belief_http_corpus`.
//!
//! **2. Every negative assertion has a positive counterpart (plan §8.4's
//! Class P).** "A stranger cannot read X" is passed by a mechanism that returns
//! nothing to anybody. Each test here asserts both directions against the same
//! fixture: the owner's viewer sees the private row, a stranger's does not.
//! Without the first half a fail-closed regression — the filter over-matching,
//! or the group bind going empty — looks exactly like success.
//!
//! # Falsification under mutation — what was actually run
//!
//! A test that passes with the predicate removed is not coverage. PR-07's
//! standard of proof is to break the mechanism and watch the test fail, so both
//! halves of PR-09's filtering were mutated separately — the two halves use
//! different spellings and one mutation cannot reach both.
//!
//! **M1 — the spliced sites.** `Viewer::predicate_fragment`'s `Scoped` arm was
//! given a trailing `OR true` (a tautology rather than an empty string, so the
//! statement keeps its bind arity and fails on rows, not on Postgres). Result:
//! `system_stats_hides_...`, `list_match_candidates_hides_...` and
//! `list_events_hides_...` **FAILED**; every Class-P counterpart still passed.
//! `recall_context_hides_...` was untouched, which is correct — `recall.rs`
//! uses `sqlx::query!` macros and never calls `splice`.
//!
//! **M2 — the macro sites.** `Viewer::bypass_bind()` was made to return `true`
//! unconditionally, which disables the static three-bind form
//! `($N::bool OR ... visibility = 'public' OR ...)` that the ten
//! `fetch_batched_context` macros carry. Result:
//! `recall_context_hides_a_private_sibling_paragraph` **FAILED**, and the three
//! splice-site `_hides_` tests passed — the complementary picture, as expected.
//!
//! Between them the two mutations kill every negative assertion in this file
//! and no positive one, which is the shape that says the assertions are reading
//! the predicate rather than an empty corpus.
//!
//! **One result in the M2 sweep was NOT a mutation kill and is recorded so the
//! table above is not read as cleaner than it was.**
//! `list_match_candidates_shows_the_owner_its_own_pair` also failed under M2,
//! which made no sense — `MatchCandidateRepo::list` goes through `splice` and
//! never reads `bypass_bind`. Chasing it turned up a defect in this file's own
//! fixture rather than in the code under test: `seed_candidate` inserted its
//! pair unsorted against a `claim_a < claim_b` CHECK, so it failed on about
//! half of all runs regardless of any mutation. Fixed below. The lesson is the
//! one this module doc is otherwise about — an unexplained failure in a
//! falsification sweep is evidence about the test, not decoration on the
//! result.
//!
//! # Why these use the tool functions, not the `#[tool_router]` dispatch
//!
//! Driving the router needs an `rmcp::service::RequestContext`, which the
//! surrounding integration tests do not synthesize either. The dispatch layer's
//! job — that a viewer is acquired at all — is covered as a source property by
//! `tool_viewer_coverage.rs::every_content_reading_tool_derives_a_viewer`. This
//! file covers the other half: that the acquired viewer changes the rows.

#![allow(clippy::wildcard_imports)]

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use common::{build_test_server, first_text};
use epigraph_db::visibility::Viewer;
use epigraph_mcp::types::{ListEventsParams, ListMatchCandidatesParams, SystemStatsParams};
use epigraph_mcp::{tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

/// Owner and stranger, each a real principal with a real personal group.
///
/// `fixture::seed_agent_with_group` mirrors `AgentRepository::ensure_personal_group`,
/// so `Viewer::resolve` finds a non-empty group set — the property that makes
/// the two viewers actually differ. `common::admin_auth()` is deliberately NOT
/// used: it carries `agent_id: None`, which after PR-09 is refused outright by
/// `request_viewer` and could never express membership anyway.
struct Tenants {
    owner: Uuid,
    owner_group: Uuid,
    owner_viewer: Viewer,
    stranger_viewer: Viewer,
}

async fn tenants(pool: &PgPool) -> Tenants {
    let (owner, owner_group) = fixture::seed_agent_with_group(pool, "owner").await;
    let (stranger, _stranger_group) = fixture::seed_agent_with_group(pool, "stranger").await;
    Tenants {
        owner,
        owner_group,
        owner_viewer: Viewer::resolve(pool, owner).await.expect("owner viewer"),
        stranger_viewer: Viewer::resolve(pool, stranger)
            .await
            .expect("stranger viewer"),
    }
}

fn claims_count(v: &serde_json::Value) -> i64 {
    v.get("claims")
        .and_then(serde_json::Value::as_i64)
        .expect("system_stats reports a claims count")
}

// ── system_stats ────────────────────────────────────────────────────────────
//
// The largest behaviour change in PR-09 and, before it, the one with no
// coverage at all: `tools/batch.rs::system_stats` already took a `&Viewer` and
// used it for exactly one call while issuing eight raw `SELECT COUNT(*)`
// statements beside it. No test asserted any of those counts, so "the suite
// stayed green" would have been evidence of nothing.

#[sqlx::test(migrations = "../../migrations")]
async fn system_stats_hides_a_group_private_claim_from_a_stranger(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let before = {
        let r = tools::batch::system_stats(
            &server,
            &t.stranger_viewer,
            SystemStatsParams { detailed: None },
        )
        .await
        .expect("stats");
        claims_count(&first_text(&r))
    };

    fixture::seed_group_claim(&pool, t.owner, t.owner_group, "owner's private claim").await;

    let after = {
        let r = tools::batch::system_stats(
            &server,
            &t.stranger_viewer,
            SystemStatsParams { detailed: None },
        )
        .await
        .expect("stats");
        claims_count(&first_text(&r))
    };

    assert_eq!(
        before, after,
        "a group-private claim the stranger is not a member of must not move \
         the stranger's claim count; system_stats was a corpus-cardinality \
         oracle before PR-09"
    );
}

/// Class P: the same fixture, from the owner's side.
#[sqlx::test(migrations = "../../migrations")]
async fn system_stats_shows_the_owner_its_own_group_private_claim(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let before = {
        let r = tools::batch::system_stats(
            &server,
            &t.owner_viewer,
            SystemStatsParams { detailed: None },
        )
        .await
        .expect("stats");
        claims_count(&first_text(&r))
    };

    fixture::seed_group_claim(&pool, t.owner, t.owner_group, "owner's private claim").await;

    let after = {
        let r = tools::batch::system_stats(
            &server,
            &t.owner_viewer,
            SystemStatsParams { detailed: None },
        )
        .await
        .expect("stats");
        claims_count(&first_text(&r))
    };

    assert_eq!(
        after,
        before + 1,
        "the owner must count its own group-private claim — a filter that \
         returns nothing to anybody passes the isolation assertion above and is \
         a fail-closed regression"
    );
}

/// A public claim is visible to both, which is what `public` means under D3
/// (any authenticated agent; there is no anonymous read path).
#[sqlx::test(migrations = "../../migrations")]
async fn system_stats_counts_a_public_claim_for_both_tenants(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let stranger_before = claims_count(&first_text(
        &tools::batch::system_stats(
            &server,
            &t.stranger_viewer,
            SystemStatsParams { detailed: None },
        )
        .await
        .expect("stats"),
    ));

    fixture::seed_public_claim(&pool, t.owner, "a public claim").await;

    let stranger_after = claims_count(&first_text(
        &tools::batch::system_stats(
            &server,
            &t.stranger_viewer,
            SystemStatsParams { detailed: None },
        )
        .await
        .expect("stats"),
    ));

    assert_eq!(
        stranger_after,
        stranger_before + 1,
        "`public` means any authenticated agent (D3); a stranger must count it"
    );
}

// ── list_match_candidates ───────────────────────────────────────────────────
//
// `match_candidates` has no tenancy column. Visibility is derived from the pair
// it names, and the leakiest column is `verifier_rationale` — free text an LLM
// wrote from BOTH claims' content.

/// Insert one `pending` candidate over the pair `{a, b}`.
///
/// The pair is sorted before insert. `match_candidates` carries a
/// `match_candidates_canonical_order` CHECK requiring `claim_a < claim_b`, and
/// the two claim ids here are `Uuid::new_v4()`s — so an unsorted fixture
/// violates the constraint on roughly half of all runs. It did: these two tests
/// passed in isolation, passed the first mutation sweep, and then failed inside
/// the full `--workspace` run on a different coin flip. A 50%-flaky fixture is
/// indistinguishable from a real mutation kill, which is exactly how it was
/// first mis-read as one.
async fn seed_candidate(pool: &PgPool, a: Uuid, b: Uuid) -> Uuid {
    let (a, b) = if a < b { (a, b) } else { (b, a) };
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO match_candidates (id, claim_a, claim_b, score, status, features, \
                                       verifier_rationale) \
         VALUES ($1, $2, $3, 0.9, 'pending', '{}'::jsonb, \
                 'both claims describe the same private result')",
    )
    .bind(id)
    .bind(a)
    .bind(b)
    .execute(pool)
    .await
    .expect("seed candidate");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_match_candidates_hides_a_pair_naming_a_private_claim(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let public = fixture::seed_public_claim(&pool, t.owner, "a public claim").await;
    let private = fixture::seed_group_claim(&pool, t.owner, t.owner_group, "a private claim").await;
    let candidate = seed_candidate(&pool, public, private).await;

    let out = tools::matching::list_match_candidates(
        &server,
        &t.stranger_viewer,
        ListMatchCandidatesParams {
            status: Some("pending".into()),
            limit: Some(50),
        },
    )
    .await
    .expect("list");
    let body = first_text(&out).to_string();

    assert!(
        !body.contains(&candidate.to_string()),
        "a candidate naming a claim the stranger cannot read must be absent, \
         not partially rendered — its verifier_rationale is derived from both \
         claims' content. Got: {body}"
    );
    assert!(
        !body.contains(&private.to_string()),
        "the private claim's id must not ride out on the candidate row: {body}"
    );
}

/// Class P.
#[sqlx::test(migrations = "../../migrations")]
async fn list_match_candidates_shows_the_owner_its_own_pair(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let public = fixture::seed_public_claim(&pool, t.owner, "a public claim").await;
    let private = fixture::seed_group_claim(&pool, t.owner, t.owner_group, "a private claim").await;
    let candidate = seed_candidate(&pool, public, private).await;

    let out = tools::matching::list_match_candidates(
        &server,
        &t.owner_viewer,
        ListMatchCandidatesParams {
            status: Some("pending".into()),
            limit: Some(50),
        },
    )
    .await
    .expect("list");
    let body = first_text(&out).to_string();

    assert!(
        body.contains(&candidate.to_string()),
        "the owner must still see a candidate over its own claims; otherwise the \
         filter is over-matching and the isolation assertion above is vacuous. \
         Got: {body}"
    );
}

// ── list_events ─────────────────────────────────────────────────────────────
//
// `events` has no tenancy column either, but the payload carries `claim_id`,
// `agent_id` and `initial_truth` (epigraph-events/src/events.rs).

async fn seed_event(pool: &PgPool, claim_id: Uuid) {
    sqlx::query(
        "INSERT INTO events (event_type, actor_id, payload, graph_version) \
         VALUES ('claim.created', NULL, jsonb_build_object('claim_id', $1::text, \
                 'initial_truth', 0.8), 1)",
    )
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("seed event");
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_events_hides_an_event_naming_a_private_claim(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let private = fixture::seed_group_claim(&pool, t.owner, t.owner_group, "private").await;
    seed_event(&pool, private).await;

    let out = tools::events::list_events(
        &server,
        &t.stranger_viewer,
        ListEventsParams {
            event_type: Some("claim.created".into()),
            actor_id: None,
            limit: Some(100),
        },
    )
    .await
    .expect("list_events");
    let body = first_text(&out).to_string();

    assert!(
        !body.contains(&private.to_string()),
        "an event payload naming a claim the stranger cannot read discloses that \
         claim's id and initial_truth; the event must be absent. Got: {body}"
    );
}

/// Class P, plus the "names no claim" case — the reason the filter is written
/// as `NOT EXISTS (<a payload uuid that resolves to a claim you cannot read>)`
/// rather than as a join predicate. Most events name no claim at all.
#[sqlx::test(migrations = "../../migrations")]
async fn list_events_shows_the_owner_its_event_and_keeps_claimless_events(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let private = fixture::seed_group_claim(&pool, t.owner, t.owner_group, "private").await;
    seed_event(&pool, private).await;
    sqlx::query(
        "INSERT INTO events (event_type, actor_id, payload, graph_version) \
         VALUES ('agent.registered', NULL, '{\"note\":\"no claim here\"}'::jsonb, 2)",
    )
    .execute(&pool)
    .await
    .expect("seed claimless event");

    let owner_body = first_text(
        &tools::events::list_events(
            &server,
            &t.owner_viewer,
            ListEventsParams {
                event_type: Some("claim.created".into()),
                actor_id: None,
                limit: Some(100),
            },
        )
        .await
        .expect("list_events"),
    )
    .to_string();
    assert!(
        owner_body.contains(&private.to_string()),
        "the owner must see the event for its own claim: {owner_body}"
    );

    let stranger_body = first_text(
        &tools::events::list_events(
            &server,
            &t.stranger_viewer,
            ListEventsParams {
                event_type: Some("agent.registered".into()),
                actor_id: None,
                limit: Some(100),
            },
        )
        .await
        .expect("list_events"),
    )
    .to_string();
    assert!(
        stranger_body.contains("no claim here"),
        "an event that names no claim must survive the filter — a rule written \
         as `every payload uuid must be visible` is vacuously true over an \
         empty uuid set, and that is the common case. Got: {stranger_body}"
    );
}

// ── fetch_batched_context ───────────────────────────────────────────────────
//
// The single largest fail-open PR-09 closes: ten statements, four of which
// selected `c.content` directly, all reached from a call site that already held
// a viewer and passed it to seven other calls.

#[sqlx::test(migrations = "../../migrations")]
async fn recall_context_hides_a_private_sibling_paragraph(pool: PgPool) {
    let t = tenants(&pool).await;

    // section --decomposes_to--> {public paragraph, private paragraph}
    let section = fixture::seed_public_claim(&pool, t.owner, "the section").await;
    set_level(&pool, section, 1).await;
    let public_para = fixture::seed_public_claim(&pool, t.owner, "the public paragraph").await;
    set_level(&pool, public_para, 2).await;
    let private_para =
        fixture::seed_group_claim(&pool, t.owner, t.owner_group, "SECRET paragraph text").await;
    set_level(&pool, private_para, 2).await;
    common::insert_claim_edge(&pool, section, public_para, "decomposes_to").await;
    common::insert_claim_edge(&pool, section, private_para, "decomposes_to").await;

    let ctx = tools::recall::__test_only::fetch_batched_context(
        &pool,
        &t.stranger_viewer,
        &[public_para],
        8,
        4,
        4,
    )
    .await
    .expect("batched context");

    let siblings = ctx
        .siblings_by_paragraph
        .get(&public_para)
        .cloned()
        .unwrap_or_default();
    assert!(
        siblings.iter().all(|s| s.paragraph_id != private_para),
        "a group-private sibling paragraph must not appear in a stranger's \
         recall context; its full `content` rides on the SiblingParagraph"
    );
    assert!(
        !ctx.paragraph_meta.contains_key(&private_para),
        "and its content must not arrive through paragraph_meta either"
    );
}

/// Class P: the owner still gets the sibling, with its content.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_context_shows_the_owner_its_private_sibling_paragraph(pool: PgPool) {
    let t = tenants(&pool).await;

    let section = fixture::seed_public_claim(&pool, t.owner, "the section").await;
    set_level(&pool, section, 1).await;
    let public_para = fixture::seed_public_claim(&pool, t.owner, "the public paragraph").await;
    set_level(&pool, public_para, 2).await;
    let private_para =
        fixture::seed_group_claim(&pool, t.owner, t.owner_group, "SECRET paragraph text").await;
    set_level(&pool, private_para, 2).await;
    common::insert_claim_edge(&pool, section, public_para, "decomposes_to").await;
    common::insert_claim_edge(&pool, section, private_para, "decomposes_to").await;

    let ctx = tools::recall::__test_only::fetch_batched_context(
        &pool,
        &t.owner_viewer,
        &[public_para],
        8,
        4,
        4,
    )
    .await
    .expect("batched context");

    let siblings = ctx
        .siblings_by_paragraph
        .get(&public_para)
        .cloned()
        .unwrap_or_default();
    assert!(
        siblings.iter().any(|s| s.paragraph_id == private_para),
        "the owner must still receive its own group-private sibling — without \
         this, an over-matching predicate looks identical to a correct one"
    );
}

// ── fetch_batched_context: the `edges` aliases (F-edges-unfiltered) ─────────
//
// The two tests above hide a neighbour whose CLAIMS row is private. These hide
// a PRIVATE EDGE between claims that are all public — the shape migration 070
// arm (b) keeps when an edge is declared ('group', G) between public endpoints.
// No claims predicate can withhold it; only the edge predicate can. The
// fixture exercises every one of the fifteen `edges` aliases, both `UNION ALL`
// arms of each bidirectional block included, and pins each hidden relation
// from both sides (stranger withheld, owner shown).

/// A claim→`target` edge of `relationship` from `source` of `source_type`,
/// returned by id so it can be privatised.
async fn edge_of(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    relationship: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, $3, 'claim', $4) RETURNING id",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("insert edge")
}

async fn private_edge_of(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    relationship: &str,
    group: Uuid,
) {
    let id = edge_of(pool, source, source_type, target, relationship).await;
    insert_edge_visibility(pool, id, group).await;
}

async fn leveled(pool: &PgPool, agent: Uuid, label: &str, level: Option<i32>) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, label).await;
    if let Some(l) = level {
        set_level(pool, id, l).await;
    }
    id
}

async fn paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO papers (doi, title) VALUES ($1, 'fixture') RETURNING id")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("insert paper")
}

/// Every claim public; every "hidden" relation is a group-private edge.
struct RecallEdges {
    p: Uuid,
    q: Uuid,
    p2: Uuid,
    p3: Uuid,
    p4: Uuid,
    a0: Uuid,
    a1: Uuid,
    x: Uuid,
    b0: Uuid,
    b1: Uuid,
    b2: Uuid,
    y: Uuid,
    n1: Uuid,
    n2: Uuid,
    n3: Uuid,
    n4: Uuid,
    n5: Uuid,
}

async fn recall_edge_fixture(pool: &PgPool, t: &Tenants) -> RecallEdges {
    let a = t.owner;
    let g = t.owner_group;
    let s = leveled(pool, a, "section S", Some(1)).await;
    let s2 = leveled(pool, a, "section S2", Some(1)).await;
    let p = leveled(pool, a, "paragraph P", Some(2)).await;
    let q = leveled(pool, a, "paragraph Q", Some(2)).await;
    let p2 = leveled(pool, a, "sibling P2", Some(2)).await;
    let p3 = leveled(pool, a, "continuation P3", Some(2)).await;
    let p4 = leveled(pool, a, "continued-from P4", Some(2)).await;
    let x = leveled(pool, a, "other parent X", Some(2)).await;
    let y = leveled(pool, a, "atom-b parent Y", Some(2)).await;
    let a0 = leveled(pool, a, "atom A0", Some(3)).await;
    let a1 = leveled(pool, a, "atom A1", Some(3)).await;
    let b0 = leveled(pool, a, "atom B0", Some(3)).await;
    let b1 = leveled(pool, a, "atom B1", Some(3)).await;
    let b2 = leveled(pool, a, "atom B2", Some(3)).await;
    let n1 = leveled(pool, a, "corroborator N1", None).await;
    let n2 = leveled(pool, a, "contradicted N2", None).await;
    let n3 = leveled(pool, a, "corroborator N3", None).await;
    let n4 = leveled(pool, a, "corroborating-in N4", None).await;
    let n5 = leveled(pool, a, "refuting-in N5", None).await;

    edge_of(pool, s, "claim", p, "decomposes_to").await;
    private_edge_of(pool, s, "claim", p2, "decomposes_to", g).await; // 6. sibling
    private_edge_of(pool, s2, "claim", q, "decomposes_to", g).await; // 3. section parent
    edge_of(pool, p, "claim", a0, "decomposes_to").await;
    private_edge_of(pool, p, "claim", a1, "decomposes_to", g).await; // 4. atom
    private_edge_of(pool, x, "claim", a0, "decomposes_to", g).await; // 5. bridge
    private_edge_of(pool, p, "claim", n1, "CORROBORATES", g).await; // 7. source arm
    private_edge_of(pool, n4, "claim", p, "CORROBORATES", g).await; // 7. target arm
    edge_of(pool, p, "claim", n3, "CORROBORATES").await;
    let paper_n3 = paper(pool, "10.0/hidden-n3").await;
    private_edge_of(pool, paper_n3, "paper", n3, "asserts", g).await; // 7. asserts_e
    private_edge_of(pool, p, "claim", n2, "contradicts", g).await; // 7b. source arm
    private_edge_of(pool, n5, "claim", p, "refutes", g).await; // 7b. target arm
    private_edge_of(pool, p, "claim", p3, "continues_argument", g).await; // 8. source arm
    private_edge_of(pool, p4, "claim", p, "continues_argument", g).await; // 8. target arm
    private_edge_of(pool, a0, "claim", b0, "supports", g).await; // 9. forward
    private_edge_of(pool, b2, "claim", a0, "supports", g).await; // 9. backward
    edge_of(pool, a0, "claim", b1, "supports").await;
    private_edge_of(pool, y, "claim", b1, "decomposes_to", g).await; // 10. atom_b parent
    let paper_p = paper(pool, "10.0/hidden-p").await;
    private_edge_of(pool, paper_p, "paper", p, "asserts", g).await; // 2. paper

    RecallEdges {
        p,
        q,
        p2,
        p3,
        p4,
        a0,
        a1,
        x,
        b0,
        b1,
        b2,
        y,
        n1,
        n2,
        n3,
        n4,
        n5,
    }
}

async fn edge_context(
    pool: &PgPool,
    viewer: &Viewer,
    f: &RecallEdges,
) -> tools::recall::__test_only::BatchedContext {
    tools::recall::__test_only::fetch_batched_context(pool, viewer, &[f.p, f.q], 8, 8, 8)
        .await
        .expect("batched context")
}

/// Which of the fixture's hidden relations a context exposes, one flag each.
fn exposed(
    ctx: &tools::recall::__test_only::BatchedContext,
    f: &RecallEdges,
) -> Vec<(&'static str, bool)> {
    let siblings = ctx
        .siblings_by_paragraph
        .get(&f.p)
        .cloned()
        .unwrap_or_default();
    let atoms = ctx
        .atoms_by_paragraph
        .get(&f.p)
        .cloned()
        .unwrap_or_default();
    let a0 = atoms.iter().find(|x| x.atom_id == f.a0);
    let corr = ctx
        .corroborates_by_paragraph
        .get(&f.p)
        .cloned()
        .unwrap_or_default();
    let epi = ctx
        .epistemic_edges_by_paragraph
        .get(&f.p)
        .cloned()
        .unwrap_or_default();
    let cont = ctx
        .continues_argument_by_paragraph
        .get(&f.p)
        .cloned()
        .unwrap_or_default();
    let links = ctx
        .atom_atom_links_by_atom
        .get(&f.a0)
        .cloned()
        .unwrap_or_default();
    let b1_parents = ctx
        .paragraphs_by_atom
        .get(&f.b1)
        .cloned()
        .unwrap_or_default();
    vec![
        (
            "3. section parent of Q",
            ctx.section_meta.contains_key(&f.q),
        ),
        ("4. atom A1 of P", atoms.iter().any(|x| x.atom_id == f.a1)),
        (
            "4. atoms_total of P counts A1",
            ctx.atoms_total_by_paragraph.get(&f.p) == Some(&2),
        ),
        (
            "5. bridge A0 -> X",
            a0.is_some_and(|x| x.bridge_to_paragraphs.contains(&f.x)),
        ),
        (
            "6. sibling P2 of P",
            siblings.iter().any(|x| x.paragraph_id == f.p2),
        ),
        (
            "7. CORROBORATES P -> N1",
            corr.iter().any(|x| x.claim_id == f.n1),
        ),
        (
            "7. CORROBORATES N4 -> P",
            corr.iter().any(|x| x.claim_id == f.n4),
        ),
        (
            "7. paper_doi of N3 via asserts_e",
            corr.iter()
                .any(|x| x.claim_id == f.n3 && x.paper_doi.is_some()),
        ),
        (
            "7b. contradicts P -> N2",
            epi.iter().any(|x| x.claim_id == f.n2),
        ),
        (
            "7b. refutes N5 -> P",
            epi.iter().any(|x| x.claim_id == f.n5),
        ),
        ("8. continues_argument P -> P3", cont.contains(&f.p3)),
        ("8. continues_argument P4 -> P", cont.contains(&f.p4)),
        (
            "9. atom link A0 -> B0",
            links.iter().any(|(b, _)| *b == f.b0),
        ),
        (
            "9. atom link B2 -> A0",
            links.iter().any(|(b, _)| *b == f.b2),
        ),
        ("10. parent Y of B1", b1_parents.contains(&f.y)),
        ("2. paper of P", ctx.paper_meta.contains_key(&f.p)),
    ]
}

#[sqlx::test(migrations = "../../migrations")]
async fn recall_context_withholds_every_private_edge_between_public_claims(pool: PgPool) {
    let t = tenants(&pool).await;
    let f = recall_edge_fixture(&pool, &t).await;
    let ctx = edge_context(&pool, &t.stranger_viewer, &f).await;

    let leaked: Vec<&str> = exposed(&ctx, &f)
        .into_iter()
        .filter_map(|(what, shown)| shown.then_some(what))
        .collect();
    assert!(
        leaked.is_empty(),
        "every claim in this fixture is public and each listed relation is a \
         group-private EDGE; a stranger's recall context must expose none of \
         them. Leaked: {leaked:?}"
    );

    // The public relations beside them still arrive, so the empty list above
    // is not an empty context.
    let corr = ctx
        .corroborates_by_paragraph
        .get(&f.p)
        .cloned()
        .unwrap_or_default();
    assert!(
        corr.iter().any(|x| x.claim_id == f.n3),
        "public N3 still corroborates P"
    );
    let links = ctx
        .atom_atom_links_by_atom
        .get(&f.a0)
        .cloned()
        .unwrap_or_default();
    assert!(
        links.iter().any(|(b, _)| *b == f.b1),
        "public A0 -> B1 still links"
    );
    assert_eq!(
        ctx.atoms_total_by_paragraph.get(&f.p),
        Some(&1),
        "P's atom total counts only the public child"
    );
}

/// Class P: the owner — a member of every private edge's group — sees all of
/// them on the same fixture.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_context_shows_the_owner_every_private_edge(pool: PgPool) {
    let t = tenants(&pool).await;
    let f = recall_edge_fixture(&pool, &t).await;
    let ctx = edge_context(&pool, &t.owner_viewer, &f).await;

    let missing: Vec<&str> = exposed(&ctx, &f)
        .into_iter()
        .filter_map(|(what, shown)| (!shown).then_some(what))
        .collect();
    assert!(
        missing.is_empty(),
        "the owner must receive every relation the stranger is denied — without \
         this an over-matching edge predicate looks identical to a correct one. \
         Missing: {missing:?}"
    );
}

/// The static edge form is the co-owner INTERSECTION, not `owner_group_id`
/// alone. An edge co-owned by G and H (migration 072's cross-group shape) must
/// not reach a principal in G only — here, the owner. A transcription that
/// dropped the `co_owner_group_id` clause would pass every other test in this
/// file, because none of their edges has a co-owner.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_context_withholds_a_co_owned_edge_from_a_member_of_one_owner(pool: PgPool) {
    let t = tenants(&pool).await;
    let (_other, other_group) = fixture::seed_agent_with_group(&pool, "co-owner").await;
    let p = leveled(&pool, t.owner, "paragraph P", Some(2)).await;
    let n = leveled(&pool, t.owner, "corroborator N", None).await;
    let e = edge_of(&pool, p, "claim", n, "CORROBORATES").await;

    let before = edge_context_for(&pool, &t.owner_viewer, p).await;
    assert!(
        before
            .corroborates_by_paragraph
            .get(&p)
            .is_some_and(|v| v.iter().any(|x| x.claim_id == n)),
        "calibration: while the edge is public the owner receives N"
    );

    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = $3 \
         WHERE id = $1",
    )
    .bind(e)
    .bind(t.owner_group)
    .bind(other_group)
    .execute(&pool)
    .await
    .expect("co-own the edge");

    let after = edge_context_for(&pool, &t.owner_viewer, p).await;
    assert!(
        !after
            .corroborates_by_paragraph
            .get(&p)
            .is_some_and(|v| v.iter().any(|x| x.claim_id == n)),
        "the owner is a member of the edge's owner_group only, not its \
         co_owner_group; membership in one of the two groups must not be enough"
    );
}

async fn edge_context_for(
    pool: &PgPool,
    viewer: &Viewer,
    paragraph: Uuid,
) -> tools::recall::__test_only::BatchedContext {
    tools::recall::__test_only::fetch_batched_context(pool, viewer, &[paragraph], 8, 8, 8)
        .await
        .expect("batched context")
}

/// `properties->>'level'` is what the recall queries key on; the fixture's
/// `seed_claim` does not set it.
async fn set_level(pool: &PgPool, claim: Uuid, level: i32) {
    sqlx::query(
        "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) \
                                        || jsonb_build_object('level', $2::int) \
         WHERE id = $1",
    )
    .bind(claim)
    .bind(level)
    .execute(pool)
    .await
    .expect("set level");
}

// ── list_events: payload shapes that carry no `claim_id` key ────────────────
//
// The first revision of `EventRepository::list` keyed on
// `payload->>'claim_id'` alone and was default-OPEN for every other shape,
// while its doc asserted the opposite. The live emitters refute the narrow
// rule directly, so these two cases pin the rule the SQL now actually has:
// *any* uuid anywhere in the payload that names a claim the viewer cannot read
// drops the event.

/// The `conflict.resolved` shape, verbatim from
/// `epigraph-api/src/routes/conflicts.rs`: three claim ids, none of them under
/// the key `claim_id`. Under the narrow rule every one of them reached a
/// stranger.
#[sqlx::test(migrations = "../../migrations")]
async fn list_events_hides_an_event_whose_payload_names_a_private_claim_under_another_key(
    pool: PgPool,
) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let private_a = fixture::seed_group_claim(&pool, t.owner, t.owner_group, "private A").await;
    let private_b = fixture::seed_group_claim(&pool, t.owner, t.owner_group, "private B").await;

    sqlx::query(
        "INSERT INTO events (event_type, actor_id, payload, graph_version) \
         VALUES ('conflict.resolved', NULL, \
                 jsonb_build_object('claim_a_id', $1::text, 'claim_b_id', $2::text, \
                                    'winner_id', $1::text), 11)",
    )
    .bind(private_a)
    .bind(private_b)
    .execute(&pool)
    .await
    .expect("seed conflict.resolved event");

    let body = first_text(
        &tools::events::list_events(
            &server,
            &t.stranger_viewer,
            ListEventsParams {
                event_type: Some("conflict.resolved".into()),
                actor_id: None,
                limit: Some(100),
            },
        )
        .await
        .expect("list_events"),
    )
    .to_string();

    assert!(
        !body.contains(&private_a.to_string()) && !body.contains(&private_b.to_string()),
        "a `conflict.resolved` payload names its claims under `claim_a_id` / \
         `claim_b_id` / `winner_id` and NEVER under `claim_id`. A filter keyed \
         on `claim_id` passes this row through untouched. Got: {body}"
    );

    // Class P, on the same fixture: the rule must not be "drop everything".
    let owner_body = first_text(
        &tools::events::list_events(
            &server,
            &t.owner_viewer,
            ListEventsParams {
                event_type: Some("conflict.resolved".into()),
                actor_id: None,
                limit: Some(100),
            },
        )
        .await
        .expect("list_events"),
    )
    .to_string();
    assert!(
        owner_body.contains(&private_a.to_string()),
        "the owner must still receive its own conflict event: {owner_body}"
    );
}

/// A uuid that resolves to no `claims` row is deliberately NOT a reason to drop
/// an event — otherwise `graph_snapshot`'s replay would depend on referential
/// integrity rather than on visibility, and an `agent_id` in a payload would
/// suppress the event carrying it.
#[sqlx::test(migrations = "../../migrations")]
async fn list_events_keeps_an_event_whose_payload_uuid_names_no_claim(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let orphan = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO events (event_type, actor_id, payload, graph_version) \
         VALUES ('workflow.created', NULL, \
                 jsonb_build_object('goal', 'mentions ' || $1::text, 'marker', 'KEEPME'), 12)",
    )
    .bind(orphan)
    .execute(&pool)
    .await
    .expect("seed orphan-uuid event");

    let body = first_text(
        &tools::events::list_events(
            &server,
            &t.stranger_viewer,
            ListEventsParams {
                event_type: Some("workflow.created".into()),
                actor_id: None,
                limit: Some(100),
            },
        )
        .await
        .expect("list_events"),
    )
    .to_string();

    assert!(
        body.contains("KEEPME"),
        "a uuid naming no claims row has no owner to protect and must not \
         suppress its event — dropping it would make the filter a referential \
         -integrity check. Got: {body}"
    );
}

// ── system_stats, `detailed` branch ─────────────────────────────────────────

fn detail_count(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key)
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(|| panic!("system_stats detailed must report `{key}`: {v}"))
}

/// `detailed = true` builds a SECOND spliced statement (three markers,
/// including one over `challenges`). Nothing executed it: every other
/// `SystemStatsParams` in the tree passes `detailed: None`, and it is a raw
/// `query_as`, so there is no compile-time schema check either.
#[sqlx::test(migrations = "../../migrations")]
async fn system_stats_detailed_counts_narrow_for_a_stranger_and_widen_for_the_owner(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    // An `async fn` rather than a closure returning `async move`: a closure's
    // return type cannot name the lifetime of its own `&Viewer` argument, which
    // is why the previous shape had to clone the viewer to get a `'static`-ish
    // future. `epigraph_db::Viewer` is no longer `Clone`, and this borrows it
    // for exactly the call that spends it — which is what the test wanted all
    // along.
    async fn stats(server: &EpiGraphMcpFull, viewer: &Viewer) -> serde_json::Value {
        first_text(
            &tools::batch::system_stats(
                server,
                viewer,
                SystemStatsParams {
                    detailed: Some(true),
                },
            )
            .await
            .expect("detailed stats"),
        )
    }

    let stranger_before = detail_count(&stats(&server, &t.stranger_viewer).await, "workflows");
    let owner_before = detail_count(&stats(&server, &t.owner_viewer).await, "workflows");

    let private =
        fixture::seed_group_claim(&pool, t.owner, t.owner_group, "a private workflow claim").await;
    sqlx::query("UPDATE claims SET labels = ARRAY['workflow']::text[] WHERE id = $1")
        .bind(private)
        .execute(&pool)
        .await
        .expect("label the claim");

    assert_eq!(
        detail_count(&stats(&server, &t.stranger_viewer).await, "workflows"),
        stranger_before,
        "the stranger's `workflows` count must not move for a group-private \
         claim it cannot read"
    );
    assert_eq!(
        detail_count(&stats(&server, &t.owner_viewer).await, "workflows"),
        owner_before + 1,
        "the owner must count its own — without this the assertion above is \
         satisfied by a statement that returns nothing to anybody"
    );
}

// ── suggest_alternative_sets ────────────────────────────────────────────────
//
// Three claims and three edges. The edge predicates are the point: the
// `contradicts` edge alone being invisible must suppress the pair, because the
// `reason` string asserts that edge exists.

async fn insert_edge_visibility(pool: &PgPool, edge: Uuid, group: Uuid) {
    sqlx::query("UPDATE edges SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(edge)
        .bind(group)
        .execute(pool)
        .await
        .expect("privatise edge");
}

/// Seed a target `T`, two supporters `A`/`B`, `A→T`, `B→T` and `A↔B`
/// contradicts. Returns `(target, a, b, contradicts_edge_id)`.
async fn seed_alternative_fixture(pool: &PgPool, agent: Uuid) -> (Uuid, Uuid, Uuid, Uuid) {
    let target = fixture::seed_public_claim(pool, agent, "the shared target").await;
    let a = fixture::seed_public_claim(pool, agent, "supporter A").await;
    let b = fixture::seed_public_claim(pool, agent, "supporter B").await;
    for c in [a, b] {
        sqlx::query("UPDATE claims SET pignistic_prob = 0.9 WHERE id = $1")
            .bind(c)
            .execute(pool)
            .await
            .expect("set BetP");
        common::insert_claim_edge(pool, c, target, "supports").await;
    }
    common::insert_claim_edge(pool, a, b, "contradicts").await;
    let contr: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges WHERE relationship = 'contradicts' \
           AND source_id = $1 AND target_id = $2",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("find the contradicts edge");
    (target, a, b, contr)
}

#[sqlx::test(migrations = "../../migrations")]
async fn suggest_alternative_sets_hides_a_pair_whose_contradicts_edge_is_private(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let (target, a, _b, contr) = seed_alternative_fixture(&pool, t.owner).await;

    // Class P first, on the SAME fixture and before the mutation: with every
    // row public the stranger DOES get the pair. Without this the assertion
    // below is satisfied by a scan that finds nothing for any reason at all.
    let before = first_text(
        &tools::alternative_sets::suggest_alternative_sets(
            &server,
            &t.stranger_viewer,
            alt_params(target),
        )
        .await
        .expect("suggest"),
    )
    .to_string();
    assert!(
        before.contains(&a.to_string()),
        "the fixture must produce a suggestion when everything is public, or \
         the hiding assertion below proves nothing. Got: {before}"
    );

    insert_edge_visibility(&pool, contr, t.owner_group).await;

    let after = first_text(
        &tools::alternative_sets::suggest_alternative_sets(
            &server,
            &t.stranger_viewer,
            alt_params(target),
        )
        .await
        .expect("suggest"),
    )
    .to_string();
    assert!(
        !after.contains(&a.to_string()),
        "all three claims are public but the `contradicts` edge between the \
         supporters is group-private. The response's own `reason` asserts that \
         edge exists, so the pair must be suppressed. Got: {after}"
    );

    // Class P, second half: the owner — who is a member of the edge's group —
    // still gets it.
    let owner_after = first_text(
        &tools::alternative_sets::suggest_alternative_sets(
            &server,
            &t.owner_viewer,
            alt_params(target),
        )
        .await
        .expect("suggest"),
    )
    .to_string();
    assert!(
        owner_after.contains(&a.to_string()),
        "the owner must still receive the pair: {owner_after}"
    );
}

fn alt_params(target: Uuid) -> epigraph_mcp::tools::alternative_sets::SuggestAlternativeSetsParams {
    epigraph_mcp::tools::alternative_sets::SuggestAlternativeSetsParams {
        target_claim_id: Some(target.to_string()),
        min_pair_strength: 0.1,
        exclude_settled: false,
        surface_reconsiderations: false,
    }
}

// ── find_cross_source_matches ───────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn find_cross_source_matches_hides_a_corroborates_edge_to_a_private_claim(pool: PgPool) {
    let t = tenants(&pool).await;
    let server = build_test_server(pool.clone());

    let anchor = fixture::seed_public_claim(&pool, t.owner, "the anchor claim").await;
    let private =
        fixture::seed_group_claim(&pool, t.owner, t.owner_group, "the private far end").await;
    common::insert_claim_edge(&pool, anchor, private, "CORROBORATES").await;

    let stranger = first_text(
        &tools::matching::find_cross_source_matches(
            &server,
            &t.stranger_viewer,
            epigraph_mcp::types::FindCrossSourceMatchesParams {
                claim_id: anchor.to_string(),
            },
        )
        .await
        .expect("find_cross_source_matches"),
    )
    .to_string();
    assert!(
        !stranger.contains(&private.to_string()),
        "a CORROBORATES edge whose far end is a claim the stranger cannot read \
         discloses that claim's id. Got: {stranger}"
    );

    let owner = first_text(
        &tools::matching::find_cross_source_matches(
            &server,
            &t.owner_viewer,
            epigraph_mcp::types::FindCrossSourceMatchesParams {
                claim_id: anchor.to_string(),
            },
        )
        .await
        .expect("find_cross_source_matches"),
    )
    .to_string();
    assert!(
        owner.contains(&private.to_string()),
        "the owner must still see the edge to its own claim: {owner}"
    );
}

// ── embedding_neighborhood_density ──────────────────────────────────────────
//
// Exercised at the repo layer rather than through the tool, because the tool
// embeds `params.query` through `server.embedder`, which needs a live provider.
// The two statements are the whole of what PR-09 changed there, and the
// breakdown is the sharper of the two leaks: it answers "is there private
// material near this topic, and of what level and source type" without ever
// returning an id.

/// A 1536-dimension pgvector literal that is 1.0 in one slot and 0 elsewhere.
fn unit_vector(slot: usize) -> String {
    let mut v = vec!["0"; 1536];
    v[slot] = "1";
    format!("[{}]", v.join(","))
}

async fn set_embedding(pool: &PgPool, claim: Uuid, slot: usize) {
    sqlx::query("UPDATE claims SET embedding = $2::vector WHERE id = $1")
        .bind(claim)
        .bind(unit_vector(slot))
        .execute(pool)
        .await
        .expect("set embedding");
}

#[sqlx::test(migrations = "../../migrations")]
async fn embedding_neighborhood_hides_a_private_claim_from_both_density_and_breakdown(
    pool: PgPool,
) {
    let t = tenants(&pool).await;

    let private = fixture::seed_group_claim(&pool, t.owner, t.owner_group, "private near").await;
    set_embedding(&pool, private, 0).await;
    sqlx::query(
        "UPDATE claims SET properties = jsonb_build_object('level', 2, \
                                                           'source_type', 'lab-notebook') \
         WHERE id = $1",
    )
    .bind(private)
    .execute(&pool)
    .await
    .expect("set properties");

    let probe = unit_vector(0);

    let (stranger_n, _, _) = epigraph_db::ClaimRepository::embedding_radius_density(
        &pool,
        &t.stranger_viewer,
        &probe,
        0.5,
    )
    .await
    .expect("density");
    assert_eq!(
        stranger_n, 0,
        "a group-private claim inside the radius must not be counted for a \
         stranger — the count alone is a membership oracle over any \
         caller-chosen probe"
    );

    let stranger_rows = epigraph_db::ClaimRepository::embedding_radius_breakdown(
        &pool,
        &t.stranger_viewer,
        &probe,
        0.5,
        500,
    )
    .await
    .expect("breakdown");
    assert!(
        stranger_rows.is_empty(),
        "the level/source_type histogram is the sharper leak: it discloses that \
         private material exists near the probe, and of what kind, without \
         returning an id. Got: {stranger_rows:?}"
    );

    // Class P for both statements.
    let (owner_n, _, _) =
        epigraph_db::ClaimRepository::embedding_radius_density(&pool, &t.owner_viewer, &probe, 0.5)
            .await
            .expect("density");
    assert_eq!(
        owner_n, 1,
        "the owner must count its own claim, or both assertions above are \
         satisfied by a predicate that matches nothing"
    );
    let owner_rows = epigraph_db::ClaimRepository::embedding_radius_breakdown(
        &pool,
        &t.owner_viewer,
        &probe,
        0.5,
        500,
    )
    .await
    .expect("breakdown");
    assert_eq!(owner_rows.len(), 1, "and must see it in the breakdown too");
}
