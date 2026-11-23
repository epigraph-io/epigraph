//! Integration tests for `derive_source_key`.
//!
//! Requires a live PostgreSQL database reachable via `DATABASE_URL`.
//! Tests skip automatically when the database is unavailable.

use epigraph_engine::matching::source_key::derive_source_key;
use sqlx::PgPool;
use uuid::Uuid;

// --- seed helpers ---

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("insert agent");
    id
}

async fn insert_claim_with_properties(
    pool: &PgPool,
    agent_id: Uuid,
    properties: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, properties)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent_id)
    .bind(properties)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

async fn insert_claim(pool: &PgPool, agent_id: Uuid) -> Uuid {
    insert_claim_with_properties(pool, agent_id, serde_json::json!({})).await
}

async fn insert_paper(pool: &PgPool, doi: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(doi)
        .bind(format!("paper {}", id))
        .execute(pool)
        .await
        .expect("insert paper");
    id
}

async fn insert_asserts_edge(pool: &PgPool, paper_id: Uuid, claim_id: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper_id)
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("insert asserts edge");
}

async fn insert_derived_from(pool: &PgPool, child: Uuid, parent: Uuid) {
    // source_type and target_type are NOT NULL; both are 'claim' here.
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', 'derived_from')",
    )
    .bind(child)
    .bind(parent)
    .execute(pool)
    .await
    .expect("insert derived_from edge");
}

// --- tests ---

#[sqlx::test(migrations = "../../migrations")]
async fn derive_extracts_paper_doi_from_asserts_edge(pool: PgPool) {
    // Canonical paper provenance is relational: the DOI lives on the papers
    // row and is reached via a paper -asserts-> claim edge, NOT in
    // properties->>'paper_doi' (which no write path ever populates).
    let agent_id = insert_agent(&pool).await;
    let claim_id = insert_claim(&pool, agent_id).await;
    let paper_id = insert_paper(&pool, "10.1/regression").await;
    insert_asserts_edge(&pool, paper_id, claim_id).await;

    let key = derive_source_key(&pool, claim_id).await.expect("derive");
    assert_eq!(key.paper_dois, vec!["10.1/regression".to_string()]);
    assert_eq!(key.agent_id, agent_id);
    assert_eq!(key.derivation_root, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn derive_chases_derivation_root(pool: PgPool) {
    let agent_id = insert_agent(&pool).await;
    let root = insert_claim(&pool, agent_id).await;
    let mid = insert_claim(&pool, agent_id).await;
    let leaf = insert_claim(&pool, agent_id).await;
    insert_derived_from(&pool, mid, root).await;
    insert_derived_from(&pool, leaf, mid).await;
    let key = derive_source_key(&pool, leaf).await.expect("derive");
    assert_eq!(key.derivation_root, Some(root));
}

/// 50b19b4e: a claim asserted by TWO papers keeps both DOIs, so a claim that
/// shares only the second paper is still detected as same-source. The DOIs are
/// chosen so the non-shared one sorts first: the former
/// `ORDER BY depth, doi LIMIT 1` kept exactly that one and let the pair pass
/// the filter as cross-source.
#[sqlx::test(migrations = "../../migrations")]
async fn derive_keeps_every_asserting_paper_doi(pool: PgPool) {
    use epigraph_engine::matching::source_key::{is_same_source, SourceFilterConfig};

    let agent_a = insert_agent(&pool).await;
    let agent_b = insert_agent(&pool).await;
    let claim_a = insert_claim(&pool, agent_a).await;
    let claim_b = insert_claim(&pool, agent_b).await;
    let p_only_a = insert_paper(&pool, "10.1/only-a").await;
    let p_shared = insert_paper(&pool, "10.2/shared").await;
    insert_asserts_edge(&pool, p_only_a, claim_a).await;
    insert_asserts_edge(&pool, p_shared, claim_a).await;
    insert_asserts_edge(&pool, p_shared, claim_b).await;

    let ka = derive_source_key(&pool, claim_a).await.expect("derive a");
    let kb = derive_source_key(&pool, claim_b).await.expect("derive b");
    assert_eq!(
        ka.paper_dois,
        vec!["10.1/only-a".to_string(), "10.2/shared".to_string()],
        "every asserting paper, sorted"
    );
    assert_eq!(kb.paper_dois, vec!["10.2/shared".to_string()]);
    assert!(
        is_same_source(&ka, &kb, SourceFilterConfig::default()),
        "claims sharing paper 10.2/shared must be same-source, got {ka:?} vs {kb:?}"
    );
}

// --- 9da3cf2b: intra-source closure (migration 041's edge set) ---

/// Insert a claim-to-claim edge of `relationship`.
async fn insert_claim_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("insert claim edge");
}

/// The `agent -asserts-> claim` attribution edge ingest writes on every
/// planned claim. It is NOT a paper anchor: a walk that treated any `asserts`
/// edge as an anchor would stop at every real claim and catch nothing.
async fn insert_agent_asserts(pool: &PgPool, agent_id: Uuid, claim_id: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'agent', $2, 'claim', 'asserts')",
    )
    .bind(agent_id)
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("insert agent asserts edge");
}

/// A claim by a fresh agent that also carries that agent's attribution edge.
/// Every claim gets its own agent, so the same-agent non-paper rule can never
/// be what makes a pair same-source here.
async fn claim_by_fresh_agent(pool: &PgPool) -> Uuid {
    let agent = insert_agent(pool).await;
    let claim = insert_claim(pool, agent).await;
    insert_agent_asserts(pool, agent, claim).await;
    claim
}

/// 9da3cf2b: claims that reach paper P only through `section_follows`,
/// `continues_argument` or `same_source` edges (no paper `asserts` edge on
/// them or on a `decomposes_to` ancestor) are same-source with P's claims.
/// The edges point both ways along the chain, so the walk must be undirected
/// over those relationships. Before the fix, `paper_dois` for `y`, `z` and `v`
/// was empty and, with distinct agents, every pair below passed as
/// cross-source.
#[sqlx::test(migrations = "../../migrations")]
async fn claims_linked_to_a_paper_only_by_intra_source_edges_are_same_source(pool: PgPool) {
    use epigraph_engine::matching::source_key::{is_same_source, SourceFilterConfig};

    let paper = insert_paper(&pool, "10.9/intra-source").await;
    let x = claim_by_fresh_agent(&pool).await;
    let w = claim_by_fresh_agent(&pool).await;
    insert_asserts_edge(&pool, paper, x).await;
    insert_asserts_edge(&pool, paper, w).await;

    // x -section_follows-> y            (forward from the anchor)
    // z -continues_argument-> y         (reached against the edge direction)
    // x -same_source-> v
    let y = claim_by_fresh_agent(&pool).await;
    let z = claim_by_fresh_agent(&pool).await;
    let v = claim_by_fresh_agent(&pool).await;
    insert_claim_edge(&pool, x, y, "section_follows").await;
    insert_claim_edge(&pool, z, y, "continues_argument").await;
    insert_claim_edge(&pool, x, v, "same_source").await;

    let kw = derive_source_key(&pool, w).await.expect("derive w");
    assert!(kw.paper_anchored, "w is asserted by the paper");
    for (name, id) in [("y", y), ("z", z), ("v", v)] {
        let k = derive_source_key(&pool, id).await.expect("derive");
        assert_eq!(
            k.paper_dois,
            vec!["10.9/intra-source".to_string()],
            "{name} reaches the paper only through intra-source edges"
        );
        assert!(
            !k.paper_anchored,
            "{name}'s DOI comes from the closure, not from an asserts anchor"
        );
        assert!(
            is_same_source(&k, &kw, SourceFilterConfig::default()),
            "{name} and w are claims of one paper; got {k:?} vs {kw:?}"
        );
    }
}

/// A paper-asserted claim's DOIs are its own asserting papers (plus its
/// `decomposes_to` ancestry). A lateral edge to a claim asserted by ANOTHER
/// paper does not add that paper: the walk stops at paper-anchored claims, so
/// two papers are never merged through their anchored claims. (Mutation: walk
/// on through anchored claims and `x` picks up `10.9/q`.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_paper_anchored_claim_does_not_inherit_a_neighbours_paper(pool: PgPool) {
    use epigraph_engine::matching::source_key::{is_same_source, SourceFilterConfig};

    let p = insert_paper(&pool, "10.9/p").await;
    let q = insert_paper(&pool, "10.9/q").await;
    let x = claim_by_fresh_agent(&pool).await;
    let y = claim_by_fresh_agent(&pool).await;
    let w = claim_by_fresh_agent(&pool).await;
    insert_asserts_edge(&pool, p, x).await;
    insert_asserts_edge(&pool, q, y).await;
    insert_asserts_edge(&pool, q, w).await;
    insert_claim_edge(&pool, x, y, "section_follows").await;

    let kx = derive_source_key(&pool, x).await.expect("derive x");
    let kw = derive_source_key(&pool, w).await.expect("derive w");
    assert_eq!(kx.paper_dois, vec!["10.9/p".to_string()]);
    assert!(!is_same_source(&kx, &kw, SourceFilterConfig::default()));
}

/// `decomposes_to` is followed child -> parent only. Atoms dedupe on content
/// hash, so one atom can sit under compounds of two papers; walking DOWN into
/// it and back UP would merge both papers' hierarchies. The shared atom `s`
/// belongs to both papers; its sibling `t`, under P's paragraph only, must not
/// pick up Q. (Mutation: follow `decomposes_to` parent -> child too and `t`
/// gains `10.9/q`.)
#[sqlx::test(migrations = "../../migrations")]
async fn decomposes_to_is_walked_upward_only(pool: PgPool) {
    let p = insert_paper(&pool, "10.9/p").await;
    let q = insert_paper(&pool, "10.9/q").await;
    let section_p = claim_by_fresh_agent(&pool).await;
    let section_q = claim_by_fresh_agent(&pool).await;
    insert_asserts_edge(&pool, p, section_p).await;
    insert_asserts_edge(&pool, q, section_q).await;
    // Unanchored paragraphs under each section, a shared atom under both
    // paragraphs and an atom under P's paragraph only.
    let para_p = claim_by_fresh_agent(&pool).await;
    let para_q = claim_by_fresh_agent(&pool).await;
    let s = claim_by_fresh_agent(&pool).await;
    let t = claim_by_fresh_agent(&pool).await;
    insert_claim_edge(&pool, section_p, para_p, "decomposes_to").await;
    insert_claim_edge(&pool, section_q, para_q, "decomposes_to").await;
    insert_claim_edge(&pool, para_p, s, "decomposes_to").await;
    insert_claim_edge(&pool, para_q, s, "decomposes_to").await;
    insert_claim_edge(&pool, para_p, t, "decomposes_to").await;

    let ks = derive_source_key(&pool, s).await.expect("derive s");
    let kt = derive_source_key(&pool, t).await.expect("derive t");
    assert_eq!(
        ks.paper_dois,
        vec!["10.9/p".to_string(), "10.9/q".to_string()]
    );
    assert_eq!(kt.paper_dois, vec!["10.9/p".to_string()]);
    // An atom of a paper-asserted compound is a paper claim through its
    // ancestry, exactly as before the closure was added: it must not fall
    // under the non-paper same-agent rule.
    assert!(ks.paper_anchored && kt.paper_anchored);
}

/// 9da3cf2b review: the closure's upward `decomposes_to` step. `para` reaches
/// paper P only through `x -continues_argument-> para`; its atom has no
/// lateral edge and no paper-asserted ancestor, so walk 1 (the ancestry)
/// finds nothing and only walk 2 climbing `atom -> para` and then crossing to
/// `x` resolves P. (Mutation: drop `'decomposes_to'` from the closure's
/// reverse branch and the atom resolves no paper.)
#[sqlx::test(migrations = "../../migrations")]
async fn closure_climbs_decomposes_to_from_an_unanchored_parent(pool: PgPool) {
    let p = insert_paper(&pool, "10.9/p").await;
    let x = claim_by_fresh_agent(&pool).await;
    insert_asserts_edge(&pool, p, x).await;
    let para = claim_by_fresh_agent(&pool).await;
    let atom = claim_by_fresh_agent(&pool).await;
    insert_claim_edge(&pool, x, para, "continues_argument").await;
    insert_claim_edge(&pool, para, atom, "decomposes_to").await;

    let k = derive_source_key(&pool, atom).await.expect("derive atom");
    assert_eq!(k.paper_dois, vec!["10.9/p".to_string()]);
    assert!(!k.paper_anchored);
}

/// 9da3cf2b review: folding the closure into `paper_dois` must not let a
/// non-paper claim escape the same-agent rule. One agent writes two non-paper
/// claims `m1` and `m2`; `m1` gets a `same_source` edge to a claim of paper
/// P. Before the closure both had no DOI and the pair was a same-agent
/// restatement (same-source). With the closure `m1` carries P and `m2` does
/// not, and a rule reading `paper_dois.is_empty()` passed them as
/// cross-source, so the matcher could propose them as corroboration.
#[sqlx::test(migrations = "../../migrations")]
async fn a_closure_doi_does_not_lift_the_same_agent_rule(pool: PgPool) {
    use epigraph_engine::matching::source_key::{is_same_source, SourceFilterConfig};

    let p = insert_paper(&pool, "10.9/probe").await;
    let x = claim_by_fresh_agent(&pool).await;
    insert_asserts_edge(&pool, p, x).await;
    let author = insert_agent(&pool).await;
    let m1 = insert_claim(&pool, author).await;
    let m2 = insert_claim(&pool, author).await;
    insert_agent_asserts(&pool, author, m1).await;
    insert_agent_asserts(&pool, author, m2).await;
    insert_claim_edge(&pool, m1, x, "same_source").await;

    let k1 = derive_source_key(&pool, m1).await.expect("derive m1");
    let k2 = derive_source_key(&pool, m2).await.expect("derive m2");
    assert_eq!(k1.paper_dois, vec!["10.9/probe".to_string()]);
    assert!(k2.paper_dois.is_empty());
    assert!(
        is_same_source(&k1, &k2, SourceFilterConfig::default()),
        "two non-paper claims of one agent stay same-source; got {k1:?} vs {k2:?}"
    );
}

/// 9da3cf2b review: a RETRACTED lateral edge (valid window closed) no longer
/// links a claim to the paper, in either walk direction. `same_source` is
/// writable (and retractable) through `POST /edges`, so a mistaken edge that
/// was later withdrawn must stop suppressing matches. (Mutation: drop the
/// in-force filter from either branch and `v_in` or `v_out` resolves P.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_lateral_edge_does_not_link_to_the_paper(pool: PgPool) {
    let p = insert_paper(&pool, "10.9/p").await;
    let x = claim_by_fresh_agent(&pool).await;
    insert_asserts_edge(&pool, p, x).await;
    let v_in = claim_by_fresh_agent(&pool).await;
    let v_out = claim_by_fresh_agent(&pool).await;
    for (source, target) in [(x, v_in), (v_out, x)] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship,
                                valid_from, valid_to)
             VALUES ($1, 'claim', $2, 'claim', 'same_source',
                     now() - interval '2 hours', now() - interval '1 hour')",
        )
        .bind(source)
        .bind(target)
        .execute(&pool)
        .await
        .expect("insert retracted edge");
    }

    for (name, id) in [("v_in", v_in), ("v_out", v_out)] {
        let k = derive_source_key(&pool, id).await.expect("derive");
        assert!(
            k.paper_dois.is_empty(),
            "{name} is linked to P only by a retracted edge; got {k:?}"
        );
    }
}

/// 9da3cf2b cost measurement, not a correctness test: `#[ignore]`d, run with
/// `cargo test -p epigraph-engine --test source_key_derivation -- --ignored
/// --nocapture measure_intra_source_walk_cost`.
///
/// Builds, per size N, one paper-asserted head claim followed by a chain of N
/// unanchored claims linked by `section_follows`, and times
/// `derive_source_key` on the head (anchored: the closure walk stops at hop
/// zero) and on the far end of the chain (the walk visits all N claims).
///
/// Recorded 2026-11-22 on a freshly migrated CI-configured pgvector database
/// (mean of 20 calls, small idle tables, so these are lower bounds for a
/// loaded corpus):
///
/// | N    | anchored head | unanchored tail |
/// |------|---------------|-----------------|
/// | 10   | 1.28 ms       | 0.67 ms         |
/// | 100  | 1.41 ms       | 2.75 ms         |
/// | 1000 | 0.85 ms       | 3.75 ms         |
///
/// A prod-sized figure depends on the size of the largest unanchored
/// component, which only the operator can measure.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "measurement; run explicitly with --ignored --nocapture"]
async fn measure_intra_source_walk_cost(pool: PgPool) {
    const CALLS: u32 = 20;
    let agent = insert_agent(&pool).await;
    for n in [10_usize, 100, 1000] {
        let paper = insert_paper(&pool, &format!("10.9/measure-{n}")).await;
        let head = insert_claim(&pool, agent).await;
        insert_asserts_edge(&pool, paper, head).await;
        let mut prev = head;
        for _ in 0..n {
            let next = insert_claim(&pool, agent).await;
            insert_claim_edge(&pool, prev, next, "section_follows").await;
            prev = next;
        }
        let tail = prev;
        sqlx::query("ANALYZE edges")
            .execute(&pool)
            .await
            .expect("analyze");

        let time = |claim: Uuid| {
            let pool = pool.clone();
            async move {
                let t0 = std::time::Instant::now();
                for _ in 0..CALLS {
                    let k = derive_source_key(&pool, claim).await.expect("derive");
                    assert_eq!(k.paper_dois.len(), 1);
                }
                t0.elapsed() / CALLS
            }
        };
        let anchored = time(head).await;
        let unanchored = time(tail).await;
        eprintln!("N={n}: anchored head {anchored:?}, unanchored tail {unanchored:?}");
    }
}
