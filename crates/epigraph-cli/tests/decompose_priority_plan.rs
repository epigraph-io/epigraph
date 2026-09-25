//! Integration cover for `decompose_claims`'s candidate selection
//! (`--priority`, `--ids-file`, eligibility filters) and its `--plan` /
//! `--apply-plan` round trip, against a migrated `#[sqlx::test]` database.
//!
//! Selection runs under a SCOPED viewer (`public_viewer`), so the group bind
//! index of every new spliced query is exercised, not just the bypass
//! rendering the maintenance binary uses.
#![cfg(feature = "db")]

mod viewer_fixture;

use epigraph_cli::decompose::{
    persist_planned, plan_decomposition_batches, read_plan_jsonl, select_candidates, verify_plan,
    write_plan_jsonl, BatchClaim, EligibilityFilters, Ineligible, PlanDrift, Priority,
};
use epigraph_cli::enrichment::llm_client::FixtureLlmClient;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let mut pk = vec![0u8; 32];
    for b in pk.iter_mut() {
        *b = rand::random();
    }
    sqlx::query_scalar("INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id")
        .bind(&pk)
        .bind("decompose-priority-test")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    age_secs: i64,
    labels: &[&str],
) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    let labels: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, created_at) \
         VALUES ($1, $2, $3, 0.5, $4, now() - make_interval(secs => $5)) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(&labels)
    .bind(age_secs as f64)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn seed_edge(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str, age_secs: i64) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, created_at) \
         VALUES ($1, 'claim', $2, 'claim', $3, now() - make_interval(secs => $4)) RETURNING id",
    )
    .bind(src)
    .bind(tgt)
    .bind(rel)
    .bind(age_secs as f64)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn compound(tag: &str) -> String {
    format!("Claim {tag} has a first part. Claim {tag} also has a second part.")
}

fn ids(sel: &epigraph_cli::decompose::Selection) -> Vec<Uuid> {
    sel.chosen.iter().map(|c| c.id).collect()
}

/// `--priority conflict`: only conflict targets, ordered by edge count desc,
/// then newest edge desc. Retired and non-conflict edges do not count; a
/// decomposed parent is not in the undecomposed set at all; an upper-case
/// stored relationship still counts.
#[sqlx::test(migrations = "../../migrations")]
async fn conflict_priority_orders_by_edge_count_then_newest_edge(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let src = seed_claim(
        &pool,
        agent,
        "Some source claim that disputes things.",
        500,
        &[],
    )
    .await;
    let src2 = seed_claim(
        &pool,
        agent,
        "A second disputing source claim here.",
        500,
        &[],
    )
    .await;

    let two_edges = seed_claim(&pool, agent, &compound("A"), 400, &[]).await;
    let one_new = seed_claim(&pool, agent, &compound("B"), 400, &[]).await;
    let one_old = seed_claim(&pool, agent, &compound("C"), 400, &[]).await;
    let only_supports = seed_claim(&pool, agent, &compound("D"), 400, &[]).await;
    let only_retired = seed_claim(&pool, agent, &compound("E"), 400, &[]).await;
    let decomposed = seed_claim(&pool, agent, &compound("F"), 400, &[]).await;
    let atom = seed_claim(&pool, agent, "Claim F has a first part.", 300, &[]).await;

    seed_edge(&pool, src, two_edges, "contradicts", 100).await;
    seed_edge(&pool, src2, two_edges, "REFUTES", 200).await;
    seed_edge(&pool, src, one_new, "refutes", 10).await;
    seed_edge(&pool, src, one_old, "contradicts", 50).await;
    seed_edge(&pool, src, only_supports, "supports", 5).await;
    let r = seed_edge(&pool, src, only_retired, "contradicts", 5).await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 hour' WHERE id = $1")
        .bind(r)
        .execute(&pool)
        .await
        .unwrap();
    seed_edge(&pool, decomposed, atom, "decomposes_to", 5).await;
    seed_edge(&pool, src, decomposed, "contradicts", 1).await;

    let sel = select_candidates(
        &pool,
        &viewer,
        Priority::Conflict,
        None,
        EligibilityFilters::default(),
        100,
        10_000,
    )
    .await
    .unwrap();
    assert_eq!(ids(&sel), vec![two_edges, one_new, one_old]);
    assert_eq!(sel.chosen[0].conflict_edges, 2);
    assert_eq!(sel.chosen[1].conflict_edges, 1);
}

/// A conflict edge from a RETIRED source is not a live dispute: it neither
/// makes its target a conflict candidate nor raises its rank, the same rule
/// `ClaimRepository::dispute_batch` (recall's dispute signal) applies.
#[sqlx::test(migrations = "../../migrations")]
async fn conflict_priority_ignores_edges_from_retired_sources(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let live = seed_claim(&pool, agent, "A live disputing source claim.", 500, &[]).await;
    let retired = seed_claim(&pool, agent, "A superseded disputing claim.", 500, &[]).await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(retired)
        .execute(&pool)
        .await
        .unwrap();

    let first = seed_claim(&pool, agent, &compound("first"), 400, &[]).await;
    let second = seed_claim(&pool, agent, &compound("second"), 400, &[]).await;
    let only_retired = seed_claim(&pool, agent, &compound("only-retired"), 400, &[]).await;
    // `first` has one live conflict, newer than `second`'s one live conflict.
    seed_edge(&pool, live, first, "refutes", 10).await;
    seed_edge(&pool, live, second, "refutes", 50).await;
    // Counting the retired source would lift `second` to two edges, above
    // `first`, and make `only_retired` a candidate.
    seed_edge(&pool, retired, second, "contradicts", 5).await;
    seed_edge(&pool, retired, only_retired, "contradicts", 5).await;

    let sel = select_candidates(
        &pool,
        &viewer,
        Priority::Conflict,
        None,
        EligibilityFilters::default(),
        100,
        10_000,
    )
    .await
    .unwrap();
    assert_eq!(ids(&sel), vec![first, second]);
    assert_eq!(
        sel.chosen[1].conflict_edges, 1,
        "the retired edge is not counted"
    );
}

/// `recent` is `created_at DESC`, `oldest` is `created_at ASC`, both with an
/// id tiebreaker, and both select the same population.
#[sqlx::test(migrations = "../../migrations")]
async fn recent_and_oldest_are_reverse_orders_of_the_same_population(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let old = seed_claim(&pool, agent, &compound("old"), 300, &[]).await;
    let mid = seed_claim(&pool, agent, &compound("mid"), 200, &[]).await;
    let new = seed_claim(&pool, agent, &compound("new"), 100, &[]).await;
    let f = EligibilityFilters::default();

    let recent = select_candidates(&pool, &viewer, Priority::Recent, None, f, 100, 10_000)
        .await
        .unwrap();
    let oldest = select_candidates(&pool, &viewer, Priority::Oldest, None, f, 100, 10_000)
        .await
        .unwrap();
    assert_eq!(ids(&recent), vec![new, mid, old]);
    assert_eq!(ids(&oldest), vec![old, mid, new]);
}

/// The filters run in Rust over PAGES, so a head of skipped rows cannot
/// starve the run: 600 short atomic claims (more than one 500-row page) sit
/// ahead of one compound claim in `oldest` order, and `--limit 1` still
/// reaches it.
#[sqlx::test(migrations = "../../migrations")]
async fn filters_page_past_a_head_of_skipped_claims(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    sqlx::query(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, created_at) \
         SELECT 'Short atomic claim number ' || g, \
                decode(md5(g::text) || md5(g::text), 'hex'), $1, 0.5, \
                now() - interval '1 day' - make_interval(secs => g) \
         FROM generate_series(1, 600) g",
    )
    .bind(agent)
    .execute(&pool)
    .await
    .unwrap();
    let target = seed_claim(&pool, agent, &compound("late"), 10, &[]).await;

    let sel = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        None,
        EligibilityFilters::default(),
        1,
        10_000,
    )
    .await
    .unwrap();
    assert_eq!(ids(&sel), vec![target]);
    assert_eq!(sel.skipped.len(), 600);
    assert!(sel.scanned > 500, "had to read past the first page");

    // And `--max-scan` bounds the read, reporting that it did.
    let capped = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        None,
        EligibilityFilters::default(),
        1,
        500,
    )
    .await
    .unwrap();
    assert!(capped.chosen.is_empty());
    assert!(capped.scan_capped);
}

/// `--ids-file`: file order, filters still apply, and every named id that is
/// not decomposed is reported with a reason — a looks-atomic id, a backlog
/// id, and an id outside the undecomposed population (an atom).
#[sqlx::test(migrations = "../../migrations")]
async fn ids_file_reports_every_named_id_it_does_not_decompose(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let ok_b = seed_claim(&pool, agent, &compound("b"), 100, &[]).await;
    let ok_a = seed_claim(&pool, agent, &compound("a"), 200, &[]).await;
    let short = seed_claim(&pool, agent, "Already a single short sentence.", 100, &[]).await;
    let backlog = seed_claim(&pool, agent, &compound("backlog"), 100, &["backlog"]).await;
    let parent = seed_claim(&pool, agent, &compound("parent"), 100, &[]).await;
    let atom = seed_claim(&pool, agent, "Claim parent has a first part.", 50, &[]).await;
    seed_edge(&pool, parent, atom, "decomposes_to", 5).await;
    let absent = Uuid::new_v4();

    let named = vec![ok_b, short, backlog, atom, absent, ok_a];
    let sel = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        Some(&named),
        EligibilityFilters::default(),
        100,
        10_000,
    )
    .await
    .unwrap();
    assert_eq!(
        ids(&sel),
        vec![ok_b, ok_a],
        "file order, not created_at order"
    );
    assert!(sel
        .skipped
        .iter()
        .any(|(id, why)| *id == short && matches!(why, Ineligible::LooksAtomic { .. })));
    assert!(sel
        .skipped
        .iter()
        .any(|(id, why)| *id == backlog && *why == Ineligible::Backlog));
    assert_eq!(sel.not_undecomposed, vec![atom, absent]);

    // `--limit 1`: the second eligible id is REPORTED as over the limit, not
    // silently dropped; a repeated id is chosen once.
    let mut repeated = named.clone();
    repeated.insert(1, ok_b);
    let limited = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        Some(&repeated),
        EligibilityFilters::default(),
        1,
        10_000,
    )
    .await
    .unwrap();
    assert_eq!(ids(&limited), vec![ok_b]);
    assert_eq!(limited.over_limit, vec![ok_a]);
    let every_named_is_accounted_for = named.iter().all(|id| {
        limited.chosen.iter().any(|c| c.id == *id)
            || limited.over_limit.contains(id)
            || limited.not_undecomposed.contains(id)
            || limited.skipped.iter().any(|(s, _)| s == id)
    });
    assert!(every_named_is_accounted_for, "{limited:?}");

    // Opting out of both filters decomposes the two skipped ids too.
    let all = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        Some(&named),
        EligibilityFilters {
            skip_backlog: false,
            skip_short: false,
        },
        100,
        10_000,
    )
    .await
    .unwrap();
    assert_eq!(ids(&all), vec![ok_b, short, backlog, ok_a]);
}

async fn atoms_of(pool: &PgPool, parent: Uuid) -> Vec<String> {
    let mut rows: Vec<String> = sqlx::query_scalar(
        "SELECT c.content FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'decomposes_to'",
    )
    .bind(parent)
    .fetch_all(pool)
    .await
    .unwrap();
    rows.sort();
    rows
}

async fn insert_atom(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    seed_claim(pool, agent, content, 0, &[]).await
}

/// `--plan` then `--apply-plan`: the plan is written with ONE LLM call and no
/// graph write; applying it persists exactly the planned atoms with NO further
/// LLM call; a plan line whose parent text changed in between is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn plan_then_apply_plan_persists_the_reviewed_atoms_with_no_second_llm_call(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let text_a = compound("plan-a");
    let text_b = compound("plan-b");
    let a = seed_claim(&pool, agent, &text_a, 100, &[]).await;
    let b = seed_claim(&pool, agent, &text_b, 100, &[]).await;
    let llm = FixtureLlmClient::from_json(&serde_json::json!({
        text_a.clone(): {"atoms": ["Claim plan-a has a first part.", "Claim plan-a also has a second part."], "generality": [0, 1]},
        text_b.clone(): {"atoms": ["Claim plan-b has a first part.", "Claim plan-b also has a second part."], "generality": [1, 2]},
    }))
    .unwrap();
    let claims = vec![
        BatchClaim {
            claim_id: a,
            agent_id: agent,
            content: text_a.clone(),
        },
        BatchClaim {
            claim_id: b,
            agent_id: agent,
            content: text_b.clone(),
        },
    ];
    let edges_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges")
        .fetch_one(&pool)
        .await
        .unwrap();
    let claims_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims")
        .fetch_one(&pool)
        .await
        .unwrap();

    // --plan
    let plans = plan_decomposition_batches(&claims, &llm, 10).await;
    assert_eq!(llm.call_count(), 1);
    let path = std::env::temp_dir().join(format!("decomp-plan-{}.jsonl", Uuid::new_v4()));
    write_plan_jsonl(&path, &plans).unwrap();
    let edges_mid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges")
        .fetch_one(&pool)
        .await
        .unwrap();
    let claims_mid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        (edges_mid, claims_mid),
        (edges_before, claims_before),
        "--plan writes nothing"
    );

    // The operator edits claim b's text between plan and apply.
    sqlx::query("UPDATE claims SET content = content || ' Edited.' WHERE id = $1")
        .bind(b)
        .execute(&pool)
        .await
        .unwrap();

    // --apply-plan
    let read_back = read_plan_jsonl(&path).unwrap();
    assert_eq!(read_back, plans, "the plan file round-trips exactly");
    let (ok, drifted) = verify_plan(&pool, &viewer, read_back).await.unwrap();
    assert_eq!(ok.len(), 1);
    assert_eq!(drifted.len(), 1);
    assert_eq!(drifted[0].0.claim_id, b);
    assert_eq!(drifted[0].1, PlanDrift::ContentChanged);

    let pool_c = pool.clone();
    let submit = move |t: String, _g: i64, a: Uuid| {
        let pool_c = pool_c.clone();
        async move { Ok(insert_atom(&pool_c, a, &t).await) }
    };
    let totals = persist_planned(&pool, &viewer, &ok, None, &submit)
        .await
        .unwrap();
    assert_eq!(llm.call_count(), 1, "--apply-plan makes no LLM call");
    assert_eq!(totals.atoms, 2);
    assert_eq!(
        atoms_of(&pool, a).await,
        {
            let mut v = plans
                .iter()
                .find(|p| p.claim_id == a)
                .unwrap()
                .atoms
                .clone();
            v.sort();
            v
        },
        "exactly the reviewed atoms"
    );
    assert!(
        atoms_of(&pool, b).await.is_empty(),
        "the drifted line is not applied"
    );

    // Re-applying the same plan: the parent is decomposed now, so it drifts.
    let (ok2, drifted2) = verify_plan(&pool, &viewer, read_plan_jsonl(&path).unwrap())
        .await
        .unwrap();
    assert!(ok2.is_empty());
    assert!(drifted2.iter().all(|(_, why)| matches!(
        why,
        PlanDrift::NoLongerUndecomposed | PlanDrift::ContentChanged
    )));
    std::fs::remove_file(&path).ok();
}

/// The fake atom submit, idempotent the way `POST /api/v1/claims` with
/// `if_not_exists: true` is: the same text by the same author returns the
/// same claim id.
async fn get_or_insert_atom(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(hash.as_slice())
            .bind(agent)
            .fetch_optional(pool)
            .await
            .unwrap();
    match existing {
        Some(id) => id,
        None => insert_atom(pool, agent, content).await,
    }
}

fn three_atom_plan(
    claim_id: Uuid,
    agent: Uuid,
    text: &str,
) -> epigraph_cli::decompose::PlannedDecomposition {
    epigraph_cli::decompose::PlannedDecomposition {
        kind: "decomposition".into(),
        claim_id,
        agent_id: agent,
        content: text.to_string(),
        atoms: vec![
            "Partial atom one.".into(),
            "Partial atom two.".into(),
            "Partial atom three.".into(),
        ],
        generality: vec![0, 0, 0],
        model: "fixture".into(),
    }
}

/// A submit that fails partway through a parent's atoms (an API restart, a
/// 502 on atom 2 of 3) leaves the parent UNdecomposed — no decomposes_to edge
/// at all — so the same reviewed line passes `verify_plan` again and a
/// re-apply completes it with exactly the planned atoms. A second line in the
/// same plan is still applied: one failure does not strand the rest.
#[sqlx::test(migrations = "../../migrations")]
async fn a_submit_failure_mid_parent_leaves_it_reapplicable(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let text = compound("partial");
    let other_text = compound("other");
    let parent = seed_claim(&pool, agent, &text, 100, &[]).await;
    let other = seed_claim(&pool, agent, &other_text, 100, &[]).await;
    let mut other_plan = three_atom_plan(other, agent, &other_text);
    other_plan.atoms = vec!["Other atom one.".into(), "Other atom two.".into()];
    other_plan.generality = vec![0, 0];
    let plan = vec![three_atom_plan(parent, agent, &text), other_plan];

    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (pool_c, calls_c) = (pool.clone(), calls.clone());
    let flaky = move |t: String, _g: i64, a: Uuid| {
        let pool_c = pool_c.clone();
        // The 2nd submit of the whole run is atom 2 of the first parent.
        let n = calls_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move {
            if n == 1 {
                return Err::<Uuid, Box<dyn std::error::Error>>("HTTP 502 (API restarting)".into());
            }
            Ok(get_or_insert_atom(&pool_c, a, &t).await)
        }
    };
    let (ok, _) = verify_plan(&pool, &viewer, plan.clone()).await.unwrap();
    let totals = persist_planned(&pool, &viewer, &ok, None, &flaky)
        .await
        .unwrap();

    assert_eq!(
        totals.failed.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        vec![parent],
        "the failed line is reported: {totals:?}"
    );
    assert!(
        atoms_of(&pool, parent).await.is_empty(),
        "no decomposes_to edge until every atom is submitted"
    );
    assert_eq!(
        atoms_of(&pool, other).await.len(),
        2,
        "the next line still ran"
    );

    // Re-apply the SAME reviewed plan with a healthy submit.
    let (ok2, drifted2) = verify_plan(&pool, &viewer, plan).await.unwrap();
    assert_eq!(
        ok2.iter().map(|p| p.claim_id).collect::<Vec<_>>(),
        vec![parent],
        "the failed parent is still undecomposed; the applied one drifts: {drifted2:?}"
    );
    let pool_h = pool.clone();
    let healthy = move |t: String, _g: i64, a: Uuid| {
        let pool_h = pool_h.clone();
        async move { Ok(get_or_insert_atom(&pool_h, a, &t).await) }
    };
    let totals2 = persist_planned(&pool, &viewer, &ok2, None, &healthy)
        .await
        .unwrap();
    assert!(totals2.failed.is_empty(), "{totals2:?}");
    assert_eq!(
        atoms_of(&pool, parent).await,
        vec![
            "Partial atom one.".to_string(),
            "Partial atom three.".to_string(),
            "Partial atom two.".to_string()
        ]
    );
}
