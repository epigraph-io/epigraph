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
    persist_planned, plan_decomposition_batches, read_plan_jsonl, run_decomposition_batches,
    select_candidates, verify_plan, write_plan_jsonl, AtomParent, BatchClaim, EligibilityFilters,
    Ineligible, PlanDrift, Priority, SingletonLedger,
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
        None,
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
        None,
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

    let recent = select_candidates(&pool, &viewer, Priority::Recent, None, f, None, 100, 10_000)
        .await
        .unwrap();
    let oldest = select_candidates(&pool, &viewer, Priority::Oldest, None, f, None, 100, 10_000)
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
    let submit = move |t: String, _g: i64, p: AtomParent| {
        let pool_c = pool_c.clone();
        async move { Ok(insert_atom(&pool_c, p.agent_id, &t).await) }
    };
    let totals = persist_planned(&pool, &viewer, &ok, None, None, &submit)
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
    let flaky = move |t: String, _g: i64, p: AtomParent| {
        let a = p.agent_id;
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
    let totals = persist_planned(&pool, &viewer, &ok, None, None, &flaky)
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
    let healthy = move |t: String, _g: i64, p: AtomParent| {
        let a = p.agent_id;
        let pool_h = pool_h.clone();
        async move { Ok(get_or_insert_atom(&pool_h, a, &t).await) }
    };
    let totals2 = persist_planned(&pool, &viewer, &ok2, None, None, &healthy)
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

/// `verify_plan` refuses lines it cannot attribute to exactly one live
/// parent and its author:
/// * two lines for the SAME parent (e.g. two `--plan` outputs concatenated)
///   — both refused, where applying both gave the parent atoms [A, B, X, Y];
/// * a line whose `agent_id` is not the parent's author — the atoms would be
///   POSTed under someone else's identity.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_plan_refuses_duplicate_parents_and_foreign_authors(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let stranger = seed_agent(&pool).await;
    let dup_text = compound("dup");
    let dup = seed_claim(&pool, agent, &dup_text, 100, &[]).await;
    let foreign_text = compound("foreign");
    let foreign = seed_claim(&pool, agent, &foreign_text, 100, &[]).await;
    let fine_text = compound("fine");
    let fine = seed_claim(&pool, agent, &fine_text, 100, &[]).await;

    let first = three_atom_plan(dup, agent, &dup_text);
    let mut second = three_atom_plan(dup, agent, &dup_text);
    second.atoms = vec!["X.".into(), "Y.".into()];
    second.generality = vec![0, 0];
    let mut wrong_author = three_atom_plan(foreign, agent, &foreign_text);
    wrong_author.agent_id = stranger;
    let good = three_atom_plan(fine, agent, &fine_text);

    let (ok, drifted) = verify_plan(&pool, &viewer, vec![first, second, wrong_author, good])
        .await
        .unwrap();

    assert_eq!(
        ok.iter().map(|p| p.claim_id).collect::<Vec<_>>(),
        vec![fine]
    );
    let why: Vec<(Uuid, PlanDrift)> = drifted.into_iter().map(|(p, w)| (p.claim_id, w)).collect();
    assert_eq!(
        why,
        vec![
            (dup, PlanDrift::DuplicateInPlan),
            (dup, PlanDrift::DuplicateInPlan),
            (foreign, PlanDrift::AgentChanged),
        ]
    );
}

/// Production selects under the maintenance BYPASS viewer
/// (`SystemReason::TenancyBackfill`), so it sees group-private claims — but
/// atoms are POSTed public (`if_not_exists` is public-tier only) and carry the
/// parent's text as derivation evidence (U041). A non-public parent must
/// therefore never be chosen: not by the paged crawl, and not from
/// `--ids-file` even with every overridable filter off, and each one is
/// reported with the reason. Without this the API's `derived_from` refusal of
/// a non-public parent would abort the whole normal run.
#[sqlx::test(migrations = "../../migrations")]
async fn non_public_parents_are_never_selected_under_the_bypass_viewer(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "u041-selection").await;
    let public = viewer_fixture::seed_public_claim(&pool, agent, &compound("public")).await;
    let private = viewer_fixture::seed_group_claim(&pool, agent, group, &compound("private")).await;

    let crawl = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        None,
        EligibilityFilters::default(),
        None,
        100,
        10_000,
    )
    .await
    .unwrap();
    assert!(
        ids(&crawl).contains(&public),
        "the public parent is chosen: {crawl:?}"
    );
    assert!(
        !ids(&crawl).contains(&private),
        "a group-private parent must not be chosen by the crawl: {crawl:?}"
    );
    assert!(
        crawl.skipped.iter().any(|(id, why)| *id == private
            && *why
                == Ineligible::NotPublic {
                    visibility: "group".to_string()
                }),
        "the private parent is reported as NotPublic: {crawl:?}"
    );

    let named = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        Some(&[private, public]),
        EligibilityFilters {
            skip_backlog: false,
            skip_short: false,
        },
        None,
        100,
        10_000,
    )
    .await
    .unwrap();
    assert_eq!(
        ids(&named),
        vec![public],
        "--ids-file with every overridable filter off still refuses the private parent"
    );
    assert!(
        named
            .skipped
            .iter()
            .any(|(id, why)| *id == private && matches!(why, Ineligible::NotPublic { .. })),
        "the named private parent is reported, not silently dropped: {named:?}"
    );
}

/// Backlog 68d03c24 (U040): a parent the model answers with ONE atom ("already
/// atomic") gets no `decomposes_to` edge, so it stays in the undecomposed
/// population. Unless the verdict is recorded, the next run selects it again
/// and spends another LLM call on the same answer, every run, forever; the
/// weekly `oldest` crawl's head filled with exactly these (atoms per run fell
/// 457 -> 284 -> 158 -> 13). The parent here is two sentences, so the
/// `looks_atomic` filter does NOT skip it: only a recorded verdict can.
///
/// The control `c` (two atoms, decomposed) and the untouched compound `u`
/// prove selection reads the real predicate: `c` leaves the population through
/// its edges, and `u` is still chosen, so `s` is not "not chosen" merely
/// because selection saw nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn llm_singleton_parent_is_not_reselected_by_the_next_run(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let s_text = "The rotor arm turns freely. Its friction coefficient is about 4e-22 N m s.";
    let s = seed_claim(&pool, agent, s_text, 300, &[]).await;
    let c_text = compound("u040-control");
    let c = seed_claim(&pool, agent, &c_text, 300, &[]).await;
    let u = seed_claim(&pool, agent, &compound("u040-untouched"), 300, &[]).await;
    assert!(
        epigraph_cli::decompose::check_eligibility(s_text, &[], EligibilityFilters::default())
            .is_ok(),
        "precondition: the singleton parent passes the default filters"
    );

    let llm = FixtureLlmClient::from_json(&serde_json::json!({
        s_text: {"atoms": [s_text], "generality": [0]},
        c_text.clone(): {
            "atoms": ["Claim u040-control has a first part.", "Claim u040-control also has a second part."],
            "generality": [0, 1]
        },
    }))
    .unwrap();
    let claims = vec![
        BatchClaim {
            claim_id: s,
            agent_id: agent,
            content: s_text.to_string(),
        },
        BatchClaim {
            claim_id: c,
            agent_id: agent,
            content: c_text.clone(),
        },
    ];
    // The run records its own verdicts; the test never writes the ledger.
    let ledger_path = std::env::temp_dir().join(format!("judged-atomic-{}.jsonl", Uuid::new_v4()));
    let mut ledger = SingletonLedger::open_for_append(&ledger_path).unwrap();
    let pool_c = pool.clone();
    let totals = run_decomposition_batches(
        &pool,
        &viewer,
        &claims,
        &llm,
        10,
        None,
        Some(&mut ledger),
        move |t: String, _g: i64, p: AtomParent| {
            let pool_c = pool_c.clone();
            async move { Ok(insert_atom(&pool_c, p.agent_id, &t).await) }
        },
    )
    .await
    .unwrap();
    assert_eq!(totals.singletons, vec![s], "the model judged `s` atomic");
    assert_eq!(atoms_of(&pool, c).await.len(), 2, "the control decomposed");

    // The next run's selection, through a ledger read back from the FILE: a
    // verdict held only in the first run's memory would not survive to the
    // next scheduled run.
    let next_run = SingletonLedger::load(&ledger_path).unwrap();
    let sel = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        None,
        EligibilityFilters::default(),
        Some(&next_run),
        100,
        10_000,
    )
    .await
    .unwrap();
    assert!(
        ids(&sel).contains(&u),
        "the untouched compound is still chosen: {sel:?}"
    );
    assert!(
        !ids(&sel).contains(&c),
        "the decomposed control left the population: {sel:?}"
    );
    assert!(
        !ids(&sel).contains(&s),
        "a parent the model judged atomic was re-selected; it will cost an LLM call every run \
         forever: {sel:?}"
    );
    assert!(
        sel.skipped
            .iter()
            .any(|(id, why)| *id == s && *why == Ineligible::JudgedAtomic),
        "the passed-over parent is reported as JudgedAtomic: {sel:?}"
    );

    // Named in --ids-file, it is reported with the reason, not silently dropped.
    let named = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        Some(&[s, u]),
        EligibilityFilters::default(),
        Some(&next_run),
        100,
        10_000,
    )
    .await
    .unwrap();
    assert_eq!(ids(&named), vec![u]);
    assert!(
        named
            .skipped
            .iter()
            .any(|(id, why)| *id == s && *why == Ineligible::JudgedAtomic),
        "the named judged-atomic parent is reported: {named:?}"
    );

    // Without the ledger (no flag, or --include-judged-atomic) it is chosen
    // again: the ledger, not some other rule, is what passed it over.
    let without = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        None,
        EligibilityFilters::default(),
        None,
        100,
        10_000,
    )
    .await
    .unwrap();
    assert!(ids(&without).contains(&s), "{without:?}");
    std::fs::remove_file(&ledger_path).ok();
}

/// Whether a default-filter `oldest` crawl, reading the ledger at `path` the
/// way the next scheduled run would, chooses `id`.
async fn crawl_chooses(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    path: &std::path::Path,
    id: Uuid,
) -> bool {
    let ledger = SingletonLedger::load(path).unwrap();
    let sel = select_candidates(
        pool,
        viewer,
        Priority::Oldest,
        None,
        EligibilityFilters::default(),
        Some(&ledger),
        100,
        10_000,
    )
    .await
    .unwrap();
    ids(&sel).contains(&id)
}

/// `--apply-plan` records the singleton lines of a reviewed plan (a `--plan`
/// records nothing, so applying it is where the verdict is made), keyed on
/// the text the model judged: once the parent's text changes, the old
/// verdict no longer covers it and it is selected again.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_plan_records_singletons_and_an_edited_parent_requalifies(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let text = "The stator ring is rigid. Its thermal expansion is negligible at 300 K.";
    let s = seed_claim(&pool, agent, text, 300, &[]).await;
    let llm = FixtureLlmClient::from_json(&serde_json::json!({
        text: {"atoms": [text], "generality": [0]},
    }))
    .unwrap();
    let claims = vec![BatchClaim {
        claim_id: s,
        agent_id: agent,
        content: text.to_string(),
    }];
    let plans = plan_decomposition_batches(&claims, &llm, 10).await;
    assert_eq!(plans.len(), 1);
    // That `--plan` records nothing is covered through the binary
    // (decompose_claims_bin_ledger.rs): planning never sees the ledger here.
    let ledger_path = std::env::temp_dir().join(format!("judged-atomic-{}.jsonl", Uuid::new_v4()));

    let (ok, _) = verify_plan(&pool, &viewer, plans).await.unwrap();
    let mut ledger = SingletonLedger::open_for_append(&ledger_path).unwrap();
    let submit = |_t: String, _g: i64, _p: AtomParent| async move {
        Err::<Uuid, Box<dyn std::error::Error>>("a singleton must submit nothing".into())
    };
    let totals = persist_planned(&pool, &viewer, &ok, None, Some(&mut ledger), &submit)
        .await
        .unwrap();
    assert_eq!(totals.singletons, vec![s]);
    assert!(totals.failed.is_empty(), "{:?}", totals.failed);

    assert!(
        !crawl_chooses(&pool, &viewer, &ledger_path, s).await,
        "the applied singleton verdict passes the parent over"
    );

    sqlx::query("UPDATE claims SET content = content || ' It was re-measured.' WHERE id = $1")
        .bind(s)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        crawl_chooses(&pool, &viewer, &ledger_path, s).await,
        "the verdict was on the old text; the edited parent must be asked again"
    );
    std::fs::remove_file(&ledger_path).ok();
}

/// A ledger append that fails (the disk filled, the file was moved away) is
/// a failed LINE, like a failed atom submit: the rest of a reviewed plan is
/// still applied and the summary still names it. Aborting would strand every
/// later line and print no `FAILED` / summary lines for the ones already
/// persisted. The failed parent stays undecomposed and unrecorded, so a
/// re-run of the plan records it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_ledger_append_failure_fails_its_line_and_the_plan_goes_on(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let s_text = "The idler gear is stiff. Its backlash is below one picometre.";
    let s = seed_claim(&pool, agent, s_text, 300, &[]).await;
    let c_text = compound("u040-after-ledger-failure");
    let c = seed_claim(&pool, agent, &c_text, 300, &[]).await;
    let llm = FixtureLlmClient::from_json(&serde_json::json!({
        s_text: {"atoms": [s_text], "generality": [0]},
        c_text.clone(): {
            "atoms": ["Claim u040-after-ledger-failure has a first part.",
                      "Claim u040-after-ledger-failure also has a second part."],
            "generality": [0, 1]
        },
    }))
    .unwrap();
    let claims = vec![
        BatchClaim {
            claim_id: s,
            agent_id: agent,
            content: s_text.to_string(),
        },
        BatchClaim {
            claim_id: c,
            agent_id: agent,
            content: c_text.clone(),
        },
    ];
    let plans = plan_decomposition_batches(&claims, &llm, 10).await;
    let (ok, _) = verify_plan(&pool, &viewer, plans).await.unwrap();
    assert_eq!(ok.len(), 2);
    assert_eq!(ok[0].claim_id, s, "the singleton line comes first");

    let ledger_path = std::env::temp_dir().join(format!("judged-atomic-{}.jsonl", Uuid::new_v4()));
    let mut ledger = SingletonLedger::open_for_append(&ledger_path).unwrap();
    // `record` reopens the file without creating it: the append now fails.
    std::fs::remove_file(&ledger_path).unwrap();
    let pool_c = pool.clone();
    let submit = move |t: String, _g: i64, p: AtomParent| {
        let pool_c = pool_c.clone();
        async move { Ok(insert_atom(&pool_c, p.agent_id, &t).await) }
    };
    let totals = persist_planned(&pool, &viewer, &ok, None, Some(&mut ledger), &submit)
        .await
        .expect("a ledger append failure must not abort the whole plan");
    assert_eq!(totals.failed.len(), 1, "{:?}", totals.failed);
    assert_eq!(totals.failed[0].0, s);
    assert!(
        totals.failed[0].1.contains("singleton ledger"),
        "the reason names the ledger: {:?}",
        totals.failed
    );
    assert_eq!(
        atoms_of(&pool, c).await.len(),
        2,
        "the line after the failed append was still applied"
    );
    assert!(
        !ledger.contains(s, s_text),
        "an unwritten verdict is not held"
    );
}

/// Only a ONE-atom answer is a verdict that the text is atomic. A plan line
/// with no atoms at all (a hand-edited `--apply-plan` file; live parsing
/// drops such entries) persists nothing as before, but it is not recorded,
/// so the parent is asked again.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_answer_is_not_recorded_as_judged_atomic(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let text = "The cam follower slips. Its contact force is under one nanonewton.";
    let e = seed_claim(&pool, agent, text, 300, &[]).await;
    let one_text = "The pawl engages. Its tooth count is twelve.";
    let one = seed_claim(&pool, agent, one_text, 300, &[]).await;
    let line = |claim_id: Uuid, content: &str, atoms: Vec<String>| {
        epigraph_cli::decompose::PlannedDecomposition {
            kind: epigraph_cli::decompose::PlannedDecomposition::KIND.to_string(),
            claim_id,
            agent_id: agent,
            content: content.to_string(),
            generality: vec![0; atoms.len()],
            atoms,
            model: "hand-edited".to_string(),
        }
    };
    let planned = vec![
        line(e, text, vec![]),
        line(one, one_text, vec![one_text.to_string()]),
    ];
    let ledger_path = std::env::temp_dir().join(format!("judged-atomic-{}.jsonl", Uuid::new_v4()));
    let mut ledger = SingletonLedger::open_for_append(&ledger_path).unwrap();
    let submit = |_t: String, _g: i64, _p: AtomParent| async move {
        Err::<Uuid, Box<dyn std::error::Error>>("nothing is submitted here".into())
    };
    let totals = persist_planned(&pool, &viewer, &planned, None, Some(&mut ledger), &submit)
        .await
        .unwrap();
    assert!(totals.failed.is_empty(), "{:?}", totals.failed);
    let back = SingletonLedger::load(&ledger_path).unwrap();
    assert!(
        back.contains(one, one_text),
        "the one-atom answer is recorded"
    );
    assert!(
        !back.contains(e, text),
        "an empty answer is not a verdict that the text is atomic"
    );
    std::fs::remove_file(&ledger_path).ok();
}

/// The ledger is consulted AFTER every other rule, so `skipped_judged_atomic`
/// counts only parents a model call would otherwise have been spent on. A
/// recorded parent that is also backlog-labelled is reported as `Backlog`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ledger_is_consulted_after_every_other_rule(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let text = "The ratchet holds. Its pawl spring is stiff at room temperature.";
    let b = seed_claim(&pool, agent, text, 300, &["backlog"]).await;
    let path = std::env::temp_dir().join(format!("judged-atomic-{}.jsonl", Uuid::new_v4()));
    let mut ledger = SingletonLedger::open_for_append(&path).unwrap();
    ledger.record(b, text, "m").unwrap();

    let sel = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        None,
        EligibilityFilters::default(),
        Some(&ledger),
        100,
        10_000,
    )
    .await
    .unwrap();
    let why: Vec<&Ineligible> = sel
        .skipped
        .iter()
        .filter(|(id, _)| *id == b)
        .map(|(_, w)| w)
        .collect();
    assert_eq!(why, vec![&Ineligible::Backlog], "{sel:?}");
    std::fs::remove_file(&path).ok();
}

/// Verdicts are appended per chunk: a normal run that aborts on a later
/// chunk (a persist failure) keeps the verdicts it already paid for.
#[sqlx::test(migrations = "../../migrations")]
async fn a_run_that_aborts_later_keeps_the_verdicts_of_earlier_chunks(pool: PgPool) {
    let viewer = viewer_fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let s_text = "The escapement ticks. Its period is one microsecond.";
    let s = seed_claim(&pool, agent, s_text, 300, &[]).await;
    let c_text = compound("u040-aborting-chunk");
    let c = seed_claim(&pool, agent, &c_text, 300, &[]).await;
    let llm = FixtureLlmClient::from_json(&serde_json::json!({
        s_text: {"atoms": [s_text], "generality": [0]},
        c_text.clone(): {
            "atoms": ["Claim u040-aborting-chunk has a first part.",
                      "Claim u040-aborting-chunk also has a second part."],
            "generality": [0, 1]
        },
    }))
    .unwrap();
    let claims = vec![
        BatchClaim {
            claim_id: s,
            agent_id: agent,
            content: s_text.to_string(),
        },
        BatchClaim {
            claim_id: c,
            agent_id: agent,
            content: c_text.clone(),
        },
    ];
    let path = std::env::temp_dir().join(format!("judged-atomic-{}.jsonl", Uuid::new_v4()));
    let mut ledger = SingletonLedger::open_for_append(&path).unwrap();
    let err = run_decomposition_batches(
        &pool,
        &viewer,
        &claims,
        &llm,
        1,
        None,
        Some(&mut ledger),
        |_t: String, _g: i64, _p: AtomParent| async move {
            Err::<Uuid, Box<dyn std::error::Error>>("API down".into())
        },
    )
    .await
    .expect_err("the second chunk's submit failure aborts the run");
    assert!(err.to_string().contains("API down"), "{err}");
    assert!(
        SingletonLedger::load(&path).unwrap().contains(s, s_text),
        "the first chunk's verdict was lost with the aborted run"
    );
    std::fs::remove_file(&path).ok();
}
