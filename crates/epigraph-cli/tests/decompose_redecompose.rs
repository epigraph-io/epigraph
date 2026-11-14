//! `decompose_claims --redecompose` (backlog `c4a8436b`): a compound ATOM, the
//! target of a `decomposes_to` edge, can be selected, split and verified,
//! which the undecomposed population can never do; a re-run writes nothing
//! twice; an atom that would close a `decomposes_to` cycle is refused; and the
//! re-decomposed atom becomes a `--retarget` input.
//!
//! The atom submit is a fake that dedups on (author, text), as the API's
//! `if_not_exists` does, so atom ids are deterministic without an API server.
#![cfg(feature = "db")]

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_cli::decompose::{
    persist_decomposition, persist_planned, select_candidates, select_redecompose_candidates,
    verify_plan, verify_plan_for, Decomposition, EligibilityFilters, Ineligible, PlanDrift,
    PlannedDecomposition, Population, Priority,
};
use epigraph_db::repos::decomposition_priority::DecompositionPriorityRepository as R;
use sqlx::PgPool;
use uuid::Uuid;

const PARAGRAPH: &str = "The pump failed. The backup took over. The alarm rang at noon.";
const COMPOUND_ATOM: &str = "The pump failed, but the backup took over.";
const ATOMIC_ATOM: &str = "The alarm rang at noon.";

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2,'hex'))")
        .bind(id)
        .bind("cc".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    id
}

/// The claim `agent` authored with exactly `content`, created if absent: the
/// `if_not_exists` contract of `POST /api/v1/claims`.
async fn claim_if_not_exists(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    if let Some(id) =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM claims WHERE agent_id = $1 AND content = $2")
            .bind(agent)
            .bind(content)
            .fetch_optional(pool)
            .await
            .unwrap()
    {
        return id;
    }
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, $2, 0.5, $3, true) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(rel)
    .execute(pool)
    .await
    .unwrap();
}

async fn decomposes_count(pool: &PgPool, source: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND relationship = 'decomposes_to'",
    )
    .bind(source)
    .fetch_one(pool)
    .await
    .unwrap()
}

struct World {
    agent: Uuid,
    paragraph: Uuid,
    compound_atom: Uuid,
    atomic_atom: Uuid,
    disputer: Uuid,
}

async fn seed(pool: &PgPool) -> World {
    let agent = seed_agent(pool).await;
    let paragraph = claim_if_not_exists(pool, agent, PARAGRAPH).await;
    let compound_atom = claim_if_not_exists(pool, agent, COMPOUND_ATOM).await;
    let atomic_atom = claim_if_not_exists(pool, agent, ATOMIC_ATOM).await;
    edge(pool, paragraph, compound_atom, "decomposes_to").await;
    edge(pool, paragraph, atomic_atom, "decomposes_to").await;
    // A dispute of ONE conjunct, landed on the compound atom.
    let disputer = claim_if_not_exists(pool, agent, "The backup never took over.").await;
    edge(pool, disputer, compound_atom, "contradicts").await;
    World {
        agent,
        paragraph,
        compound_atom,
        atomic_atom,
        disputer,
    }
}

fn split() -> Decomposition {
    Decomposition {
        atoms: vec!["The pump failed.".into(), "The backup took over.".into()],
        generality: vec![0, 0],
    }
}

async fn persist(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    parent: Uuid,
    agent: Uuid,
    d: &Decomposition,
) -> Result<epigraph_cli::decompose::PersistOutcome, String> {
    let p = pool.clone();
    persist_decomposition(pool, viewer, parent, d, None, move |text, _g| {
        let p = p.clone();
        async move { Ok(claim_if_not_exists(&p, agent, &text).await) }
    })
    .await
    .map_err(|e| e.to_string())
}

/// [`persist`] that also counts the atom submits it made.
async fn persist_counting(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    parent: Uuid,
    agent: Uuid,
    d: &Decomposition,
) -> (epigraph_cli::decompose::PersistOutcome, usize) {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let p = pool.clone();
    let c = calls.clone();
    let out = persist_decomposition(pool, viewer, parent, d, None, move |text, _g| {
        let p = p.clone();
        c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move { Ok(claim_if_not_exists(&p, agent, &text).await) }
    })
    .await
    .map_err(|e| e.to_string())
    .unwrap();
    (out, calls.load(std::sync::atomic::Ordering::SeqCst))
}

async fn claims_with_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_redecompose_selects_a_compound_atom(pool: PgPool) {
    let w = seed(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let filters = EligibilityFilters::default();

    // The undecomposed selection cannot reach it: it is a decomposes_to target.
    let old = select_candidates(
        &pool,
        &viewer,
        Priority::Oldest,
        Some(&[w.compound_atom]),
        filters,
        None,
        10,
        100,
    )
    .await
    .unwrap();
    assert!(old.chosen.is_empty());
    assert_eq!(old.not_undecomposed, vec![w.compound_atom]);

    let sel = select_redecompose_candidates(
        &pool,
        &viewer,
        &[w.compound_atom, w.atomic_atom, w.paragraph],
        filters,
        None,
        10,
        false,
    )
    .await
    .unwrap();
    let chosen: Vec<Uuid> = sel.chosen.iter().map(|c| c.id).collect();
    assert_eq!(chosen, vec![w.compound_atom]);
    assert!(sel
        .skipped
        .contains(&(w.atomic_atom, Ineligible::NotCompound { conjunct_count: 1 })));
    assert!(sel
        .skipped
        .contains(&(w.paragraph, Ineligible::AlreadySplit { children: 2 })));

    // The opt-outs: --include-short takes the atomic atom, --include-decomposed
    // the paragraph.
    let wide = select_redecompose_candidates(
        &pool,
        &viewer,
        &[w.atomic_atom, w.paragraph],
        EligibilityFilters {
            skip_backlog: true,
            skip_short: false,
        },
        None,
        10,
        true,
    )
    .await
    .unwrap();
    assert_eq!(wide.chosen.len(), 2, "{:?}", wide.skipped);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_redecomposition_keeps_existing_edges_and_writes_nothing_twice(pool: PgPool) {
    let w = seed(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;

    let first = persist(&pool, &viewer, w.compound_atom, w.agent, &split())
        .await
        .unwrap();
    assert_eq!(first.edges_created, 2);
    assert_eq!(decomposes_count(&pool, w.compound_atom).await, 2);
    assert_eq!(
        decomposes_count(&pool, w.paragraph).await,
        2,
        "the paragraph's edges are untouched"
    );

    // Re-applying the same answer returns the same atoms and writes no edge.
    let again = persist(&pool, &viewer, w.compound_atom, w.agent, &split())
        .await
        .unwrap();
    assert_eq!(
        again.atom_claim_ids, first.atom_claim_ids,
        "deterministic ids"
    );
    assert_eq!(again.edges_created, 0);

    // And a second selection no longer chooses it: it has children now.
    let sel = select_redecompose_candidates(
        &pool,
        &viewer,
        &[w.compound_atom],
        EligibilityFilters::default(),
        None,
        10,
        false,
    )
    .await
    .unwrap();
    assert!(sel.chosen.is_empty());
    assert_eq!(
        sel.skipped,
        vec![(w.compound_atom, Ineligible::AlreadySplit { children: 2 })]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_that_would_close_a_cycle_is_refused(pool: PgPool) {
    let w = seed(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    // The model returns the paragraph's own text: if_not_exists hands back
    // the paragraph, an ancestor of the atom.
    let ancestor = Decomposition {
        atoms: vec![PARAGRAPH.into(), "The pump failed.".into()],
        generality: vec![0, 0],
    };
    // Review M2: refused BEFORE any atom is POSTed. The real API records a
    // derivation on a dedup hit, so a submit here would already have written
    // the paragraph a derivation naming its own atom, and left the sibling
    // atom behind as an orphan.
    let (out, submits) =
        persist_counting(&pool, &viewer, w.compound_atom, w.agent, &ancestor).await;
    assert_eq!(out.refused_cycle, Some(w.paragraph));
    assert_eq!(out.edges_created, 0);
    assert_eq!(submits, 0, "no atom may be POSTed for a refused answer");
    // ...or the atom's own text: a self-loop.
    let itself = Decomposition {
        atoms: vec![COMPOUND_ATOM.into(), "The pump failed.".into()],
        generality: vec![0, 0],
    };
    let (out, submits) = persist_counting(&pool, &viewer, w.compound_atom, w.agent, &itself).await;
    assert_eq!(out.refused_cycle, Some(w.compound_atom));
    assert_eq!(submits, 0, "no atom may be POSTed for a refused answer");
    assert_eq!(
        claims_with_content(&pool, "The pump failed.").await,
        0,
        "the sibling atom of a refused answer is not left behind as an orphan"
    );
    assert_eq!(
        decomposes_count(&pool, w.compound_atom).await,
        0,
        "no edge was written for the refused parent"
    );

    // Through persist_planned, the path a scheduled run and --apply-plan
    // take: a cycle is reported per parent, NOT as a failure (a failure
    // aborts a normal run), and the next line is still applied.
    let line = |claim_id: Uuid, content: &str, atoms: Vec<String>| PlannedDecomposition {
        kind: PlannedDecomposition::KIND.into(),
        claim_id,
        agent_id: w.agent,
        content: content.into(),
        atoms,
        generality: vec![0, 0],
        model: "fixture".into(),
    };
    let p = pool.clone();
    let agent = w.agent;
    let submit = move |text: String, _g: i64, _parent: epigraph_cli::decompose::AtomParent| {
        let p = p.clone();
        async move { Ok::<_, Box<dyn std::error::Error>>(claim_if_not_exists(&p, agent, &text).await) }
    };
    let totals = persist_planned(
        &pool,
        &viewer,
        &[
            line(w.compound_atom, COMPOUND_ATOM, ancestor.atoms.clone()),
            line(
                w.disputer,
                "The backup never took over.",
                vec!["The backup stalled.".into(), "It never restarted.".into()],
            ),
        ],
        None,
        None,
        &submit,
    )
    .await
    .unwrap();
    assert!(totals.failed.is_empty(), "{:?}", totals.failed);
    assert_eq!(totals.cycles, vec![(w.compound_atom, w.paragraph)]);
    assert_eq!(totals.edges, 2, "the next line was applied");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_redecompose_plan_line_verifies_only_under_redecompose(pool: PgPool) {
    let w = seed(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let line = || PlannedDecomposition {
        kind: PlannedDecomposition::KIND.into(),
        claim_id: w.compound_atom,
        agent_id: w.agent,
        content: COMPOUND_ATOM.into(),
        atoms: split().atoms,
        generality: vec![0, 0],
        model: "fixture".into(),
    };
    let (ok, drifted) = verify_plan(&pool, &viewer, vec![line()]).await.unwrap();
    assert!(ok.is_empty());
    assert_eq!(drifted[0].1, PlanDrift::NoLongerUndecomposed);

    let redecompose = Population::Redecompose {
        include_decomposed: false,
    };
    let (ok, drifted) = verify_plan_for(&pool, &viewer, vec![line()], redecompose)
        .await
        .unwrap();
    assert_eq!(ok.len(), 1, "{drifted:?}");

    // Once split, the same line is refused: applying it would add atoms twice.
    persist(&pool, &viewer, w.compound_atom, w.agent, &split())
        .await
        .unwrap();
    let (ok, drifted) = verify_plan_for(&pool, &viewer, vec![line()], redecompose)
        .await
        .unwrap();
    assert!(ok.is_empty());
    assert_eq!(drifted[0].1, PlanDrift::NoLongerUndecomposed);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_redecomposed_atom_becomes_a_retarget_input(pool: PgPool) {
    let w = seed(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let targets = |pool: PgPool| async move {
        let viewer = fixture::public_viewer(&pool).await;
        R::list_parent_conflict_edges(&pool, &viewer, false, 100, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.source_id, e.parent_id))
            .collect::<Vec<_>>()
    };
    assert!(
        !targets(pool.clone())
            .await
            .contains(&(w.disputer, w.compound_atom)),
        "an unsplit atom's dispute has no atom to move to"
    );
    persist(&pool, &viewer, w.compound_atom, w.agent, &split())
        .await
        .unwrap();
    assert!(
        targets(pool.clone())
            .await
            .contains(&(w.disputer, w.compound_atom)),
        "after the split, --retarget sees the dispute and can move it onto the atom it targets"
    );
}
