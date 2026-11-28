//! `decompose_claims --redecompose` (backlog `c4a8436b`): a compound ATOM, the
//! target of a `decomposes_to` edge, can be selected, split and verified,
//! which the undecomposed population can never do; a re-run writes nothing
//! twice; an atom that would close a `decomposes_to` cycle is refused; and the
//! re-decomposed atom becomes a `--retarget` input; and the parent's open
//! challenges are reported on its plan line and retarget entry while no
//! challenge row changes (backlog `122ac356`).
//!
//! The atom submit is a fake that dedups on (author, text), as the API's
//! `if_not_exists` does, so atom ids are deterministic without an API server.
#![cfg(feature = "db")]

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_cli::decompose::{
    attach_open_challenges, persist_decomposition, persist_planned, read_plan_jsonl,
    select_candidates, select_redecompose_candidates, verify_plan, verify_plan_for,
    write_plan_jsonl, Decomposition, EligibilityFilters, Ineligible, OpenChallenge, PlanDrift,
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
    persist_decomposition(pool, viewer, parent, d, move |text, _g| {
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
    let out = persist_decomposition(pool, viewer, parent, d, move |text, _g| {
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
        parent_open_challenges: Vec::new(),
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
        parent_open_challenges: Vec::new(),
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

async fn seed_challenge(pool: &PgPool, claim: Uuid, challenger: Uuid, state: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO challenges (claim_id, challenger_id, challenge_type, explanation, state) \
         VALUES ($1, $2, 'factual_error', 'the backup did not take over', $3) RETURNING id",
    )
    .bind(claim)
    .bind(challenger)
    .bind(state)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The whole challenge row, every column: `claim_id`, `owner_group_id`,
/// `visibility`, `state` and the resolution columns among them.
async fn challenge_row(pool: &PgPool, id: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT to_jsonb(c) FROM challenges c WHERE c.id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Backlog 122ac356: a compound with one pending challenge (and one already
/// rejected), re-decomposed, lists exactly the pending challenge on its plan
/// line (the `--redecompose --plan` manifest entry, through the JSONL file)
/// and on a `--retarget` manifest entry for its conflict edge, and applying
/// the plan leaves every challenge row exactly as it was: challenges stay on
/// the parent by design.
#[sqlx::test(migrations = "../../migrations")]
async fn a_redecomposition_reports_the_parents_open_challenges_and_changes_none(pool: PgPool) {
    let w = seed(&pool).await;
    let viewer = fixture::public_viewer(&pool).await;
    let pending = seed_challenge(&pool, w.compound_atom, w.agent, "pending").await;
    let rejected = seed_challenge(&pool, w.compound_atom, w.agent, "rejected").await;
    let before = (
        challenge_row(&pool, pending).await,
        challenge_row(&pool, rejected).await,
    );
    let want = vec![OpenChallenge {
        id: pending,
        state: "pending".into(),
        challenger_id: Some(w.agent),
    }];

    let mut plans = vec![PlannedDecomposition {
        kind: PlannedDecomposition::KIND.into(),
        claim_id: w.compound_atom,
        agent_id: w.agent,
        content: COMPOUND_ATOM.into(),
        atoms: split().atoms,
        generality: vec![0, 0],
        model: "fixture".into(),
        parent_open_challenges: Vec::new(),
    }];
    attach_open_challenges(&pool, &viewer, &mut plans)
        .await
        .unwrap();
    assert_eq!(plans[0].parent_open_challenges, want);

    // The plan file carries it, and reads back.
    let path =
        std::env::temp_dir().join(format!("redecompose-challenges-{}.jsonl", Uuid::new_v4()));
    write_plan_jsonl(&path, &plans).unwrap();
    let line: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
    assert_eq!(
        line["parent_open_challenges"],
        serde_json::json!([{"id": pending, "state": "pending", "challenger_id": w.agent}])
    );
    assert_eq!(read_plan_jsonl(&path).unwrap(), plans);
    std::fs::remove_file(&path).ok();

    // Apply the plan, as --apply-plan --redecompose does.
    let redecompose = Population::Redecompose {
        include_decomposed: false,
    };
    let (ok, drifted) = verify_plan_for(&pool, &viewer, plans, redecompose)
        .await
        .unwrap();
    assert!(drifted.is_empty(), "{drifted:?}");
    let p = pool.clone();
    let agent = w.agent;
    let submit = move |text: String, _g: i64, _parent: epigraph_cli::decompose::AtomParent| {
        let p = p.clone();
        async move { Ok::<_, Box<dyn std::error::Error>>(claim_if_not_exists(&p, agent, &text).await) }
    };
    let totals = persist_planned(&pool, &viewer, &ok, None, &submit)
        .await
        .unwrap();
    assert_eq!(totals.edges, 2, "{:?}", totals.failed);

    // The parent's conflict edge is now a retarget input; its manifest entry
    // reports the same open challenge.
    let mut entries: Vec<epigraph_cli::retarget::RetargetPlanEntry> =
        R::list_parent_conflict_edges(&pool, &viewer, false, 100, 0)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.parent_id == w.compound_atom)
            .map(|e| epigraph_cli::retarget::RetargetPlanEntry {
                kind: epigraph_cli::retarget::RetargetPlanEntry::KIND.into(),
                edge_id: e.edge_id,
                relationship: "contradicts".into(),
                source_id: e.source_id,
                parent_id: e.parent_id,
                atoms: vec![],
                verdict: "unclear".into(),
                reason: None,
                chosen_atom_ids: vec![],
                model: "fixture".into(),
                parent_open_challenges: Vec::new(),
            })
            .collect();
    assert_eq!(entries.len(), 1);
    epigraph_cli::retarget::attach_parent_open_challenges(&pool, &viewer, &mut entries)
        .await
        .unwrap();
    assert_eq!(entries[0].parent_open_challenges, want);

    // No challenge row changed: same claim, owner, visibility, state.
    assert_eq!(
        (
            challenge_row(&pool, pending).await,
            challenge_row(&pool, rejected).await,
        ),
        before
    );
}

// ---- The binary's own wiring of the open-challenge report (backlog 122ac356).
//
// The test above drives the library helpers directly. These run the real
// `decompose_claims` binary, so they prove its `--redecompose --plan` and
// `--retarget` paths call those helpers and print the report.

const BIN: &str = env!("CARGO_BIN_EXE_decompose_claims");

/// The disputer's text: the `contradicts` source `seed` lands on the
/// compound atom, and the key of the retarget fixture.
const DISPUTER: &str = "The backup never took over.";

struct BinRun {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl BinRun {
    #[track_caller]
    fn ok(self) -> Self {
        assert_eq!(
            self.code,
            Some(0),
            "decompose_claims failed\nstdout:\n{}\nstderr:\n{}",
            self.stdout,
            self.stderr
        );
        self
    }

    fn open_challenge_lines(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|l| l.starts_with("OPEN-CHALLENGE "))
            .collect()
    }
}

fn temp_path(stem: &str, ext: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("redecompose-{stem}-{}.{ext}", Uuid::new_v4()))
}

/// Run the binary on the maintenance path with `fixture` as the LLM, in a
/// clean environment. No mode these tests run writes through the API, so the
/// token is never presented.
async fn run_bin(pool: &PgPool, args: &[&str], fixture: serde_json::Value) -> BinRun {
    let url = fixture::database_url_for(pool).await;
    let fixture_path = temp_path("fixture", "json");
    std::fs::write(&fixture_path, fixture.to_string()).unwrap();
    let out = std::process::Command::new(BIN)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        .env("EPIGRAPH_TOKEN", "never-presented-by-a-read-only-mode")
        .env("DECOMPOSE_FIXTURE_PATH", &fixture_path)
        .args(["--provider", "fixture"])
        .args(args)
        .current_dir(std::env::temp_dir())
        .output()
        .expect("run decompose_claims");
    std::fs::remove_file(&fixture_path).ok();
    BinRun {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `decompose_claims --redecompose --plan`: the compound atom's plan line in
/// the written file carries its pending challenge (not the rejected one) as
/// `parent_open_challenges`, and stderr names it on an `OPEN-CHALLENGE` line
/// and counts it. No challenge row changes.
#[sqlx::test(migrations = "../../migrations")]
async fn the_redecompose_plan_binary_writes_and_prints_the_parents_open_challenges(pool: PgPool) {
    let w = seed(&pool).await;
    let pending = seed_challenge(&pool, w.compound_atom, w.agent, "pending").await;
    let rejected = seed_challenge(&pool, w.compound_atom, w.agent, "rejected").await;
    let before = (
        challenge_row(&pool, pending).await,
        challenge_row(&pool, rejected).await,
    );
    let ids = temp_path("ids", "txt");
    std::fs::write(&ids, format!("{}\n", w.compound_atom)).unwrap();
    let plan = temp_path("plan", "jsonl");

    let r = run_bin(
        &pool,
        &[
            "--redecompose",
            "--ids-file",
            ids.to_str().unwrap(),
            "--plan",
            plan.to_str().unwrap(),
        ],
        serde_json::json!({ COMPOUND_ATOM: {
            "atoms": ["The pump failed.", "The backup took over."],
            "generality": [0, 0],
        }}),
    )
    .await
    .ok();

    let raw = std::fs::read_to_string(&plan)
        .unwrap_or_else(|e| panic!("no plan file ({e})\nstderr:\n{}", r.stderr));
    let lines: Vec<serde_json::Value> = raw
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 1, "{raw}\nstderr:\n{}", r.stderr);
    assert_eq!(lines[0]["claim_id"], serde_json::json!(w.compound_atom));
    assert_eq!(
        lines[0]["parent_open_challenges"],
        serde_json::json!([{"id": pending, "state": "pending", "challenger_id": w.agent}]),
        "{raw}"
    );
    assert_eq!(
        r.open_challenge_lines(),
        vec![format!(
            "OPEN-CHALLENGE parent={} challenge={pending} state=pending challenger={}",
            w.compound_atom, w.agent
        )],
        "stderr:\n{}",
        r.stderr
    );
    assert!(
        r.stderr
            .lines()
            .any(|l| l.starts_with("open challenges: 1 on 1 of 1 touched parents")),
        "stderr:\n{}",
        r.stderr
    );
    assert_eq!(
        (
            challenge_row(&pool, pending).await,
            challenge_row(&pool, rejected).await,
        ),
        before
    );
    std::fs::remove_file(&ids).ok();
    std::fs::remove_file(&plan).ok();
}

/// `decompose_claims --retarget` (dry run): once the compound atom has atoms,
/// its conflict edge's manifest entry carries the parent's pending challenge
/// (not the withdrawn one), and stderr names and counts it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_retarget_binary_writes_and_prints_the_parents_open_challenges(pool: PgPool) {
    let w = seed(&pool).await;
    let pump = claim_if_not_exists(&pool, w.agent, "The pump failed.").await;
    let backup = claim_if_not_exists(&pool, w.agent, "The backup took over.").await;
    edge(&pool, w.compound_atom, pump, "decomposes_to").await;
    edge(&pool, w.compound_atom, backup, "decomposes_to").await;
    let pending = seed_challenge(&pool, w.compound_atom, w.agent, "pending").await;
    let withdrawn = seed_challenge(&pool, w.compound_atom, w.agent, "withdrawn").await;
    let before = (
        challenge_row(&pool, pending).await,
        challenge_row(&pool, withdrawn).await,
    );
    let manifest = temp_path("manifest", "jsonl");

    let r = run_bin(
        &pool,
        &["--retarget", "--manifest", manifest.to_str().unwrap()],
        serde_json::json!({ DISPUTER: {"atoms": [1]} }),
    )
    .await
    .ok();

    let raw = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("no manifest ({e})\nstderr:\n{}", r.stderr));
    let entries: Vec<serde_json::Value> = raw
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|e| e["parent_id"] == serde_json::json!(w.compound_atom))
        .collect();
    assert_eq!(entries.len(), 1, "{raw}\nstderr:\n{}", r.stderr);
    assert_eq!(entries[0]["source_id"], serde_json::json!(w.disputer));
    assert_eq!(
        entries[0]["parent_open_challenges"],
        serde_json::json!([{"id": pending, "state": "pending", "challenger_id": w.agent}]),
        "{raw}"
    );
    assert_eq!(
        r.open_challenge_lines(),
        vec![format!(
            "OPEN-CHALLENGE parent={} challenge={pending} state=pending challenger={}",
            w.compound_atom, w.agent
        )],
        "stderr:\n{}",
        r.stderr
    );
    assert!(
        r.stderr
            .lines()
            .any(|l| l.starts_with("open challenges: 1 on 1 of ")),
        "stderr:\n{}",
        r.stderr
    );
    assert_eq!(
        (
            challenge_row(&pool, pending).await,
            challenge_row(&pool, withdrawn).await,
        ),
        before
    );
    std::fs::remove_file(&manifest).ok();
}
