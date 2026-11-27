//! The live belief readers that list or count claims by `truth_value` know
//! the claim's role (backlog ef58c6ad, fe1cdcdf; the register
//! `no_role_blind_belief_reads.rs`).
//!
//! A compound's cached `truth_value` is a fold of its own BBAs, not a value
//! derived from its leaves, so a reader must not gate, rank or count it as if
//! it were a belief:
//!
//! * the **listing** readers (`list_by_labels`, `list_filtered` /
//!   `count_filtered`, `rag_hybrid_context`, `list_active_network`,
//!   `get_claims_for_analysis`) apply the truth gate and the truth order to
//!   non-compounds only. A compound passes the gate ungated, so no compound
//!   disappears from a listing, and it is ranked after the atoms with no
//!   belief term of its own;
//! * the **attribution** readers (`get_claims_attributed_to`,
//!   `count_claims_attributed_to`) exclude compounds when a truth gate is in
//!   force (`min_truth > 0`); at the default `0` the gate is vacuous and
//!   every attributed claim is listed and counted, as before.
//!
//! A compound here is a claim with an in-force `decomposes_to` out-edge to a
//! current child (`claim_role::IS_COMPOUND_SQL`). Every expectation is a set
//! or order of fixture ids chosen by construction.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::BTreeSet;

use epigraph_db::{
    AnalysisRecord, AnalysisRepository, ClaimListFilter, ClaimRepository, ClaimSortField,
    ClaimSortOrder, EdgeRepository, LabelQuery, PolicyRepository,
};
use sqlx::PgPool;
use uuid::Uuid;

// ── seeding ────────────────────────────────────────────────────────────────

async fn agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'role-aware listings', 'system', \
                 ARRAY['test']) RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A public claim with a cached `truth_value` and `labels`.
async fn claim(pool: &PgPool, agent: Uuid, what: &str, truth: f64, labels: &[&str]) -> Uuid {
    let content = format!("{what} {}", Uuid::new_v4());
    let labels: Vec<String> = labels.iter().map(|l| (*l).to_string()).collect();
    let world = fixture::world_group(pool).await;
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, labels, \
                             visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), $2, $3, $4, 'public', $5) RETURNING id",
    )
    .bind(&content)
    .bind(truth)
    .bind(agent)
    .bind(&labels)
    .bind(world)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// A compound: a claim carrying `truth` in its cache, with an in-force
/// `decomposes_to` edge to a fresh, current, unlabelled child.
async fn compound(pool: &PgPool, agent: Uuid, what: &str, truth: f64, labels: &[&str]) -> Uuid {
    let parent = claim(pool, agent, what, truth, labels).await;
    let child = claim(pool, agent, "child", 0.5, &[]).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(parent)
    .bind(child)
    .execute(pool)
    .await
    .expect("seed decomposes_to");
    parent
}

fn ids<T>(rows: &[T], id: impl Fn(&T) -> Uuid) -> Vec<Uuid> {
    rows.iter().map(id).collect()
}

fn set(v: &[Uuid]) -> BTreeSet<Uuid> {
    v.iter().copied().collect()
}

// ── list_by_labels ─────────────────────────────────────────────────────────

/// `min_truth` gates atoms only: an atom below it is dropped, a compound below
/// it is still listed.
#[sqlx::test(migrations = "../../migrations")]
async fn list_by_labels_gates_atoms_and_lists_every_compound(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let a = agent(&pool).await;
    let label = format!("role-aware-{}", Uuid::new_v4().simple());
    let atom_low = claim(&pool, a, "atom low", 0.1, &[&label]).await;
    let atom_high = claim(&pool, a, "atom high", 0.9, &[&label]).await;
    let compound_low = compound(&pool, a, "compound low", 0.1, &[&label]).await;

    let rows = ClaimRepository::list_by_labels(
        &pool,
        &viewer,
        LabelQuery {
            labels: std::slice::from_ref(&label),
            min_truth: 0.5,
            limit: 50,
            ..Default::default()
        },
    )
    .await
    .expect("list_by_labels");
    let got = set(&ids(&rows, |(c, _)| c.id.into()));
    assert_eq!(
        got,
        set(&[atom_high, compound_low]),
        "the atom below min_truth is dropped ({atom_low}); the compound below it is listed"
    );
}

// ── list_filtered / count_filtered ─────────────────────────────────────────

async fn page(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    filter: &ClaimListFilter<'_>,
) -> (Vec<Uuid>, i64) {
    let rows = ClaimRepository::list_filtered(pool, viewer, filter, 50, 0)
        .await
        .expect("list_filtered");
    let total = ClaimRepository::count_filtered(pool, viewer, filter)
        .await
        .expect("count_filtered");
    (ids(&rows, |c| c.id.into()), total)
}

/// `truth_min` / `truth_max` gate atoms only, the count agrees with the page,
/// and a `truth_value` sort ranks the atoms and puts every compound after
/// them, in either direction.
#[sqlx::test(migrations = "../../migrations")]
async fn list_filtered_gates_and_sorts_atoms_only(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let a = agent(&pool).await;
    let atom_low = claim(&pool, a, "atom low", 0.1, &[]).await;
    let atom_mid = claim(&pool, a, "atom mid", 0.6, &[]).await;
    let atom_high = claim(&pool, a, "atom high", 0.8, &[]).await;
    let compound_high = compound(&pool, a, "compound high", 0.95, &[]).await;
    let compound_low = compound(&pool, a, "compound low", 0.1, &[]).await;
    let all = [atom_low, atom_mid, atom_high, compound_high, compound_low];

    // truth_min: the low atom is gated out, both compounds pass ungated.
    let (rows, total) = page(
        &pool,
        &viewer,
        &ClaimListFilter {
            ids: Some(&all),
            truth_min: Some(0.5),
            sort_by: ClaimSortField::TruthValue,
            sort_order: ClaimSortOrder::Desc,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        total, 4,
        "count = atoms >= 0.5 plus every compound: {rows:?}"
    );
    assert_eq!(rows.len(), 4);
    assert_eq!(
        rows[..2],
        [atom_high, atom_mid],
        "atoms first, by truth_value DESC (the 0.95 compound does not outrank them)"
    );
    assert_eq!(set(&rows[2..]), set(&[compound_high, compound_low]));

    // ASC: the atoms ascend, the compounds still come after them.
    let (rows, _) = page(
        &pool,
        &viewer,
        &ClaimListFilter {
            ids: Some(&all),
            truth_min: Some(0.5),
            sort_by: ClaimSortField::TruthValue,
            sort_order: ClaimSortOrder::Asc,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(rows[..2], [atom_mid, atom_high]);
    assert_eq!(set(&rows[2..]), set(&[compound_high, compound_low]));

    // truth_max: the 0.95 compound is not gated out either.
    let (rows, total) = page(
        &pool,
        &viewer,
        &ClaimListFilter {
            ids: Some(&all),
            truth_max: Some(0.5),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(total, 3, "{rows:?}");
    assert_eq!(set(&rows), set(&[atom_low, compound_high, compound_low]));
}

// ── rag_hybrid_context ─────────────────────────────────────────────────────

fn unit_vector() -> String {
    let mut v = vec!["0"; 1536];
    v[0] = "1";
    format!("[{}]", v.join(","))
}

/// `min_truth` gates atoms only, and a compound's `hybrid_score` carries no
/// `truth_value` term, so a high cached value does not rank it above an atom.
#[sqlx::test(migrations = "../../migrations")]
async fn rag_hybrid_context_gates_and_ranks_atoms_only(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let a = agent(&pool).await;
    let domain = format!("role-aware-{}", Uuid::new_v4().simple());
    let vec = unit_vector();
    let atom_high = claim(&pool, a, "atom high", 0.9, &[&domain]).await;
    let atom_low = claim(&pool, a, "atom low", 0.1, &[&domain]).await;
    let compound_high = compound(&pool, a, "compound high", 0.95, &[&domain]).await;
    let compound_low = compound(&pool, a, "compound low", 0.1, &[&domain]).await;
    for id in [atom_high, atom_low, compound_high, compound_low] {
        fixture::set_claim_embedding(&pool, id, &vec).await;
    }

    let hits = ClaimRepository::rag_hybrid_context(&pool, &viewer, &vec, 0.5, Some(&domain), 10)
        .await
        .expect("rag_hybrid_context");
    let got = ids(&hits, |h| h.claim_id);
    assert_eq!(
        set(&got),
        set(&[atom_high, compound_high, compound_low]),
        "the atom below min_truth is dropped ({atom_low}); both compounds are kept"
    );
    assert_eq!(
        got[0], atom_high,
        "a compound's cached 0.95 does not rank it above the 0.9 atom: {hits:#?}"
    );
    for h in &hits {
        let structural = h.similarity * 0.6 + (h.edge_count as f64 / 10.0).min(1.0) * 0.2;
        let want = if h.claim_id == atom_high {
            structural + h.truth_value * 0.2
        } else {
            structural
        };
        assert!(
            (h.hybrid_score - want).abs() < 1e-9,
            "{}: hybrid_score {} != {want}",
            h.claim_id,
            h.hybrid_score
        );
    }
}

// ── attribution ────────────────────────────────────────────────────────────

async fn attribute(pool: &PgPool, claim: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'agent', 'attributed_to')",
    )
    .bind(claim)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed attributed_to");
}

/// Under a truth gate the attribution list and count exclude compounds; at the
/// default `min_truth = 0` they list and count every attributed claim.
#[sqlx::test(migrations = "../../migrations")]
async fn attribution_truth_gate_excludes_compounds(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let a = agent(&pool).await;
    let author = agent(&pool).await;
    let atom_high = claim(&pool, a, "atom high", 0.9, &[]).await;
    let atom_low = claim(&pool, a, "atom low", 0.1, &[]).await;
    let compound_high = compound(&pool, a, "compound high", 0.9, &[]).await;
    for c in [atom_high, atom_low, compound_high] {
        attribute(&pool, c, author).await;
    }

    let gated = EdgeRepository::get_claims_attributed_to(&pool, &viewer, author, 0.5, 50, 0)
        .await
        .expect("get_claims_attributed_to");
    let gated_total = EdgeRepository::count_claims_attributed_to(&pool, &viewer, author, 0.5)
        .await
        .expect("count_claims_attributed_to");
    assert_eq!(
        ids(&gated, |r| r.id),
        vec![atom_high],
        "the compound's cached 0.9 does not pass the truth gate"
    );
    assert_eq!(gated_total, 1, "the count agrees with the list");

    let all = EdgeRepository::get_claims_attributed_to(&pool, &viewer, author, 0.0, 50, 0)
        .await
        .expect("get_claims_attributed_to");
    let all_total = EdgeRepository::count_claims_attributed_to(&pool, &viewer, author, 0.0)
        .await
        .expect("count_claims_attributed_to");
    assert_eq!(
        set(&ids(&all, |r| r.id)),
        set(&[atom_high, atom_low, compound_high]),
        "with no gate every attributed claim is listed"
    );
    assert_eq!(all_total, 3);
}

// ── list_active_network ────────────────────────────────────────────────────

/// Policy claims: the truth gate and the order apply to atoms; compounds pass
/// ungated and come after the atoms.
#[sqlx::test(migrations = "../../migrations")]
async fn list_active_network_gates_and_orders_atoms_only(pool: PgPool) {
    let a = agent(&pool).await;
    let labels = ["policy:active", "policy:network"];
    let atom_high = claim(&pool, a, "policy atom high", 0.9, &labels).await;
    let atom_mid = claim(&pool, a, "policy atom mid", 0.7, &labels).await;
    let atom_low = claim(&pool, a, "policy atom low", 0.2, &labels).await;
    let compound_low = compound(&pool, a, "policy compound low", 0.1, &labels).await;
    let compound_high = compound(&pool, a, "policy compound high", 0.95, &labels).await;

    let rows = PolicyRepository::list_active_network(&pool, 0.5)
        .await
        .expect("list_active_network");
    let got = ids(&rows, |(id, _, _)| *id);
    assert_eq!(
        got.len(),
        4,
        "{got:?} (the low atom {atom_low} is gated out)"
    );
    assert_eq!(
        got[..2],
        [atom_high, atom_mid],
        "atoms first, by truth DESC"
    );
    assert_eq!(set(&got[2..]), set(&[compound_low, compound_high]));
}

// ── get_claims_for_analysis ────────────────────────────────────────────────

/// An analysis's concluded claims: atoms by truth DESC, then every compound.
#[sqlx::test(migrations = "../../migrations")]
async fn get_claims_for_analysis_orders_atoms_by_truth_then_compounds(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let a = agent(&pool).await;
    let atom_low = claim(&pool, a, "concluded atom low", 0.3, &[]).await;
    let compound_high = compound(&pool, a, "concluded compound", 0.95, &[]).await;
    let atom_high = claim(&pool, a, "concluded atom high", 0.7, &[]).await;
    let record = AnalysisRecord {
        id: Uuid::new_v4(),
        analysis_type: "role-aware test".to_string(),
        method_description: "fixture".to_string(),
        inference_path: "fixture".to_string(),
        constraints: None,
        coverage_context: serde_json::json!({}),
        input_evidence_ids: Vec::new(),
        agent_id: a,
        properties: serde_json::json!({}),
        created_at: chrono::Utc::now(),
    };
    let analysis = AnalysisRepository::persist_bundle(
        &pool,
        None,
        &record,
        &[atom_low, compound_high, atom_high],
        &[],
    )
    .await
    .expect("persist_bundle");

    let rows = AnalysisRepository::get_claims_for_analysis(&pool, &viewer, analysis)
        .await
        .expect("get_claims_for_analysis");
    assert_eq!(
        ids(&rows, |r| r.id),
        vec![atom_high, atom_low, compound_high],
        "the compound's cached 0.95 does not rank it first"
    );
}
