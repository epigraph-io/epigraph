//! The live belief readers that list or count claims by `truth_value` know
//! the claim's role (backlog ef58c6ad, fe1cdcdf; the register
//! `no_role_blind_belief_reads.rs`).
//!
//! A compound's cached `truth_value` is a fold of its own BBAs, not a value
//! derived from its leaves, so a reader must not gate, rank or count it as if
//! it were a belief:
//!
//! * every **gated** reader (`list_by_labels`, `list_filtered` /
//!   `count_filtered`, `rag_hybrid_context`, `list_active_network`,
//!   `get_claims_attributed_to` / `count_claims_attributed_to`) FAILS CLOSED
//!   on a compound: under a non-vacuous truth gate a compound is excluded,
//!   whatever its cached value; under a vacuous one (`min_truth <= 0`,
//!   `truth_max >= 1`) it is listed and counted, as before. A compound must
//!   never pass a gate ungated, because "compound" is `decomposes_to`
//!   structure that any `edges:write` caller can add between two public
//!   claims: passing it would let that caller push a refuted claim, or a
//!   policy an admin drove below the gate, past the gate;
//! * the **ordering** readers (`list_filtered`'s truth sort,
//!   `rag_hybrid_context`'s score, `list_active_network`,
//!   `get_claims_for_analysis`) rank non-compounds by truth and put every
//!   compound after them, with no belief term of its own;
//! * the role is decided on the CALLER's connection, so a reader whose row
//!   security hides a compound's decomposition sees that claim as a plain
//!   claim, and a private decomposition sends an outsider no signal.
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

async fn by_label(
    executor: impl sqlx::PgExecutor<'_>,
    viewer: &epigraph_db::visibility::Viewer,
    label: &str,
    min_truth: f64,
) -> BTreeSet<Uuid> {
    let labels = [label.to_string()];
    let rows = ClaimRepository::list_by_labels(
        executor,
        viewer,
        LabelQuery {
            labels: &labels,
            min_truth,
            limit: 50,
            ..Default::default()
        },
    )
    .await
    .expect("list_by_labels");
    set(&ids(&rows, |(c, _)| c.id.into()))
}

/// Under a gate, `min_truth` lists only atoms that reach it: a compound is
/// excluded even when its cached value would pass (fail closed). At the
/// default `0` every labelled claim, compounds included, is listed.
#[sqlx::test(migrations = "../../migrations")]
async fn list_by_labels_gate_fails_closed_on_compounds(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let a = agent(&pool).await;
    let label = format!("role-aware-{}", Uuid::new_v4().simple());
    let atom_low = claim(&pool, a, "atom low", 0.1, &[&label]).await;
    let atom_high = claim(&pool, a, "atom high", 0.9, &[&label]).await;
    let compound_low = compound(&pool, a, "compound low", 0.1, &[&label]).await;
    let compound_high = compound(&pool, a, "compound high", 0.9, &[&label]).await;

    assert_eq!(
        by_label(&pool, &viewer, &label, 0.5).await,
        set(&[atom_high]),
        "only the atom that reaches min_truth is listed: not the low atom ({atom_low}), \
         not the low compound ({compound_low}), and not the compound whose cached 0.9 \
         would pass ({compound_high})"
    );
    assert_eq!(
        by_label(&pool, &viewer, &label, 0.0).await,
        set(&[atom_low, atom_high, compound_low, compound_high]),
        "with no gate every labelled claim is listed"
    );
}

/// The role is decided on the caller's stamped application connection. A
/// public, labelled claim whose only decomposition (edge and child) is private
/// to a group is a compound to a member of that group, so a gate excludes it;
/// to an outsider, whose row security hides the decomposition, it is a plain
/// claim and its own value decides, so the outsider gets no signal that a
/// private decomposition exists. Deciding the role with migration 193's
/// whole-graph definer here instead would drop it for the outsider too, and
/// that absence would disclose the hidden decomposition.
#[sqlx::test(migrations = "../../migrations")]
async fn list_by_labels_decides_the_role_on_the_callers_row_security(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "ef58c6ad-member").await;
    let (outsider, _) = fixture::seed_agent_with_group(&pool, "ef58c6ad-outsider").await;
    let a = agent(&pool).await;
    let label = format!("role-aware-{}", Uuid::new_v4().simple());
    let atom = claim(&pool, a, "public atom", 0.9, &[&label]).await;
    let hidden = claim(&pool, a, "public, private decomposition", 0.9, &[&label]).await;
    let child = fixture::seed_group_claim(&pool, member, group, "private child").await;
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to') RETURNING id",
    )
    .bind(hidden)
    .bind(child)
    .fetch_one(&pool)
    .await
    .expect("seed decomposes_to");
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(group)
    .execute(&pool)
    .await
    .expect("make the decomposition private");

    let url = fixture::database_url_for(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let mut seen = Vec::new();
    for agent in [member, outsider] {
        let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent)
            .await
            .expect("resolve viewer");
        let mut tx = scoped.begin_as(&viewer).await.expect("stamped transaction");
        let who: String = sqlx::query_scalar("SELECT session_user::text")
            .fetch_one(&mut *tx)
            .await
            .expect("session_user");
        assert_eq!(who, "epigraph_app", "calibration: the application role");
        let gated = by_label(&mut *tx, &viewer, &label, 0.5).await;
        let open = by_label(&mut *tx, &viewer, &label, 0.0).await;
        tx.rollback().await.expect("rollback");
        seen.push((gated, open));
    }
    let (member_gated, member_open) = &seen[0];
    let (outsider_gated, outsider_open) = &seen[1];
    assert_eq!(
        member_open,
        &set(&[atom, hidden]),
        "calibration: with no gate the member lists both"
    );
    assert_eq!(
        outsider_open,
        &set(&[atom, hidden]),
        "calibration: with no gate the outsider lists both"
    );
    assert_eq!(
        member_gated,
        &set(&[atom]),
        "the member sees the decomposition, so the compound fails the gate closed"
    );
    assert_eq!(
        outsider_gated,
        &set(&[atom, hidden]),
        "the outsider cannot see the decomposition: the claim is plain to it and its own \
         0.9 passes, so its listing carries no trace of the private structure"
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

/// A non-vacuous `truth_min` / `truth_max` lists only atoms that meet it
/// (fail closed on every compound, whatever its cached value), the count
/// agrees with the page, vacuous bounds list everything, and a `truth_value`
/// sort ranks the atoms and puts every compound after them, in either
/// direction.
#[sqlx::test(migrations = "../../migrations")]
async fn list_filtered_gates_fail_closed_and_sort_atoms_only(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let a = agent(&pool).await;
    let atom_low = claim(&pool, a, "atom low", 0.1, &[]).await;
    let atom_mid = claim(&pool, a, "atom mid", 0.6, &[]).await;
    let atom_high = claim(&pool, a, "atom high", 0.8, &[]).await;
    let compound_high = compound(&pool, a, "compound high", 0.95, &[]).await;
    let compound_low = compound(&pool, a, "compound low", 0.1, &[]).await;
    let all = [atom_low, atom_mid, atom_high, compound_high, compound_low];

    // truth_min: the low atom is gated out, and so is every compound, the
    // 0.95 one included.
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
        rows,
        [atom_high, atom_mid],
        "only the atoms >= 0.5, by truth_value DESC"
    );
    assert_eq!(total, 2, "the count agrees with the page");

    // truth_max: the 0.1 compound does not slip under it either.
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
    assert_eq!(rows, [atom_low], "only the atom <= 0.5");
    assert_eq!(total, 1);

    // Vacuous bounds gate nothing: every claim, compounds included.
    let (rows, total) = page(
        &pool,
        &viewer,
        &ClaimListFilter {
            ids: Some(&all),
            truth_min: Some(0.0),
            truth_max: Some(1.0),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(set(&rows), set(&all));
    assert_eq!(total, 5);

    // The sort: atoms by truth_value, then the compounds, in both directions.
    let (rows, _) = page(
        &pool,
        &viewer,
        &ClaimListFilter {
            ids: Some(&all),
            sort_by: ClaimSortField::TruthValue,
            sort_order: ClaimSortOrder::Desc,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        rows[..3],
        [atom_high, atom_mid, atom_low],
        "atoms first, by truth_value DESC (the 0.95 compound does not outrank them)"
    );
    assert_eq!(set(&rows[3..]), set(&[compound_high, compound_low]));
    let (rows, _) = page(
        &pool,
        &viewer,
        &ClaimListFilter {
            ids: Some(&all),
            sort_by: ClaimSortField::TruthValue,
            sort_order: ClaimSortOrder::Asc,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(rows[..3], [atom_low, atom_mid, atom_high]);
    assert_eq!(set(&rows[3..]), set(&[compound_high, compound_low]));
}

// ── rag_hybrid_context ─────────────────────────────────────────────────────

fn unit_vector() -> String {
    let mut v = vec!["0"; 1536];
    v[0] = "1";
    format!("[{}]", v.join(","))
}

/// Under a gate `min_truth` keeps only atoms that reach it (fail closed on
/// every compound, so no structural edit can put a refuted claim into the
/// context); at `0` the compounds are kept, and a compound's `hybrid_score`
/// carries no `truth_value` term, so a high cached value does not rank it
/// above an atom.
#[sqlx::test(migrations = "../../migrations")]
async fn rag_hybrid_context_gate_fails_closed_and_ranks_atoms_only(pool: PgPool) {
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
    assert_eq!(
        ids(&hits, |h| h.claim_id),
        vec![atom_high],
        "only the atom that reaches min_truth: not the low atom ({atom_low}), and no \
         compound, not even the one whose cached 0.95 would pass ({compound_high})"
    );

    let hits = ClaimRepository::rag_hybrid_context(&pool, &viewer, &vec, 0.0, Some(&domain), 10)
        .await
        .expect("rag_hybrid_context");
    let got = ids(&hits, |h| h.claim_id);
    assert_eq!(
        set(&got),
        set(&[atom_high, atom_low, compound_high, compound_low]),
        "with no gate every claim is kept"
    );
    assert_eq!(
        got[0], atom_high,
        "a compound's cached 0.95 does not rank it above the 0.9 atom: {hits:#?}"
    );
    for h in &hits {
        let structural = h.similarity * 0.6 + (h.edge_count as f64 / 10.0).min(1.0) * 0.2;
        let want = if h.claim_id == atom_high || h.claim_id == atom_low {
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

/// Policy claims (an allow list): under a gate only atoms that reach it are
/// listed, by truth DESC. A compound is excluded whatever its cached value,
/// so a `decomposes_to` edge any `edges:write` caller can add cannot re-list
/// a policy an admin drove below the gate (fail closed). At `0` every policy
/// is listed, the compounds after the atoms.
#[sqlx::test(migrations = "../../migrations")]
async fn list_active_network_gate_fails_closed_on_compounds(pool: PgPool) {
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
    assert_eq!(
        ids(&rows, |(id, _, _)| *id),
        vec![atom_high, atom_mid],
        "the low atom ({atom_low}) and both compounds ({compound_low}, {compound_high}) \
         are out"
    );

    let rows = PolicyRepository::list_active_network(&pool, 0.0)
        .await
        .expect("list_active_network");
    let got = ids(&rows, |(id, _, _)| *id);
    assert_eq!(
        got[..3],
        [atom_high, atom_mid, atom_low],
        "atoms first, by truth DESC"
    );
    assert_eq!(set(&got[3..]), set(&[compound_low, compound_high]));
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
