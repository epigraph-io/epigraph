//! Criterion benchmarks for epigraph-engine core operations
//!
//! Measures performance of:
//! - Bayesian truth updates (single and sequential)
//! - Evidence weight calculation across evidence types
//! - DAG cycle detection at varying graph sizes
//! - Agent reputation calculation from claim histories
//! - Propagation through a claim dependency chain

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_engine::reputation::{ClaimOutcome, ReputationCalculator};
use epigraph_engine::{
    BayesianUpdater, DagValidator, EvidenceType, EvidenceWeighter, PropagationOrchestrator,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a test claim with the given truth value.
fn make_claim(truth: f64) -> Claim {
    let agent_id = AgentId::new();
    Claim::new(
        "Benchmark claim".to_string(),
        agent_id,
        [0u8; 32],
        TruthValue::new(truth).unwrap(),
    )
}

// ---------------------------------------------------------------------------
// Bayesian update benchmarks
// ---------------------------------------------------------------------------

fn bench_bayesian_single_update(c: &mut Criterion) {
    let updater = BayesianUpdater::new();
    let prior = TruthValue::new(0.5).unwrap();

    c.bench_function("bayesian_single_update", |b| {
        b.iter(|| {
            updater
                .update(black_box(prior), black_box(0.8), black_box(0.2))
                .unwrap()
        });
    });
}

fn bench_bayesian_sequential_updates(c: &mut Criterion) {
    let updater = BayesianUpdater::new();

    c.bench_function("bayesian_100_sequential_updates", |b| {
        b.iter(|| {
            let mut truth = TruthValue::new(0.5).unwrap();
            for _ in 0..100 {
                truth = updater
                    .update_with_support(black_box(truth), black_box(0.7))
                    .unwrap();
            }
            truth
        });
    });
}

fn bench_bayesian_initial_truth(c: &mut Criterion) {
    c.bench_function("bayesian_calculate_initial_truth", |b| {
        b.iter(|| BayesianUpdater::calculate_initial_truth(black_box(0.6), black_box(3)));
    });
}

// ---------------------------------------------------------------------------
// Evidence weight benchmarks
// ---------------------------------------------------------------------------

fn bench_evidence_weight_calculation(c: &mut Criterion) {
    let weighter = EvidenceWeighter::new();
    let source_truth = TruthValue::new(0.8).unwrap();

    let evidence_types = [
        ("empirical", EvidenceType::Empirical),
        ("statistical", EvidenceType::Statistical),
        ("logical", EvidenceType::Logical),
        ("testimonial", EvidenceType::Testimonial),
        ("circumstantial", EvidenceType::Circumstantial),
    ];

    for (name, ev_type) in &evidence_types {
        c.bench_function(&format!("evidence_weight_{name}"), |b| {
            b.iter(|| {
                weighter
                    .calculate_weight(
                        black_box(*ev_type),
                        black_box(Some(source_truth)),
                        black_box(0.85),
                        black_box(7.0),
                    )
                    .unwrap()
            });
        });
    }
}

fn bench_evidence_combine_weights(c: &mut Criterion) {
    let weighter = EvidenceWeighter::new();
    let weights: Vec<f64> = (0..10).map(|i| f64::from(i).mul_add(0.07, 0.3)).collect();

    c.bench_function("evidence_combine_10_weights", |b| {
        b.iter(|| weighter.combine_weights(black_box(&weights)));
    });
}

// ---------------------------------------------------------------------------
// DAG cycle-detection benchmarks
// ---------------------------------------------------------------------------

/// Build a linear chain DAG: 0 -> 1 -> 2 -> ... -> (n-1).
/// Uses unique UUIDs to support any size.
fn build_chain_dag(n: usize) -> (DagValidator, Vec<Uuid>) {
    let mut dag = DagValidator::new();
    let uuids: Vec<Uuid> = (0..n).map(|_| Uuid::new_v4()).collect();
    for w in uuids.windows(2) {
        dag.add_edge(w[0], w[1]).unwrap();
    }
    (dag, uuids)
}

/// Build a wide DAG: single root fans out to (n-2) middle nodes, all converging
/// to a single sink. Total nodes = n, edges = 2*(n-2).
fn build_wide_dag(n: usize) -> (DagValidator, Vec<Uuid>) {
    let mut dag = DagValidator::new();
    let uuids: Vec<Uuid> = (0..n).map(|_| Uuid::new_v4()).collect();
    let root = uuids[0];
    let sink = uuids[n - 1];
    for id in &uuids[1..n - 1] {
        dag.add_edge(root, *id).unwrap();
        dag.add_edge(*id, sink).unwrap();
    }
    (dag, uuids)
}

fn bench_dag_cycle_detection_small(c: &mut Criterion) {
    let (dag, _) = build_chain_dag(10);

    c.bench_function("dag_cycle_detection_10_nodes", |b| {
        b.iter(|| black_box(dag.is_valid()));
    });
}

fn bench_dag_cycle_detection_large(c: &mut Criterion) {
    let (dag, _) = build_wide_dag(1000);

    c.bench_function("dag_cycle_detection_1000_nodes", |b| {
        b.iter(|| black_box(dag.is_valid()));
    });
}

fn bench_dag_add_edge_with_cycle_check(c: &mut Criterion) {
    c.bench_function("dag_add_edge_with_cycle_check", |b| {
        b.iter_batched(
            || {
                let mut dag = DagValidator::new();
                let a = Uuid::new_v4();
                let b_uuid = Uuid::new_v4();
                dag.add_node(a);
                dag.add_node(b_uuid);
                (dag, a, b_uuid)
            },
            |(mut dag, a, b_uuid)| {
                let _ = dag.add_edge(black_box(a), black_box(b_uuid));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_dag_topological_order(c: &mut Criterion) {
    let (dag, _) = build_chain_dag(100);

    c.bench_function("dag_topological_order_100_nodes", |b| {
        b.iter(|| dag.topological_order().unwrap());
    });
}

// ---------------------------------------------------------------------------
// Reputation calculation benchmarks
// ---------------------------------------------------------------------------

fn bench_reputation_calculation(c: &mut Criterion) {
    let calc = ReputationCalculator::new();

    let outcomes: Vec<ClaimOutcome> = (0..100)
        .map(|i| ClaimOutcome {
            truth_value: (f64::from(i) % 7.0).mul_add(0.1, 0.3),
            age_days: f64::from(i) * 0.5,
            was_refuted: i % 5 == 0,
        })
        .collect();

    c.bench_function("reputation_from_100_outcomes", |b| {
        b.iter(|| calc.calculate(black_box(&outcomes)).unwrap());
    });
}

fn bench_reputation_few_claims(c: &mut Criterion) {
    let calc = ReputationCalculator::new();

    let outcomes: Vec<ClaimOutcome> = (0..3)
        .map(|i| ClaimOutcome {
            truth_value: 0.7,
            age_days: f64::from(i) * 2.0,
            was_refuted: false,
        })
        .collect();

    c.bench_function("reputation_from_3_outcomes_stability_penalty", |b| {
        b.iter(|| calc.calculate(black_box(&outcomes)).unwrap());
    });
}

// ---------------------------------------------------------------------------
// Propagation orchestrator benchmarks
// ---------------------------------------------------------------------------

fn bench_propagation_linear_chain(c: &mut Criterion) {
    c.bench_function("propagation_10_node_chain", |b| {
        b.iter_batched(
            || {
                let mut orch = PropagationOrchestrator::new();
                let mut claim_ids = Vec::new();
                for _ in 0..10 {
                    let claim = make_claim(0.5);
                    let id = claim.id;
                    orch.register_claim(claim).unwrap();
                    claim_ids.push(id);
                }
                for w in claim_ids.windows(2) {
                    orch.add_dependency(w[0], w[1], true, 0.8, EvidenceType::Empirical, 0.0)
                        .unwrap();
                }
                (orch, claim_ids[0])
            },
            |(mut orch, root_id)| {
                orch.update_and_propagate(
                    black_box(root_id),
                    black_box(TruthValue::new(0.9).unwrap()),
                )
                .unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

// ---------------------------------------------------------------------------
// Group and main
// ---------------------------------------------------------------------------

criterion_group!(
    bayesian_benches,
    bench_bayesian_single_update,
    bench_bayesian_sequential_updates,
    bench_bayesian_initial_truth,
);

criterion_group!(
    evidence_benches,
    bench_evidence_weight_calculation,
    bench_evidence_combine_weights,
);

criterion_group!(
    dag_benches,
    bench_dag_cycle_detection_small,
    bench_dag_cycle_detection_large,
    bench_dag_add_edge_with_cycle_check,
    bench_dag_topological_order,
);

criterion_group!(
    reputation_benches,
    bench_reputation_calculation,
    bench_reputation_few_claims,
);

criterion_group!(propagation_benches, bench_propagation_linear_chain,);

criterion_main!(
    bayesian_benches,
    evidence_benches,
    dag_benches,
    reputation_benches,
    propagation_benches,
);
