//! Criterion benchmarks for epigraph-crypto operations
//!
//! Measures performance of:
//! - BLAKE3 hashing at different payload sizes (1 KB, 1 MB)
//! - Ed25519 key generation, signing, and verification
//! - Canonical JSON serialization for deterministic hashing

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use epigraph_crypto::{AgentSigner, ContentHasher, SignatureVerifier};
use serde_json::json;

// ---------------------------------------------------------------------------
// BLAKE3 hashing benchmarks
// ---------------------------------------------------------------------------

fn bench_blake3_hash_small(c: &mut Criterion) {
    // 1 KB payload
    let data = vec![0xABu8; 1024];

    c.bench_function("blake3_hash_1kb", |b| {
        b.iter(|| ContentHasher::hash(black_box(&data)));
    });
}

fn bench_blake3_hash_large(c: &mut Criterion) {
    // 1 MB payload
    let data = vec![0xCDu8; 1_048_576];

    c.bench_function("blake3_hash_1mb", |b| {
        b.iter(|| ContentHasher::hash(black_box(&data)));
    });
}

fn bench_blake3_hash_canonical(c: &mut Criterion) {
    let value = json!({
        "claim_id": "550e8400-e29b-41d4-a716-446655440000",
        "content": "The Earth orbits the Sun",
        "truth_value": 0.95,
        "evidence_count": 42,
        "agent": {
            "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "reputation": 0.87
        }
    });

    c.bench_function("blake3_hash_canonical_json", |b| {
        b.iter(|| ContentHasher::hash_canonical(black_box(&value)).unwrap());
    });
}

fn bench_blake3_hash_combine(c: &mut Criterion) {
    let hashes: Vec<[u8; 32]> = (0u8..10).map(|i| ContentHasher::hash(&[i; 64])).collect();

    c.bench_function("blake3_hash_combine_10_items", |b| {
        b.iter(|| ContentHasher::hash_combine(black_box(&hashes)));
    });
}

fn bench_blake3_incremental(c: &mut Criterion) {
    // Simulate streaming 1 MB in 4 KB chunks
    let chunks: Vec<Vec<u8>> = (0u8..=255).map(|i| vec![i; 4096]).collect();

    c.bench_function("blake3_incremental_1mb_4kb_chunks", |b| {
        b.iter(|| {
            let mut hasher = ContentHasher::incremental();
            for chunk in &chunks {
                hasher.update(black_box(chunk));
            }
            let result: [u8; 32] = hasher.finalize().into();
            result
        });
    });
}

// ---------------------------------------------------------------------------
// Ed25519 signing benchmarks
// ---------------------------------------------------------------------------

fn bench_ed25519_keygen(c: &mut Criterion) {
    c.bench_function("ed25519_key_generation", |b| {
        b.iter(AgentSigner::generate);
    });
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let signer = AgentSigner::generate();
    let message = b"This is a claim that needs to be signed for integrity verification";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| signer.sign(black_box(message)));
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let signer = AgentSigner::generate();
    let message = b"This is a claim that needs to be verified for integrity";
    let signature = signer.sign(message);
    let public_key = signer.public_key();

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            SignatureVerifier::verify(
                black_box(&public_key),
                black_box(message),
                black_box(&signature),
            )
            .unwrap()
        });
    });
}

fn bench_ed25519_sign_canonical(c: &mut Criterion) {
    let signer = AgentSigner::generate();
    let value = json!({
        "claim": "Benchmark canonical signing",
        "truth_value": 0.75,
        "evidence": ["source_a", "source_b"]
    });

    c.bench_function("ed25519_sign_canonical", |b| {
        b.iter(|| signer.sign_canonical(black_box(&value)).unwrap());
    });
}

fn bench_ed25519_verify_canonical(c: &mut Criterion) {
    let signer = AgentSigner::generate();
    let value = json!({
        "claim": "Benchmark canonical verify",
        "truth_value": 0.75,
        "evidence": ["source_a", "source_b"]
    });
    let signature = signer.sign_canonical(&value).unwrap();
    let public_key = signer.public_key();

    c.bench_function("ed25519_verify_canonical", |b| {
        b.iter(|| {
            SignatureVerifier::verify_canonical(
                black_box(&public_key),
                black_box(&value),
                black_box(&signature),
            )
            .unwrap()
        });
    });
}

// ---------------------------------------------------------------------------
// Canonical serialization benchmarks
// ---------------------------------------------------------------------------

fn bench_canonical_serialization(c: &mut Criterion) {
    let value = json!({
        "z_field": "last",
        "a_field": "first",
        "nested": {
            "z_inner": 100,
            "a_inner": 1,
            "m_inner": 50
        },
        "array": [3, 1, 4, 1, 5, 9, 2, 6],
        "bool_val": true,
        "null_val": null
    });

    c.bench_function("canonical_serialization_nested_json", |b| {
        b.iter(|| epigraph_crypto::to_canonical_json(black_box(&value)).unwrap());
    });
}

fn bench_canonical_serialization_large(c: &mut Criterion) {
    // Build a JSON object with 100 keys to stress key-sorting
    let mut map = serde_json::Map::new();
    for i in (0..100).rev() {
        map.insert(
            format!("key_{i:03}"),
            serde_json::Value::Number(serde_json::Number::from(i)),
        );
    }
    let value = serde_json::Value::Object(map);

    c.bench_function("canonical_serialization_100_keys", |b| {
        b.iter(|| epigraph_crypto::to_canonical_json(black_box(&value)).unwrap());
    });
}

// ---------------------------------------------------------------------------
// Constant-time comparison benchmark
// ---------------------------------------------------------------------------

fn bench_constant_time_eq(c: &mut Criterion) {
    let a = ContentHasher::hash(b"hash_a");
    let b_hash = ContentHasher::hash(b"hash_b");

    c.bench_function("constant_time_eq_32_bytes", |b| {
        b.iter(|| SignatureVerifier::constant_time_eq(black_box(&a), black_box(&b_hash)));
    });
}

// ---------------------------------------------------------------------------
// Group and main
// ---------------------------------------------------------------------------

criterion_group!(
    blake3_benches,
    bench_blake3_hash_small,
    bench_blake3_hash_large,
    bench_blake3_hash_canonical,
    bench_blake3_hash_combine,
    bench_blake3_incremental,
);

criterion_group!(
    ed25519_benches,
    bench_ed25519_keygen,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_ed25519_sign_canonical,
    bench_ed25519_verify_canonical,
);

criterion_group!(
    canonical_benches,
    bench_canonical_serialization,
    bench_canonical_serialization_large,
    bench_constant_time_eq,
);

criterion_main!(blake3_benches, ed25519_benches, canonical_benches,);
