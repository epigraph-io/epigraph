//! Repository round-trip tests for `FrameRepository`'s per-frame
//! evidence-type weight accessors (Phase 4 of issue #197).
//!
//! Covers:
//!   * `set_evidence_type_weight` / `get_per_frame_evidence_type_weights`
//!     round-trip on canonical and aliased keys.
//!   * Case normalisation on read (operator writes "Empirical", reader
//!     sees "empirical").
//!   * Malformed JSON value: object replaced with a string → Ok(None).
//!   * Non-numeric weight in an otherwise-valid map: drops bad entry,
//!     keeps valid ones.
//!   * Out-of-range weight ([0.0, 1.0] clamp per Q10): dropped with
//!     warn-log; if only entry, Ok(None).
//!   * Missing `evidence_type_weights` key (other properties present):
//!     Ok(None).
//!   * Missing frame: Ok(None) (graceful, not error).
//!
//! All tests use `epigraph_db_repo_test` via `#[sqlx::test]`.

use epigraph_db::FrameRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_frame(pool: &PgPool, name: &str) -> Uuid {
    let row = FrameRepository::create(
        pool,
        name,
        Some("phase4 test frame"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("create frame");
    row.id
}

#[sqlx::test(migrations = "../../migrations")]
async fn roundtrip_canonical_key(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_canonical").await;
    FrameRepository::set_evidence_type_weight(&pool, frame_id, "empirical", 0.5)
        .await
        .expect("set weight");

    let map = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights")
        .expect("Some(map)");
    assert_eq!(map.len(), 1, "expected single entry, got {map:?}");
    let w = map
        .get("empirical")
        .copied()
        .expect("empirical key present");
    assert!(
        (w - 0.5).abs() < f64::EPSILON,
        "expected empirical=0.5 round-trip, got {w}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn roundtrip_multiple_keys(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_multi").await;
    FrameRepository::set_evidence_type_weight(&pool, frame_id, "empirical", 0.5)
        .await
        .expect("set empirical");
    FrameRepository::set_evidence_type_weight(&pool, frame_id, "logical", 0.9)
        .await
        .expect("set logical");

    let map = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights")
        .expect("Some(map)");
    assert_eq!(map.len(), 2, "expected 2 entries, got {map:?}");
    assert!((map["empirical"] - 0.5).abs() < f64::EPSILON);
    assert!((map["logical"] - 0.9).abs() < f64::EPSILON);
}

#[sqlx::test(migrations = "../../migrations")]
async fn case_normalised_on_read(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_case").await;
    // Write with mixed case via raw set_property → JSONB stores
    // "Empirical" literally.
    FrameRepository::set_property(
        &pool,
        frame_id,
        "evidence_type_weights",
        &serde_json::json!({"Empirical": 0.7}),
    )
    .await
    .expect("set property");

    let map = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights")
        .expect("Some(map)");
    // Reader lowercases on parse — caller can probe with "empirical".
    let w = map
        .get("empirical")
        .copied()
        .expect("case-normalised key present");
    assert!((w - 0.7).abs() < f64::EPSILON);
    assert!(
        !map.contains_key("Empirical"),
        "mixed-case key must not survive lowercasing"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn malformed_value_returns_none(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_malformed").await;
    // Operator wrote a string under the key instead of an object.
    FrameRepository::set_property(
        &pool,
        frame_id,
        "evidence_type_weights",
        &serde_json::json!("not-an-object"),
    )
    .await
    .expect("set property");

    let result = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights");
    assert!(
        result.is_none(),
        "non-object value must return Ok(None), got {result:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn non_numeric_entry_dropped_valid_kept(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_nonnum").await;
    FrameRepository::set_property(
        &pool,
        frame_id,
        "evidence_type_weights",
        &serde_json::json!({"empirical": "string", "logical": 0.85}),
    )
    .await
    .expect("set property");

    let map = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights")
        .expect("Some(map) — logical entry is valid");
    assert_eq!(
        map.len(),
        1,
        "expected only logical to survive, got {map:?}"
    );
    assert!((map["logical"] - 0.85).abs() < f64::EPSILON);
    assert!(
        !map.contains_key("empirical"),
        "non-numeric empirical entry must be dropped"
    );
}

/// Phase 4 Q10 locked decision: out-of-range values dropped with warn-log.
/// 5.0 > 1.0 (the [0.0, 1.0] clamp); the dropped entry is the only one,
/// so the accessor returns Ok(None).
#[sqlx::test(migrations = "../../migrations")]
async fn out_of_range_only_entry_returns_none(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_oor_only").await;
    FrameRepository::set_property(
        &pool,
        frame_id,
        "evidence_type_weights",
        &serde_json::json!({"empirical": 5.0}),
    )
    .await
    .expect("set property");

    let result = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights");
    assert!(
        result.is_none(),
        "out-of-range only entry → empty map → Ok(None), got {result:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn out_of_range_mixed_drops_bad_keeps_good(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_oor_mixed").await;
    FrameRepository::set_property(
        &pool,
        frame_id,
        "evidence_type_weights",
        &serde_json::json!({
            "empirical": 5.0,    // out of range, dropped
            "logical": 0.85,     // valid, kept
            "testimonial": -0.1, // negative, dropped
        }),
    )
    .await
    .expect("set property");

    let map = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights")
        .expect("Some(map) — logical kept");
    assert_eq!(
        map.len(),
        1,
        "expected only logical to survive, got {map:?}"
    );
    assert!((map["logical"] - 0.85).abs() < f64::EPSILON);
}

/// Phase 4 boundary values: 0.0 and 1.0 are both inclusive per Q10.
#[sqlx::test(migrations = "../../migrations")]
async fn boundary_values_zero_and_one_accepted(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_boundary").await;
    FrameRepository::set_property(
        &pool,
        frame_id,
        "evidence_type_weights",
        &serde_json::json!({"empirical": 0.0, "logical": 1.0}),
    )
    .await
    .expect("set property");

    let map = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights")
        .expect("Some(map)");
    assert_eq!(
        map.len(),
        2,
        "expected both boundary entries kept, got {map:?}"
    );
    assert!((map["empirical"] - 0.0).abs() < f64::EPSILON);
    assert!((map["logical"] - 1.0).abs() < f64::EPSILON);
}

/// Other property keys are present but `evidence_type_weights` is
/// absent → Ok(None). Phase 2's `intra_evidence_locality_factor` key
/// must NOT leak into the Phase 4 accessor.
#[sqlx::test(migrations = "../../migrations")]
async fn missing_evidence_type_weights_key_returns_none(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_missing_key").await;
    FrameRepository::set_property(
        &pool,
        frame_id,
        "intra_evidence_locality_factor",
        &serde_json::json!(0.5),
    )
    .await
    .expect("set Phase-2 key only");

    let result = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights");
    assert!(
        result.is_none(),
        "Phase 2 key alone must not satisfy Phase 4 accessor, got {result:?}"
    );
}

/// Querying a nonexistent frame_id returns Ok(None), not an error.
#[sqlx::test(migrations = "../../migrations")]
async fn missing_frame_returns_none(pool: PgPool) {
    let result = FrameRepository::get_per_frame_evidence_type_weights(&pool, Uuid::new_v4())
        .await
        .expect("get weights on missing frame should not error");
    assert!(
        result.is_none(),
        "missing frame must return Ok(None), got {result:?}"
    );
}

/// `set_evidence_type_weight` is a read-modify-write merge. Setting a
/// new key on top of an existing object preserves the existing entries.
#[sqlx::test(migrations = "../../migrations")]
async fn set_evidence_type_weight_merges_into_existing_map(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_merge").await;
    FrameRepository::set_evidence_type_weight(&pool, frame_id, "empirical", 0.5)
        .await
        .expect("first write");
    FrameRepository::set_evidence_type_weight(&pool, frame_id, "logical", 0.9)
        .await
        .expect("second write");

    let map = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights")
        .expect("Some(map)");
    assert_eq!(
        map.len(),
        2,
        "second write must preserve first entry, got {map:?}"
    );
    assert!((map["empirical"] - 0.5).abs() < f64::EPSILON);
    assert!((map["logical"] - 0.9).abs() < f64::EPSILON);
}

/// `set_evidence_type_weight` on the same key twice overwrites.
#[sqlx::test(migrations = "../../migrations")]
async fn set_evidence_type_weight_overwrites_existing_key(pool: PgPool) {
    let frame_id = seed_frame(&pool, "phase4_overwrite").await;
    FrameRepository::set_evidence_type_weight(&pool, frame_id, "empirical", 0.5)
        .await
        .expect("first write");
    FrameRepository::set_evidence_type_weight(&pool, frame_id, "empirical", 0.8)
        .await
        .expect("second write");

    let map = FrameRepository::get_per_frame_evidence_type_weights(&pool, frame_id)
        .await
        .expect("get weights")
        .expect("Some(map)");
    assert_eq!(map.len(), 1, "single key after overwrite, got {map:?}");
    assert!(
        (map["empirical"] - 0.8).abs() < f64::EPSILON,
        "second write must overwrite, got {}",
        map["empirical"]
    );
}
