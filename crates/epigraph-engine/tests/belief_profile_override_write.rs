//! Belief profile, frame tier: an override object is validated when it is
//! WRITTEN, not only when it is read (backlog dc32b884, part 3).
//!
//! Before this, `FrameRepository::set_property` stored any JSON under
//! `frames.properties.belief_profile`, and an invalid object only surfaced at
//! read time as a warning ("belief_profile override rejected; tier ignored")
//! while the frame silently folded under the tier below. Asserted here:
//!
//! - the generic `set_property` refuses the `belief_profile` key outright,
//!   whatever the value, and writes nothing (it cannot validate: the profile
//!   type lives in the engine);
//! - the engine's `set_frame_overrides` refuses every object the read path
//!   would reject (out of range, unknown parameter, `lens`, not an object, a
//!   mixed object whose valid half would otherwise land) and writes nothing;
//! - a valid object is stored verbatim and the read path resolves it: the
//!   frame tier moves exactly the parameter it names.

use epigraph_db::{DbError, FrameRepository, PgPool};
use epigraph_engine::belief_profile::{
    overrides_in, set_frame_overrides, BeliefProfile, FrameTier, OverrideWriteError,
    PerspectiveTier, PROFILE_PROPERTY_KEY,
};
use uuid::Uuid;

async fn frame(pool: &PgPool, name: &str) -> Uuid {
    FrameRepository::create(pool, name, None, &["H0".to_string(), "H1".to_string()])
        .await
        .expect("create frame")
        .id
}

async fn frame_properties(pool: &PgPool, frame_id: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT properties FROM frames WHERE id = $1")
        .bind(frame_id)
        .fetch_one(pool)
        .await
        .expect("read frame properties")
}

async fn stored_override(pool: &PgPool, frame_id: Uuid) -> Option<serde_json::Value> {
    frame_properties(pool, frame_id)
        .await
        .get(PROFILE_PROPERTY_KEY)
        .cloned()
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_generic_setter_refuses_the_belief_profile_key(pool: PgPool) {
    let f = frame(&pool, "override-write generic").await;
    // Out of range: the read path would ignore this object with a warning.
    let invalid = serde_json::json!({ "testimonial_ceiling": 1.5 });
    let err = FrameRepository::set_property(&pool, f, PROFILE_PROPERTY_KEY, &invalid)
        .await
        .expect_err("the generic setter must not store an unvalidated override");
    assert!(matches!(err, DbError::InvalidData { .. }), "{err:?}");
    assert_eq!(stored_override(&pool, f).await, None, "nothing written");

    // Even a valid object: the generic setter cannot tell the two apart, so
    // the key is refused whatever its value.
    let valid = serde_json::json!({ "testimonial_ceiling": 0.2 });
    assert!(
        FrameRepository::set_property(&pool, f, PROFILE_PROPERTY_KEY, &valid)
            .await
            .is_err()
    );
    assert_eq!(stored_override(&pool, f).await, None, "nothing written");

    // Other keys are untouched by the guard.
    FrameRepository::set_property(&pool, f, "intra_evidence_locality_factor", &0.4.into())
        .await
        .expect("an unrelated key still writes");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_engine_setter_refuses_every_object_the_read_path_would_ignore(pool: PgPool) {
    let f = frame(&pool, "override-write invalid").await;
    for (what, bad) in [
        (
            "out of range",
            serde_json::json!({ "testimonial_ceiling": 1.5 }),
        ),
        (
            "unknown parameter",
            serde_json::json!({ "testimonial_cieling": 0.2 }),
        ),
        ("lens", serde_json::json!({ "lens": {} })),
        ("not an object", serde_json::json!(0.5)),
        ("null", serde_json::Value::Null),
        (
            "mixed: a valid half and an invalid half",
            serde_json::json!({
                "testimonial_ceiling": 0.2,
                "forecast": { "model_weight": 7.0 }
            }),
        ),
    ] {
        // The read path rejects it ...
        assert!(
            BeliefProfile::served().with_overrides(&bad).is_err(),
            "{what}: the read path accepts it, so the fixture is wrong"
        );
        // ... so the write refuses it, and stores nothing.
        let err = set_frame_overrides(&pool, f, &bad).await.expect_err(what);
        assert!(
            matches!(err, OverrideWriteError::Invalid(_)),
            "{what}: {err:?}"
        );
        assert_eq!(
            stored_override(&pool, f).await,
            None,
            "{what}: nothing written"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_valid_override_is_stored_and_the_read_path_resolves_it(pool: PgPool) {
    let f = frame(&pool, "override-write valid").await;
    let served = BeliefProfile::served();
    let moved = if (served.reliability.unknown_evidence_type_weight - 0.25).abs() < 1e-9 {
        0.35
    } else {
        0.25
    };
    let ok = serde_json::json!({
        "reliability": { "unknown_evidence_type_weight": moved }
    });
    set_frame_overrides(&pool, f, &ok)
        .await
        .expect("a valid override writes");
    assert_eq!(
        stored_override(&pool, f).await,
        Some(ok.clone()),
        "stored verbatim"
    );

    // The read path resolves what was stored, through the same accessor the
    // fold uses, and moves exactly that parameter.
    let props = frame_properties(&pool, f).await;
    let resolved = served.resolve(
        FrameTier {
            overrides: overrides_in(&props),
            ..FrameTier::default()
        },
        PerspectiveTier::default(),
    );
    assert_eq!(resolved.reliability.unknown_evidence_type_weight, moved);
    let mut expected = served.clone();
    expected.reliability.unknown_evidence_type_weight = moved;
    assert_eq!(resolved, expected, "nothing else moved");

    // An unknown frame is the db's NotFound, not a validation error.
    let err = set_frame_overrides(&pool, Uuid::new_v4(), &ok)
        .await
        .expect_err("no such frame");
    assert!(
        matches!(err, OverrideWriteError::Db(DbError::NotFound { .. })),
        "{err:?}"
    );
}
