//! `/health` reports the belief modes this process read from its environment
//! (SPEC §10.2, "Visibility").
//!
//! Every belief-mode flag is read once per process, at startup. A flag flip is
//! therefore a restart window over N processes, and the pre-flip mode check
//! (SPEC §10.4) compares what each
//! live process says it is running. `/health` is where the API says it, so it
//! must report the modes the process actually parsed from ITS environment,
//! not the defaults and not what some other process was configured with.
//!
//! The modes are process-global, so this binary holds exactly one test, and it
//! sets the environment before anything in the process can read it. Every one
//! of the seven flags is set to a NON-default value: a handler that returned
//! the defaults (or any hard-coded table) cannot pass. Two values are spelled
//! the way an operator might type them (mixed case, padding), which the
//! report must normalise rather than echo.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use tower::ServiceExt;

/// (environment variable, value set, the value `/health` must report).
const SET: [(&str, &str, &str); 7] = [
    ("EPIGRAPH_ATOM_FOLD", "aef_standalone", "aef_standalone"),
    ("EPIGRAPH_COMPOUND_BELIEF", " Shadow ", "shadow"),
    ("EPIGRAPH_COMPOUND_WRITE_GUARD", "REFUSE", "refuse"),
    ("EPIGRAPH_COMPOUND_SOURCE_EDGES", "excluded", "excluded"),
    ("EPIGRAPH_ATOM_CACHE_MODE", "pure", "pure"),
    ("EPIGRAPH_INFERENCE", "shadow", "shadow"),
    ("EPIGRAPH_BP_APPLY", "on", "on"),
];

/// The JSON key `/health` → `belief_modes` reports each flag under.
const KEY: [(&str, &str); 7] = [
    ("EPIGRAPH_ATOM_FOLD", "atom_fold"),
    ("EPIGRAPH_COMPOUND_BELIEF", "compound_belief"),
    ("EPIGRAPH_COMPOUND_WRITE_GUARD", "compound_write_guard"),
    ("EPIGRAPH_COMPOUND_SOURCE_EDGES", "compound_source_edges"),
    ("EPIGRAPH_ATOM_CACHE_MODE", "atom_cache_mode"),
    ("EPIGRAPH_INFERENCE", "inference"),
    ("EPIGRAPH_BP_APPLY", "bp_apply"),
];

fn key_for(env: &str) -> &'static str {
    KEY.iter()
        .find(|(e, _)| *e == env)
        .map(|(_, k)| *k)
        .expect("every flag has a key")
}

#[tokio::test]
async fn health_reports_the_belief_modes_this_process_read_from_its_environment() {
    for (env, value, _) in SET {
        std::env::set_var(env, value);
    }
    // `AppState::new` builds a lazy pool; it never connects in this test.
    if std::env::var("DATABASE_URL").is_err() {
        std::env::set_var("DATABASE_URL", "postgres://test:test@localhost:5432/test");
    }
    let router = create_router(AppState::new(ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
        ..ApiConfig::default()
    }));

    let response = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("/health is JSON");

    let modes = body
        .get("belief_modes")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("/health has no `belief_modes` object: {body}"));

    // Exactly the seven flags: a missing one cannot be compared across processes,
    // and an extra one would be a mode no process can be configured with.
    let mut keys: Vec<&str> = modes.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected_keys: Vec<&str> = KEY.iter().map(|(_, k)| *k).collect();
    expected_keys.sort_unstable();
    assert_eq!(keys, expected_keys, "belief_modes keys");

    for (env, value, reported) in SET {
        let key = key_for(env);
        assert_eq!(
            modes.get(key).and_then(serde_json::Value::as_str),
            Some(reported),
            "{env}={value:?} must be reported as belief_modes.{key} = {reported:?}; got {body}"
        );
    }
}
