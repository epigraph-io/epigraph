#![cfg(feature = "db")]
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn openapi_documents_in_scope_paths() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/openapi.json"))
        .send()
        .await
        .unwrap();
    let doc: serde_json::Value = resp.json().await.unwrap();
    let paths = doc["paths"].as_object().expect("paths object");
    for required in [
        "/api/v1/claims/{id}/supersede",
        "/api/v1/claims/{id}/dedup",
        "/api/v1/claims/{id}",
        "/api/v1/claims/{id}/labels",
        "/api/v1/workflows/steps/{id}/evolve",
        "/api/v1/workflows/hierarchical/search",
        "/api/v1/workflows/hierarchical/{id}/outcome",
        "/api/v1/workflows/{id}/improve",
        "/api/v1/workflows/{id}",
        "/api/v1/workflows/ingest",
    ] {
        assert!(
            paths.contains_key(required),
            "OpenAPI doc missing required path: {required}\nGot: {:?}",
            paths.keys().collect::<Vec<_>>()
        );
    }

    // -------------------------------------------------------------------------
    // POST /api/v1/claims/{id}/dedup
    // -------------------------------------------------------------------------
    let dedup_post = &paths["/api/v1/claims/{id}/dedup"]["post"];
    assert!(
        dedup_post.is_object(),
        "POST /api/v1/claims/{{id}}/dedup not registered as a path operation"
    );
    {
        let security = dedup_post["security"]
            .as_array()
            .expect("POST /api/v1/claims/{id}/dedup: security array missing");
        let scheme_names: Vec<&str> = security
            .iter()
            .flat_map(|obj| obj.as_object().unwrap().keys().map(String::as_str))
            .collect();
        assert!(
            scheme_names.contains(&"ed25519_signature"),
            "POST /api/v1/claims/{{id}}/dedup missing ed25519_signature: got {:?}",
            scheme_names
        );
    }
    {
        let req_body_schema = dedup_post["requestBody"]["content"]["application/json"]["schema"]
            ["$ref"]
            .as_str()
            .expect("POST /api/v1/claims/{id}/dedup: request body schema must be a $ref (typed), not inline");
        assert!(
            req_body_schema.ends_with("/DedupRequest"),
            "POST /api/v1/claims/{{id}}/dedup body should be DedupRequest, got $ref={req_body_schema}"
        );
    }

    // -------------------------------------------------------------------------
    // PATCH /api/v1/claims/{id}/labels
    // -------------------------------------------------------------------------
    let labels_patch = &paths["/api/v1/claims/{id}/labels"]["patch"];
    assert!(
        labels_patch.is_object(),
        "PATCH /api/v1/claims/{{id}}/labels not registered as a path operation"
    );
    {
        let security = labels_patch["security"]
            .as_array()
            .expect("PATCH /api/v1/claims/{id}/labels: security array missing");
        let scheme_names: Vec<&str> = security
            .iter()
            .flat_map(|obj| obj.as_object().unwrap().keys().map(String::as_str))
            .collect();
        assert!(
            scheme_names.contains(&"ed25519_signature"),
            "PATCH /api/v1/claims/{{id}}/labels missing ed25519_signature: got {:?}",
            scheme_names
        );
    }
    {
        let req_body_schema = labels_patch["requestBody"]["content"]["application/json"]["schema"]
            ["$ref"]
            .as_str()
            .expect("PATCH /api/v1/claims/{id}/labels: request body schema must be a $ref (typed), not inline");
        assert!(
            req_body_schema.ends_with("/UpdateLabelsRequest"),
            "PATCH /api/v1/claims/{{id}}/labels body should be UpdateLabelsRequest, got $ref={req_body_schema}"
        );
    }

    // -------------------------------------------------------------------------
    // POST /api/v1/claims/{id}/supersede
    // -------------------------------------------------------------------------
    let supersede_post = &paths["/api/v1/claims/{id}/supersede"]["post"];
    assert!(
        supersede_post.is_object(),
        "POST /api/v1/claims/{{id}}/supersede not registered as a path operation"
    );
    {
        let security = supersede_post["security"]
            .as_array()
            .expect("POST /api/v1/claims/{id}/supersede: security array missing");
        let scheme_names: Vec<&str> = security
            .iter()
            .flat_map(|obj| obj.as_object().unwrap().keys().map(String::as_str))
            .collect();
        assert!(
            scheme_names.contains(&"ed25519_signature"),
            "POST /api/v1/claims/{{id}}/supersede missing ed25519_signature: got {:?}",
            scheme_names
        );
    }
    {
        let req_body_schema = supersede_post["requestBody"]["content"]["application/json"]
            ["schema"]["$ref"]
            .as_str()
            .expect("POST /api/v1/claims/{id}/supersede: request body schema must be a $ref (typed), not inline");
        assert!(
            req_body_schema.ends_with("/SupersedeRequest"),
            "POST /api/v1/claims/{{id}}/supersede body should be SupersedeRequest, got $ref={req_body_schema}"
        );
    }

    // -------------------------------------------------------------------------
    // PATCH /api/v1/claims/{id}
    // -------------------------------------------------------------------------
    let claim_patch = &paths["/api/v1/claims/{id}"]["patch"];
    assert!(
        claim_patch.is_object(),
        "PATCH /api/v1/claims/{{id}} not registered as a path operation"
    );
    {
        let security = claim_patch["security"]
            .as_array()
            .expect("PATCH /api/v1/claims/{id}: security array missing");
        let scheme_names: Vec<&str> = security
            .iter()
            .flat_map(|obj| obj.as_object().unwrap().keys().map(String::as_str))
            .collect();
        assert!(
            scheme_names.contains(&"ed25519_signature"),
            "PATCH /api/v1/claims/{{id}} missing ed25519_signature: got {:?}",
            scheme_names
        );
    }
    {
        let req_body_schema = claim_patch["requestBody"]["content"]["application/json"]["schema"]
            ["$ref"]
            .as_str()
            .expect(
                "PATCH /api/v1/claims/{id}: request body schema must be a $ref (typed), not inline",
            );
        assert!(
            req_body_schema.ends_with("/PatchClaimRequest"),
            "PATCH /api/v1/claims/{{id}} body should be PatchClaimRequest, got $ref={req_body_schema}"
        );
    }

    // -------------------------------------------------------------------------
    // POST /api/v1/workflows/steps/{id}/evolve
    // -------------------------------------------------------------------------
    let evolve_post = &paths["/api/v1/workflows/steps/{id}/evolve"]["post"];
    assert!(
        evolve_post.is_object(),
        "POST /api/v1/workflows/steps/{{id}}/evolve not registered as a path operation"
    );
    {
        let security = evolve_post["security"]
            .as_array()
            .expect("POST /api/v1/workflows/steps/{id}/evolve: security array missing");
        let scheme_names: Vec<&str> = security
            .iter()
            .flat_map(|obj| obj.as_object().unwrap().keys().map(String::as_str))
            .collect();
        assert!(
            scheme_names.contains(&"ed25519_signature"),
            "POST /api/v1/workflows/steps/{{id}}/evolve missing ed25519_signature: got {:?}",
            scheme_names
        );
    }
    {
        let req_body_schema = evolve_post["requestBody"]["content"]["application/json"]["schema"]
            ["$ref"]
            .as_str()
            .expect("POST /api/v1/workflows/steps/{id}/evolve: request body schema must be a $ref (typed), not inline");
        assert!(
            req_body_schema.ends_with("/EvolveStepRequest"),
            "POST /api/v1/workflows/steps/{{id}}/evolve body should be EvolveStepRequest, got $ref={req_body_schema}"
        );
    }
}
