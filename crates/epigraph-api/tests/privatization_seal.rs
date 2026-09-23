//! PR-21 — the seal ceremony over its own HTTP surface.
//!
//! `crates/epigraph-db/tests/seal_side_channels.rs` is where the §6.5.4 TCB
//! mutation is measured, corpus-wide, against a `pg_dump`. This file measures
//! the other half: the ROUTE contract — who may ask for a manifest, what a
//! commit must contain, and what happens when it does not contain it.
//!
//! # It plays the client, because there is no other way to test this
//!
//! Seal is client-driven and the server holds no key, so an end-to-end test has
//! to derive an epoch key, pad, and produce field-tagged ciphertext exactly as
//! `epigraph-privatize` does. It uses `epigraph-privacy` rather than
//! hand-rolled bytes for the reason the CLI's own tests give: hand-rolled bytes
//! would assert this file's idea of the wire format instead of the one the tool
//! writes.

#[path = "privatization_fixture.rs"]
mod fx;

use epigraph_api::errors::ApiError;
use epigraph_api::routes::privatization as routes;
use epigraph_crypto::EncryptedPayload;
use epigraph_privacy::{decrypt_content, encrypt_content, encryptor::FieldTag, pad, unpad};
use fx::viewer_fixture;
use sqlx::PgPool;
use uuid::Uuid;

use base64::Engine as _;

/// The base key the fixture stands in for a KMS handle with.
const BASE_KEY: [u8; 32] = [0x7c; 32];

/// The bucket every plan here is created at.
const PAD_TO: u32 = 256;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Promote the fixture's target group to a keyed `team` with an active epoch.
///
/// Migration 081's plan guard refuses `mode='seal'` against anything else, and
/// `groups_public_key_shape` requires 32 bytes on a keyed group. Done here
/// rather than in `World::seed` because every other test in this slice is about
/// `restrict` and must keep exercising the ordinary shape.
async fn make_keyed(pool: &PgPool, group: Uuid) {
    sqlx::query(
        "UPDATE groups SET kind = 'team', public_key = decode(repeat('ab', 32), 'hex') \
          WHERE id = $1",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("promote the target group");
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("seed the active key epoch");
}

/// A claim owned by the seal target, with one version and one evidence row.
async fn seed_subject(pool: &PgPool, world: &fx::World, content: &str) -> Uuid {
    let claim = viewer_fixture::seed_public_claim(pool, world.actor, content).await;
    sqlx::query(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, \
                                     created_by, visibility, owner_group_id) \
         SELECT $1, 1, $2, 0.8, $3, c.visibility, c.owner_group_id \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .bind(content)
    .bind(world.actor)
    .execute(pool)
    .await
    .expect("seed a version");
    let evidence = viewer_fixture::seed_evidence(pool, claim, "document").await;
    sqlx::query("UPDATE evidence SET raw_content = $2 WHERE id = $1")
        .bind(evidence)
        .bind(content)
        .execute(pool)
        .await
        .expect("give the evidence plaintext");
    claim
}

/// Create a `seal` plan through the ROUTE and apply it.
///
/// Through the route, because "the route no longer answers 501 for
/// `mode='seal'`" is one of the things this file is here to assert, and a plan
/// persisted through the repository would prove nothing about it.
async fn applied_seal_plan(pool: &PgPool, world: &fx::World, seeds: &[Uuid]) -> Uuid {
    let state = fx::split_state(pool).await;
    let auth = fx::auth_for(world.actor);

    let (status, preview) = routes::create_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state.clone()),
        Some(axum::Extension(auth.clone())),
        axum::Json(routes::CreatePlanRequest {
            mode: Some("seal".to_string()),
            target_group_id: world.target_group,
            seeds: routes::PlanSeeds {
                ids: Some(routes::SeedIds {
                    claims: seeds.to_vec(),
                }),
                predicate: None,
                saved_query: None,
            },
            closure: None,
            on_conflict: None,
            pad_to: Some(i32::try_from(PAD_TO).unwrap()),
        }),
    )
    .await
    .expect("create a seal plan");
    assert_eq!(status, axum::http::StatusCode::CREATED);
    assert_eq!(preview.0.mode, "seal");
    // §6.5.4 requires the preview to say what a seal destroys BEFORE the admin
    // clicks. A seal plan whose side_effects block is silent about the deleted
    // extractions is a consent the operator did not give.
    let effects = &preview.0.side_effects;
    assert!(
        effects
            .destroys_derived_rows
            .is_some_and(|t| t.contains(&"entity_mentions")),
        "the seal preview must name the derived tables it destroys"
    );
    assert!(effects.unrecoverable.is_some());
    assert!(effects.reversibility.is_some());

    let plan = preview.0.plan_id;
    let scoped = fx::scoped(pool).await;
    let correlation = fx::dispatch(pool, world, plan, "applying").await;
    fx::run_apply(&scoped, &fx::apply_job(plan, world.actor, &correlation), 50)
        .await
        .expect("apply the restrict pass");
    assert_eq!(
        fx::plan_state(pool, plan).await,
        "applied",
        "restrict first, then seal: 081 refuses to seal a still-public claim"
    );
    plan
}

/// Fetch a manifest page and turn it into a commit body.
///
/// This is `epigraph-privatize seal`, inlined.
async fn seal_body(manifest: &routes::SealManifest) -> routes::SealCommitRequest {
    let epoch = u32::try_from(manifest.epoch).unwrap();
    let epoch_key = epigraph_crypto::derive_epoch_key(&BASE_KEY, epoch);
    let pad_to = u32::try_from(manifest.pad_to).unwrap();

    let seal = |plaintext: &[u8], id: Uuid, tag: FieldTag| -> Vec<u8> {
        let padded = pad(plaintext, pad_to).expect("pad");
        encrypt_content(&padded, &epoch_key, id, epoch, tag)
            .expect("encrypt")
            .to_bytes()
    };

    routes::SealCommitRequest {
        manifest_digest: manifest.manifest_digest.clone(),
        items: manifest
            .items
            .iter()
            .map(|item| {
                let content_ct = seal(item.content.as_bytes(), item.claim_id, FieldTag::Content);
                routes::SealCommitEntry {
                    claim_id: item.claim_id,
                    content_hash_b64: b64(blake3::hash(&content_ct).as_bytes()),
                    content_ct_b64: b64(&content_ct),
                    labels_ct_b64: b64(&seal(
                        serde_json::to_vec(&item.labels).unwrap().as_slice(),
                        item.claim_id,
                        FieldTag::Labels,
                    )),
                    properties_ct_b64: b64(&seal(
                        serde_json::to_vec(&item.properties).unwrap().as_slice(),
                        item.claim_id,
                        FieldTag::Properties,
                    )),
                    versions: item
                        .versions
                        .iter()
                        .map(|v| routes::CommitVersion {
                            id: v.id,
                            ct_b64: b64(&seal(
                                v.content.as_bytes(),
                                v.id,
                                FieldTag::VersionContent,
                            )),
                        })
                        .collect(),
                    evidence: item
                        .evidence
                        .iter()
                        .map(|e| routes::CommitEvidence {
                            id: e.id,
                            ct_b64: b64(&seal(
                                serde_json::to_vec(&e.raw_content).unwrap().as_slice(),
                                e.id,
                                FieldTag::EvidenceContent,
                            )),
                            props_ct_b64: b64(&seal(
                                serde_json::to_vec(&e.properties).unwrap().as_slice(),
                                e.id,
                                FieldTag::EvidenceProperties,
                            )),
                        })
                        .collect(),
                }
            })
            .collect(),
    }
}

async fn fetch_seal_manifest(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
) -> Result<routes::SealManifest, ApiError> {
    fetch_seal_manifest_page(pool, world, plan, None, None).await
}

/// One page of a plan's seal manifest, at an explicit cursor and limit.
///
/// The un-paged helper above delegates here, so the paging test and the six
/// single-page tests drive the SAME call rather than two arrangements of it.
async fn fetch_seal_manifest_page(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
    cursor: Option<Uuid>,
    limit: Option<i64>,
) -> Result<routes::SealManifest, ApiError> {
    let state = fx::split_state(pool).await;
    routes::seal_manifest(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::extract::Query(routes::ManifestQuery { cursor, limit }),
    )
    .await
    .map(|json| json.0)
}

async fn post_seal_commit(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
    body: routes::SealCommitRequest,
) -> Result<routes::CommitResponse, ApiError> {
    let state = fx::split_state(pool).await;
    routes::seal_commit(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::Json(body),
    )
    .await
    .map(|json| json.0)
}

// =========================================================================

/// The whole ceremony, both directions, through the routes.
#[sqlx::test(migrations = "../../migrations")]
async fn the_seal_ceremony_round_trips_through_its_own_routes(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let plaintext = "a confidential result about a catalyst";
    let claim = seed_subject(&pool, &world, plaintext).await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;

    // --- seal ---
    let manifest = fetch_seal_manifest(&pool, &world, plan)
        .await
        .expect("seal manifest");
    assert_eq!(manifest.items.len(), 1);
    assert_eq!(
        manifest.items[0].content, plaintext,
        "the manifest is the one response that carries plaintext, and it must carry the WHOLE \
         plaintext or the commit that follows it seals a subset"
    );
    assert_eq!(manifest.items[0].versions.len(), 1);
    assert_eq!(manifest.items[0].evidence.len(), 1);
    assert_eq!(manifest.pad_to, i32::try_from(PAD_TO).unwrap());

    let body = seal_body(&manifest).await;
    let resp = post_seal_commit(&pool, &world, plan, body)
        .await
        .expect("seal commit");
    assert_eq!(resp.committed, 1);
    assert_eq!(resp.already_done, 0);

    let sealed_content: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("read the sealed claim");
    assert_eq!(sealed_content, format!("[sealed:x{}]", claim.simple()));

    // The manifest read is DUAL-LOGGED — §6.5.6 requires both, and neither
    // substitutes for the other: `security_events` is principal-keyed and
    // `privatization_audit` is plan-keyed.
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events WHERE event_type = 'plan.seal_manifest' \
           AND agent_id = $1",
    )
    .bind(world.actor)
    .fetch_one(&pool)
    .await
    .expect("count security events");
    assert_eq!(events, 1);
    let actions = fx::audit_actions(&pool, plan).await;
    assert!(actions.contains(&"plan.seal_manifest".to_string()));
    assert!(actions.contains(&"item.seal".to_string()));

    // --- unseal ---
    let state = fx::split_state(&pool).await;
    let unseal = routes::unseal_manifest(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state.clone()),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::extract::Query(routes::ManifestQuery {
            cursor: None,
            limit: None,
        }),
    )
    .await
    .expect("unseal manifest")
    .0;
    assert_eq!(unseal.items.len(), 1);

    let entry = &unseal.items[0];
    let epoch = u32::try_from(entry.epoch).unwrap();
    let epoch_key = epigraph_crypto::derive_epoch_key(&BASE_KEY, epoch);
    let open = |ct_b64: &str, id: Uuid, tag: FieldTag| -> Vec<u8> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .expect("base64");
        let payload = EncryptedPayload::from_bytes(&bytes).expect("payload");
        let padded = decrypt_content(&payload, &epoch_key, id, epoch, tag).expect("decrypt");
        unpad(&padded, u32::try_from(entry.pad_to).unwrap()).expect("unpad")
    };

    let recovered = String::from_utf8(open(
        &entry.content_ct_b64,
        entry.claim_id,
        FieldTag::Content,
    ))
    .unwrap();
    assert_eq!(
        recovered, plaintext,
        "the ceremony must round-trip the plaintext, or the seal is a delete"
    );

    let commit = routes::UnsealCommitRequest {
        items: vec![routes::UnsealCommitEntry {
            claim_id: entry.claim_id,
            content_hash_b64: b64(blake3::hash(recovered.as_bytes()).as_bytes()),
            content: recovered.clone(),
            labels: serde_json::from_slice(&open(
                entry.labels_ct_b64.as_deref().unwrap(),
                entry.claim_id,
                FieldTag::Labels,
            ))
            .unwrap(),
            properties: serde_json::from_slice(&open(
                entry.properties_ct_b64.as_deref().unwrap(),
                entry.claim_id,
                FieldTag::Properties,
            ))
            .unwrap(),
            versions: entry
                .versions
                .iter()
                .map(|v| routes::UnsealCommitVersionEntry {
                    id: v.id,
                    content: String::from_utf8(open(&v.ct_b64, v.id, FieldTag::VersionContent))
                        .unwrap(),
                })
                .collect(),
            evidence: entry
                .evidence
                .iter()
                .map(|e| routes::UnsealCommitEvidenceEntry {
                    id: e.id,
                    raw_content: serde_json::from_slice(&open(
                        &e.ct_b64,
                        e.id,
                        FieldTag::EvidenceContent,
                    ))
                    .unwrap(),
                    properties: serde_json::from_slice(&open(
                        &e.props_ct_b64,
                        e.id,
                        FieldTag::EvidenceProperties,
                    ))
                    .unwrap(),
                })
                .collect(),
        }],
    };

    let resp = routes::unseal_commit(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::Json(commit),
    )
    .await
    .expect("unseal commit")
    .0;
    assert_eq!(resp.committed, 1);

    let (content, ciphertext_rows): (String, i64) = sqlx::query_as(
        "SELECT c.content, \
                (SELECT count(*) FROM claim_encryption ce WHERE ce.claim_id = c.id) \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("read the unsealed claim");
    assert_eq!(content, plaintext);
    assert_eq!(ciphertext_rows, 0);

    // ops F14: the vector was destroyed by the seal, so unseal must ASK for it
    // back rather than leaving the claim to the un-prioritised backfill.
    //
    // THE PAYLOAD IS EXTERNALLY TAGGED. `EpiGraphJob` carries no serde tag
    // attribute, so `EmbeddingGeneration { claim_id }` serialises as
    // `{"EmbeddingGeneration": {"claim_id": "…"}}` and NOT as a flat object with
    // a top-level `claim_id`. FINAL-PLAN §6.5.4's audit clause reads
    // `payload->>'claim_id'`, which matches nothing on that shape; the CLAUDE.md
    // clause is written against the real one and this assertion is what pins the
    // two together.
    let jobs: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM jobs WHERE job_type = 'embedding_generation' \
           AND payload #>> '{EmbeddingGeneration,claim_id}' = $1::text",
    )
    .bind(claim)
    .fetch_all(&pool)
    .await
    .expect("read embedding jobs");
    assert_eq!(
        jobs.len(),
        1,
        "unseal-commit enqueues one embedding job per claim; jobs = {jobs:?}"
    );
}

/// A commit that omits a TCB member is refused, and NOTHING is sealed.
///
/// The second half is the assertion that matters: §6.5.4's indictment of the
/// previous revision is not that it refused badly, it is that it succeeded
/// partially.
#[sqlx::test(migrations = "../../migrations")]
async fn a_commit_missing_a_tcb_member_is_refused_and_seals_nothing(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let plaintext = "a subject with a version the commit will forget";
    let claim = seed_subject(&pool, &world, plaintext).await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;

    let manifest = fetch_seal_manifest(&pool, &world, plan)
        .await
        .expect("seal manifest");
    let mut body = seal_body(&manifest).await;
    assert_eq!(body.items[0].versions.len(), 1);
    body.items[0].versions.clear();

    let err = post_seal_commit(&pool, &world, plan, body)
        .await
        .expect_err("a commit missing a claim_versions row must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("claim_versions")),
        "expected a refusal naming the uncovered table, got {err:?}"
    );

    let (content, ciphertext_rows): (String, i64) = sqlx::query_as(
        "SELECT c.content, \
                (SELECT count(*) FROM claim_encryption ce WHERE ce.claim_id = c.id) \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("read the claim");
    assert_eq!(
        content, plaintext,
        "a refused commit must leave the plaintext exactly as it was; a partially applied seal \
         reports success over a row that is still readable"
    );
    assert_eq!(ciphertext_rows, 0);
}

/// A stale manifest digest is a 409, and it is stale because the TCB GREW.
///
/// This is the whole reason the digest is recomputed from the database rather
/// than compared against the manifest the server served: a version row inserted
/// after the manifest would otherwise keep its plaintext through a commit that
/// called itself complete.
#[sqlx::test(migrations = "../../migrations")]
async fn a_row_added_after_the_manifest_makes_the_commit_stale(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let claim = seed_subject(&pool, &world, "a subject that grows a version").await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;

    let manifest = fetch_seal_manifest(&pool, &world, plan)
        .await
        .expect("seal manifest");
    let body = seal_body(&manifest).await;

    sqlx::query(
        "INSERT INTO claim_versions (claim_id, version_number, content, truth_value, \
                                     created_by, visibility, owner_group_id) \
         SELECT $1, 2, 'a later revision', 0.8, $2, c.visibility, c.owner_group_id \
           FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .bind(world.actor)
    .execute(&pool)
    .await
    .expect("insert a late version");

    let err = post_seal_commit(&pool, &world, plan, body)
        .await
        .expect_err("a commit against a TCB that has moved must be refused");
    assert!(
        matches!(&err, ApiError::Conflict { .. }),
        "expected a 409, got {err:?}"
    );

    let ciphertext_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claim_encryption WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(ciphertext_rows, 0);
}

/// `mode='seal'` with `pad_to = 0` is a 400 at the route, not a 500 from a
/// CHECK.
///
/// Migration 080's `pp_seal_needs_pad` is the real control and it is applied and
/// frozen; this asserts the route answers before the database has to, which is
/// also what settles §6.5.4's "`pad_to = 0` requires an explicit override":
/// there is no override to build.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unpadded_seal_is_refused_with_a_sentence(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let claim = viewer_fixture::seed_public_claim(&pool, world.actor, "unpadded subject").await;
    let state = fx::split_state(&pool).await;

    let err = routes::create_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::Json(routes::CreatePlanRequest {
            mode: Some("seal".to_string()),
            target_group_id: world.target_group,
            seeds: routes::PlanSeeds {
                ids: Some(routes::SeedIds {
                    claims: vec![claim],
                }),
                predicate: None,
                saved_query: None,
            },
            closure: None,
            on_conflict: None,
            pad_to: Some(0),
        }),
    )
    .await
    .expect_err("mode=seal with pad_to=0 must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("pad_to")),
        "expected a 400 naming pad_to, got {err:?}"
    );
}

/// A manifest is refused before the plan has been applied.
///
/// Restrict first, then seal. Migration 081's `claim_encryption_no_public_sealed`
/// is the backstop and raises `42501`; this asserts the surface refuses earlier,
/// with a sentence, and — the part that matters — that it refuses on the PLAN's
/// state rather than discovering the problem one row at a time.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seal_manifest_is_refused_before_the_plan_is_applied(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let claim = seed_subject(&pool, &world, "not yet restricted").await;
    let state = fx::split_state(&pool).await;

    let (_status, preview) = routes::create_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(&pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::Json(routes::CreatePlanRequest {
            mode: Some("seal".to_string()),
            target_group_id: world.target_group,
            seeds: routes::PlanSeeds {
                ids: Some(routes::SeedIds {
                    claims: vec![claim],
                }),
                predicate: None,
                saved_query: None,
            },
            closure: None,
            on_conflict: None,
            pad_to: Some(i32::try_from(PAD_TO).unwrap()),
        }),
    )
    .await
    .expect("create the plan");

    let err = fetch_seal_manifest(&pool, &world, preview.0.plan_id)
        .await
        .expect_err("a manifest for a plan that has not been applied must be refused");
    assert!(
        matches!(&err, ApiError::Conflict { reason } if reason.contains("applied")),
        "expected a 409 about the plan's state, got {err:?}"
    );

    // CALIBRATION: the claim really is still public, so the refusal is about
    // the ordering and not about an empty plan.
    let visibility: String = sqlx::query_scalar("SELECT visibility FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("read visibility");
    assert_eq!(visibility, "public");
}

/// Seal a whole plan through the routes, and assert it sealed everything.
async fn seal_through_routes(pool: &PgPool, world: &fx::World, plan: Uuid, expect: usize) {
    let manifest = fetch_seal_manifest(pool, world, plan)
        .await
        .expect("seal manifest");
    assert_eq!(manifest.items.len(), expect);
    let body = seal_body(&manifest).await;
    let resp = post_seal_commit(pool, world, plan, body)
        .await
        .expect("seal commit");
    assert_eq!(resp.committed, expect);
}

/// One page of a plan's unseal manifest, through the route.
async fn fetch_unseal_manifest(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
) -> routes::UnsealManifest {
    fetch_unseal_manifest_page(pool, world, plan, None, None).await
}

/// One page of a plan's unseal manifest, at an explicit cursor and limit.
async fn fetch_unseal_manifest_page(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
    cursor: Option<Uuid>,
    limit: Option<i64>,
) -> routes::UnsealManifest {
    let state = fx::split_state(pool).await;
    routes::unseal_manifest(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::extract::Query(routes::ManifestQuery { cursor, limit }),
    )
    .await
    .expect("unseal manifest")
    .0
}

/// The client's half of unseal: decrypt one manifest entry into a commit entry.
fn unseal_entry(entry: &routes::UnsealManifestEntry) -> routes::UnsealCommitEntry {
    let epoch = u32::try_from(entry.epoch).unwrap();
    let epoch_key = epigraph_crypto::derive_epoch_key(&BASE_KEY, epoch);
    let pad_to = u32::try_from(entry.pad_to).unwrap();
    let open = |ct_b64: &str, id: Uuid, tag: FieldTag| -> Vec<u8> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ct_b64)
            .expect("base64");
        let payload = EncryptedPayload::from_bytes(&bytes).expect("payload");
        let padded = decrypt_content(&payload, &epoch_key, id, epoch, tag).expect("decrypt");
        unpad(&padded, pad_to).expect("unpad")
    };
    let content = String::from_utf8(open(
        &entry.content_ct_b64,
        entry.claim_id,
        FieldTag::Content,
    ))
    .unwrap();
    routes::UnsealCommitEntry {
        claim_id: entry.claim_id,
        content_hash_b64: b64(blake3::hash(content.as_bytes()).as_bytes()),
        content,
        labels: serde_json::from_slice(&open(
            entry.labels_ct_b64.as_deref().unwrap(),
            entry.claim_id,
            FieldTag::Labels,
        ))
        .unwrap(),
        properties: serde_json::from_slice(&open(
            entry.properties_ct_b64.as_deref().unwrap(),
            entry.claim_id,
            FieldTag::Properties,
        ))
        .unwrap(),
        versions: entry
            .versions
            .iter()
            .map(|v| routes::UnsealCommitVersionEntry {
                id: v.id,
                content: String::from_utf8(open(&v.ct_b64, v.id, FieldTag::VersionContent))
                    .unwrap(),
            })
            .collect(),
        evidence: entry
            .evidence
            .iter()
            .map(|e| routes::UnsealCommitEvidenceEntry {
                id: e.id,
                raw_content: serde_json::from_slice(&open(
                    &e.ct_b64,
                    e.id,
                    FieldTag::EvidenceContent,
                ))
                .unwrap(),
                properties: serde_json::from_slice(&open(
                    &e.props_ct_b64,
                    e.id,
                    FieldTag::EvidenceProperties,
                ))
                .unwrap(),
            })
            .collect(),
    }
}

async fn post_unseal_commit(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
    body: routes::UnsealCommitRequest,
) -> Result<routes::CommitResponse, ApiError> {
    let state = fx::split_state(pool).await;
    routes::unseal_commit(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::Json(body),
    )
    .await
    .map(|json| json.0)
}

/// An unseal-commit may only name claims its own plan froze.
///
/// The authority §6.6 grants is over the plan's TARGET GROUP, so the set of rows
/// a commit may mutate has to be the set that authority was granted over. The
/// seal direction has always checked it; this asserts the reverse direction does
/// too, because an unseal writes CALLER-SUPPLIED plaintext and then drops the
/// ciphertext — and the server holds no key with which to tell the supplied
/// plaintext from any other string.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unseal_commit_is_scoped_to_its_own_plan(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;

    let mine = seed_subject(&pool, &world, "the claim this plan froze").await;
    let theirs = seed_subject(&pool, &world, "a claim another ceremony sealed").await;

    let my_plan = applied_seal_plan(&pool, &world, &[mine]).await;
    seal_through_routes(&pool, &world, my_plan, 1).await;
    let other_plan = applied_seal_plan(&pool, &world, &[theirs]).await;
    seal_through_routes(&pool, &world, other_plan, 1).await;

    let sentinel = format!("[sealed:x{}]", theirs.simple());
    let injected = routes::UnsealCommitRequest {
        items: vec![routes::UnsealCommitEntry {
            claim_id: theirs,
            content_hash_b64: b64(blake3::hash(b"substituted").as_bytes()),
            content: "substituted".to_string(),
            labels: Vec::new(),
            properties: serde_json::json!({}),
            versions: Vec::new(),
            evidence: Vec::new(),
        }],
    };
    let err = post_unseal_commit(&pool, &world, my_plan, injected)
        .await
        .expect_err("an unseal-commit naming a claim outside its plan must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message } if message.contains("not items of plan")),
        "expected a refusal naming the plan, got {err:?}"
    );

    let (content, ciphertext_rows): (String, i64) = sqlx::query_as(
        "SELECT c.content, \
                (SELECT count(*) FROM claim_encryption ce WHERE ce.claim_id = c.id) \
           FROM claims c WHERE c.id = $1",
    )
    .bind(theirs)
    .fetch_one(&pool)
    .await
    .expect("read the other plan's claim");
    assert_eq!(
        content, sentinel,
        "a refused unseal must leave the other plan's claim exactly as it was"
    );
    assert_eq!(
        ciphertext_rows, 1,
        "the ciphertext is the only remaining copy of that plaintext; a refused commit must not \
         delete it"
    );
}

/// An unseal-commit that omits a sealed row is refused, and the ciphertext lives.
///
/// The mirror of `a_commit_missing_a_tcb_member_is_refused_and_seals_nothing`,
/// and the stakes are higher in this direction: the seal already destroyed the
/// plaintext, so a version row whose ciphertext is dropped without its plaintext
/// being restored is unrecoverable by anyone, key-holder included.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unseal_commit_that_omits_a_sealed_row_is_refused(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let claim = seed_subject(&pool, &world, "a subject whose version the unseal forgets").await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;
    seal_through_routes(&pool, &world, plan, 1).await;

    let manifest = fetch_unseal_manifest(&pool, &world, plan).await;
    assert_eq!(manifest.items.len(), 1);
    let mut entry = unseal_entry(&manifest.items[0]);
    assert_eq!(entry.versions.len(), 1);
    entry.versions.clear();

    let err = post_unseal_commit(
        &pool,
        &world,
        plan,
        routes::UnsealCommitRequest { items: vec![entry] },
    )
    .await
    .expect_err("an unseal-commit that leaves a ciphertext row uncovered must be refused");
    assert!(
        matches!(&err, ApiError::BadRequest { message }
                 if message.contains("claim_version_encryption")),
        "expected a refusal naming the uncovered table, got {err:?}"
    );

    let (versions, heads): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM claim_version_encryption WHERE claim_id = $1), \
                (SELECT count(*) FROM claim_encryption WHERE claim_id = $1)",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("count ciphertext rows");
    assert_eq!(
        (versions, heads),
        (1, 1),
        "a refused unseal must leave every ciphertext row in place"
    );
    let content: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("read the claim");
    assert_eq!(content, format!("[sealed:x{}]", claim.simple()));
}

/// Unseal a whole plan through the routes, and assert it restored everything.
async fn unseal_through_routes(pool: &PgPool, world: &fx::World, plan: Uuid, expect: usize) {
    let manifest = fetch_unseal_manifest(pool, world, plan).await;
    assert_eq!(manifest.items.len(), expect);
    let items = manifest.items.iter().map(unseal_entry).collect();
    let resp = post_unseal_commit(pool, world, plan, routes::UnsealCommitRequest { items })
        .await
        .expect("unseal commit");
    assert_eq!(resp.committed, expect);
}

/// The digest a dispatch route wants echoed back, as the route spells it.
async fn echoed_digest(pool: &PgPool, plan: Uuid) -> String {
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT plan_digest FROM privatization_plans WHERE id = $1")
            .bind(plan)
            .fetch_one(pool)
            .await
            .expect("read the plan's stored digest");
    format!("b3:{}", hex::encode(stored))
}

/// Ask the revert route to un-apply a plan.
async fn post_revert(
    pool: &PgPool,
    world: &fx::World,
    plan: Uuid,
) -> Result<axum::http::StatusCode, ApiError> {
    let state = fx::split_state(pool).await;
    let digest = echoed_digest(pool, plan).await;
    routes::revert_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::extract::Path(plan),
        axum::Json(routes::RevertRequest {
            plan_digest: digest,
        }),
    )
    .await
    .map(|(status, _)| status)
}

/// FINAL-PLAN acceptance clause 10, POSITIVE arm — a seal plan becomes
/// revertible once its items are unsealed, and the revert actually runs.
///
/// # Why it lives here and not in `privatization_revert.rs`
///
/// That file measures the refusal's CONDITION against a stub ciphertext, which
/// keeps its assertions independent of the key ceremony. Clause 10's positive
/// arm is the opposite requirement: it is only meaningful over ciphertext the
/// PRODUCT wrote and the product removed, because the thing it must prove is
/// that `seal-commit`'s row and `unseal-commit`'s deletion are the same row the
/// revert route counts. The drivers for both are in this file.
///
/// # Both arms, in one run, against one plan
///
/// The 409 is asserted first on the SAME plan that is then unsealed and
/// reverted. Two separate plans would leave open the possibility that the
/// refusal and the acceptance differ for some reason other than the seal — a
/// revert that always 409'd and a revert that always 202'd would each pass one
/// half of a two-plan version of this test.
///
/// # The effect, not the status
///
/// A `202` only says the dispatch was accepted. The revert handler is run and
/// the claim's tenancy is read afterwards, because clause 10 is a claim about
/// the corpus ending up back where it started, not about a status code.
#[sqlx::test(migrations = "../../migrations")]
async fn a_sealed_plan_becomes_revertible_once_its_items_are_unsealed(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let plaintext = "a result that is sealed, unsealed and then un-privatized";
    let claim = seed_subject(&pool, &world, plaintext).await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;

    seal_through_routes(&pool, &world, plan, 1).await;

    // The negative arm, over ciphertext this ceremony actually wrote.
    let err = post_revert(&pool, &world, plan)
        .await
        .expect_err("a plan whose item is sealed must not be revertible");
    assert!(
        matches!(&err, ApiError::Conflict { reason } if reason.contains('1')),
        "expected a 409 carrying the still-sealed count, got {err:?}"
    );
    assert_eq!(
        fx::plan_state(&pool, plan).await,
        "applied",
        "a refused revert must not move the plan"
    );

    unseal_through_routes(&pool, &world, plan, 1).await;
    let sealed_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claim_encryption WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count ciphertext rows");
    assert_eq!(
        sealed_rows, 0,
        "CALIBRATION: the unseal must remove the row the 409 counts, or the acceptance below \
         measures nothing about the seal"
    );

    // The positive arm.
    let status = post_revert(&pool, &world, plan)
        .await
        .expect("a fully unsealed seal plan must be revertible");
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);
    assert_eq!(fx::plan_state(&pool, plan).await, "reverting");

    // And it completes: the claim goes back to the tenancy the apply moved it
    // out of, carrying the plaintext the unseal restored.
    let scoped = fx::scoped(&pool).await;
    // The correlation id the ROUTE minted, not one this test invents: §6.5.5's
    // sixth re-validation condition compares the job's correlation id against
    // the dispatch event, so a fabricated one would make the handler refuse.
    let correlation = sqlx::query_scalar::<_, String>(
        "SELECT correlation_id FROM security_events \
          WHERE event_type = $1 AND details->>'plan_id' = $2::text \
            AND correlation_id IS NOT NULL \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(epigraph_jobs::privatization::DISPATCH_EVENT_TYPE)
    .bind(plan)
    .fetch_one(&pool)
    .await
    .expect("the revert dispatch wrote a correlated security event");
    fx::run_revert(
        &scoped,
        &fx::revert_job(plan, world.actor, &correlation),
        50,
    )
    .await
    .expect("run the revert");

    assert_eq!(
        fx::plan_state(&pool, plan).await,
        "reverted",
        "the revert handler must carry the plan to its terminal state"
    );
    let (visibility, content): (String, String) =
        sqlx::query_as("SELECT visibility, content FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read the reverted claim");
    assert_eq!(
        (visibility.as_str(), content.as_str()),
        ("public", plaintext),
        "clause 10 asks for the corpus back where it started: public, with its plaintext"
    );
}

/// Give `claim` a harvester source fragment, and return the fragment id.
///
/// The fragment inherits the claim's own tenancy, so the rows are consistent
/// whatever visibility the claim is at when this is called.
async fn seed_fragment(pool: &PgPool, claim: Uuid, text: &str) -> Uuid {
    let source: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_sources (content_hash, modality, status) \
         VALUES ($1, 'text', 'completed') RETURNING id",
    )
    // Per-call nonces: `harvester_sources.content_hash` is UNIQUE and one claim
    // may cite more than one source, so a hash derived from the claim id alone
    // makes the second seed a 23505.
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .fetch_one(pool)
    .await
    .expect("seed harvester source");
    let fragment: Uuid = sqlx::query_scalar(
        "INSERT INTO harvester_fragments (source_id, content_hash, content_text, \
                                          context_window, status, visibility, owner_group_id) \
         SELECT $1, $2, $3, $3, 'completed', c.visibility, c.owner_group_id \
           FROM claims c WHERE c.id = $4 RETURNING id",
    )
    .bind(source)
    .bind(Uuid::new_v4().as_bytes().to_vec())
    .bind(text)
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("seed harvester fragment");
    cite_fragment(pool, claim, fragment).await;
    fragment
}

/// Link an existing fragment to a second claim, which is what makes it SHARED.
async fn cite_fragment(pool: &PgPool, claim: Uuid, fragment: Uuid) {
    sqlx::query(
        "INSERT INTO harvester_claim_provenance (claim_id, fragment_id, visibility, \
                                                 owner_group_id) \
         SELECT $1, $2, c.visibility, c.owner_group_id FROM claims c WHERE c.id = $1",
    )
    .bind(claim)
    .bind(fragment)
    .execute(pool)
    .await
    .expect("seed harvester provenance");
}

/// `D-PR21-shared-fragment-count` — the seal preview reports the MAGNITUDE of
/// the shared-fragment loss it already describes.
///
/// # What was there, and what was missing
///
/// `SEAL_UNRECOVERABLE` states the property unconditionally: a fragment is one
/// row, so blanking it takes the source text from every claim that cites it,
/// including claims outside the plan. The behaviour is deliberate and is
/// asserted in `epigraph-db/tests/seal_side_channels.rs`. What the operator
/// could not see is how much of it there is — a plan that blanks one shared
/// fragment and one that blanks four hundred read identically.
///
/// # Two plans, and the second is what makes the first mean anything
///
/// A count of shared fragments is only informative if it can be zero. The
/// unshared plan is asserted first for exactly that reason: a field hard-wired
/// to the plan's fragment count, or to any non-zero constant, would satisfy the
/// shared case on its own.
///
/// # `restrict` gets `None`, not `0`
///
/// A restrict plan blanks no fragments at all, so a zero there would read as
/// "measured, and there is no sharing" rather than "this question does not
/// arise". The distinction matters because the count exists to qualify a
/// sentence that a restrict preview does not carry.
#[sqlx::test(migrations = "../../migrations")]
async fn the_seal_preview_counts_the_source_fragments_it_would_blank_for_outsiders(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;

    // A plan whose fragment nobody else cites.
    let lonely = seed_subject(&pool, &world, "a claim whose source nobody else cites").await;
    seed_fragment(&pool, lonely, "a source only one claim cites").await;
    assert_eq!(
        seal_preview(&pool, &world, &[lonely])
            .await
            .counts
            .shared_source_fragments,
        Some(0),
        "a plan whose fragments are cited by nobody outside it shares nothing; a non-zero here \
         would mean the count is measuring the plan's own citations"
    );

    // A plan whose fragment IS cited from outside.
    let sealed = seed_subject(&pool, &world, "a claim whose source is cited twice").await;
    let outsider = seed_subject(&pool, &world, "a claim this plan does not touch").await;
    let shared = seed_fragment(&pool, sealed, "a source two claims cite").await;
    cite_fragment(&pool, outsider, shared).await;
    seed_fragment(&pool, sealed, "a second source, cited once").await;

    let preview = seal_preview(&pool, &world, &[sealed]).await;
    assert_eq!(
        preview.counts.total, 1,
        "CALIBRATION: the outsider must be OUTSIDE the frozen set, or the count below is asked \
         about a plan that contains both claims and there is nothing outside it to share with"
    );
    assert_eq!(
        preview.counts.shared_source_fragments,
        Some(1),
        "one of this plan's two fragments is cited from outside it; the count is of FRAGMENTS \
         that lose their text for outsiders, not of the plan's fragments and not of the outside \
         claims affected"
    );
    assert!(
        preview.side_effects.unrecoverable.is_some(),
        "the count qualifies the unconditional sentence; it does not replace it"
    );

    // A restrict plan blanks no fragment, so the question does not arise.
    let restrict = restrict_preview(&pool, &world, &[sealed]).await;
    assert_eq!(
        restrict.counts.shared_source_fragments, None,
        "a restrict preview must report absence, not zero: zero would read as 'measured, and \
         there is no sharing'"
    );
    assert!(restrict.side_effects.unrecoverable.is_none());
}

/// Create a plan through the ROUTE and return its preview, without applying it.
///
/// The preview is the consent surface, so the assertions above read the field
/// out of the route's own response. A helper that re-issued the repository's
/// query would assert a copy of the statement against itself and would pass
/// even if nothing ever reached the operator.
async fn seal_preview(pool: &PgPool, world: &fx::World, seeds: &[Uuid]) -> routes::PlanPreview {
    let state = fx::split_state(pool).await;
    let (_status, preview) = routes::create_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::Json(routes::CreatePlanRequest {
            mode: Some("seal".to_string()),
            target_group_id: world.target_group,
            seeds: routes::PlanSeeds {
                ids: Some(routes::SeedIds {
                    claims: seeds.to_vec(),
                }),
                predicate: None,
                saved_query: None,
            },
            closure: None,
            on_conflict: None,
            pad_to: Some(i32::try_from(PAD_TO).unwrap()),
        }),
    )
    .await
    .expect("create a seal plan");
    preview.0
}

/// A `restrict` plan's preview, for the `None` arm.
async fn restrict_preview(pool: &PgPool, world: &fx::World, seeds: &[Uuid]) -> routes::PlanPreview {
    let state = fx::split_state(pool).await;
    let (_status, preview) = routes::create_plan(
        epigraph_api::middleware::bearer::ViewerExtractor(
            epigraph_db::visibility::Viewer::resolve(pool, world.actor)
                .await
                .expect("resolve the actor's viewer"),
        ),
        axum::extract::State(state),
        Some(axum::Extension(fx::auth_for(world.actor))),
        axum::Json(routes::CreatePlanRequest {
            mode: None,
            target_group_id: world.target_group,
            seeds: routes::PlanSeeds {
                ids: Some(routes::SeedIds {
                    claims: seeds.to_vec(),
                }),
                predicate: None,
                saved_query: None,
            },
            closure: None,
            on_conflict: None,
            pad_to: None,
        }),
    )
    .await
    .expect("create a restrict plan");
    preview.0
}

/// How many times a manifest read was audited for this plan.
async fn manifest_reads(pool: &PgPool, plan: Uuid, action: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM privatization_audit WHERE plan_id = $1 AND action = $2",
    )
    .bind(plan)
    .bind(action)
    .fetch_one(pool)
    .await
    .expect("count audited manifest reads")
}

/// `D-PR21-manifest-paging-untested` — both manifests page, and a short final
/// page ENDS the walk.
///
/// # What was untested
///
/// Every manifest call in this file passed `cursor: None, limit: None`, and
/// `manifest_limit` turns `None` into the 500 ceiling, so every test was a
/// single page. Neither route's `next_cursor` nor the CLI's loop over it had
/// ever been exercised.
///
/// # A measurement that corrects the recorded hazard
///
/// The obligation predicted "a cursor that failed to advance would loop
/// forever". It would not: both CLI loops break on an empty page. What the code
/// actually did was hand back a cursor after a page that did not fill the
/// limit, so every walk ended with one extra request. On this route that is not
/// merely wasteful — a manifest read is dual-logged as a plaintext disclosure,
/// so the trailing request wrote an audit pair for a read that served nothing.
/// The routes now end the walk on a short page, matching `list_plans`, and the
/// audit count below is what holds them to it.
///
/// # Why the pages are compared as a SET
///
/// The failure a paging test exists to catch is a cursor that advances wrongly
/// and skips a row — a claim the operator can then never finish sealing.
/// Asserting page lengths alone would pass over exactly that: two pages of two
/// and one are the right shape whether or not they are the right three claims.
#[sqlx::test(migrations = "../../migrations")]
async fn both_manifests_page_and_a_short_final_page_ends_the_walk(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let mut seeded = Vec::new();
    for n in 0..3 {
        seeded.push(seed_subject(&pool, &world, &format!("paged subject {n}")).await);
    }
    let plan = applied_seal_plan(&pool, &world, &seeded).await;
    let expected: std::collections::BTreeSet<Uuid> = seeded.iter().copied().collect();

    // --- seal direction ---
    let first = fetch_seal_manifest_page(&pool, &world, plan, None, Some(2))
        .await
        .expect("first seal page");
    assert_eq!(first.items.len(), 2, "limit=2 must bound the page");
    let cursor = first
        .next_cursor
        .expect("a full page must offer a cursor, or the walk cannot continue");

    let second = fetch_seal_manifest_page(&pool, &world, plan, Some(cursor), Some(2))
        .await
        .expect("second seal page");
    assert_eq!(second.items.len(), 1, "the tail page holds the remainder");
    assert_eq!(
        second.next_cursor, None,
        "a page short of the limit is the last page; offering a cursor here buys one more \
         request whose only answer is empty, and audits it as a plaintext read"
    );

    let walked: std::collections::BTreeSet<Uuid> = first
        .items
        .iter()
        .chain(second.items.iter())
        .map(|i| i.claim_id)
        .collect();
    assert_eq!(
        walked, expected,
        "the walk must visit every frozen claim exactly once; a cursor that advanced wrongly \
         would skip one and the operator could never finish sealing it"
    );
    assert_eq!(
        manifest_reads(&pool, plan, "plan.seal_manifest").await,
        2,
        "two pages, two audited reads — a third would be the trailing empty page"
    );

    // Each page is committable on its own, which is what the CLI's loop does.
    for page in [&first, &second] {
        let resp = post_seal_commit(&pool, &world, plan, seal_body(page).await)
            .await
            .expect("commit one page");
        assert_eq!(resp.committed, page.items.len());
    }

    // --- unseal direction ---
    let first = fetch_unseal_manifest_page(&pool, &world, plan, None, Some(2)).await;
    assert_eq!(first.items.len(), 2);
    let cursor = first.next_cursor.expect("a full page offers a cursor");
    let second = fetch_unseal_manifest_page(&pool, &world, plan, Some(cursor), Some(2)).await;
    assert_eq!(second.items.len(), 1);
    assert_eq!(
        second.next_cursor, None,
        "the unseal manifest must end its walk on a short page too — it is the direction that \
         hands back the ciphertext, so a spurious audited read matters more here, not less"
    );
    let walked: std::collections::BTreeSet<Uuid> = first
        .items
        .iter()
        .chain(second.items.iter())
        .map(|i| i.claim_id)
        .collect();
    assert_eq!(walked, expected);
    assert_eq!(
        manifest_reads(&pool, plan, "plan.unseal_manifest").await,
        2,
        "two pages, two audited reads"
    );
}

// ── ops F14: the runner half of the re-embedding the unseal asks for ──────

/// The `EmbeddingJobService` the runner installs, over a deterministic
/// provider.
///
/// The provider is a mock, and the boot-time rule is that a mock provider must
/// NOT be registered — those are not in tension. The rule is about which
/// PROVIDER may write the live ANN column and is asserted by
/// `embedding_restore::tests::only_openai_may_write_the_claim_embedding_column`.
/// What this file measures is the service's own behaviour — which row it reads,
/// which row it writes, and which row it refuses — and that is a property of
/// the statements it issues, not of the vectors' contents.
fn restore_service(
    scoped: &std::sync::Arc<epigraph_db::ScopedPool>,
) -> epigraph_api::embedding_restore::ClaimEmbeddingJobService {
    let embedder = std::sync::Arc::new(epigraph_embeddings::MockProvider::new(
        epigraph_embeddings::EmbeddingConfig::openai(1536),
    ));
    epigraph_api::embedding_restore::ClaimEmbeddingJobService::new(
        std::sync::Arc::clone(scoped),
        embedder,
    )
}

/// The one pending `embedding_generation` job naming `claim`, as the runner
/// would see it.
///
/// Read through `PostgresJobQueue::get` rather than reconstructed from the row,
/// so the `Job` the handler is given is the one the queue actually yields.
async fn pending_embedding_job(pool: &PgPool, claim: Uuid) -> epigraph_jobs::Job {
    let id: Uuid = sqlx::query_scalar(
        "SELECT id FROM jobs \
          WHERE job_type = 'embedding_generation' AND state = 'pending' \
            AND payload #>> '{EmbeddingGeneration,claim_id}' = $1::text",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("the unseal enqueued exactly one pending embedding job for this claim");
    epigraph_jobs::JobQueue::get(
        &epigraph_jobs::PostgresJobQueue::new(pool.clone()),
        epigraph_jobs::JobId::from_uuid(id),
    )
    .await
    .expect("the queue yields the enqueued job")
}

/// `(embedding, embedding_3072)` as text, so a NULL is distinguishable.
async fn vectors(pool: &PgPool, claim: Uuid) -> (Option<String>, Option<String>) {
    sqlx::query_as("SELECT embedding::text, embedding_3072::text FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the claim's vector columns")
}

/// `D-PR21-embedding-handler-unregistered` — the enqueued job now RESTORES a
/// vector instead of marking that one is wanted.
///
/// # What the defect was, precisely
///
/// `ConfigurableEmbeddingHandler` and its `EmbeddingJobService` trait have both
/// existed for a long time. Nothing implemented the trait, so the handler could
/// not be constructed, so the runner registered nothing for the job type
/// `unseal-commit` enqueues. The row went in and nothing ever took it out.
///
/// # Why this asserts the column and not the status code
///
/// A `202` from `unseal-commit` and a `pending` row in `jobs` are exactly what
/// the tree had before this change, and are exactly the defect. The only
/// assertion that can tell the fix from the defect is `claims.embedding` moving
/// from NULL to non-NULL — so that transition is measured at three points, with
/// the job's departure from the queue measured beside it.
///
/// # `embedding_3072` is deliberately still NULL at the end
///
/// The seal nulls both vector columns; this job restores the 1536-dimension one
/// that `claims.embedding` holds and that the audit's gap clause reads. The
/// 3072-dimension column is written by `epigraph-cli reembed` and is not part
/// of this path. The assertion is here so that the half this closes and the
/// half it does not are both on the record.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unsealed_claim_regains_its_embedding_when_the_job_is_drained(pool: PgPool) {
    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let plaintext = "a catalyst result whose vector must come back";
    let claim = seed_subject(&pool, &world, plaintext).await;
    fx::give_embedding(&pool, claim).await;
    assert!(
        vectors(&pool, claim).await.0.is_some(),
        "CALIBRATION: the claim must start WITH a vector, or 'the seal removed it' is unmeasured"
    );

    let plan = applied_seal_plan(&pool, &world, &[claim]).await;
    seal_through_routes(&pool, &world, plan, 1).await;
    assert_eq!(
        vectors(&pool, claim).await,
        (None, None),
        "the seal must null BOTH vector columns; a plaintext-derived vector surviving a seal is \
         a confidentiality failure, not an embedding gap"
    );

    unseal_through_routes(&pool, &world, plan, 1).await;
    assert_eq!(
        vectors(&pool, claim).await.0,
        None,
        "CALIBRATION: unseal restores plaintext, not vectors — if the column were already \
         non-NULL here the handler below would be proving nothing"
    );

    // Drain, exactly as the runner's loop does: take the job the queue yields,
    // hand it to the registered handler, and record the outcome.
    let scoped = fx::scoped(&pool).await;
    let handler = epigraph_jobs::ConfigurableEmbeddingHandler::new(std::sync::Arc::new(
        restore_service(&scoped),
    ));
    assert_eq!(
        epigraph_jobs::JobHandler::job_type(&handler),
        "embedding_generation",
        "CALIBRATION: the handler must claim the job type unseal-commit enqueues, or the runner \
         would never route this job to it"
    );
    let mut job = pending_embedding_job(&pool, claim).await;
    epigraph_jobs::JobHandler::handle(&handler, &job)
        .await
        .expect("the embedding job must succeed for an unsealed claim");
    job.transition_to(epigraph_jobs::JobState::Running)
        .expect("pending -> running");
    job.transition_to(epigraph_jobs::JobState::Completed)
        .expect("running -> completed");
    epigraph_jobs::JobQueue::update(&epigraph_jobs::PostgresJobQueue::new(pool.clone()), &job)
        .await
        .expect("record the terminal state");

    let (embedding, embedding_3072) = vectors(&pool, claim).await;
    assert!(
        embedding.is_some(),
        "THE FIX: a drained embedding_generation job must leave the claim with a vector; it is \
         still NULL, so the job is still a marker"
    );
    assert_eq!(
        embedding_3072, None,
        "the 3072-dimension column is NOT restored by this path; `epigraph-cli reembed` writes \
         it, and recording that here keeps the closed half from reading as the whole"
    );

    let still_pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM jobs \
          WHERE job_type = 'embedding_generation' AND state = 'pending' \
            AND payload #>> '{EmbeddingGeneration,claim_id}' = $1::text",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("count pending embedding jobs");
    assert_eq!(
        still_pending, 0,
        "the job must LEAVE the queue; a handler that ran but left the row pending would be \
         re-run forever"
    );
}

/// A claim that is SEALED gets no vector, and the refusal is in the statement.
///
/// # Why this is the more important of the two directions
///
/// The failure this guards is not "the restoration did not happen". It is a
/// plaintext-derived vector written onto a row whose content is ciphertext the
/// server cannot read — which the operational audit treats as a confidentiality
/// violation rather than an embedding gap, and which no amount of later
/// backfill undoes.
///
/// The window is real: the job is enqueued by one ceremony and drained later,
/// and a second plan can seal the same claim in between. So the check cannot
/// live in the handler's control flow, and both halves are asserted here — the
/// read refuses to hand over text, and the write refuses the row even when text
/// is supplied directly.
#[sqlx::test(migrations = "../../migrations")]
async fn a_sealed_claim_is_refused_a_vector_by_both_halves_of_the_restore(pool: PgPool) {
    use epigraph_jobs::EmbeddingJobService as _;

    let world = fx::World::seed(&pool).await;
    make_keyed(&pool, world.target_group).await;
    let claim = seed_subject(&pool, &world, "a subject that stays sealed").await;
    let plan = applied_seal_plan(&pool, &world, &[claim]).await;
    seal_through_routes(&pool, &world, plan, 1).await;

    let scoped = fx::scoped(&pool).await;
    let service = restore_service(&scoped);

    // Half one: no text is handed out, so the provider is never called on a
    // sealed row and the handler fails the job.
    assert_eq!(
        service.get_claim_text(claim).await,
        None,
        "a sealed claim must yield no text to embed"
    );

    // Half two: even given text, the write refuses the row. This is the half
    // that closes the window between the two, and it is the half a reviewer
    // cannot see by reading the handler.
    let stored = service
        .generate_and_store(claim, "plaintext that must not become a vector")
        .await;
    assert!(
        stored.is_err(),
        "storing a vector on a sealed claim must fail, got {stored:?}"
    );

    let (embedding, embedding_3072) = vectors(&pool, claim).await;
    assert_eq!(
        (embedding, embedding_3072),
        (None, None),
        "THE INVARIANT: a sealed claim carries no vector on either column"
    );
    let ciphertext: i64 =
        sqlx::query_scalar("SELECT count(*) FROM claim_encryption WHERE claim_id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("count ciphertext rows");
    assert_eq!(
        ciphertext, 1,
        "CALIBRATION: the claim must still be sealed, or the refusals above are about an \
         ordinary claim"
    );
}

/// The runner actually registers the handler — asserted against the binary's
/// own source.
///
/// # Why a source-text assertion
///
/// `bin/server.rs` is a `[[bin]]`, so its wiring is reachable from no test. The
/// defect this batch closes was not a broken handler; it was a correct handler
/// that nothing registered, and every test that drives the handler directly —
/// including the two above — would pass just as well with the registration
/// deleted. `resource_metadata_challenge.rs` reads the same file for the same
/// reason.
///
/// # Scope, stated so this is not mistaken for a parity ratchet
///
/// This pins ONE job type. It does not assert that every `EpiGraphJob` variant
/// has a registered handler; that broader property is not true today and
/// establishing it is a separate decision with its own owner.
#[test]
fn the_server_binary_registers_a_handler_for_the_job_the_unseal_enqueues() {
    const SERVER_BIN: &str = include_str!("../src/bin/server.rs");
    assert!(
        SERVER_BIN.contains("ConfigurableEmbeddingHandler::new"),
        "bin/server.rs no longer constructs the embedding handler; the job unseal-commit \
         enqueues would go back to being a marker nothing drains"
    );
    assert!(
        SERVER_BIN.contains("ClaimEmbeddingJobService::new"),
        "bin/server.rs no longer installs the production EmbeddingJobService; the handler is \
         generic and a different service would restore something else"
    );
    assert!(
        SERVER_BIN.contains("may_restore_claim_embeddings"),
        "the registration is no longer gated on the provider; an unconditional one would let a \
         development-fallback embedder write the live vector column"
    );
}

/// The preview's list and the mutation's list are the SAME set.
///
/// `routes::SEAL_DESTROYS` is what the operator is told a seal destroys;
/// `epigraph_db::repos::privatization::SEAL_DELETE_TABLES` is what it actually
/// deletes. They are deliberately two constants — one is a consent surface and
/// the other is a statement — and this is what keeps them honest. A table added
/// to the mutation without being added to the preview is a seal that destroys
/// something the admin was not warned about; the reverse is a warning about a
/// loss that does not happen.
#[test]
fn the_preview_names_exactly_the_tables_the_seal_deletes() {
    let told: std::collections::BTreeSet<&str> = routes::SEAL_DESTROYS.iter().copied().collect();
    let done: std::collections::BTreeSet<&str> =
        epigraph_db::repos::privatization::SEAL_DELETE_TABLES
            .iter()
            .copied()
            .collect();
    assert_eq!(
        told, done,
        "the seal preview's destroyed-table list and the seal mutation's DELETE list disagree"
    );
    assert!(
        told.len() >= 6,
        "the list shrank to {}; a seal that stopped deleting a derived extraction would pass a \
         set-equality check while leaving plaintext behind",
        told.len()
    );
}
