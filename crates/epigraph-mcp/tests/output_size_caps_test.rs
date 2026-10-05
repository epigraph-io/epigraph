//! Regression tests for backlog `0e6ec456`: `get_provenance` and `query_paper`
//! had no output-size bound and blew the MCP tool output token limit on dense
//! subgraphs, **erroring the call out entirely** rather than returning a
//! bounded first answer.
//!
//! At the branch point:
//!
//! * `tools/provenance.rs::get_provenance` called
//!   `LineageRepository::get_lineage(&pool, claim_id, Some(5), None)` — the 4th
//!   argument is `max_nodes: Option<usize>`, and `None` disables the cap — and
//!   then emitted the FULL `lc.content` for every claim entity. Observed:
//!   145K-235K-character responses.
//! * `tools/paper_queries.rs::query_paper` called
//!   `PaperRepository::list_asserted_claims(&pool, paper.id, 100)` with a
//!   hardcoded 100 and no caller-supplied limit/offset. Observed: 62K.
//!
//! **Both tests here call the tools with NO new parameters**, so they compile
//! against pre-fix code and are genuine before/after regressions rather than
//! new-surface guards: the assertions are about what the DEFAULTS now do.
//! Verified by reverting each hunk (see the commit message for the recorded
//! pre-fix failures).
//!
//! The paging/limit-echo assertions in `query_paper_pages_instead_of_erroring`
//! are the exception and are called out inline — `limit`/`offset` are new
//! fields, so those specific lines could not have run pre-fix.

use epigraph_mcp::tools::paper_queries::query_paper;
use epigraph_mcp::tools::provenance::get_provenance;
use epigraph_mcp::types::{GetProvenanceParams, QueryPaperParams};
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;
use common::build_test_server;

/// The default `DEFAULT_MAX_NODES` cap in `tools/provenance.rs`.
const EXPECTED_DEFAULT_MAX_NODES: usize = 50;
/// The default `DEFAULT_MAX_CONTENT_CHARS` cap in `tools/provenance.rs`.
const EXPECTED_DEFAULT_MAX_CONTENT_CHARS: usize = 500;

/// A dense lineage: one target claim with 80 direct parents, each carrying 2,000
/// characters of content — the paragraph/atom shape of a hierarchical document
/// decomposition, and pre-fix worth ~162K characters of `content` alone, inside
/// the 145K-235K band the backlog reports.
///
/// With NO parameters the bundle must come back bounded in BOTH dimensions and
/// must SAY it was bounded. A node cap alone would not fix this: 80 nodes was
/// never the problem, 80 x 2,000 characters was.
#[sqlx::test(migrations = "../../migrations")]
async fn get_provenance_bounds_nodes_and_content_by_default(pool: PgPool) {
    const PARENTS: usize = 80;
    const CONTENT_CHARS: usize = 2_000;

    let agent = seed_agent(&pool).await;
    // Every claim (target included) carries a 4-char index prefix, so each is
    // exactly CONTENT_CHARS + 4 characters long and `content_chars` is uniform.
    let target = seed_claim(&pool, agent, &format!("9999{}", "T".repeat(CONTENT_CHARS))).await;
    for i in 0..PARENTS {
        let parent = seed_claim(
            &pool,
            agent,
            &format!("{i:04}{}", "P".repeat(CONTENT_CHARS)),
        )
        .await;
        // lineage recurses parent -> target: source_id is the ancestor.
        seed_claim_edge(&pool, parent, target).await;
    }

    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;

    let result = get_provenance(
        &server,
        &viewer,
        GetProvenanceParams {
            claim_id: target.to_string(),
            // NOTHING supplied: this is the defaults-only path, the one the
            // failing enrichment workflow actually took.
            max_depth: None,
            max_nodes: None,
            max_content_chars: None,
        },
    )
    .await
    .expect("get_provenance must succeed, not error out on size");

    let raw = raw_text(&result);
    let bundle: Value = serde_json::from_str(&raw).expect("bundle is JSON");

    // ---- (1) Node count is capped ----
    let claim_entities: Vec<&Value> = bundle["entities"]
        .as_array()
        .expect("entities array")
        .iter()
        .filter(|e| e["@id"].as_str().is_some_and(|id| id.starts_with("claim:")))
        .collect();
    assert!(
        claim_entities.len() <= EXPECTED_DEFAULT_MAX_NODES,
        "claim entities must be capped at {EXPECTED_DEFAULT_MAX_NODES} by default, got {} \
         (pre-fix: max_nodes was None, so all {} nodes came back)",
        claim_entities.len(),
        PARENTS + 1
    );
    assert!(
        claim_entities.len() > 1,
        "the cap must not collapse the bundle to nothing useful: {}",
        claim_entities.len()
    );

    // ---- (2) Per-claim content is capped, and says so ----
    for entity in &claim_entities {
        let content = entity["content"].as_str().expect("content string");
        assert!(
            content.chars().count() <= EXPECTED_DEFAULT_MAX_CONTENT_CHARS,
            "entity content must be capped at {EXPECTED_DEFAULT_MAX_CONTENT_CHARS} chars, \
             got {} — a node cap alone does not bound bytes",
            content.chars().count()
        );
        assert_eq!(
            entity["content_truncated"],
            Value::Bool(true),
            "a trimmed entity must be flagged: {entity}"
        );
        assert_eq!(
            entity["content_chars"],
            Value::from(CONTENT_CHARS + 4),
            "the ORIGINAL length must be reported so the caller knows what it is \
             missing: {entity}"
        );
    }

    // ---- (3) The whole response is small enough to survive the token limit ----
    // 145,000 chars is the LOW end of the observed failures. The bounded bundle
    // must be an order of magnitude under it: 50 nodes x 500 chars = 25,000
    // chars of claim text plus JSON scaffolding.
    assert!(
        raw.len() < 60_000,
        "bounded bundle must be far below the 145K low-water mark of the observed \
         failures, got {} chars",
        raw.len()
    );

    // ---- (4) The caller can tell a bounded answer from a complete one ----
    assert_eq!(
        bundle["truncated"],
        Value::Bool(true),
        "the bundle must surface LineageResult::truncated; without it a capped \
         answer is indistinguishable from the full lineage: {}",
        &raw[..raw.len().min(400)]
    );
    assert_eq!(
        bundle["claim_node_count"],
        Value::from(claim_entities.len()),
        "claim_node_count must match the claim entities actually emitted"
    );
    assert_eq!(
        bundle["limits"]["max_nodes"],
        Value::from(EXPECTED_DEFAULT_MAX_NODES),
        "the applied limits must be echoed so a caller can widen them: {}",
        bundle["limits"]
    );
    assert_eq!(
        bundle["limits"]["max_content_chars"],
        Value::from(EXPECTED_DEFAULT_MAX_CONTENT_CHARS)
    );

    // ---- (5) The caps are overridable, and `truncated` is not hardcoded ----
    // A lineage that fits entirely inside the supplied caps must report
    // truncated = false, which is what proves assertion (4) discriminates.
    let result = get_provenance(
        &server,
        &viewer,
        GetProvenanceParams {
            claim_id: target.to_string(),
            max_depth: Some(1),
            max_nodes: Some(PARENTS + 1),
            max_content_chars: Some(CONTENT_CHARS + 10),
        },
    )
    .await
    .expect("get_provenance with widened caps");
    let bundle: Value = serde_json::from_str(&raw_text(&result)).expect("bundle is JSON");
    assert_eq!(
        bundle["entities"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["@id"].as_str().is_some_and(|id| id.starts_with("claim:")))
            .count(),
        PARENTS + 1,
        "a widened max_nodes must actually return the full set"
    );
    for entity in bundle["entities"].as_array().unwrap() {
        if entity["@id"]
            .as_str()
            .is_some_and(|id| id.starts_with("claim:"))
        {
            assert_eq!(
                entity["content_truncated"],
                Value::Bool(false),
                "content within budget must NOT be flagged truncated: {entity}"
            );
        }
    }
}

/// The default `DEFAULT_MAX_OUTPUT_CHARS` total budget in `tools/provenance.rs`.
const EXPECTED_DEFAULT_MAX_OUTPUT_CHARS: usize = 40_000;
/// The `MAX_EVIDENCE_PER_CLAIM` cap in `tools/provenance.rs`.
const EXPECTED_MAX_EVIDENCE_PER_CLAIM: usize = 10;

/// The shape that still failed in prod AFTER the node and content caps landed
/// (backlog `31c10a5a`, re-measured 2026-10-04): `get_provenance` on
/// `07d46bc3…` with defaults errored at 83,074 characters, of which 50 claim
/// entities were only ~36K. The other ~35K were 151 evidence entities and 36
/// trace entities, which carry no content field and had NO count cap, plus
/// pretty-printing. The node x content product does not bound that.
///
/// This lineage reproduces it: 80 parents x 2,000 chars as above, but every
/// claim also carries evidence rows and a reasoning trace, and the target
/// carries more evidence than one claim may emit.
///
/// Asserted on the defaults-only call (compiles against pre-fix code):
/// 1. the whole response fits the default total budget;
/// 2. every reference the bundle emits resolves to an entity in it
///    (#397 finding: `parent_ids` named claims the node cap had dropped);
/// 3. the target's evidence is capped per claim and says so;
/// 4. the bundle says it was cut.
///
/// Failures are collected and reported together so one red run shows every
/// independent way the pre-fix bundle is wrong.
#[sqlx::test(migrations = "../../migrations")]
async fn get_provenance_bounds_total_output_when_evidence_dense(pool: PgPool) {
    const PARENTS: usize = 80;
    const CONTENT_CHARS: usize = 2_000;
    const EVIDENCE_PER_PARENT: usize = 6;
    const TARGET_EVIDENCE: usize = 25;

    let agent = seed_agent(&pool).await;
    let target = seed_claim(&pool, agent, &format!("9999{}", "T".repeat(CONTENT_CHARS))).await;
    for _ in 0..TARGET_EVIDENCE {
        seed_evidence(&pool, target).await;
    }
    seed_trace(&pool, target).await;
    let mut parents = Vec::new();
    for i in 0..PARENTS {
        let parent = seed_claim(
            &pool,
            agent,
            &format!("{i:04}{}", "P".repeat(CONTENT_CHARS)),
        )
        .await;
        seed_claim_edge(&pool, parent, target).await;
        for _ in 0..EVIDENCE_PER_PARENT {
            seed_evidence(&pool, parent).await;
        }
        seed_trace(&pool, parent).await;
        parents.push(parent);
    }

    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;

    let raw = raw_text(
        &get_provenance(
            &server,
            &viewer,
            GetProvenanceParams {
                claim_id: target.to_string(),
                max_depth: None,
                max_nodes: None,
                max_content_chars: None,
            },
        )
        .await
        .expect("get_provenance must succeed, not error out on size"),
    );
    let bundle: Value = serde_json::from_str(&raw).expect("bundle is JSON");
    let entities = bundle["entities"].as_array().expect("entities array");

    let mut failures: Vec<String> = Vec::new();

    // ---- (1) total size ----
    if raw.len() > EXPECTED_DEFAULT_MAX_OUTPUT_CHARS {
        failures.push(format!(
            "total output {} chars exceeds the default budget {EXPECTED_DEFAULT_MAX_OUTPUT_CHARS} \
             ({} entities)",
            raw.len(),
            entities.len()
        ));
    }

    // ---- (2) reference closure ----
    let ids: std::collections::HashSet<&str> =
        entities.iter().filter_map(|e| e["@id"].as_str()).collect();
    let mut dangling: Vec<String> = Vec::new();
    let mut check = |field: &str, v: &Value| {
        if let Some(s) = v.as_str() {
            if !ids.contains(s) {
                dangling.push(format!("{field} -> {s}"));
            }
        }
    };
    check("root_claim", &bundle["root_claim"]);
    for v in bundle["topological_order"].as_array().into_iter().flatten() {
        check("topological_order", v);
    }
    for e in entities {
        check("claim_id", &e["claim_id"]);
        for field in ["parent_ids", "evidence_ids", "parent_trace_ids"] {
            for v in e[field].as_array().into_iter().flatten() {
                check(field, v);
            }
        }
    }
    if !dangling.is_empty() {
        failures.push(format!(
            "{} emitted references resolve to no entity in the bundle, e.g. {:?}",
            dangling.len(),
            &dangling[..dangling.len().min(3)]
        ));
    }

    // ---- (3) per-claim evidence cap on the target ----
    let target_ref = format!("claim:{target}");
    let target_entity = entities.iter().find(|e| e["@id"] == target_ref.as_str());
    match target_entity {
        None => failures.push("the target claim must always be emitted".into()),
        Some(t) => {
            let emitted_for_target = entities
                .iter()
                .filter(|e| {
                    e["@type"] == "prov:Entity"
                        && e["claim_id"] == target_ref.as_str()
                        && e["@id"].as_str().is_some_and(|i| i.starts_with("evidence:"))
                })
                .count();
            if emitted_for_target != EXPECTED_MAX_EVIDENCE_PER_CLAIM
                || t["evidence_count"] != Value::from(TARGET_EVIDENCE)
                || t["evidence_truncated"] != Value::Bool(true)
            {
                failures.push(format!(
                    "target evidence must be capped at {EXPECTED_MAX_EVIDENCE_PER_CLAIM} entities \
                     and report evidence_count={TARGET_EVIDENCE}, evidence_truncated=true; got \
                     {emitted_for_target} entities, evidence_count={}, evidence_truncated={}",
                    t["evidence_count"], t["evidence_truncated"]
                ));
            }
        }
    }

    // ---- (4) the cut is reported ----
    if bundle["truncated"] != Value::Bool(true) {
        failures.push(format!("truncated must be true, got {}", bundle["truncated"]));
    }

    assert!(
        failures.is_empty(),
        "evidence-dense lineage, defaults only:\n  - {}",
        failures.join("\n  - ")
    );

    // The budget must still leave a useful bundle, nearest ancestors first.
    let claim_entities = entities
        .iter()
        .filter(|e| e["@id"].as_str().is_some_and(|i| i.starts_with("claim:")))
        .count();
    assert!(
        claim_entities > 5,
        "the budget must not collapse the bundle to the target alone: {claim_entities}"
    );
    assert_eq!(bundle["claim_node_count"], Value::from(claim_entities));
    assert_eq!(bundle["budget_exhausted"], Value::Bool(true), "{}", bundle["limits"]);

    // ---- Control: a lineage inside every budget is NOT reported as cut ----
    // One parent alone: itself, 6 evidence rows, 1 trace. Proves `truncated`,
    // `budget_exhausted` and `evidence_truncated` are not hardcoded.
    let small: Value = serde_json::from_str(&raw_text(
        &get_provenance(
            &server,
            &viewer,
            GetProvenanceParams {
                claim_id: parents[0].to_string(),
                max_depth: None,
                max_nodes: None,
                max_content_chars: None,
            },
        )
        .await
        .expect("get_provenance on a single parent"),
    ))
    .expect("bundle is JSON");
    let small_entities = small["entities"].as_array().unwrap();
    assert_eq!(
        small_entities
            .iter()
            .filter(|e| e["@id"].as_str().is_some_and(|i| i.starts_with("evidence:")))
            .count(),
        EVIDENCE_PER_PARENT,
        "every evidence row of a small lineage must come back: {small}"
    );
    assert_eq!(
        small_entities
            .iter()
            .filter(|e| e["@type"] == "prov:Activity")
            .count(),
        1,
        "the trace must come back: {small}"
    );
    assert_eq!(small["truncated"], Value::Bool(false), "{small}");
    assert_eq!(small["budget_exhausted"], Value::Bool(false), "{small}");
    assert_eq!(
        small_entities[0]["evidence_truncated"],
        Value::Bool(false),
        "{small}"
    );
}

/// NEGATIVE CASE for the bundle-level `truncated` flag.
///
/// `get_provenance_bounds_nodes_and_content_by_default` only ever observes
/// `truncated == true`, so on its own it cannot tell a real
/// `LineageResult::truncated` from a hardcoded `true`. A three-node lineage with
/// short content fits inside every default cap — `max_depth_reached` is 1
/// against a `max_depth` of 5, and 3 nodes is far under 50 — so the bundle must
/// report `truncated: false`.
///
/// This has to be a SEPARATE fixture rather than another arm of the test above:
/// passing `max_depth: Some(1)` to shrink that lineage would make
/// `max_depth_reached == max_depth`, which `get_lineage` infers as truncation,
/// so the widened-caps arm there cannot serve as the negative case.
#[sqlx::test(migrations = "../../migrations")]
async fn get_provenance_reports_untruncated_when_the_lineage_fits(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let target = seed_claim(&pool, agent, "short target").await;
    for i in 0..2 {
        let parent = seed_claim(&pool, agent, &format!("short parent {i}")).await;
        seed_claim_edge(&pool, parent, target).await;
    }

    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let result = get_provenance(
        &server,
        &viewer,
        GetProvenanceParams {
            claim_id: target.to_string(),
            max_depth: None,
            max_nodes: None,
            max_content_chars: None,
        },
    )
    .await
    .expect("get_provenance");
    let bundle: Value = serde_json::from_str(&raw_text(&result)).expect("bundle is JSON");

    assert_eq!(
        bundle["claim_node_count"],
        Value::from(3),
        "the whole lineage must come back: {bundle}"
    );
    assert_eq!(
        bundle["truncated"],
        Value::Bool(false),
        "a lineage that fits inside every default cap must NOT be reported as \
         truncated — this is what proves the flag is read from LineageResult \
         rather than hardcoded: {bundle}"
    );
    for entity in bundle["entities"].as_array().unwrap() {
        assert_eq!(
            entity["content_truncated"],
            Value::Bool(false),
            "short content must not be flagged: {entity}"
        );
    }
}

/// `query_paper` against a paper with 60 asserted claims must return a bounded
/// FIRST PAGE and report the full total, instead of one 60-claim response that
/// exceeds the output limit and errors out.
#[sqlx::test(migrations = "../../migrations")]
async fn query_paper_pages_instead_of_erroring(pool: PgPool) {
    const ASSERTED: usize = 60;
    const EXPECTED_DEFAULT_LIMIT: usize = 25;

    let agent = seed_agent(&pool).await;
    let doi = "10.48550/arXiv.2607.05794";
    let paper = seed_paper(&pool, doi).await;
    let mut claim_ids = Vec::new();
    for i in 0..ASSERTED {
        // 1,500 chars each: the paragraph-claim shape behind the observed 62K.
        let claim = seed_claim(&pool, agent, &format!("{i:04}{}", "C".repeat(1_500))).await;
        seed_asserts_edge(&pool, paper, claim).await;
        claim_ids.push(claim);
    }

    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;

    // ---- Defaults only: compiles and runs against pre-fix code ----
    let result = query_paper(
        &server,
        &viewer,
        QueryPaperParams {
            doi: doi.to_string(),
            limit: None,
            offset: None,
        },
    )
    .await
    .expect("query_paper");
    let raw = raw_text(&result);
    let body: Value = serde_json::from_str(&raw).expect("response is JSON");

    let page = body["claims"].as_array().expect("claims array");
    assert!(
        page.len() <= EXPECTED_DEFAULT_LIMIT,
        "the default page must be at most {EXPECTED_DEFAULT_LIMIT} claims, got {} \
         (pre-fix: a hardcoded 100 returned all {ASSERTED})",
        page.len()
    );
    assert_eq!(
        body["claim_count"],
        Value::from(ASSERTED),
        "claim_count must stay the FULL total — the nightly dedup probe reads it, \
         and a pager needs it to know where it is: {raw}"
    );
    // Size: assert the RELATIVE property the limit change actually delivers,
    // not an absolute byte count that depends on this fixture's content length.
    // `limit: Some(100)` reproduces the exact pre-fix call
    // (`list_asserted_claims(pool, paper.id, 100)`), so this compares the new
    // default against the old behaviour over identical data.
    let prefix_raw = raw_text(
        &query_paper(
            &server,
            &viewer,
            QueryPaperParams {
                doi: doi.to_string(),
                limit: Some(100),
                offset: None,
            },
        )
        .await
        .expect("query_paper at the old hardcoded limit"),
    );
    assert!(
        raw.len() * 2 < prefix_raw.len(),
        "the default page must be less than HALF the payload the old hardcoded \
         limit of 100 produced over the same paper: default {} chars vs {} chars",
        raw.len(),
        prefix_raw.len()
    );

    // ---- New-surface (these fields did not exist pre-fix) ----
    assert_eq!(body["returned"], Value::from(page.len()));
    assert_eq!(body["offset"], Value::from(0));
    assert_eq!(body["limit"], Value::from(EXPECTED_DEFAULT_LIMIT));
    assert_eq!(
        body["has_more"],
        Value::Bool(true),
        "25 of 60 returned must advertise more pages: {raw}"
    );

    // Paging reaches claim 60, which the hardcoded 100-with-no-offset could
    // return but never page past; and consecutive pages must not overlap.
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0i64;
    loop {
        let body: Value = serde_json::from_str(&raw_text(
            &query_paper(
                &server,
                &viewer,
                QueryPaperParams {
                    doi: doi.to_string(),
                    limit: Some(25),
                    offset: Some(offset),
                },
            )
            .await
            .expect("query_paper page"),
        ))
        .expect("response is JSON");
        let rows = body["claims"].as_array().unwrap();
        for row in rows {
            assert!(
                seen.insert(row["id"].as_str().unwrap().to_string()),
                "claim appeared on two pages — paging is unstable"
            );
        }
        if body["has_more"] != Value::Bool(true) {
            assert_eq!(
                body["returned"],
                Value::from(rows.len()),
                "the last page must still report its own size"
            );
            break;
        }
        offset += 25;
        assert!(offset < 200, "paging failed to terminate");
    }
    assert_eq!(
        seen.len(),
        ASSERTED,
        "paging must enumerate every asserted claim exactly once"
    );

    // A limit above MAX_PAPER_CLAIM_LIMIT is clamped, not honoured — a caller
    // cannot re-create the unbounded case.
    let body: Value = serde_json::from_str(&raw_text(
        &query_paper(
            &server,
            &viewer,
            QueryPaperParams {
                doi: doi.to_string(),
                limit: Some(100_000),
                offset: None,
            },
        )
        .await
        .expect("query_paper clamped"),
    ))
    .expect("response is JSON");
    assert_eq!(
        body["limit"],
        Value::from(200),
        "limit must clamp to MAX_PAPER_CLAIM_LIMIT: {body}"
    );
}

/// `has_more` must TERMINATE on a partially-ingested paper.
///
/// `claim_count` is `max(asserted_count, labeled_count)`, but a page can only
/// contain `asserts`-edge rows. A paper whose claims carry the `doi:<doi>` label
/// but have no edge linked yet — the partial-ingestion state
/// `query_paper_duplicate_gate.rs` exists to cover — has `claim_count = 3` and
/// zero returnable rows. Comparing `offset + returned` against `claim_count`
/// alone (the first form of this change) advertises another page forever and
/// sends a pager into an infinite loop over empty results.
///
/// NEW-SURFACE GUARD: `has_more` did not exist at the branch point. It guards a
/// defect this change's own paging contract introduced, not a pre-existing one.
#[sqlx::test(migrations = "../../migrations")]
async fn has_more_terminates_when_claim_count_comes_from_the_doi_label_floor(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let doi = "10.48550/arXiv.9999.00001";
    seed_paper(&pool, doi).await;

    // Three claims labelled `doi:<doi>` and NOT edge-linked: labeled_count = 3,
    // asserted_count = 0, so claim_count = 3 while the page is empty.
    for i in 0..3 {
        let claim = seed_claim(&pool, agent, &format!("labelled but unlinked {i}")).await;
        sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
            .bind(vec![format!("doi:{doi}")])
            .bind(claim)
            .execute(&pool)
            .await
            .expect("label claim");
    }

    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let body: Value = serde_json::from_str(&raw_text(
        &query_paper(
            &server,
            &viewer,
            QueryPaperParams {
                doi: doi.to_string(),
                limit: None,
                offset: None,
            },
        )
        .await
        .expect("query_paper"),
    ))
    .expect("response is JSON");

    // The fixture must actually be in the divergent state, or the assertion
    // below is vacuous.
    assert_eq!(
        body["claim_count"],
        Value::from(3),
        "claim_count must still surface the doi-label floor (the \
         duplicate-ingestion gate reads it): {body}"
    );
    assert_eq!(
        body["returned"],
        Value::from(0),
        "no asserts edge exists, so the page must be empty: {body}"
    );
    assert_eq!(
        body["has_more"],
        Value::Bool(false),
        "a short page is the end of the set; advertising another page here would \
         loop a pager forever over empty results: {body}"
    );
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn raw_text(result: &CallToolResult) -> String {
    result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content block")
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, $3, 0.5, $4)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// `ancestor -> descendant`, the direction `get_lineage`'s recursive CTE walks
/// (`e.source_id = c.id AND e.target_id = l.id`).
async fn seed_claim_edge(pool: &PgPool, ancestor: Uuid, descendant: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'DERIVED_FROM')",
    )
    .bind(ancestor)
    .bind(descendant)
    .execute(pool)
    .await
    .expect("seed claim edge");
}

/// An evidence row attached to `claim_id` (shape from `source_strength_tests.rs`).
async fn seed_evidence(pool: &PgPool, claim_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, content_hash, evidence_type, claim_id) \
         VALUES ($1, $2, 'testimony', $3)",
    )
    .bind(id)
    .bind(id.as_bytes().repeat(2))
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("seed evidence");
    id
}

/// A reasoning trace for `claim_id`; `get_lineage` selects traces by
/// `reasoning_traces.claim_id`.
async fn seed_trace(pool: &PgPool, claim_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, confidence, explanation) \
         VALUES ($1, 'deductive', 0.9, 'provenance size probe') RETURNING id",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .expect("seed reasoning trace")
}

async fn seed_paper(pool: &PgPool, doi: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(doi)
        .bind("A densely decomposed paper")
        .execute(pool)
        .await
        .expect("seed paper");
    id
}

async fn seed_asserts_edge(pool: &PgPool, paper: Uuid, claim: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(claim)
    .execute(pool)
    .await
    .expect("seed asserts edge");
}
