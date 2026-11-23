//! MCP `list_workflows`: an exhaustive, paginated enumeration of the workflow
//! registry (backlog 039ef40a).
//!
//! Before it, the only way to walk the hierarchical registry over MCP was
//! `find_workflow_hierarchical`, an ILIKE substring match: a lineage whose goal
//! and canonical_name lack the query text is never returned, however the
//! caller pages. These tests pin what an enumeration must do instead:
//!
//! * every lineage the caller reads is listed exactly once, through pages
//!   smaller than the registry, as its HEAD (highest generation), and the walk
//!   terminates with a null cursor;
//! * the head is picked BEFORE the deprecation filter, so a lineage with a
//!   deprecated head is omitted, never listed through an older live generation;
//! * a lineage that gains a generation mid-walk is not listed a second time;
//! * a group-private lineage (and a group-private generation, and its count)
//!   is listed to readers of the group only;
//! * flat `workflow`-labelled claims follow the lineages;
//! * a cursor the tool did not issue is `invalid_params`.
//!
//! Every server here runs as `epigraph_app` under FORCEd row security (the
//! hierarchical half has no in-query predicate: the `workflows` row policy IS
//! the filter, so a superuser fixture would make the stranger arms vacuous).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use std::collections::BTreeMap;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::workflow_hierarchical::{find_workflow_hierarchical, list_workflows};
use epigraph_mcp::types::{FindWorkflowHierarchicalParams, ListWorkflowsParams};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn app_role_server(pool: &PgPool) -> EpiGraphMcpFull {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every visibility arm here is vacuous"
    );
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    build_scoped_test_server(plain, scoped)
}

/// Insert one `workflows` row on the superuser pool, with explicit tenancy and
/// an explicit `created_at` offset (seconds from now), so the tests control
/// both the head and the time order.
#[allow(clippy::too_many_arguments)]
async fn seed_generation(
    pool: &PgPool,
    canonical: &str,
    generation: i32,
    goal: &str,
    truth: f64,
    visibility: &str,
    owner_group: Uuid,
    created_offset_secs: i64,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows \
             (id, canonical_name, generation, goal, parent_id, metadata, created_at, \
              truth_value, visibility, owner_group_id) \
         VALUES ($1, $2, $3, $4, NULL, '{}', NOW() + make_interval(secs => $5), $6, $7, $8)",
    )
    .bind(id)
    .bind(canonical)
    .bind(generation)
    .bind(goal)
    .bind(created_offset_secs as f64)
    .bind(truth)
    .bind(visibility)
    .bind(owner_group)
    .execute(pool)
    .await
    .expect("seed workflows row");
    id
}

/// A `workflow`-labelled claim (the flat store), public or owned by `group`.
async fn seed_flat(pool: &PgPool, agent: Uuid, group: Option<Uuid>, content: &str) -> Uuid {
    let id = match group {
        Some(g) => fixture::seed_group_claim(pool, agent, g, content).await,
        None => fixture::seed_public_claim(pool, agent, content).await,
    };
    sqlx::query("UPDATE claims SET labels = ARRAY['workflow']::text[] WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("label flat workflow");
    id
}

async fn call(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    limit: i64,
    cursor: Option<String>,
    include_deprecated: Option<bool>,
) -> Result<Value, epigraph_mcp::errors::McpError> {
    let result = list_workflows(
        server,
        viewer,
        ListWorkflowsParams {
            limit: Some(limit),
            cursor,
            include_deprecated,
        },
    )
    .await?;
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content");
    Ok(serde_json::from_str(&text).expect("json body"))
}

/// Every page of a walk, first to last. Fails if the walk does not terminate.
async fn walk(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    limit: i64,
    include_deprecated: Option<bool>,
) -> Vec<Value> {
    let mut pages = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..200 {
        let page = call(server, viewer, limit, cursor.clone(), include_deprecated)
            .await
            .expect("list_workflows");
        let entries = page["workflows"].as_array().expect("workflows array");
        assert!(
            entries.len() as i64 <= limit,
            "a page never exceeds its limit: {page}"
        );
        cursor = page["next_cursor"].as_str().map(str::to_string);
        pages.push(page);
        if cursor.is_none() {
            return pages;
        }
    }
    panic!("the walk did not terminate in 200 pages: {pages:?}");
}

fn entries(pages: &[Value]) -> Vec<Value> {
    pages
        .iter()
        .flat_map(|p| p["workflows"].as_array().cloned().unwrap_or_default())
        .collect()
}

/// `canonical_name -> (workflow_id, generation, generations)` of the
/// hierarchical entries, failing on a lineage listed twice.
fn lineages(entries: &[Value]) -> BTreeMap<String, (Uuid, i64, i64)> {
    let mut out = BTreeMap::new();
    for e in entries.iter().filter(|e| e["store"] == "hierarchical") {
        let name = e["canonical_name"].as_str().expect("name").to_string();
        let id = Uuid::parse_str(e["workflow_id"].as_str().expect("id")).expect("uuid");
        let prior = out.insert(
            name.clone(),
            (
                id,
                e["generation"].as_i64().expect("generation"),
                e["generations"].as_i64().expect("generations"),
            ),
        );
        assert!(prior.is_none(), "lineage {name} listed twice: {entries:?}");
    }
    out
}

fn flat_ids(entries: &[Value]) -> Vec<Uuid> {
    entries
        .iter()
        .filter(|e| e["store"] == "flat")
        .map(|e| Uuid::parse_str(e["workflow_id"].as_str().expect("id")).expect("uuid"))
        .collect()
}

struct Registry {
    member: Viewer,
    stranger: Viewer,
    /// canonical_name -> (head id, head generation, generations), as the
    /// MEMBER reads it, deprecated lineage excluded.
    member_view: BTreeMap<String, (Uuid, i64, i64)>,
    retired_head: Uuid,
    split_public_gen0: Uuid,
    flat_public: Uuid,
    flat_private: Uuid,
    flat_retired: Uuid,
}

/// Six lineages, of which only ONE has "workflow" in its name or goal, and
/// three flat workflow claims:
///
/// * `alpha-calibration`: three public generations; the head's goal diverged.
/// * `bravo-intake`, `charlie-recompute` (two generations): public.
/// * `delta-roadmap`: one generation, private to the member's group.
/// * `split-tenancy`: gen 0 public, gen 1 (the head) private to the group.
/// * `zz-workflow-audit`: the one lineage a keyword search for "workflow" finds.
/// * `retired-plan`: gen 0 live, gen 1 the head, DEPRECATED (truth 0.05).
/// * flat: one public, one group-private, one public but not current.
///
/// The created_at order is deliberately NOT the canonical_name order.
async fn seed_registry(pool: &PgPool) -> Registry {
    let (member_id, group) = fixture::seed_agent_with_group(pool, "list-wf-member").await;
    let (stranger_id, _) = fixture::seed_agent_with_group(pool, "list-wf-stranger").await;
    let public = |name: &'static str, g: i32, goal: &'static str, at: i64| {
        seed_generation(pool, name, g, goal, 1.0, "public", group, at)
    };

    public("alpha-calibration", 0, "calibrate the probe", 50).await;
    public("alpha-calibration", 1, "calibrate the probe v2", 60).await;
    let alpha_head = public("alpha-calibration", 2, "retune the probe after a fault", 70).await;
    let bravo = public("bravo-intake", 0, "screen incoming requests", 10).await;
    public("charlie-recompute", 0, "recompute the batch", 5).await;
    let charlie_head = public("charlie-recompute", 1, "recompute the batch again", 40).await;
    let delta = seed_generation(
        pool,
        "delta-roadmap",
        0,
        "draft the roadmap model",
        1.0,
        "group",
        group,
        30,
    )
    .await;
    let split_public_gen0 = public("split-tenancy", 0, "a plan with a private sequel", 20).await;
    let split_head = seed_generation(
        pool,
        "split-tenancy",
        1,
        "the private sequel",
        1.0,
        "group",
        group,
        25,
    )
    .await;
    let audit = public("zz-workflow-audit", 0, "audit every workflow", 1).await;
    seed_generation(
        pool,
        "retired-plan",
        0,
        "an older live generation",
        1.0,
        "public",
        group,
        2,
    )
    .await;
    let retired_head = seed_generation(
        pool,
        "retired-plan",
        1,
        "the deprecated head",
        0.05,
        "public",
        group,
        3,
    )
    .await;

    let flat_public = seed_flat(pool, member_id, None, "flat public workflow").await;
    let flat_private = seed_flat(pool, member_id, Some(group), "flat private workflow").await;
    let flat_retired = seed_flat(pool, member_id, None, "flat retired workflow").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(flat_retired)
        .execute(pool)
        .await
        .expect("retire flat workflow");

    let member_view = BTreeMap::from([
        ("alpha-calibration".to_string(), (alpha_head, 2, 3)),
        ("bravo-intake".to_string(), (bravo, 0, 1)),
        ("charlie-recompute".to_string(), (charlie_head, 1, 2)),
        ("delta-roadmap".to_string(), (delta, 0, 1)),
        ("split-tenancy".to_string(), (split_head, 1, 2)),
        ("zz-workflow-audit".to_string(), (audit, 0, 1)),
    ]);
    Registry {
        member: Viewer::resolve(pool, member_id).await.expect("member"),
        stranger: Viewer::resolve(pool, stranger_id).await.expect("stranger"),
        member_view,
        retired_head,
        split_public_gen0,
        flat_public,
        flat_private,
        flat_retired,
    }
}

/// The backlog symptom and its fix: a keyword search for "workflow" finds one
/// lineage of six, while a walk in pages of two lists every lineage once, as
/// its head with its generation count, then the flat claims, and ends.
#[sqlx::test(migrations = "../../migrations")]
async fn a_paged_walk_lists_every_lineage_once_as_its_head(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let r = seed_registry(&pool).await;

    // The audit's old recipe: a keyword search. It misses five lineages.
    let found = find_workflow_hierarchical(
        &server,
        &r.member,
        FindWorkflowHierarchicalParams {
            query: "workflow".to_string(),
            limit: Some(50),
            resolve_to_latest: Some(true),
            min_truth: None,
        },
    )
    .await
    .expect("find_workflow_hierarchical");
    let found: Value = serde_json::from_str(
        &found
            .content
            .first()
            .and_then(|c| c.as_text())
            .expect("text")
            .text,
    )
    .expect("json");
    let found_names: Vec<&str> = found["workflows"]
        .as_array()
        .expect("array")
        .iter()
        .map(|w| w["canonical_name"].as_str().expect("name"))
        .collect();
    assert_eq!(found_names, vec!["zz-workflow-audit"], "{found}");

    let pages = walk(&server, &r.member, 2, None).await;
    let all = entries(&pages);
    assert_eq!(
        lineages(&all),
        r.member_view,
        "every live lineage the member reads, once, as its head: {all:?}"
    );
    assert!(
        pages.len() >= 4,
        "six lineages and two flat claims in pages of two take at least four pages: {pages:?}"
    );

    // Lineages first, in canonical_name order, then the flat claims.
    let stores: Vec<&str> = all
        .iter()
        .map(|e| e["store"].as_str().expect("store"))
        .collect();
    let first_flat = stores
        .iter()
        .position(|s| *s == "flat")
        .expect("a flat entry");
    assert!(
        stores[first_flat..].iter().all(|s| *s == "flat"),
        "no lineage after the first flat entry: {stores:?}"
    );
    let names: Vec<&str> = all[..first_flat]
        .iter()
        .map(|e| e["canonical_name"].as_str().expect("name"))
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "lineages in canonical_name order");

    let mut flats = flat_ids(&all);
    flats.sort();
    let mut want = vec![r.flat_public, r.flat_private];
    want.sort();
    assert_eq!(
        flats, want,
        "the current flat workflows, once each: {all:?}"
    );
    assert!(all.iter().all(|e| e["deprecated"] == false), "{all:?}");
}

/// Head first, filter second: the deprecated head of `retired-plan` hides the
/// lineage by default; it is NOT listed through its older live generation. With
/// include_deprecated the lineage is listed as that head, flagged, and the
/// retired flat claim is listed too.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deprecated_head_hides_its_lineage_unless_asked_for(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let r = seed_registry(&pool).await;

    let default_walk = entries(&walk(&server, &r.member, 50, None).await);
    assert!(
        !lineages(&default_walk).contains_key("retired-plan"),
        "a lineage whose head is deprecated is not listed by default: {default_walk:?}"
    );
    assert!(!flat_ids(&default_walk).contains(&r.flat_retired));

    let all = entries(&walk(&server, &r.member, 3, Some(true)).await);
    let listed = lineages(&all);
    assert_eq!(
        listed.get("retired-plan"),
        Some(&(r.retired_head, 1, 2)),
        "listed as its deprecated head, never as the live generation 0: {all:?}"
    );
    let retired = all
        .iter()
        .find(|e| e["canonical_name"] == "retired-plan")
        .expect("retired-plan entry");
    assert_eq!(retired["deprecated"], true, "{retired}");
    assert!(flat_ids(&all).contains(&r.flat_retired), "{all:?}");
    let flat_retired = all
        .iter()
        .find(|e| e["workflow_id"] == r.flat_retired.to_string())
        .expect("flat retired entry");
    assert_eq!(flat_retired["deprecated"], true, "{flat_retired}");
    assert_eq!(flat_retired["is_current"], false, "{flat_retired}");
}

/// A caller outside the group sees neither the group's private lineage nor its
/// private generation: `split-tenancy` is listed to it as its public gen 0,
/// counted as one generation, and the private flat claim is absent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stranger_is_listed_only_what_it_reads(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let r = seed_registry(&pool).await;

    let all = entries(&walk(&server, &r.stranger, 2, None).await);
    let mut want = r.member_view.clone();
    want.remove("delta-roadmap");
    want.insert("split-tenancy".to_string(), (r.split_public_gen0, 0, 1));
    assert_eq!(
        lineages(&all),
        want,
        "no private lineage, and the split lineage's private generation is neither its head \
         nor counted: {all:?}"
    );
    assert_eq!(flat_ids(&all), vec![r.flat_public], "{all:?}");
}

/// A lineage that gains a generation between two pages keeps its place: it is
/// not listed again on a later page (a created_at-keyed cursor would move its
/// head past the cursor and list it twice).
#[sqlx::test(migrations = "../../migrations")]
async fn a_lineage_that_gains_a_generation_mid_walk_is_listed_once(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let r = seed_registry(&pool).await;
    let (_, group) = fixture::seed_agent_with_group(&pool, "list-wf-late-writer").await;

    let first = call(&server, &r.member, 1, None, None)
        .await
        .expect("first page");
    let first_entries = first["workflows"].as_array().expect("array").clone();
    assert_eq!(first_entries.len(), 1, "{first}");
    assert_eq!(
        first_entries[0]["canonical_name"], "alpha-calibration",
        "{first}"
    );

    // A new head, created after every row seeded so far.
    seed_generation(
        &pool,
        "alpha-calibration",
        3,
        "a generation written mid-walk",
        1.0,
        "public",
        group,
        500,
    )
    .await;

    let mut all = first_entries;
    let mut cursor = first["next_cursor"].as_str().map(str::to_string);
    let mut guard = 0;
    while let Some(c) = cursor {
        guard += 1;
        assert!(guard < 100, "the walk does not terminate");
        let page = call(&server, &r.member, 1, Some(c), None)
            .await
            .expect("page");
        all.extend(page["workflows"].as_array().expect("array").iter().cloned());
        cursor = page["next_cursor"].as_str().map(str::to_string);
    }
    // `lineages` fails on a lineage listed twice.
    let listed = lineages(&all);
    assert_eq!(
        listed.keys().collect::<Vec<_>>(),
        r.member_view.keys().collect::<Vec<_>>(),
        "{all:?}"
    );
}

/// A cursor the tool did not issue is the caller's error, not the server's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cursor_the_tool_did_not_issue_is_invalid_params(pool: PgPool) {
    let server = app_role_server(&pool).await;
    let r = seed_registry(&pool).await;
    for bad in ["x:alpha", "h:", "f:not-a-uuid", "alpha-calibration"] {
        let err = call(&server, &r.member, 5, Some(bad.to_string()), None)
            .await
            .expect_err(bad);
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "{bad}: {err:?}"
        );
    }
    // The cursors it does issue parse: a hierarchical one and a flat one.
    call(
        &server,
        &r.member,
        5,
        Some("h:charlie-recompute".to_string()),
        None,
    )
    .await
    .expect("hierarchical cursor");
    call(
        &server,
        &r.member,
        5,
        Some(format!("f:{}", Uuid::nil())),
        None,
    )
    .await
    .expect("flat cursor");
}
