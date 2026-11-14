//! Every non-GET route in the `db` router names its scope, or names why it
//! has none (backlog f00d75ab).
//!
//! # Why this file exists
//!
//! Bearer authentication is a router layer; scope is not. A handler that took
//! `State` and a body and nothing else was reachable by any valid bearer, a
//! `claims:read` token included, and about thirty write routes were exactly
//! that until the same branch gated them. Nothing noticed, because the
//! property "this write checks a scope" lives in each handler's source and no
//! test enumerated the route table against it.
//!
//! # What it checks
//!
//! * [`every_non_get_route_is_registered_exactly`]: the set of handlers behind
//!   a `post`/`put`/`patch`/`delete` in `routes/mod.rs`'s `db`
//!   `create_router_with_extensions` equals [`ROUTE_GATES`], in both
//!   directions. A new write route fails until it is given a [`Gate`]; a
//!   deleted one fails until its entry goes.
//! * [`every_scoped_route_checks_its_scope`]: for a [`Gate::Scope`] entry, the
//!   handler's `db` definition shows the scope, either as a `RequireScope*`
//!   extractor in its signature or as the scope literal inside a
//!   `check_scopes(` / `has_scope(` call's arguments. For [`Gate::Via`], the handler calls
//!   the named helper and the helper's body shows the scope that way.
//! * [`every_exemption_says_why`]: a [`Gate::Exempt`] carries a reason.
//! * [`the_scope_evidence_scanner_is_not_vacuous`]: calibration. A handler
//!   with no gate yields no evidence; each accepted spelling yields its scope.
//!
//! # What it does not check
//!
//! The `not(feature = "db")` router (a stub build with no database) and
//! routes added by an embedder through `extensions` (whose scope checks the
//! extension contract makes the embedder's own job). It proves that a scope is
//! CHECKED, not that the check is the right one for the route: the table says
//! which scope, and a reviewer reads the table. Like `viewer_route_table_lint`,
//! it is a source lint because axum erases handler signatures at registration.

mod lint_text;

use lint_text::strip_comments;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// How a write route is authorized.
#[derive(Debug, Clone, Copy)]
enum Gate {
    /// The handler itself checks this scope.
    Scope(&'static str),
    /// The handler calls `helper`, a function in the same file that checks
    /// this scope.
    Via(&'static str, &'static str),
    /// No scope, for the stated reason.
    Exempt(&'static str),
}

use Gate::{Exempt, Scope, Via};

const READ_ONLY_POST: &str =
    "a read shaped as POST: the body is a query, the handler writes nothing and its reads are \
     viewer-filtered";
const PURE_COMPUTE: &str = "pure computation over the request body: no database read or write";
/// Honest, not a clean bill: these read on the unstamped `state.db_pool`
/// with no viewer, so row security admits only what an anonymous session
/// sees. A scope would not change what they read; whether they leak beyond
/// public rows is a viewer question, recorded as a found-not-fixed item.
const RAW_POOL_READ_POST: &str =
    "a read shaped as POST that writes nothing, but reads on the unstamped `state.db_pool` with \
     no viewer (not viewer-filtered); a scope would not narrow what it reads";
const OAUTH: &str =
    "OAuth protocol endpoint: authenticated by the protocol's own client or user credential, \
     before any bearer exists";
const ELEVATE_CEREMONY: &str =
    "elevation ceremony step: authenticated by its own WebAuthn ticket or challenge state";
const INSTANCE_ADMIN: &str =
    "privatization: authorized by instance-admin authority over the target group \
     (`require_instance_admin_for_group` / `require_plan_authority`), a membership check \
     stronger than any token scope";

/// Every handler behind a non-GET route of the `db` router, and its gate.
/// Keyed by the handler path exactly as `routes/mod.rs` spells it.
const ROUTE_GATES: &[(&str, Gate)] = &[
    ("activities::complete_activity", Scope("claims:write")),
    ("activities::create_activity", Scope("claims:write")),
    ("admin::approve_client", Scope("clients:admin")),
    ("admin::register_entity_type", Scope("entity-types:write")),
    (
        "admin_acts::propose_act",
        Exempt(
            "proposes an operator act that writes nothing until an operator confirms it with a \
             WebAuthn ceremony; the MCP twin `propose_admin_act` is claims:read",
        ),
    ),
    ("agent_keys::revoke_agent_key", Scope("agents:write")),
    ("agent_keys::rotate_agent_key", Scope("agents:write")),
    ("agents::create_agent", Scope("agents:write")),
    ("agents::update_agent", Scope("agents:write")),
    (
        "analyze::unconstrained_analysis",
        Exempt(
            "writes nothing: forwards the question to the configured LLM provider and returns \
             its answer",
        ),
    ),
    ("assess::assess_claim", Scope("claims:write")),
    ("batch::batch_create_claims", Scope("claims:write")),
    ("bba_retract::retract_bba", Scope("claims:write")),
    ("bba_retract::unretract_bba", Scope("claims:write")),
    ("belief::conflict_batch", Exempt(READ_ONLY_POST)),
    ("belief::create_frame", Scope("claims:write")),
    ("belief::refine_frame", Scope("claims:write")),
    ("belief::submit_evidence", Scope("claims:write")),
    ("challenge::resolve_challenge", Scope("claims:write")),
    ("challenge::submit_challenge", Scope("claims:write")),
    (
        "claim_visibility::publicize_claims",
        Via("claims:write", "require_write"),
    ),
    (
        "claim_visibility::set_agent_default_group",
        Via("claims:write", "require_write"),
    ),
    (
        "claim_visibility::set_default_group",
        Via("claims:write", "require_write"),
    ),
    (
        "claim_visibility::share_claims_with_team",
        Via("claims:write", "require_write"),
    ),
    (
        "claims::create_claim",
        Via("claims:write", "create_claim_core"),
    ),
    ("claims::patch_claim", Scope("claims:write")),
    ("claims::update_claim", Scope("claims:write")),
    ("claims::update_labels", Scope("claims:write")),
    ("claims_batch_get::batch_get_claims", Exempt(READ_ONLY_POST)),
    ("clusters::build_from_bridges", Scope("claims:admin")),
    ("community::add_member", Scope("groups:admin")),
    ("community::create_community", Scope("groups:write")),
    ("community::remove_member", Scope("groups:admin")),
    ("computation::compose_subgraphs", Exempt(RAW_POOL_READ_POST)),
    (
        "computation::propagate_beliefs",
        Exempt(
            "a read unless `apply_updates: true`; only that write arm checks claims:write (in \
             the body, so a claims:read token still runs the read-only diagnostic), and it is \
             also refused unless the server runs with BP apply on",
        ),
    ),
    ("computation::sheaf_reconcile", Exempt(READ_ONLY_POST)),
    ("conflicts::classify_conflict", Exempt(READ_ONLY_POST)),
    ("conflicts::resolve_conflict", Scope("claims:admin")),
    ("conflicts::store_counterfactuals", Scope("claims:write")),
    ("context::create_context", Scope("claims:write")),
    ("conventions::forget_convention", Scope("claims:admin")),
    ("conventions::learn_convention", Scope("claims:admin")),
    ("conventions::share_skill", Scope("claims:write")),
    ("crate::oauth::auth_url_endpoint", Exempt(OAUTH)),
    ("crate::oauth::consent_endpoint", Exempt(OAUTH)),
    ("crate::oauth::exchange_endpoint", Exempt(OAUTH)),
    ("crate::oauth::introspect_endpoint", Exempt(OAUTH)),
    ("crate::oauth::register_endpoint", Exempt(OAUTH)),
    ("crate::oauth::revoke_endpoint", Exempt(OAUTH)),
    ("crate::oauth::token_endpoint", Exempt(OAUTH)),
    ("cross_source::decide_candidate", Scope("claims:write")),
    ("crud::assign_claim_to_frame", Scope("claims:admin")),
    ("crud::assign_unthemed", Scope("claims:admin")),
    ("crud::create_analysis", Scope("claims:write")),
    ("crud::create_evidence", Scope("evidence:write")),
    ("crud::create_reasoning_trace", Scope("claims:write")),
    ("crud::create_theme_with_centroid", Scope("claims:admin")),
    ("crud::promote_staged_edges", Scope("claims:admin")),
    ("crud::reassign_claim", Scope("claims:admin")),
    ("crud::recompute_centroids", Scope("claims:admin")),
    ("crud::update_evidence", Scope("evidence:write")),
    ("crud::upsert_cluster", Scope("claims:admin")),
    ("edges::create_edge", Scope("edges:write")),
    ("edges::create_hierarchical_edge", Scope("edges:write")),
    ("edges::delete_edge", Scope("edges:write")),
    ("edges::patch_edge", Scope("edges:write")),
    ("edges::relate_claims", Scope("edges:write")),
    ("elevate::act_assert", Exempt(ELEVATE_CEREMONY)),
    ("elevate::act_challenge", Exempt(ELEVATE_CEREMONY)),
    ("elevate::enroll_challenge", Exempt(ELEVATE_CEREMONY)),
    ("elevate::enroll_finish", Exempt(ELEVATE_CEREMONY)),
    ("elevate::ticket_assert", Exempt(ELEVATE_CEREMONY)),
    ("elevate::ticket_challenge", Exempt(ELEVATE_CEREMONY)),
    (
        "elevation::create_ticket",
        Exempt(
            "opens an elevation ticket for the caller's own human session (an \
             `UnelevatedViewer` with a refresh family); elevation is granted by the WebAuthn \
             ceremony, not by a scope",
        ),
    ),
    (
        "elevation::end_elevation",
        Exempt("ends the caller's own elevation session; narrows authority, never widens it"),
    ),
    (
        "embeddings::neighborhood_density",
        Exempt(RAW_POOL_READ_POST),
    ),
    ("entities::batch_create_mentions", Scope("claims:write")),
    ("entities::batch_create_triples", Scope("claims:write")),
    ("entities::create_entity", Scope("claims:write")),
    ("entities::query_triples", Exempt(READ_ONLY_POST)),
    ("events::create_event", Scope("claims:write")),
    (
        "experiment_loop::add_measurements",
        Via("claims:write", "require_write_scope"),
    ),
    ("experiment_loop::analyze_result", Scope("claims:write")),
    (
        "experiment_loop::create_experiment",
        Via("claims:write", "require_write_scope"),
    ),
    (
        "experiment_loop::start_experiment",
        Via("claims:write", "require_write_scope"),
    ),
    (
        "experiment_loop::submit_results",
        Via("claims:write", "require_write_scope"),
    ),
    ("experiments::add_method", Scope("claims:write")),
    ("experiments::design_experiment", Exempt(READ_ONLY_POST)),
    ("experiments::hypothesize", Exempt(READ_ONLY_POST)),
    ("gaps::gap_analysis", Scope("claims:write")),
    ("gaps::surface_gaps", Scope("claims:write")),
    ("graph_query::execute_graph_query", Exempt(READ_ONLY_POST)),
    ("groups::add_member", Scope("groups:admin")),
    ("groups::create_group", Scope("groups:write")),
    ("groups::remove_member", Scope("groups:admin")),
    ("groups::rotate_key", Scope("groups:admin")),
    ("harvest::submit_harvest", Scope("claims:write")),
    ("hypothesis::create_hypothesis", Scope("claims:write")),
    ("hypothesis::promote_hypothesis", Scope("claims:write")),
    ("ingest::ingest_paper", Scope("claims:admin")),
    ("papers::create_paper", Scope("claims:write")),
    ("perspective::create_perspective", Scope("claims:write")),
    ("perspective::set_source_reliability", Scope("claims:write")),
    ("policies::create_challenge", Scope("claims:write")),
    ("policies::decay_sweep", Scope("claims:admin")),
    ("policies::record_outcome", Scope("claims:admin")),
    ("policies::resolve_challenge", Scope("claims:admin")),
    ("political::create_coalition", Scope("claims:write")),
    ("political::create_technique", Scope("claims:write")),
    ("privatization::abort_plan", Exempt(INSTANCE_ADMIN)),
    ("privatization::apply_plan", Exempt(INSTANCE_ADMIN)),
    ("privatization::approve_plan", Exempt(INSTANCE_ADMIN)),
    ("privatization::create_plan", Exempt(INSTANCE_ADMIN)),
    ("privatization::revert_plan", Exempt(INSTANCE_ADMIN)),
    ("privatization::seal_commit", Exempt(INSTANCE_ADMIN)),
    ("privatization::unseal_commit", Exempt(INSTANCE_ADMIN)),
    ("provenance::set_provenance", Scope("claims:write")),
    ("reasoning::analyze", Scope("analysis:reasoning")),
    (
        "revoke_signature::revoke_claim_signature",
        Scope("claims:revoke-signature"),
    ),
    ("search::semantic_search", Exempt(READ_ONLY_POST)),
    ("spans::close_span", Scope("claims:write")),
    ("spans::create_span", Scope("claims:write")),
    ("staging::analyze_rejection", Exempt(PURE_COMPUTE)),
    ("staging::ingest_git", Exempt(PURE_COMPUTE)),
    ("staging::ingest_json", Exempt(PURE_COMPUTE)),
    (
        "staging::merge_staging",
        Exempt("a stub: counts what a merge would write and writes nothing"),
    ),
    ("submit::submit_packet", Scope("claims:write")),
    ("tasks::assign_task", Scope("tasks:write")),
    ("tasks::complete_task", Scope("tasks:write")),
    ("tasks::create_task", Scope("tasks:write")),
    ("tasks::fail_task", Scope("tasks:write")),
    ("versioning::mark_duplicate", Scope("claims:write")),
    ("versioning::supersede_claim", Scope("claims:write")),
    ("versioning::unmark_duplicate", Scope("claims:write")),
    ("voids::detect_voids", Exempt(READ_ONLY_POST)),
    ("webhooks::delete_webhook", Scope("webhooks:write")),
    ("webhooks::register_webhook", Scope("webhooks:write")),
    ("workflows::add_step", Scope("claims:write")),
    ("workflows::delete_step", Scope("claims:write")),
    ("workflows::deprecate_workflow", Scope("claims:write")),
    ("workflows::evolve_step", Scope("claims:write")),
    ("workflows::ingest_workflow", Scope("claims:write")),
    (
        "workflows::record_behavioral_execution",
        Scope("claims:write"),
    ),
    (
        "workflows::report_hierarchical_outcome",
        Scope("claims:write"),
    ),
    ("workflows::report_outcome", Scope("claims:write")),
    ("workflows::store_workflow", Scope("claims:write")),
];

/// The `RequireScope*` extractors of `middleware::bearer`, and their scope.
const EXTRACTORS: &[(&str, &str)] = &[
    ("RequireScopeWrite", "claims:write"),
    ("RequireScopeAdmin", "claims:admin"),
    ("RequireScopeWebhooksWrite", "webhooks:write"),
    ("RequireScopeGroupsWrite", "groups:write"),
    ("RequireScopeGroupsAdmin", "groups:admin"),
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read_stripped(rel: &str) -> String {
    let path = src_dir().join(rel);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    strip_comments(&raw)
}

/// The byte index just past the bracket that closes the one opened at `open`
/// (`src[open]` is `(` or `{`), skipping string literals.
fn close_of(src: &str, open: usize) -> usize {
    let b = src.as_bytes();
    let (o, c) = match b[open] {
        b'(' => (b'(', b')'),
        b'{' => (b'{', b'}'),
        other => panic!("close_of called on {:?}", other as char),
    };
    let (mut depth, mut i, mut in_str) = (0usize, open, false);
    while i < b.len() {
        let ch = b[i];
        if in_str {
            if ch == b'\\' {
                i += 2;
                continue;
            }
            if ch == b'"' {
                in_str = false;
            }
        } else if ch == b'"' {
            in_str = true;
        } else if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
        i += 1;
    }
    panic!("unbalanced bracket at byte {open}");
}

/// The body of the `db` `create_router_with_extensions` in `routes/mod.rs`.
fn db_router_body(mod_rs: &str) -> &str {
    let marker = "#[cfg(feature = \"db\")]\npub fn create_router_with_extensions(";
    let at = mod_rs
        .find(marker)
        .expect("routes/mod.rs has a db `create_router_with_extensions`");
    let open = at + mod_rs[at..].find('{').expect("function body");
    &mod_rs[open..close_of(mod_rs, open)]
}

/// `(METHOD, path, handler)` for every non-GET method router in `body`.
fn write_routes(body: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = body[from..].find(".route(") {
        let open = from + rel + ".route".len();
        let end = close_of(body, open);
        let args = &body[open + 1..end - 1];
        let q1 = args.find('"').expect("route path literal");
        let q2 = q1 + 1 + args[q1 + 1..].find('"').expect("route path literal end");
        let path = args[q1 + 1..q2].to_string();
        let rest = &args[q2 + 1..];
        for method in ["post", "put", "patch", "delete"] {
            let needle = format!("{method}(");
            let mut k = 0;
            while let Some(r) = rest[k..].find(&needle) {
                let at = k + r;
                let prev = rest[..at].chars().last();
                k = at + needle.len();
                if prev.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    continue;
                }
                let inner_end = at + method.len() + close_of(&rest[at + method.len()..], 0) - 1;
                let handler = rest[at + needle.len()..inner_end].trim().to_string();
                out.push((method.to_uppercase(), path.clone(), handler));
            }
        }
        from = end;
    }
    out
}

/// `(signature, body)` of the `db` definition of `name` in `src`: the
/// definition not attributed `#[cfg(not(feature = "db"))]`.
fn db_fn<'a>(src: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
    let mut from = 0;
    while let Some(rel) = src[from..].find(&format!("async fn {name}(")) {
        let at = from + rel;
        from = at + 1;
        let decl_start = at + src[at..].find('(').expect("paren");
        let line_start = src[..at].rfind('\n').map_or(0, |i| i + 1);
        // The attribute lines directly above the declaration.
        let mut attrs = String::new();
        let mut cursor = line_start;
        while cursor > 0 {
            let prev_start = src[..cursor - 1].rfind('\n').map_or(0, |i| i + 1);
            let line = src[prev_start..cursor - 1].trim();
            if line.starts_with("#[") {
                attrs.push_str(line);
                cursor = prev_start;
            } else {
                break;
            }
        }
        if attrs.contains("not(feature = \"db\")") {
            continue;
        }
        let sig_end = close_of(src, decl_start);
        let open = sig_end + src[sig_end..].find('{').expect("fn body");
        return Some((&src[decl_start..sig_end], &src[open..close_of(src, open)]));
    }
    None
}

/// The scopes a handler's own source shows it checking: a `RequireScope*`
/// extractor in its signature, or a scope literal inside the argument list of
/// a `check_scopes(` / `has_scope(` call in its body.
fn scope_evidence(signature: &str, body: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for (extractor, scope) in EXTRACTORS {
        let hit = signature.match_indices(extractor).any(|(i, _)| {
            !signature[i + extractor.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        });
        if hit {
            found.insert((*scope).to_string());
        }
    }
    // Only a literal INSIDE a check call's argument list counts: a handler
    // that checks `claims:read` and names "claims:write" in an error message
    // shows `claims:read`, not both. A call whose scope argument is a local
    // (`check_scopes(&auth, required)`) counts the literals of that local's
    // `let` statement.
    for call in ["check_scopes(", "has_scope("] {
        for (at, _) in body.match_indices(call) {
            let open = at + call.len() - 1;
            // `close_of` returns the index just past the `)`.
            let args = &body[open + 1..close_of(body, open) - 1];
            let before = found.len();
            scope_literals(args, &mut found);
            if found.len() > before {
                continue;
            }
            // The scope argument is the last one; strip `&` and whitespace.
            let last = args.rsplit(',').next().unwrap_or(args);
            let ident = last.trim().trim_start_matches('&').trim();
            if ident.is_empty() || !ident.chars().all(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            if let Some(l) = body.find(&format!("let {ident}")) {
                let end = l + body[l..].find(';').unwrap_or(body.len() - l);
                scope_literals(&body[l..end], &mut found);
            }
        }
    }
    found
}

/// Every scope-shaped string literal (`area:verb`) in `text`.
fn scope_literals(text: &str, found: &mut BTreeSet<String>) {
    let mut rest = text;
    while let Some(q1) = rest.find('"') {
        let Some(len) = rest[q1 + 1..].find('"') else {
            break;
        };
        let lit = &rest[q1 + 1..q1 + 1 + len];
        if lit.contains(':') && !lit.contains(' ') && !lit.contains('/') {
            found.insert(lit.to_string());
        }
        rest = &rest[q1 + 2 + len..];
    }
}

fn handler_source(handler: &str) -> (String, String) {
    let (module, name) = handler
        .split_once("::")
        .unwrap_or_else(|| panic!("{handler}: not module::fn"));
    (
        read_stripped(&format!("routes/{module}.rs")),
        name.to_string(),
    )
}

#[test]
fn every_non_get_route_is_registered_exactly() {
    let mod_rs = read_stripped("routes/mod.rs");
    let routes = write_routes(db_router_body(&mod_rs));
    assert!(
        routes.len() > 100,
        "CALIBRATION: the parser found {} write routes; the db router has well over 100",
        routes.len()
    );
    let routed: BTreeSet<&str> = routes.iter().map(|(_, _, h)| h.as_str()).collect();
    let table: BTreeSet<&str> = ROUTE_GATES.iter().map(|(h, _)| *h).collect();
    assert_eq!(
        table.len(),
        ROUTE_GATES.len(),
        "a handler is listed twice in ROUTE_GATES"
    );
    let missing: Vec<String> = routes
        .iter()
        .filter(|(_, _, h)| !table.contains(h.as_str()))
        .map(|(m, p, h)| format!("{m} {p} -> {h}"))
        .collect();
    assert!(
        missing.is_empty(),
        "write routes with no entry in ROUTE_GATES. Give each a Gate: the scope its handler \
         checks (preferably a RequireScope* extractor, which refuses before the body is parsed), \
         or an Exempt reason a reviewer will read:\n{}",
        missing.join("\n")
    );
    let stale: Vec<&&str> = table.iter().filter(|h| !routed.contains(**h)).collect();
    assert!(
        stale.is_empty(),
        "ROUTE_GATES entries no db write route uses (delete them): {stale:?}"
    );
}

#[test]
fn every_scoped_route_checks_its_scope() {
    let mut failures = Vec::new();
    for (handler, gate) in ROUTE_GATES {
        let (scope, helper) = match gate {
            Scope(s) => (*s, None),
            Via(s, h) => (*s, Some(*h)),
            Exempt(_) => continue,
        };
        let (src, name) = handler_source(handler);
        let Some((sig, body)) = db_fn(&src, &name) else {
            failures.push(format!("{handler}: no db definition found"));
            continue;
        };
        let evidence = match helper {
            None => scope_evidence(sig, body),
            Some(h) => {
                if !body.contains(&format!("{h}(")) {
                    failures.push(format!("{handler}: does not call its gate helper `{h}`"));
                    continue;
                }
                let Some((hsig, hbody)) = db_fn(&src, h).or_else(|| plain_fn(&src, h)) else {
                    failures.push(format!("{handler}: helper `{h}` not found in its file"));
                    continue;
                };
                scope_evidence(hsig, hbody)
            }
        };
        if !evidence.contains(scope) {
            failures.push(format!(
                "{handler}: ROUTE_GATES says {scope}, the handler's source shows {evidence:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A non-async helper (`fn require_write(...)`), for [`Gate::Via`].
fn plain_fn<'a>(src: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
    let at = src.find(&format!("fn {name}("))?;
    let decl_start = at + src[at..].find('(')?;
    let sig_end = close_of(src, decl_start);
    let open = sig_end + src[sig_end..].find('{')?;
    Some((&src[decl_start..sig_end], &src[open..close_of(src, open)]))
}

#[test]
fn every_exemption_says_why() {
    for (handler, gate) in ROUTE_GATES {
        if let Exempt(reason) = gate {
            assert!(
                reason.split_whitespace().count() >= 6,
                "{handler}: an exemption needs a reason a reviewer can check, got {reason:?}"
            );
        }
    }
}

#[test]
fn the_scope_evidence_scanner_is_not_vacuous() {
    // A handler with no gate, as the write handlers were.
    let ungated = "pub async fn create_frame(\n    State(state): State<AppState>,\n    \
                   Json(request): Json<CreateFrameRequest>,\n) -> Result<(), ApiError> {\n    \
                   let row = FrameRepository::create(&state.db_pool, \"claims:write\").await?;\n    \
                   Ok(())\n}\n";
    let (sig, body) = db_fn(ungated, "create_frame").expect("probe parses");
    assert!(
        scope_evidence(sig, body).is_empty(),
        "a scope literal with no check call is not evidence"
    );

    let extractor =
        "pub async fn f(\n    _scope: crate::middleware::bearer::RequireScopeWrite,\n    \
                     State(state): State<AppState>,\n) -> R {\n    Ok(())\n}\n";
    let (sig, body) = db_fn(extractor, "f").unwrap();
    assert_eq!(
        scope_evidence(sig, body),
        BTreeSet::from(["claims:write".to_string()])
    );
    // A longer extractor name is not the shorter one.
    let longer = "pub async fn f(\n    _s: RequireScopeWriteish,\n) -> R {\n    Ok(())\n}\n";
    let (sig, body) = db_fn(longer, "f").unwrap();
    assert!(scope_evidence(sig, body).is_empty());

    let checked = "pub async fn f(\n    auth: AuthContext,\n) -> R {\n    \
                   check_scopes(&auth, &[\"edges:write\"])?;\n    Ok(())\n}\n";
    let (sig, body) = db_fn(checked, "f").unwrap();
    assert_eq!(
        scope_evidence(sig, body),
        BTreeSet::from(["edges:write".to_string()])
    );

    // A scope named outside the check call (here in an error message) is not
    // evidence: the handler checks claims:read, and that is all it shows.
    let mismatched = "pub async fn f(\n    auth: AuthContext,\n) -> R {\n    \
                      if !auth.has_scope(\"claims:read\") {\n        \
                      return Err(forbidden(\"needs claims:write\"));\n    }\n    \
                      let _ = \"claims:write\";\n    Ok(())\n}\n";
    let (sig, body) = db_fn(mismatched, "f").unwrap();
    assert_eq!(
        scope_evidence(sig, body),
        BTreeSet::from(["claims:read".to_string()])
    );

    // A scope chosen into a local and passed to the check is read from the
    // local's `let` statement.
    let via_local = "pub async fn f(\n    auth: AuthContext,\n) -> R {\n    \
                     let required: &[&str] = if x { &[\"claims:admin\"] } else { \
                     &[\"claims:write\"] };\n    \
                     check_scopes(&auth, required)?;\n    Ok(())\n}\n";
    let (sig, body) = db_fn(via_local, "f").unwrap();
    assert_eq!(
        scope_evidence(sig, body),
        BTreeSet::from(["claims:admin".to_string(), "claims:write".to_string()])
    );

    // The db definition is chosen over a `not(db)` stub of the same name.
    let both = "#[cfg(not(feature = \"db\"))]\npub async fn f(\n) -> R {\n    Ok(())\n}\n\n\
                #[cfg(feature = \"db\")]\npub async fn f(\n    _s: RequireScopeAdmin,\n) -> R {\n    \
                Ok(())\n}\n";
    let (sig, body) = db_fn(both, "f").unwrap();
    assert_eq!(
        scope_evidence(sig, body),
        BTreeSet::from(["claims:admin".to_string()])
    );

    // The route parser sees chained and multi-line method routers.
    let router = "{\n    Router::new()\n        .route(\"/a\", get(m::read).post(m::write))\n        \
                  .route(\n            \"/b/:id\",\n            put(n::replace),\n        )\n        \
                  .route(\"/c\", get(m::only_read))\n}";
    let routes = write_routes(router);
    assert_eq!(
        routes,
        vec![
            ("POST".to_string(), "/a".to_string(), "m::write".to_string()),
            (
                "PUT".to_string(),
                "/b/:id".to_string(),
                "n::replace".to_string()
            ),
        ]
    );
}
