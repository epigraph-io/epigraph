//! Source lint for the router extension seam (`routes/extensions.rs`).
//!
//! 1. `/api/v1/ext` belongs to extensions: no first-party `.route(` or
//!    `.nest(` in `routes/mod.rs` may register at or under it, or a kernel
//!    upgrade could collide with an embedder's routes.
//! 2. In BOTH create_router variants, `extensions::mount_all(protected,
//!    extensions, &state)` heads the statement that applies `bearer_auth_middleware`
//!    (and, in the db variant, `record_elevated_access`). axum layers wrap only
//!    routes that already exist, so a mount anywhere else is unauthenticated.
//!    `tests/router_extension_seam.rs` proves this at runtime for the db
//!    variant only; this lint is what covers not(db).

const ROUTES_MOD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes/mod.rs");
/// Matched against [`compact`] source, so rustfmt's line breaks cannot hide it.
const MOUNT: &str = "letprotected=extensions::mount_all(protected,extensions,&state)";

fn source() -> String {
    std::fs::read_to_string(ROUTES_MOD).unwrap_or_else(|e| panic!("cannot read {ROUTES_MOD}: {e}"))
}

/// The source with every whitespace character removed. Used only for the
/// placement checks; string literals are not compared in this form.
fn compact(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Every string literal passed as the first argument of `.{method}(`.
fn first_literals(src: &str, method: &str) -> Vec<String> {
    let needle = format!(".{method}(");
    src.match_indices(&needle)
        .filter_map(|(i, _)| {
            let rest = src[i + needle.len()..].trim_start();
            let rest = rest.strip_prefix('"')?;
            rest.find('"').map(|end| rest[..end].to_string())
        })
        .collect()
}

#[test]
fn no_first_party_route_is_registered_under_the_extension_prefix() {
    let src = source();
    let prefix = epigraph_api::EXTENSION_PREFIX;
    let routes = first_literals(&src, "route");
    assert!(
        routes.len() > 150,
        "only {} route literals found; the scan lost the router",
        routes.len()
    );
    let mut offenders: Vec<String> = routes
        .into_iter()
        .chain(first_literals(&src, "nest"))
        .filter(|p| p == prefix || p.starts_with(&format!("{prefix}/")))
        .collect();
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "{offenders:?} registered under {prefix}, which is reserved for \
         embedder extensions (routes/extensions.rs). Move the route elsewhere."
    );
}

#[test]
fn both_variants_mount_extensions_at_the_head_of_the_auth_layer_statement() {
    let src = compact(&source());
    let starts: Vec<usize> = src.match_indices(MOUNT).map(|(i, _)| i).collect();
    assert_eq!(
        starts.len(),
        2,
        "expected `{MOUNT}` (whitespace removed) exactly twice (db, then not(db)); found {}",
        starts.len()
    );
    assert_eq!(
        src.matches("extensions::mount_all(").count(),
        2,
        "extensions::mount_all is called somewhere other than the two auth-layer statements"
    );
    for (variant, &start) in ["db", "not(db)"].iter().zip(&starts) {
        // The layer statements contain no `;` before their end.
        let stmt = &src[start..start + src[start..].find(';').expect("statement end")];
        assert!(
            stmt.contains("bearer_auth_middleware"),
            "{variant}: the mount statement does not apply bearer_auth_middleware:\n{stmt}"
        );
        if *variant == "db" {
            assert!(
                stmt.contains("record_elevated_access"),
                "db: the mount statement does not apply the per-access recorder:\n{stmt}"
            );
        }
    }
}

#[test]
fn create_router_delegates_with_no_extensions_in_both_variants() {
    let src = compact(&source());
    assert_eq!(
        src.matches("create_router_with_extensions(state,Vec::new())")
            .count(),
        2,
        "each create_router variant must delegate to create_router_with_extensions \
         with no extensions, so the two cannot drift"
    );
}
