//! `D-PR21-cli-wire-shape-pin` — the key-holding CLI and the route crate agree
//! on the seal wire format.
//!
//! # The gap
//!
//! `epigraph-privatize` declares its own private mirrors of the seal and unseal
//! wire shapes. The duplication is deliberate and sound — `epigraph-cli` must
//! not link `epigraph-api` into the tool that holds the key — but nothing
//! related the two, so a field renamed on either side compiled clean and passed
//! every gate.
//!
//! The hazard is not a build break. It is that the drift is discovered by a
//! key-holding admin MID-CEREMONY, after the plaintext has already been on the
//! wire: a `next_cursor` the CLI can no longer see deserialises to `None`, the
//! paging loop stops after one page, and the tool reports success having sealed
//! a prefix of the plan.
//!
//! # Why the sources are compared as text
//!
//! The mirrors are private items inside a `[[bin]]` target, which exports
//! nothing, so no test can name them. The three available shapes were: include
//! the bin as a module, keep a golden document both sides assert against, or
//! move the types into a shared crate. The third is barred by the very
//! constraint that makes the duplication correct. This file takes a variant of
//! the second in which the ROUTE CRATE IS THE GOLDEN, so there is no third
//! artifact to keep in step with either side.
//!
//! `resource_metadata_challenge.rs` reads `bin/server.rs` as source text for
//! the same reason: a `[[bin]]`'s contents are otherwise unreachable.

/// The CLI's source, read as text. A moved or renamed file breaks the build
/// here, which is itself worth pinning: FINAL-PLAN §6.5.7 spells this path
/// wrongly, and the tree is the authority.
const CLI_SRC: &str = include_str!("../../epigraph-cli/src/bin/privatize.rs");

/// The route crate's source — the definition the wire format actually has.
const ROUTES_SRC: &str = include_str!("../src/routes/privatization.rs");

/// The field names declared by `struct <name>` in `src`.
///
/// Deliberately naive, and calibrated rather than trusted: these are plain
/// structs with no generics, no tuple fields and no `#[serde(rename)]` on
/// either side — a rename attribute would make a field NAME differ from its
/// identifier and silently defeat this comparison, so the absence of one is
/// asserted too.
///
/// # It refuses a second definition rather than taking the first
///
/// `routes/privatization.rs` carries `#[cfg(feature = "db")]` handlers beside
/// `#[cfg(not(feature = "db"))]` stubs, so a `#[cfg]` twin of a wire type is
/// a shape this file could plausibly acquire. Taking the first match would then
/// compare the CLI against whichever body happened to be written first, and
/// nothing would say so. Measured today: every name in both tables resolves to
/// exactly one definition in each source. The assertion is what keeps that
/// true.
fn fields_of(src: &str, name: &str) -> Vec<String> {
    let head = format!("struct {name} {{");
    assert_eq!(
        src.matches(&head).count(),
        1,
        "`struct {name}` is declared {} times in this source; this extractor reads ONE definition \
         and would otherwise compare against whichever came first",
        src.matches(&head).count()
    );
    let start = src
        .find(&head)
        .unwrap_or_else(|| panic!("no `struct {name}` in this source"))
        + head.len();
    let body = &src[start..];
    let end = body
        .find("\n}")
        .unwrap_or_else(|| panic!("`struct {name}` is not closed at column 0"));
    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("pub ").unwrap_or(line);
            let (ident, rest) = line.split_once(':')?;
            // A field, not a path segment (`serde_json::Value`) or an attribute.
            if rest.starts_with(':') || ident.is_empty() {
                return None;
            }
            let ident = ident.trim();
            ident
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                .then(|| ident.to_string())
        })
        .collect()
}

/// The shapes that cross the wire, by the name BOTH files give them.
const SHARED_SHAPES: &[&str] = &[
    "SealManifest",
    "SealManifestEntry",
    "SealCommitRequest",
    "SealCommitEntry",
    "UnsealManifest",
    "UnsealManifestEntry",
    "UnsealCommitRequest",
    "CommitResponse",
];

/// Every field the CLI declares exists, under that name, on the route type.
///
/// # The direction of the check, and why it is not equality
///
/// The route type is the wire format; the CLI's mirror is a projection of it.
/// A server that ADDS a field is a compatible change and the CLI is entitled to
/// ignore it — `SealManifest.plan_id` is already such a field today. A server
/// that RENAMES or REMOVES one the CLI reads is not, and that is what this
/// catches, from either side: rename on the server and the CLI's name stops
/// existing; rename in the CLI and the new name never existed.
#[test]
fn every_field_the_cli_mirrors_exists_on_the_route_type() {
    let mut checked = 0usize;
    for shape in SHARED_SHAPES {
        let cli = fields_of(CLI_SRC, shape);
        let route = fields_of(ROUTES_SRC, shape);
        assert!(
            !cli.is_empty(),
            "CALIBRATION: parsed no fields out of the CLI's `{shape}`; the extractor is broken \
             and every assertion below would be vacuous"
        );
        for field in &cli {
            assert!(
                route.contains(field),
                "`{shape}.{field}` is declared by epigraph-privatize and does NOT exist on the \
                 route type. The seal wire format has drifted; the route crate's fields are \
                 {route:?}"
            );
        }
        checked += cli.len();
    }
    // 33 today, across the eight shapes. Pinned as an exact number rather than
    // a floor: the failure this guards is the extractor quietly matching FEWER
    // lines — a field-shape it stops recognising drops out of the comparison
    // with no other symptom, and a floor with slack absorbs exactly that. A
    // field legitimately added to either side is a deliberate edit here.
    assert_eq!(
        checked,
        33,
        "CALIBRATION: {checked} fields were compared across {} shapes, not 33. If a field was \
         added to the CLI's mirrors, update this number; if not, the extractor has stopped \
         matching a field shape and the comparison above is quietly narrower than it reads",
        SHARED_SHAPES.len()
    );
}

/// The nested entry types the two files spell DIFFERENTLY are pinned by hand.
///
/// `versions` and `evidence` carry element types whose names diverge: the CLI
/// reuses one `CommitVersion`/`CommitEvidence` pair across both directions,
/// while the route crate names each direction separately. A name-keyed
/// comparison cannot pair them, so they are paired here explicitly rather than
/// left out — they are the rows whose loss is unrecoverable, and a rename
/// inside one of them is exactly as damaging as a rename at the top level.
#[test]
fn the_nested_entry_types_agree_despite_being_named_differently() {
    for (cli_name, route_name) in [
        ("ManifestVersion", "ManifestVersion"),
        ("ManifestEvidence", "ManifestEvidence"),
        ("CommitVersion", "CommitVersion"),
        ("CommitEvidence", "CommitEvidence"),
        ("UnsealCommitVersion", "UnsealCommitVersionEntry"),
        ("UnsealCommitEvidence", "UnsealCommitEvidenceEntry"),
    ] {
        let cli = fields_of(CLI_SRC, cli_name);
        let route = fields_of(ROUTES_SRC, route_name);
        assert!(
            !cli.is_empty(),
            "CALIBRATION: no fields parsed for {cli_name}"
        );
        for field in &cli {
            assert!(
                route.contains(field),
                "`{cli_name}.{field}` in epigraph-privatize has no counterpart on the route \
                 crate's `{route_name}` ({route:?})"
            );
        }
    }
}

/// Neither side renames a field at the serde layer.
///
/// The comparison above is between IDENTIFIERS. A `#[serde(rename = "...")]`
/// would make a field's wire name differ from its identifier, at which point
/// two identical identifier sets could describe two incompatible documents and
/// this file would report agreement. Rather than teach the extractor about
/// attributes, the absence of the attribute is asserted — if one is ever
/// wanted, this test is where the decision has to be taken deliberately.
#[test]
fn no_serde_rename_hides_a_field_from_this_comparison() {
    for (label, src) in [
        ("epigraph-privatize", CLI_SRC),
        ("the route crate", ROUTES_SRC),
    ] {
        assert!(
            !src.contains("serde(rename"),
            "{label} now carries a serde rename; the identifier-level comparison in this file \
             no longer proves the two documents match"
        );
    }
}
