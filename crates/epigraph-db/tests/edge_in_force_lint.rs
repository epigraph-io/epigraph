//! Source lint: every DISPLAY-tier `edges` read carries the in-force predicate.
//!
//! # Why this file exists
//!
//! Edge removal is a retraction: `EdgeRepository::retract_by_id` (reached by
//! the MCP `delete_edge` tool and `DELETE /api/v1/edges/:id`), `retract`,
//! `retract_between`, the `mark_duplicate` collapse, semantic-link delete and
//! match retire all set `valid_to` and leave the row in place for audit. So
//! any `edges` read that does not filter on `valid_to` renders a DELETED edge
//! as live. Commit 4331efb6 enforced [`EDGE_IN_FORCE`] on the belief-bearing
//! reads and deferred the display and traversal tiers ("follow-on and listed
//! in the docs"); nothing followed, and the graph views kept showing edges the
//! user had just deleted. `docs/architecture/edge-retraction-tiers.md` records
//! the tiering; this file is what keeps the display tier honest.
//!
//! # What it checks
//!
//! For every `FROM edges <alias>` / `JOIN edges <alias>` read inside a
//! display-tier scope (a whole file in [`DISPLAY_TIER_FILES`], or one function
//! in [`DISPLAY_TIER_FNS`]), the enclosing statement must spell the in-force
//! predicate for THAT alias at least once per read of it:
//!
//! * `(<alias>.valid_to IS NULL OR <alias>.valid_to > now())` — the static
//!   spelling, derived here from [`EDGE_IN_FORCE`] rather than hard-coded, so
//!   a change to the constant's text fails every static site until each is
//!   updated (the spelling cannot drift apart silently);
//! * for an unaliased `FROM edges`, [`EDGE_IN_FORCE_UNALIASED`];
//! * a `{EDGE_IN_FORCE}` / `{EDGE_IN_FORCE_UNALIASED}` `format!` interpolation
//!   for alias `e` / unaliased respectively.
//!
//! Counting per alias matters: `neighborhood_compound_nodes` reads `edges e`
//! three times in one statement, and one predicate would satisfy a
//! "does the statement mention it" check while leaving two reads unfiltered.
//!
//! # What it deliberately does NOT check
//!
//! WHERE the predicate sits (an `ON` versus a `WHERE`), and reads that reach
//! `edges` through a Rust call rather than SQL text (the MCP / HTTP
//! neighbourhood walks). Those are covered by behavioural tests —
//! `edge_retraction_display.rs` here and the per-crate tests named in the
//! tiering doc. The scope lists are exact: a listed scope with no `edges` read
//! fails, so a function that is renamed or moved cannot silently drop out.

use std::path::{Path, PathBuf};

use epigraph_db::repos::edge::{EDGE_IN_FORCE, EDGE_IN_FORCE_UNALIASED};

/// Workspace-relative files whose EVERY `edges` read is display-tier.
const DISPLAY_TIER_FILES: &[&str] = &[
    // The explorer's cluster / neighbourhood / compound views and
    // `load_subgraph` (graph_full, graph_query). Module doc, "Retracted edges".
    "crates/epigraph-db/src/repos/graph_view.rs",
];

/// Workspace-relative `(file, fn)` display-tier functions in files that also
/// hold structural reads (which must stay unfiltered — see the tiering doc).
const DISPLAY_TIER_FNS: &[(&str, &str)] = &[
    // The in-force endpoint reads behind MCP get_neighborhood / traverse.
    (
        "crates/epigraph-db/src/repos/edge.rs",
        "get_by_source_in_force",
    ),
    (
        "crates/epigraph-db/src/repos/edge.rs",
        "get_by_target_in_force",
    ),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(workspace_root().join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The static spelling of the in-force predicate for `alias`, derived from the
/// library constant.
fn spelling_for(alias: &str) -> String {
    EDGE_IN_FORCE.replace("e.valid_to", &format!("{alias}.valid_to"))
}

/// One `edges` read: `(line, enclosing fn, alias, covered)`.
type Read = (usize, String, String, bool);

/// Every `FROM edges` / `JOIN edges` read in `src`, with whether its statement
/// spells the in-force predicate for its alias once per read.
///
/// Comment lines are blanked first (doc prose quotes SQL), and so is a trailing
/// `#[cfg(test)] mod …` block. `DELETE FROM edges` is a write and is skipped.
/// A statement's window runs between consecutive `sqlx::query` / `.splice(` /
/// `format!(` anchors, the same approximation `visibility_lint.rs` uses.
fn edges_reads(src: &str) -> Vec<Read> {
    const ANCHORS: &[&str] = &[".splice(", "sqlx::query", "format!("];
    const NOT_AN_ALIAS: &[&str] = &[
        "WHERE",
        "ON",
        "JOIN",
        "LEFT",
        "RIGHT",
        "INNER",
        "OUTER",
        "FULL",
        "CROSS",
        "GROUP",
        "ORDER",
        "LIMIT",
        "OFFSET",
        "SET",
        "USING",
        "UNION",
        "RETURNING",
        "FOR",
        "AND",
        "OR",
        "HAVING",
        "WINDOW",
        "EXCEPT",
        "INTERSECT",
        "LATERAL",
        "NATURAL",
    ];

    let mut text = String::with_capacity(src.len());
    let mut in_tests = false;
    let lines: Vec<&str> = src.split_inclusive('\n').collect();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if !in_tests && t.starts_with("#[cfg(test)]") {
            let next = lines[i + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.is_empty())
                .unwrap_or("");
            if next.starts_with("mod ") || next.starts_with("pub mod ") {
                in_tests = true;
            }
        }
        if in_tests || t.starts_with("//") {
            text.extend(line.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
        } else {
            text.push_str(line);
        }
    }

    let mut words: Vec<(usize, &str)> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() {
            if let Some(s) = start.take() {
                words.push((s, &text[s..i]));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        words.push((s, &text[s..]));
    }
    let ident = |w: &str| -> String {
        w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_string()
    };

    // (pos, fn, alias, window bounds)
    let mut raw: Vec<(usize, String, String, usize, usize)> = Vec::new();
    for i in 0..words.len() {
        let kw = words[i].1.trim_start_matches(['(', ',', '"']);
        if !kw.eq_ignore_ascii_case("FROM") && !kw.eq_ignore_ascii_case("JOIN") {
            continue;
        }
        let prev_is_delete = i > 0
            && words[i - 1]
                .1
                .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .find(|w| !w.is_empty())
                .is_some_and(|w| w.eq_ignore_ascii_case("DELETE"));
        if prev_is_delete {
            continue;
        }
        let Some(&(pos, tbl)) = words.get(i + 1) else {
            continue;
        };
        if ident(tbl) != "edges" {
            continue;
        }
        let mut alias = "edges".to_string();
        let mut j = i + 2;
        while let Some(&(_, w)) = words.get(j) {
            let a = ident(w);
            if a.is_empty() || a.eq_ignore_ascii_case("AS") {
                j += 1;
                continue;
            }
            let starts_alpha = a.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
            if starts_alpha
                && !NOT_AN_ALIAS.iter().any(|k| a.eq_ignore_ascii_case(k))
                && a.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                alias = a;
            }
            break;
        }
        let win_start = ANCHORS
            .iter()
            .filter_map(|a| text[..pos].rfind(a))
            .max()
            .unwrap_or(0);
        let win_end = ANCHORS
            .iter()
            .filter_map(|a| text[pos..].find(a).map(|k| pos + k))
            .min()
            .unwrap_or(text.len());
        let func = text[..pos]
            .rfind("fn ")
            .map(|k| {
                text[k + 3..]
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("?")
                    .to_string()
            })
            .unwrap_or_else(|| "?".to_string());
        raw.push((pos, func, alias, win_start, win_end));
    }

    raw.iter()
        .map(|(pos, func, alias, ws, we)| {
            let window = &text[*ws..*we];
            let reads_of_alias = raw
                .iter()
                .filter(|(_, _, a, s, _)| a == alias && s == ws)
                .count();
            let mut spelled = window.matches(&spelling_for(alias)).count();
            if alias == "e" {
                spelled += window.matches("{EDGE_IN_FORCE}").count();
            }
            if alias == "edges" {
                spelled += window.matches(EDGE_IN_FORCE_UNALIASED).count();
                spelled += window.matches("{EDGE_IN_FORCE_UNALIASED}").count();
            }
            (
                text[..*pos].matches('\n').count() + 1,
                func.clone(),
                alias.clone(),
                spelled >= reads_of_alias,
            )
        })
        .collect()
}

#[test]
fn the_static_spellings_agree_with_the_library_constants() {
    // The derivation above assumes the constant is written over alias `e`. If
    // someone re-spells it, this fails first and names why.
    assert!(
        EDGE_IN_FORCE.contains("e.valid_to"),
        "EDGE_IN_FORCE is no longer written over alias `e` ({EDGE_IN_FORCE:?}); \
         update spelling_for() and every static site together"
    );
    assert_eq!(
        EDGE_IN_FORCE.replace("e.valid_to", "valid_to"),
        EDGE_IN_FORCE_UNALIASED,
        "the aliased and unaliased constants must be the same predicate"
    );
}

#[test]
fn every_display_tier_edges_read_is_in_force() {
    let mut failures: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    for file in DISPLAY_TIER_FILES {
        let reads = edges_reads(&read(file));
        assert!(
            !reads.is_empty(),
            "{file} is listed as display-tier but holds no `edges` read — delete the \
             entry, or the scanner stopped matching"
        );
        for (line, func, alias, covered) in reads {
            scanned += 1;
            if !covered {
                failures.push(format!("  {file}:{line} fn {func} (`{alias}`)"));
            }
        }
    }
    for (file, want_fn) in DISPLAY_TIER_FNS {
        let reads: Vec<Read> = edges_reads(&read(file))
            .into_iter()
            .filter(|(_, f, _, _)| f == want_fn)
            .collect();
        assert!(
            !reads.is_empty(),
            "{file}::{want_fn} is listed as display-tier but no `edges` read was found \
             in it — it was renamed, moved or rewritten; update DISPLAY_TIER_FNS"
        );
        for (line, func, alias, covered) in reads {
            scanned += 1;
            if !covered {
                failures.push(format!("  {file}:{line} fn {func} (`{alias}`)"));
            }
        }
    }

    assert!(
        scanned >= 20,
        "only {scanned} display-tier `edges` reads were scanned — the scanner is \
         probably not matching and would pass vacuously"
    );
    assert!(
        failures.is_empty(),
        "\n\nDisplay-tier `edges` reads WITHOUT the in-force predicate for their alias:\n{}\n\n\
         A retracted edge (MCP delete_edge, DELETE /api/v1/edges/:id, mark_duplicate \
         collapse, match retire) keeps its row with `valid_to` set. Add \
         `AND {}` (with your alias) to each read, in the same clause as its \
         EDGE_VISIBILITY marker. See docs/architecture/edge-retraction-tiers.md.\n",
        failures.join("\n"),
        EDGE_IN_FORCE
    );
}

/// The scanner approximates a SQL parser, so it is calibrated rather than
/// trusted: one that matched nothing, or marked everything covered, would keep
/// the ratchet green forever.
#[test]
fn the_in_force_scanner_is_not_vacuous() {
    let covered = |src: &str| -> Vec<(String, bool)> {
        edges_reads(src)
            .into_iter()
            .map(|(_, _, a, c)| (a, c))
            .collect()
    };
    let e = spelling_for("e");

    // Unfiltered, aliased and unaliased: seen and NOT covered.
    assert_eq!(
        covered("fn a() { sqlx::query(\"SELECT 1 FROM edges e WHERE e.id = $1\"); }"),
        vec![("e".to_string(), false)]
    );
    assert_eq!(
        covered("fn a() { sqlx::query(\"SELECT 1 FROM edges WHERE id = $1\"); }"),
        vec![("edges".to_string(), false)]
    );
    // The predicate for THIS alias covers it; another alias's does not.
    assert_eq!(
        covered(&format!(
            "fn a() {{ sqlx::query(\"SELECT 1 FROM edges e WHERE true AND {e}\"); }}"
        )),
        vec![("e".to_string(), true)]
    );
    assert_eq!(
        covered(&format!(
            "fn a() {{ sqlx::query(\"SELECT 1 FROM edges d WHERE true AND {e}\"); }}"
        )),
        vec![("d".to_string(), false)]
    );
    // Unaliased: the unaliased constant covers it.
    assert_eq!(
        covered(&format!(
            "fn a() {{ sqlx::query(\"SELECT 1 FROM edges WHERE true AND {EDGE_IN_FORCE_UNALIASED}\"); }}"
        )),
        vec![("edges".to_string(), true)]
    );
    // Interpolation of the constant.
    assert_eq!(
        covered("fn a() { let s = format!(\"SELECT 1 FROM edges e WHERE {EDGE_IN_FORCE}\"); }"),
        vec![("e".to_string(), true)]
    );
    // Two reads of one alias need two predicates.
    assert_eq!(
        covered(&format!(
            "fn a() {{ sqlx::query(\"SELECT 1 FROM edges e WHERE {e} AND NOT EXISTS \
             (SELECT 1 FROM edges e WHERE e.id = 1)\"); }}"
        )),
        vec![("e".to_string(), false), ("e".to_string(), false)]
    );
    assert_eq!(
        covered(&format!(
            "fn a() {{ sqlx::query(\"SELECT 1 FROM edges e WHERE {e} AND NOT EXISTS \
             (SELECT 1 FROM edges e WHERE {e})\"); }}"
        )),
        vec![("e".to_string(), true), ("e".to_string(), true)]
    );
    // A predicate in the NEXT statement cannot cover this one.
    assert_eq!(
        covered(&format!(
            "fn a() {{ sqlx::query(\"SELECT 1 FROM edges e\"); \
             sqlx::query(\"SELECT 1 FROM edges e WHERE {e}\"); }}"
        )),
        vec![("e".to_string(), false), ("e".to_string(), true)]
    );
    // Not reads: DELETE, comment lines, a trailing test module.
    assert!(covered("fn a() { sqlx::query(\"DELETE FROM edges WHERE id = $1\"); }").is_empty());
    assert!(covered("/// SELECT 1 FROM edges e\nfn a() {}").is_empty());
    assert!(covered(
        "fn a() {}\n#[cfg(test)]\nmod tests { fn t() { sqlx::query(\"SELECT 1 FROM edges\"); } }"
    )
    .is_empty());
    // The fn name is the enclosing one.
    let got =
        edges_reads("fn outer() {}\nfn inner_one() { sqlx::query(\"SELECT 1 FROM edges e\"); }");
    assert_eq!(got[0].1, "inner_one");
}

// ─────────────────────────────────────────────────────────────────────────
// Callers of the UNFILTERED endpoint reads
// ─────────────────────────────────────────────────────────────────────────

/// Every non-test caller of `EdgeRepository::get_by_source` /
/// `get_by_target` — the endpoint reads that return retracted edges — keyed
/// `(workspace-relative file, enclosing fn)`, each with the reason it is not
/// display-tier. An EXACT set: a new caller fails, and so does an entry whose
/// call has been switched to `get_by_{source,target}_in_force` or removed. The
/// MCP / HTTP neighbourhood walks reach `edges` through these Rust calls, not
/// SQL text, so [`every_display_tier_edges_read_is_in_force`] cannot see them;
/// this is the ratchet that can.
const UNFILTERED_ENDPOINT_READERS: &[(&str, &str, &str)] = &[
    (
        "crates/epigraph-api/src/routes/belief.rs",
        "submit_evidence",
        "PENDING: the G8 contradiction pre-screen is belief-bearing and is \
         converted by a later commit in this series",
    ),
    (
        "crates/epigraph-api/src/routes/edges.rs",
        "claim_neighborhood",
        "PENDING: display tier, converted by a later commit in this series",
    ),
    (
        "crates/epigraph-db/src/repos/claim.rs",
        "graph_expand_seeds_since",
        "PENDING: recall graph expansion, converted by a later commit in this series",
    ),
    (
        "crates/epigraph-engine/src/export/prov.rs",
        "export_provenance_prov_o",
        "STRUCTURAL: provenance export must keep every assertion, retracted or not \
         (tiering doc, structural tier)",
    ),
    (
        "crates/epigraph-mcp/src/tools/graph.rs",
        "incoming",
        "OPT-IN: the `include_retracted: true` branch of get_neighborhood, whose \
         rows are flagged `retracted`",
    ),
    (
        "crates/epigraph-mcp/src/tools/graph.rs",
        "outgoing",
        "OPT-IN: the `include_retracted: true` branch of get_neighborhood / \
         traverse, whose rows are flagged `retracted`",
    ),
    (
        "crates/epigraph-mcp/src/tools/workflows.rs",
        "deprecate_workflow",
        "STRUCTURAL: the variant_of / supersedes lineage cascade; a6adf739 keeps \
         workflow lineage readers unfiltered",
    ),
];

/// Every `.rs` file under `crates/*/src`, workspace-relative, with contents.
fn crate_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let rel = path
                    .strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read_to_string(&path).expect("read source")));
            }
        }
    }
    let root = workspace_root()
        .canonicalize()
        .expect("canonical workspace root");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root.join("crates")).expect("read crates/") {
        let src = entry.expect("crate dir").path().join("src");
        walk(&src, &root, &mut out);
    }
    out.sort();
    out
}

/// `(line, enclosing fn)` of every unfiltered endpoint-read call in `src`,
/// skipping comment lines and a trailing `#[cfg(test)] mod` block.
fn unfiltered_endpoint_calls(src: &str) -> Vec<(usize, String)> {
    const CALLS: &[&str] = &[
        "EdgeRepository::get_by_source(",
        "EdgeRepository::get_by_target(",
    ];
    let mut out = Vec::new();
    let mut in_tests = false;
    let mut current_fn = "?".to_string();
    let lines: Vec<&str> = src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if !in_tests && t.starts_with("#[cfg(test)]") {
            let next = lines[i + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.is_empty())
                .unwrap_or("");
            if next.starts_with("mod ") || next.starts_with("pub mod ") {
                in_tests = true;
            }
        }
        if in_tests || t.starts_with("//") {
            continue;
        }
        // A `fn` item: `fn` as a whole word followed by a name.
        if let Some(k) = line
            .match_indices("fn ")
            .map(|(k, _)| k)
            .find(|&k| k == 0 || line.as_bytes()[k - 1].is_ascii_whitespace())
        {
            let name: String = line[k + 3..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                current_fn = name;
            }
        }
        for call in CALLS {
            out.extend(std::iter::repeat_n(
                (i + 1, current_fn.clone()),
                line.matches(call).count(),
            ));
        }
    }
    out
}

#[test]
fn unfiltered_endpoint_reads_are_confined_to_reviewed_callers() {
    let mut found: std::collections::BTreeMap<(String, String), Vec<usize>> =
        std::collections::BTreeMap::new();
    let sources = crate_sources();
    assert!(
        sources.len() > 200,
        "expected the workspace's crate sources, found {} files — the walker is \
         looking in the wrong place and would pass vacuously",
        sources.len()
    );
    for (file, src) in &sources {
        for (line, func) in unfiltered_endpoint_calls(src) {
            found.entry((file.clone(), func)).or_default().push(line);
        }
    }

    let expected: std::collections::BTreeSet<(String, String)> = UNFILTERED_ENDPOINT_READERS
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), (*n).to_string()))
        .collect();
    let actual: std::collections::BTreeSet<(String, String)> = found.keys().cloned().collect();

    let new: Vec<String> = actual
        .difference(&expected)
        .map(|k| format!("  (\"{}\", \"{}\") — lines {:?}", k.0, k.1, found[k]))
        .collect();
    let stale: Vec<String> = expected
        .difference(&actual)
        .map(|k| format!("  (\"{}\", \"{}\")", k.0, k.1))
        .collect();
    assert!(
        new.is_empty() && stale.is_empty(),
        "\n\nNew callers of the UNFILTERED EdgeRepository::get_by_source/get_by_target:\n{}\n\n\
         Stale entries (the call was converted or removed — delete the entry):\n{}\n\n\
         These reads return RETRACTED edges (anything removed with delete_edge). A read \
         that displays or walks the graph wants get_by_source_in_force / \
         get_by_target_in_force; a structural reader (lineage, provenance) belongs in \
         UNFILTERED_ENDPOINT_READERS with its reason. See \
         docs/architecture/edge-retraction-tiers.md.\n",
        new.join("\n"),
        stale.join("\n")
    );
}

#[test]
fn the_endpoint_call_scanner_is_not_vacuous() {
    let got = unfiltered_endpoint_calls(
        "async fn walk() {\n    let a = EdgeRepository::get_by_source(p, v, id, \"claim\");\n    \
         let b = epigraph_db::EdgeRepository::get_by_target(p, v, id, \"claim\");\n    \
         let c = EdgeRepository::get_by_source_in_force(p, v, id, \"claim\");\n}\n\
         // EdgeRepository::get_by_source( in a comment\n\
         #[cfg(test)]\nmod tests { fn t() { EdgeRepository::get_by_target(p, v, id, \"claim\"); } }\n",
    );
    assert_eq!(
        got,
        vec![(2, "walk".to_string()), (3, "walk".to_string())],
        "both unfiltered calls are found, the in-force call, the comment and the \
         test module are not"
    );
}
