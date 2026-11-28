//! Ratchets: the belief-mode flags have ONE reader,
//! `crates/epigraph-engine/src/belief_modes.rs`, and its module doc's "acted
//! on in this build" table says which flags this build acts on.
//!
//! - Backlog 820c15f1: four types parsed the same variables with their own
//!   `OnceLock` readers: `atom_items::{AtomFoldMode, CompoundSourceEdges}`,
//!   `belief_view::CompoundBeliefMode` and the API's `state::BpApply`. They
//!   could disagree with what `/health` reported.
//!   [`no_belief_flag_is_read_outside_belief_modes`] fails on any production
//!   source outside the module that names a flag's variable as a string
//!   literal, or reads the environment through a flag's `ENV` constant.
//! - Backlog fcc33cb1: the table said `bp_apply`, `compound_belief` and
//!   `compound_source_edges` were not acted on, when the code did act on them.
//! - Backlog 9a8f3bff: that check was a text scan for a field read off
//!   `current()` or a `let` binding of it, so a file that only forwarded the
//!   struct was credited when it reused a binding name, and a read through a
//!   renamed binding or a helper's parameter was missed. `BeliefModes`'s
//!   fields are now private to `belief_modes`, so outside it the ONE way to
//!   act on a flag is its accessor (`.atom_fold()`, ...; the compiler, not
//!   this scan, rules out every other way). A call of the accessor is what
//!   is measured, wherever the struct came from.
//!   [`the_acted_on_register_and_table_match_the_accessor_calls`] fails when
//!   a production file calls a flag's accessor without being listed for it
//!   in [`ACTED_ON_BY`] (or is listed and no longer calls it), and when the
//!   flag's table row says "no" while some file acts on it (or the reverse).
//!   [`the_modes_fields_are_private`] pins the privacy the scan relies on,
//!   and [`the_reader_adds_no_other_way_to_act_on_a_flag`] pins the reader
//!   itself: `BeliefModes`'s methods ([`MODE_METHODS`]), a field read only by
//!   its accessor and `fields()`, and no accessor called there (a helper in
//!   the reader that acts on a flag would hide the files that call it).
//!
//! The scan is plain text over every `crates/*/src` file, with comments and
//! `#[cfg(test)] mod` blocks excluded (`support/rust_sources.rs`).
//!
//! Known limits: a value reached through the REPORT forms (`fields()`,
//! `skew()`, `summary()`, the serde form on `/health`) is not an accessor
//! call and is not seen; those exist to report a mode, and acting on one
//! through them would be a review finding. An unrelated method that shares
//! an accessor's name (`.inference()`) would be counted, and would show as a
//! file not listed for that flag. A path call is seen through `BeliefModes`,
//! a file-local alias (`use … as M`, `type M = …`) or a qualified `<…>::`;
//! an alias declared in another module is not.

#[path = "support/rust_sources.rs"]
mod rust_sources;

use epigraph_engine::belief_modes::BeliefModes;
use rust_sources::{production_code, production_sources, workspace_root};
use std::collections::BTreeSet;

/// The one module that parses the flags.
const READER: &str = "crates/epigraph-engine/src/belief_modes.rs";

/// The type names whose `ENV` constant names a flag's variable, past and
/// present spellings.
const FLAG_TYPES: &[&str] = &[
    "AtomFold",
    "AtomFoldMode",
    "CompoundBelief",
    "CompoundBeliefMode",
    "CompoundWriteGuard",
    "ContradictCompoundGuard",
    "CompoundSourceEdges",
    "AtomCacheMode",
    "Inference",
    "BpApply",
];

/// `src` with every whitespace character removed, so a call that rustfmt
/// split over lines still matches one needle.
fn squeezed(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The places in one file's production code that parse a flag themselves.
fn flag_parses(src: &str) -> Vec<String> {
    let code = production_code(src);
    let mut hits = Vec::new();
    for field in BeliefModes::default().fields() {
        let literal = format!("\"{}\"", field.env);
        for (n, line) in code.lines().enumerate() {
            if line.contains(&literal) {
                hits.push(format!("line {}: {}", n + 1, line.trim()));
            }
        }
    }
    let flat = squeezed(&code);
    for read in ["env::var(", "env::var_os("] {
        for (i, _) in flat.match_indices(read) {
            let arg: String = flat[i + read.len()..]
                .chars()
                .take_while(|c| *c != ')')
                .collect();
            let through_a_flag = FLAG_TYPES
                .iter()
                .any(|ty| arg == format!("{ty}::ENV") || arg.ends_with(&format!("::{ty}::ENV")));
            if through_a_flag || arg.ends_with("BP_APPLY_ENV") {
                hits.push(format!("reads the environment through {arg}"));
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// `code` as tokens: identifiers (and numbers), `::`, and every other
/// non-whitespace character on its own, so a read that rustfmt split over
/// lines is the same token run as one written on a single line.
fn tokens(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = code.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c.is_alphanumeric() || c == '_' {
            let mut word = c.to_string();
            while let Some(&n) = chars.peek().filter(|n| n.is_alphanumeric() || **n == '_') {
                word.push(n);
                chars.next();
            }
            out.push(word);
        } else if c == ':' && chars.peek() == Some(&':') {
            chars.next();
            out.push("::".to_string());
        } else {
            out.push(c.to_string());
        }
    }
    out
}

/// Every production file that acts on each flag, by report key: exactly the
/// files that call the flag's accessor (see [`acts_on_flag`]). A flag no file
/// acts on has an empty list, and its table row must say "no". Sorted.
const ACTED_ON_BY: &[(&str, &[&str])] = &[
    (
        "atom_fold",
        &[
            // The CLI wave bins' refusal of a fold their writers lack.
            "crates/epigraph-cli/src/belief_mode_check.rs",
            // The single atom-cache writer's settings.
            "crates/epigraph-engine/src/edge_factor.rs",
        ],
    ),
    (
        "compound_belief",
        &["crates/epigraph-engine/src/belief_view.rs"],
    ),
    (
        "compound_write_guard",
        &[
            // Each AppState constructor takes the process's guard mode
            // (`POST /api/v1/frames/:id/evidence`, `POST .../assess`).
            "crates/epigraph-api/src/state.rs",
            // Each server constructor, for MCP `submit_ds_evidence`.
            "crates/epigraph-mcp/src/server.rs",
        ],
    ),
    (
        "contradict_compound_guard",
        &[
            // Each server constructor, for MCP `link_epistemic`.
            "crates/epigraph-mcp/src/server.rs",
        ],
    ),
    (
        "compound_source_edges",
        &[
            "crates/epigraph-cli/src/shadow_report.rs",
            "crates/epigraph-engine/src/atom_items.rs",
            "crates/epigraph-engine/src/bba_retract.rs",
            "crates/epigraph-engine/src/edge_factor.rs",
        ],
    ),
    ("atom_cache_mode", &[]),
    ("inference", &[]),
    ("bp_apply", &["crates/epigraph-api/src/bin/server.rs"]),
];

/// The names one file gives `BeliefModes` besides its own: `use …::BeliefModes
/// as M` and `type M = …BeliefModes;`.
fn mode_aliases(toks: &[String]) -> Vec<String> {
    let at = |i: usize| toks.get(i).map(String::as_str);
    let mut out = Vec::new();
    for i in 0..toks.len() {
        if at(i) == Some("BeliefModes") && at(i + 1) == Some("as") {
            if let Some(alias) = at(i + 2) {
                out.push(alias.to_string());
            }
        }
        if at(i) == Some("type") && at(i + 2) == Some("=") {
            let end = (i + 3..toks.len()).find(|&j| at(j) == Some(";"));
            if end.is_some_and(|e| at(e - 1) == Some("BeliefModes")) {
                out.push(toks[i + 1].clone());
            }
        }
    }
    out
}

/// Whether one file's production code acts on the flag reported as `key`:
/// it calls the flag's accessor, as a method (`<expr>.<key>()`, whatever the
/// receiver is called or wherever it came from) or as a path
/// (`BeliefModes::<key>`, through a file-local alias `M::<key>`, or
/// qualified `<BeliefModes>::<key>` / `<T as …>::<key>`). Passing the struct
/// on is not acting on it.
fn acts_on_flag(src: &str, key: &str) -> bool {
    let toks = tokens(&production_code(src));
    let aliases = mode_aliases(&toks);
    let at = |i: usize| toks.get(i).map(String::as_str);
    (0..toks.len()).any(|i| {
        let method = at(i) == Some(".")
            && at(i + 1) == Some(key)
            && at(i + 2) == Some("(")
            && at(i + 3) == Some(")");
        let owner =
            at(i).is_some_and(|t| t == "BeliefModes" || t == ">" || aliases.iter().any(|a| a == t));
        let path = owner && at(i + 1) == Some("::") && at(i + 2) == Some(key);
        method || path
    })
}

/// Every method of `BeliefModes`'s inherent impls in the reader: the eight
/// accessors, the constructors and the report forms. Pinned because a method
/// added there (`fn bp_writes(&self) -> bool { self.bp_apply == BpApply::On
/// }`) is a way to act on a flag that calls no accessor, so the scan of the
/// other files would not see it. Sorted.
const MODE_METHODS: &[&str] = &[
    "atom_cache_mode",
    "atom_fold",
    "bp_apply",
    "compound_belief",
    "compound_source_edges",
    "compound_write_guard",
    "contradict_compound_guard",
    "fields",
    "from_env",
    "from_lookup",
    "inference",
    "skew",
    "summary",
];

/// `code` with the contents of its string literals blanked, for brace
/// matching (`format!("{}={}")` holds braces).
fn without_strings(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut in_str = false;
    let mut escaped = false;
    for c in code.chars() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
                out.push(c);
                continue;
            }
            out.push(if c == '\n' { c } else { ' ' });
        } else {
            in_str = c == '"';
            out.push(c);
        }
    }
    out
}

/// The fns declared directly in every `impl BeliefModes { … }` of `src` (the
/// reader's source), sorted.
fn mode_methods(src: &str) -> Vec<String> {
    let toks = tokens(&without_strings(&production_code(src)));
    let at = |i: usize| toks.get(i).map(String::as_str);
    let mut out = Vec::new();
    for i in 0..toks.len() {
        if !(at(i) == Some("impl") && at(i + 1) == Some("BeliefModes") && at(i + 2) == Some("{")) {
            continue;
        }
        let mut depth = 0usize;
        for j in i + 2..toks.len() {
            match at(j) {
                Some("{") => depth += 1,
                Some("}") => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Some("fn") if depth == 1 => {
                    if let Some(name) = at(j + 1) {
                        out.push(name.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    out.sort();
    out
}

/// `(fn, key)` for every read of a flag's field in `src` (the reader's
/// source) outside a test: `.<key>` that is neither a call (`.<key>(`) nor
/// an assignment (`.<key> = `), attributed to the nearest `fn` before it.
fn flag_field_reads(src: &str) -> BTreeSet<(String, String)> {
    let toks = tokens(&without_strings(&production_code(src)));
    let at = |i: usize| toks.get(i).map(String::as_str);
    let keys: Vec<&str> = BeliefModes::default()
        .fields()
        .iter()
        .map(|f| f.key)
        .collect();
    let mut current = String::from("<module>");
    let mut out = BTreeSet::new();
    for i in 0..toks.len() {
        if at(i) == Some("fn") {
            // `fn name`, not a `fn(T) -> U` pointer type.
            if let Some(name) =
                at(i + 1).filter(|n| n.starts_with(|c: char| c.is_alphabetic() || c == '_'))
            {
                current = name.to_string();
            }
        }
        let Some(key) = at(i + 1).filter(|k| at(i) == Some(".") && keys.contains(k)) else {
            continue;
        };
        let call = at(i + 2) == Some("(");
        let assign = at(i + 2) == Some("=") && at(i + 3) != Some("=");
        if !call && !assign {
            out.insert((current.clone(), key.to_string()));
        }
    }
    out
}

/// The reader's own ways to act on a flag, one line per finding: a method of
/// `BeliefModes` not in [`MODE_METHODS`] (or a pinned one gone), a flag field
/// read anywhere but its own accessor and `fields()`, and an accessor called
/// in the reader itself (a free helper there would hide the acting file).
fn reader_findings(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let methods = mode_methods(src);
    if methods != MODE_METHODS {
        out.push(format!(
            "BeliefModes's methods are {methods:?}, MODE_METHODS pins {MODE_METHODS:?}"
        ));
    }
    let mut allowed = BTreeSet::new();
    for f in BeliefModes::default().fields() {
        allowed.insert((f.key.to_string(), f.key.to_string()));
        allowed.insert(("fields".to_string(), f.key.to_string()));
        if acts_on_flag(src, f.key) {
            out.push(format!("{READER} calls the {} accessor itself", f.key));
        }
    }
    for (unit, key) in flag_field_reads(src) {
        if !allowed.contains(&(unit.clone(), key.clone())) {
            out.push(format!("{READER}::{unit} reads the {key} field"));
        }
    }
    out
}

/// The `pub` fields of `BeliefModes` in `src` (the reader's source).
fn public_mode_fields(src: &str) -> Vec<String> {
    let code = production_code(src);
    let start = code
        .find("pub struct BeliefModes {")
        .expect("belief_modes.rs defines `pub struct BeliefModes {`");
    let body = &code[start + "pub struct BeliefModes {".len()..];
    let body = &body[..body.find('}').expect("the struct body closes")];
    body.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("pub ") || l.starts_with("pub("))
        .map(str::to_string)
        .collect()
}

/// The verdict over `sources` (production files other than the reader),
/// the `register` and the doc `table`, one line per finding.
fn acted_on_findings(
    sources: &[(String, String)],
    register: &[(&str, &[&str])],
    table: &[(String, String)],
) -> Vec<String> {
    let mut out = Vec::new();
    let fields = BeliefModes::default().fields();
    for (key, _) in register {
        if !fields.iter().any(|f| f.key == *key) {
            out.push(format!("{key}: registered, but no flag has that key"));
        }
    }
    for field in fields {
        let acting: Vec<&str> = sources
            .iter()
            .filter(|(_, src)| acts_on_flag(src, field.key))
            .map(|(file, _)| file.as_str())
            .collect();
        match register.iter().find(|(key, _)| *key == field.key) {
            None => out.push(format!("{}: no ACTED_ON_BY entry", field.key)),
            Some((_, listed)) => {
                for file in &acting {
                    if !listed.contains(file) {
                        out.push(format!(
                            "{}: {file} calls its accessor but is not listed in ACTED_ON_BY",
                            field.key
                        ));
                    }
                }
                for file in *listed {
                    if !acting.contains(file) {
                        out.push(format!(
                            "{}: {file} is listed in ACTED_ON_BY but no longer calls its accessor",
                            field.key
                        ));
                    }
                }
            }
        }
        match table.iter().find(|(env, _)| env == field.env) {
            None => out.push(format!("{}: no row in the table", field.env)),
            Some((_, acted)) if !acting.is_empty() && says_no(acted) => out.push(format!(
                "{}: the table says {acted:?}, but {} act on it",
                field.env,
                acting.join(", ")
            )),
            Some((_, acted)) if acting.is_empty() && !says_no(acted) => out.push(format!(
                "{}: the table says {acted:?}, but no production code acts on it",
                field.env
            )),
            Some(_) => {}
        }
    }
    out
}

/// Whether a table cell says the flag is not acted on.
fn says_no(acted: &str) -> bool {
    acted == "no" || acted.starts_with("no:")
}

/// The table rows of `belief_modes.rs`'s module doc: variable -> the "acted
/// on in this build" cell.
fn acted_on_table(src: &str) -> Vec<(String, String)> {
    src.lines()
        .filter_map(|l| l.strip_prefix("//! | `EPIGRAPH_"))
        .map(|row| {
            let cells: Vec<&str> = row.split(" | ").collect();
            let env = format!("EPIGRAPH_{}", cells[0].trim_end_matches('`'));
            let acted = cells
                .last()
                .expect("a table row has cells")
                .trim_end_matches('|')
                .trim()
                .to_string();
            (env, acted)
        })
        .collect()
}

#[test]
fn no_belief_flag_is_read_outside_belief_modes() {
    let root = workspace_root();
    let offenders: Vec<String> = production_sources(&root)
        .into_iter()
        .filter(|(file, _)| file != READER)
        .flat_map(|(file, src)| {
            flag_parses(&src)
                .into_iter()
                .map(move |hit| format!("{file}: {hit}"))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "a belief-mode flag is read outside {READER}; read it from \
         `belief_modes::current()` instead, so every reader and `/health` see the same \
         value:\n{}",
        offenders.join("\n")
    );
}

/// `(path, text)` per file, or `(variable, acted-on cell)` per table row.
type Pairs = Vec<(String, String)>;

/// The live tree: production sources other than the reader, its table.
fn live() -> (Pairs, Pairs) {
    let root = workspace_root();
    let doc = std::fs::read_to_string(root.join(READER)).expect("read belief_modes.rs");
    let sources = production_sources(&root)
        .into_iter()
        .filter(|(file, _)| file != READER)
        .collect();
    (sources, acted_on_table(&doc))
}

#[test]
fn the_acted_on_register_and_table_match_the_accessor_calls() {
    let (sources, table) = live();
    assert_eq!(
        table.len(),
        BeliefModes::default().fields().len(),
        "one table row per flag: {table:?}"
    );
    let stale = acted_on_findings(&sources, ACTED_ON_BY, &table);
    assert!(
        stale.is_empty(),
        "ACTED_ON_BY or the \"acted on in this build\" table in {READER} is stale:\n{}",
        stale.join("\n")
    );
}

/// The scan counts accessor calls only because nothing outside the module
/// can read a field: a `pub` field would reopen the untracked way to act on
/// a flag.
#[test]
fn the_modes_fields_are_private() {
    let doc = std::fs::read_to_string(workspace_root().join(READER)).expect("read");
    let public = public_mode_fields(&doc);
    assert!(
        public.is_empty(),
        "BeliefModes has pub fields {public:?}; keep them private to {READER} and act on \
         a flag through its accessor"
    );
    // MUTATION PROBE: the pin sees a field made `pub` (or `pub(crate)`).
    for vis in ["pub", "pub(crate)"] {
        let mutated = doc.replacen(
            "    bp_apply: BpApply,",
            &format!("    {vis} bp_apply: BpApply,"),
            1,
        );
        assert_ne!(mutated, doc, "the probe found the field");
        assert_eq!(public_mode_fields(&mutated).len(), 1, "{vis}");
    }
}

/// The reader adds no way to act on a flag besides the eight accessors: its
/// `BeliefModes` methods are pinned, a flag's field is read only by its
/// accessor and `fields()`, and it calls no accessor itself.
#[test]
fn the_reader_adds_no_other_way_to_act_on_a_flag() {
    let doc = std::fs::read_to_string(workspace_root().join(READER)).expect("read");
    let f = reader_findings(&doc);
    assert!(f.is_empty(), "{READER}:\n{}", f.join("\n"));

    // MUTATION PROBES: a new method reading a field; a free helper reading
    // a field; a free helper calling an accessor. Each must be reported.
    let anchor = "    /// The modes the process environment describes, read now.";
    assert!(doc.contains(anchor), "the probe's anchor moved");
    let method = doc.replacen(
        anchor,
        &format!(
            "    pub fn bp_writes(&self) -> bool {{\n        self.bp_apply == BpApply::On\n    }}\n\n{anchor}"
        ),
        1,
    );
    let f = reader_findings(&method);
    assert!(f.iter().any(|l| l.contains("methods are")), "{f:?}");
    assert!(
        f.iter()
            .any(|l| l.ends_with("::bp_writes reads the bp_apply field")),
        "{f:?}"
    );
    let free = format!(
        "{doc}\npub fn bp_writes() -> bool {{\n    current().bp_apply == BpApply::On\n}}\n"
    );
    let f = reader_findings(&free);
    assert!(
        f.iter()
            .any(|l| l.ends_with("::bp_writes reads the bp_apply field")),
        "{f:?}"
    );
    let via_accessor = format!(
        "{doc}\npub fn infers() -> bool {{\n    current().inference() == Inference::On\n}}\n"
    );
    let f = reader_findings(&via_accessor);
    assert!(
        f.iter()
            .any(|l| l.ends_with("calls the inference accessor itself")),
        "{f:?}"
    );
}

/// MUTATION PROBES on the live tree plus one scratch file: a file acting on
/// a flag it is not listed for is a finding, and so is the table row saying
/// "no"; dropping or adding a listed file is a finding; forwarding the
/// struct is not acting on it.
#[test]
fn the_register_check_is_not_vacuous() {
    let (sources, table) = live();
    assert!(acted_on_findings(&sources, ACTED_ON_BY, &table).is_empty());
    let scratch = "crates/epigraph-api/src/routes/scratch_modes.rs";
    let with = |src: &str| {
        let mut v = sources.clone();
        v.push((scratch.to_string(), src.to_string()));
        v
    };

    // A helper acting on `inference` through a renamed parameter, reached
    // only by forwarding the struct: the file is credited, as unlisted, and
    // the table's "no" is stale.
    let acting = with(
        "use epigraph_engine::belief_modes::{self, BeliefModes, Inference};\n\
         fn caller() -> bool { helper(belief_modes::current()) }\n\
         fn helper(cfg: &BeliefModes) -> bool {\n    let renamed = cfg;\n    renamed\n        .inference()\n        == Inference::On\n}\n",
    );
    let f = acted_on_findings(&acting, ACTED_ON_BY, &table);
    assert!(
        f.iter()
            .any(|l| l.contains(scratch) && l.contains("not listed")),
        "{f:?}"
    );
    assert!(
        f.iter()
            .any(|l| l.starts_with("EPIGRAPH_INFERENCE: the table says")),
        "{f:?}"
    );

    // Forwarding alone is not acting.
    let forwarding = with(
        "use epigraph_engine::belief_modes;\n\
         fn caller() { report(belief_modes::current()); let m = *belief_modes::current(); report(&m); }\n",
    );
    assert!(acted_on_findings(&forwarding, ACTED_ON_BY, &table).is_empty());

    // A listed file dropped from, or an extra file added to, a flag's list.
    let dropped: Vec<(&str, &[&str])> = ACTED_ON_BY
        .iter()
        .map(|(k, files)| {
            if *k == "bp_apply" {
                (*k, &[][..])
            } else {
                (*k, *files)
            }
        })
        .collect();
    let f = acted_on_findings(&sources, &dropped, &table);
    assert!(
        f.iter()
            .any(|l| l.contains("bin/server.rs calls its accessor but is not listed")),
        "{f:?}"
    );
    let extra_files: &[&str] = &[
        "crates/epigraph-api/src/bin/server.rs",
        "crates/epigraph-api/src/routes/health.rs",
    ];
    let extra: Vec<(&str, &[&str])> = ACTED_ON_BY
        .iter()
        .map(|(k, files)| {
            if *k == "bp_apply" {
                (*k, extra_files)
            } else {
                (*k, *files)
            }
        })
        .collect();
    let f = acted_on_findings(&sources, &extra, &table);
    assert!(
        f.iter()
            .any(|l| l.contains("routes/health.rs is listed in ACTED_ON_BY but no longer")),
        "{f:?}"
    );
}

/// The scanners themselves, on known text: a parse and an accessor call are
/// hits; the same text in a comment or a `#[cfg(test)] mod` is not.
#[test]
fn the_scanners_see_parses_and_accessor_calls_and_skip_comments_and_tests() {
    let parse = r#"
pub const ENV: &str = "EPIGRAPH_ATOM_FOLD";
fn on() -> bool { std::env::var(BpApply::ENV).is_ok() }
fn on2() -> bool { std::env::var(crate::belief_modes::Inference::ENV).is_ok() }
"#;
    let hits = flag_parses(parse);
    assert_eq!(hits.len(), 3, "{hits:?}");

    let quiet = r#"
// "EPIGRAPH_ATOM_FOLD" in a comment, std::env::var(BpApply::ENV) too.
#[cfg(test)]
mod tests {
    const X: &str = "EPIGRAPH_BP_APPLY";
    fn f() { let _ = crate::belief_modes::current().bp_apply(); }
}
"#;
    assert!(flag_parses(quiet).is_empty());
    assert!(!acts_on_flag(quiet, "bp_apply"));

    // An accessor call split over lines, off `current()` directly.
    let call =
        "fn f() -> bool {\n    crate::belief_modes::current()\n        .bp_apply()\n        == On\n}\n";
    assert!(acts_on_flag(call, "bp_apply"));
    assert!(!acts_on_flag(call, "atom_fold"));
    // Off any receiver: a renamed binding, a parameter, a copy.
    assert!(acts_on_flag(
        "fn g(cfg: &BeliefModes) -> bool { let c = cfg; c.atom_fold() == AtomFold::Aef }",
        "atom_fold"
    ));
    assert!(acts_on_flag(
        "let mut modes = *atom_items::modes(); let x = modes.compound_source_edges();",
        "compound_source_edges"
    ));
    // As a path: by name, through an alias, or qualified.
    assert!(acts_on_flag(
        "let read: fn(&BeliefModes) -> BpApply = BeliefModes::bp_apply;",
        "bp_apply"
    ));
    assert!(acts_on_flag(
        "use epigraph_engine::belief_modes::BeliefModes as M;\nfn f(m: &M) -> bool { M::bp_apply(m) == On }",
        "bp_apply"
    ));
    assert!(acts_on_flag(
        "type Modes = epigraph_engine::belief_modes::BeliefModes;\nfn f(m: &Modes) -> bool { Modes::inference(m) == On }",
        "inference"
    ));
    assert!(acts_on_flag(
        "fn f(m: &BeliefModes) -> bool { <BeliefModes>::bp_apply(m) == On }",
        "bp_apply"
    ));
    // Not: forwarding the struct, a longer name, another fn of the same
    // name taking arguments (`atom_items::atom_fold(rows)`), or a field of
    // another type.
    assert!(!acts_on_flag(
        "fn f() { helper(belief_modes::current()); }",
        "bp_apply"
    ));
    assert!(!acts_on_flag("let x = m.atom_fold_x();", "atom_fold"));
    assert!(!acts_on_flag(
        "let i = atom_items::atom_fold(&rows); let j = x.atom_fold(&rows);",
        "atom_fold"
    ));
    assert!(!acts_on_flag(
        "let x = settings.compound_source_edges;",
        "compound_source_edges"
    ));

    let table = acted_on_table(
        "//! | `EPIGRAPH_BP_APPLY` | `off`, `on` | `off` | no: still writes |\n\
         //! | `EPIGRAPH_INFERENCE` | `off` | `off` | yes |",
    );
    assert_eq!(
        table,
        vec![
            (
                "EPIGRAPH_BP_APPLY".to_string(),
                "no: still writes".to_string()
            ),
            ("EPIGRAPH_INFERENCE".to_string(), "yes".to_string()),
        ]
    );
}
