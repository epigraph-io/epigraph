//! PR-15: every background writer builds its pool through the maintenance
//! constructor, or is exempt for a stated reason.
//!
//! # Why this lint is keyed on POOL CONSTRUCTION and not on `DATABASE_URL`
//!
//! The plan (§4.13) specifies this file as *"fails if a file … reads
//! `DATABASE_URL` without a `MAINTENANCE_DATABASE_URL` fallback"*. That axis is
//! wrong, and wrong in the direction that certifies a broken tree as fixed.
//! Two measured reasons:
//!
//! 1. **A binary can be broken without ever reading `DATABASE_URL`.**
//!    `compare_routes.rs` builds four pools from a hardcoded loopback string.
//!    `embed_backfill`, `ingest_document`, `prune_recall_events`,
//!    `bootstrap_clients` and `dekg` read the DSN through a clap
//!    `#[arg(long, env = "DATABASE_URL")]` attribute, which no
//!    `env::var("DATABASE_URL")` grep matches. A DSN-keyed lint passes all six
//!    without reading them.
//! 2. **A binary can add the fallback and still be broken.** Before PR-15,
//!    eleven bins took a bypass `Viewer` from a `ScopedPool` and then ran every
//!    query on a *second*, raw pool — `db_connect()` or
//!    `create_pool(&cli.database_url)`. A bypass viewer emits no predicate, so
//!    under FORCE the connection is what filters and the viewer does not save
//!    it. Adding a DSN fallback to such a file changes nothing about which pool
//!    the statements run on.
//!
//! What determines whether a statement is filtered is the pool it RUNS on, and
//! for a file that builds its own pool those are the same thing. That is the
//! scope of this lint, stated precisely so nobody reads a green run as more
//! than it is: **it proves a scanned file builds no unmaintained pool.** It
//! does not prove the process is safe under FORCE — see "Known limits" below
//! for the shape it cannot see. Any pool constructed in a background process by
//! a spelling other than the maintenance constructor is a finding, **including
//! a second construction in a file that also uses the maintenance
//! constructor** — which is precisely how a partial conversion reads green.
//!
//! # Two places, or it is not a control
//!
//! Following `visibility_lint.rs`'s convention: an exemption needs both an
//! in-file `MAINTENANCE-DSN-EXEMPT:` marker explaining the specific site, and
//! an entry in [`EXEMPT`] carrying the reason. The set is asserted in both
//! directions, so a file that is fixed but left in the table fails too — an
//! exemption list nobody prunes is a comment style, not a ratchet.
//!
//! # Known limits, so nobody over-claims
//!
//! * Comment lines are skipped by prefix, so a banned spelling appended after
//!   code on the same line would be missed. Every occurrence in this tree is
//!   either its own statement or a whole-line comment.
//! * This proves a pool was built by the right constructor. It does not prove
//!   the DSN that constructor resolved is privileged — that is
//!   `epigraph_db::assert_maintenance_privilege`'s job, at run time, and it is
//!   deliberately conditioned on row security being active on some protected
//!   table (`relrowsecurity OR relforcerowsecurity`) rather than asserted
//!   unconditionally (see `maintenance_verdict`).
//! * **The Rust scan is per-CONSTRUCTION; the Python scan is per-FILE.** That
//!   asymmetry is real and is stated rather than papered over: a script with two
//!   `psycopg2.connect` sites, one converted and one not, reads green here —
//!   the same partial-conversion shape the Rust half exists to catch.
//!   `scripts/run_assessment_worker.py` is the one file in the tree with two
//!   connections, and its split is deliberate and documented at the site (a
//!   read-only role for SELECTs, the maintenance DSN for the UPDATEs). Closing
//!   the asymmetry properly needs a Python AST pass, not a substring scan.
//! * `crates/epigraph-api/src/routes/` and `crates/epigraph-mcp/src/tools/` are
//!   NOT scanned. Those serve callers and are governed by
//!   `no_bypass_in_handlers.rs`; extending this lint's roots there would
//!   confuse "must be privileged" with "must never be privileged".
//! * **The hybrid shape with an INJECTED pool is outside this lint's reach.** A
//!   file that constructs nothing, mints a bypass viewer, and runs the
//!   statement on a `PgPool` it was handed has the same defect and is invisible
//!   here, because there is no construction to key on. Two files in this tree
//!   have that shape and neither is live:
//!   `epigraph-api/src/routes/claims.rs::find_claims_needing_embeddings` HAD it
//!   and PR-15 fixed it (the statement now runs on the leased
//!   `MaintenanceConn`, which is why the repo method takes an executor); and
//!   `epigraph-jobs/src/db_reputation_service.rs::get_claim_outcomes` still has
//!   it — it mints a viewer from `self.scoped` and queries `self.pool` — but has
//!   no production constructor. A second lint keyed on that shape, with those
//!   two files as its calibration cases, is recorded as
//!   `D-PR17-hybrid-shape-lint` in `docs/tenancy/progress.json`. Until it
//!   exists, a green run here means "no scanned file builds an unmaintained
//!   pool", not "no scanned file spends a bypass on an unprivileged
//!   connection".

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Pool-construction spellings that are NOT the maintenance constructor.
///
/// Four Rust spellings existed in this tree before PR-15 and all four are here,
/// including `db_connect()` — which PR-15 deleted, and which is listed so it
/// cannot quietly come back as the eleven-bin hybrid it used to be.
const BANNED_CONSTRUCTIONS: &[&str] = &[
    "PgPoolOptions::new(",
    // No trailing paren: this must also catch `connect_with`, `connect_lazy`
    // and `connect_lazy_with`, which nothing in this tree uses today and which
    // are the obvious spellings a future edit reaches for. Neither
    // `MaintenancePool::connect` nor `ScopedPool::connect` contains this
    // substring, so the broadening costs no false positives.
    "PgPool::connect",
    "create_pool(",
    "create_pool_with_options(",
    "create_pool_from_options(",
    "db_connect(",
];

/// The maintenance constructors. A file using one of these is converted; a
/// converted file with a banned construction is a PARTIAL conversion, which is
/// reported with its own message because it is the failure mode most likely to
/// be mistaken for success.
const MAINTENANCE_CONSTRUCTIONS: &[&str] = &[
    "MaintenancePool::connect",
    "ScopedPool::connect",
    "maintenance_database_url",
];

const MARKER: &str = "MAINTENANCE-DSN-EXEMPT:";

/// Repo-relative files allowed to build a pool some other way, each with the
/// reason. Asserted as an exact set, both directions.
///
/// PR-15's acceptance requires a reason per entry, not just names — an
/// exemption whose justification lives only in a reviewer's memory is
/// indistinguishable from an oversight six months later.
const EXEMPT: &[(&str, &str)] = &[
    (
        "crates/epigraph-cli/src/bin/compare_routes.rs",
        "Dev benchmark. Builds four pools from a hardcoded loopback base against \
         epigraph_route_a/_b/_c — throwaway comparison databases that do not exist in any \
         deployment, carry no tenancy declarations and are never FORCEd. Read-only; never \
         reads DATABASE_URL at all, so a DSN-keyed lint would have passed it silently.",
    ),
    (
        "crates/epigraph-api/src/bin/epigraph-migrate.rs",
        "PR-16 DONE, and the exemption STAYS. The migrator now reads MIGRATION_DATABASE_URL \
         (falling back to DATABASE_URL with a WARN), and .github/workflows/ci.yml sets it. \
         What it still does NOT do is build its pool through a maintenance constructor, and \
         it must not: applying migrations needs DDL privilege on every tier-A table, which is \
         a strictly stronger role than epigraph_maintenance -- that role holds \
         SELECT/INSERT/UPDATE and no DDL at all (migration 070's grant block). This lint is \
         keyed on pool construction, not on the DSN variable, so the PR-16 change is invisible \
         to it by design; the entry is what records that the remaining PgPool::connect is \
         deliberate.",
    ),
    (
        "crates/epigraph-mcp/src/main.rs",
        "Serves callers, and its three maintenance tools are DEFERRED to PR-17 rather than \
         half-wired here. EpiGraphMcpFull::with_scoped_pool has no callers, so those tools \
         currently fail CLOSED with a clear error. Attaching a ScopedPool without also moving \
         the three tools' queries onto the maintenance connection would trade that hard error \
         for a silent no-op under FORCE — the exact hybrid this lint exists to catch. See \
         crates/epigraph-mcp/src/maintenance.rs.",
    ),
    (
        "scripts/subcluster_outliers.py",
        "Read-only by design on the epigraph_ro role; its docstring states 'script never \
         writes' as a property callers rely on. Threading MAINTENANCE_DATABASE_URL in would \
         silently escalate it to a writable role whenever a sibling job exports that variable.",
    ),
    (
        "scripts/lib/tiered_enrichment.py",
        "Single-claim debug lookup by operator-supplied UUID on the read-only role. Not a \
         corpus enumeration and not a write path, so FORCE has nothing to truncate here.",
    ),
];

/// Repo root. `CARGO_MANIFEST_DIR` is `crates/epigraph-db`; two parents up is
/// the workspace root. Same derivation as `no_bypass_in_handlers.rs`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two ancestors")
        .to_path_buf()
}

/// Directories and files scanned, all repo-relative.
///
/// These are the processes that run with no caller: CLI binaries, the job
/// crate, the API and MCP entry points, and the operator scripts.
const RUST_ROOTS: &[&str] = &[
    "crates/epigraph-cli/src/bin",
    "crates/epigraph-jobs/src",
    "crates/epigraph-api/src/bin",
    "crates/epigraph-mcp/src/main.rs",
];

fn collect(root: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, ext, out);
        } else if p.extension().is_some_and(|x| x == ext) {
            out.push(p);
        }
    }
}

/// Lines that are not whole-line comments.
fn code_lines(src: &str) -> impl Iterator<Item = (usize, &str)> {
    src.lines().enumerate().filter(|(_, l)| {
        let t = l.trim_start();
        !(t.starts_with("//") || t.starts_with("#!") || t.starts_with('#'))
    })
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Does this script consult the maintenance DSN in CODE (not in a comment)?
fn python_consults_maintenance_dsn(src: &str) -> bool {
    code_lines(src)
        .any(|(_, l)| l.contains("MAINTENANCE_DATABASE_URL") || l.contains("maintenance_dsn"))
}

fn exempt_names() -> BTreeSet<&'static str> {
    EXEMPT.iter().map(|(f, _)| *f).collect()
}

/// The scan is not vacuous: it must actually find the files it claims to read.
#[test]
fn the_scan_roots_resolve_and_are_not_empty() {
    let root = repo_root();
    for r in RUST_ROOTS {
        let p = root.join(r);
        assert!(
            p.exists(),
            "scan root {r} does not exist at {}",
            p.display()
        );
    }
    let mut files = Vec::new();
    for r in RUST_ROOTS {
        collect(&root.join(r), "rs", &mut files);
    }
    assert!(
        files.len() > 20,
        "expected the CLI bin directory alone to contribute >20 files; found {}. \
         A silently-empty scan is how this lint would certify a tree it never read.",
        files.len()
    );

    let mut scripts = Vec::new();
    collect(&root.join("scripts"), "py", &mut scripts);
    assert!(
        scripts.len() > 20,
        "expected >20 python scripts; found {}",
        scripts.len()
    );
}

/// The lint proper: no unconverted pool construction in a background process.
#[test]
fn every_background_process_builds_its_pool_through_the_maintenance_constructor() {
    let root = repo_root();
    let exempt = exempt_names();
    let mut files = Vec::new();
    for r in RUST_ROOTS {
        collect(&root.join(r), "rs", &mut files);
    }
    files.sort();

    let mut findings: Vec<String> = Vec::new();

    for path in &files {
        let name = rel(&root, path);
        let src = std::fs::read_to_string(path).expect("read source");

        let hits: Vec<(usize, String)> = code_lines(&src)
            .filter(|(_, l)| BANNED_CONSTRUCTIONS.iter().any(|b| l.contains(b)))
            .map(|(i, l)| (i + 1, l.trim().to_string()))
            .collect();

        if hits.is_empty() {
            continue;
        }

        // An exempt file must ALSO carry the in-file marker. Two places or it
        // is not a control.
        if exempt.contains(name.as_str()) {
            assert!(
                src.contains(MARKER),
                "{name} is in EXEMPT but carries no `{MARKER}` comment at the site. \
                 The table records the decision; the marker is what a reader of the code \
                 finds. Both are required."
            );
            continue;
        }

        let converted = MAINTENANCE_CONSTRUCTIONS.iter().any(|m| src.contains(m));
        let why = if converted {
            "PARTIAL CONVERSION — this file uses the maintenance constructor AND still builds \
             a second pool. That is the shape that reads green: the privileged handle exists, \
             and the statements run somewhere else."
        } else {
            "UNCONVERTED — this pool is built on whatever DSN happened to be around. Under \
             FORCE a corpus-wide statement on it matches zero rows and the process exits 0."
        };
        for (line, text) in hits {
            findings.push(format!("  {name}:{line}  {text}\n    {why}"));
        }
    }

    // Python: an operator script that opens a psycopg2 connection must consult
    // MAINTENANCE_DATABASE_URL (directly or through theme_lib::maintenance_dsn).
    let mut scripts = Vec::new();
    collect(&root.join("scripts"), "py", &mut scripts);
    scripts.sort();
    for path in &scripts {
        let name = rel(&root, path);
        let src = std::fs::read_to_string(path).expect("read script");
        if !src.contains("psycopg2.connect(") {
            continue;
        }
        // CODE lines only. A `#` comment explaining why a script is exempt
        // mentions `MAINTENANCE_DATABASE_URL` by name, and counting that as
        // evidence of conversion would let a file exempt itself by describing
        // the thing it does not do.
        if python_consults_maintenance_dsn(&src) {
            continue;
        }
        if exempt.contains(name.as_str()) {
            assert!(
                src.contains(MARKER),
                "{name} is in EXEMPT but carries no `{MARKER}` comment at the site."
            );
            continue;
        }
        findings.push(format!(
            "  {name}  opens a psycopg2 connection without consulting \
             MAINTENANCE_DATABASE_URL\n    UNCONVERTED — see scripts/theme_lib.py::maintenance_dsn"
        ));
    }

    assert!(
        findings.is_empty(),
        "background processes must build their pool through the maintenance constructor \
         (`epigraph_cli::MaintenancePool`, `ScopedPool::connect_with_options` on the DSN \
         `epigraph_db::maintenance_database_url` returned, or \
         `scripts/theme_lib.py::maintenance_dsn`). {} finding(s):\n{}\n\n\
         If a site genuinely cannot take a maintenance DSN, add a `{MARKER} <reason>` comment \
         at the site AND an entry with the same reason in EXEMPT in this file.",
        findings.len(),
        findings.join("\n")
    );
}

/// The exemption set is exactly what was reviewed — in both directions.
///
/// The reverse direction is the one that matters over time: a file that gets
/// converted but is left in the table turns the table into folklore.
#[test]
fn the_exemption_set_is_exactly_what_was_reviewed() {
    let root = repo_root();

    for (name, reason) in EXEMPT {
        let path = root.join(name);
        assert!(path.exists(), "EXEMPT names {name}, which does not exist");
        assert!(
            reason.len() > 80,
            "the exemption for {name} is {} chars. PR-15's acceptance requires a REASON per \
             entry, not a label; state what the site does and why FORCE cannot silence it.",
            reason.len()
        );
        let src = std::fs::read_to_string(&path).expect("read exempt file");
        assert!(
            src.contains(MARKER),
            "{name} is exempt but carries no `{MARKER}` comment"
        );

        // And it must still NEED the exemption.
        let still_needs = if name.ends_with(".py") {
            src.contains("psycopg2.connect(") && !python_consults_maintenance_dsn(&src)
        } else {
            code_lines(&src).any(|(_, l)| BANNED_CONSTRUCTIONS.iter().any(|b| l.contains(b)))
        };
        assert!(
            still_needs,
            "{name} is listed in EXEMPT but no longer builds an unmaintained pool. \
             Delete the entry and the `{MARKER}` comment: an exemption list that outlives its \
             subjects stops being a list of decisions and becomes a list of nobody-checked."
        );
    }
}

/// Calibration. The scanner must actually fire on the spellings it names —
/// otherwise a green run means "found nothing" rather than "there is nothing".
#[test]
fn the_scanner_is_not_vacuous() {
    for banned in BANNED_CONSTRUCTIONS {
        let sample = format!("    let pool = {banned}&url).await?;");
        assert!(
            code_lines(&sample).any(|(_, l)| l.contains(banned)),
            "the scanner does not detect its own banned spelling {banned}"
        );
    }
    // The broadened `PgPool::connect` entry must catch the whole family, not
    // just the bare call — that is the point of dropping the trailing paren.
    for spelling in [
        "    let p = sqlx::PgPool::connect(&url).await?;",
        "    let p = sqlx::PgPool::connect_with(opts).await?;",
        "    let p = sqlx::PgPool::connect_lazy(&url)?;",
        "    let p = sqlx::PgPool::connect_lazy_with(opts);",
    ] {
        assert!(
            code_lines(spelling).any(|(_, l)| BANNED_CONSTRUCTIONS.iter().any(|b| l.contains(b))),
            "the scanner must detect {spelling}"
        );
    }
    // And it must NOT fire on the maintenance constructors themselves, or the
    // broadening would make every converted file a finding.
    for allowed in [
        "    let maint = MaintenancePool::connect(\"ctx\").await?;",
        "    let maint = MaintenancePool::connect_to(&url, \"ctx\").await?;",
        "    let s = ScopedPool::connect_with_options(&url, mode, opts).await?;",
    ] {
        assert!(
            !code_lines(allowed).any(|(_, l)| BANNED_CONSTRUCTIONS.iter().any(|b| l.contains(b))),
            "the maintenance constructor must not be a finding: {allowed}"
        );
    }
    // And it must ignore comments, or every doc comment mentioning the old
    // spelling would be a finding.
    let commented = "    // let pool = PgPool::connect(&url).await?;";
    assert!(
        code_lines(commented).next().is_none(),
        "a whole-line comment must not be scanned"
    );
    // But an indented statement must be.
    let real = "        let pool = PgPool::connect(&url).await?;";
    assert!(
        code_lines(real).next().is_some(),
        "an indented statement must be scanned"
    );
}
