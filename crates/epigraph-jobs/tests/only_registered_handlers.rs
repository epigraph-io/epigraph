//! Every `JobHandler` this crate defines is one the drain registers (backlog
//! 47bb548f).
//!
//! `epigraph-api/src/jobs_drain.rs::build_job_runner` is the ONE place
//! production handlers are registered. A handler defined here and registered
//! nowhere is code no job can reach: it is maintained, reviewed and listed in
//! tenancy registers without ever running, and it reads as a capability the
//! system does not have. The four that accumulated (truth propagation,
//! reputation, webhook, data cleanup) were deleted for that reason; this keeps
//! a fifth from appearing. A new handler lands together with its registration.
//!
//! Both sides are read from source. The handler side is every
//! `impl ... JobHandler for <Type>` under `epigraph-jobs/src` outside a
//! `#[cfg(test)]` module; the registration side is every
//! `register_handler(Arc::new(<Type>` inside `build_job_runner`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// The source with every `#[cfg(test)] mod … { … }` removed (brace-matched),
/// so a test double implementing `JobHandler` is not counted.
fn without_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "#[cfg(test)]".len()..];
        if !after.trim_start().starts_with("mod ") {
            out.push_str("#[cfg(test)]");
            rest = after;
            continue;
        }
        let Some(open) = after.find('{') else {
            rest = "";
            break;
        };
        let mut depth = 0usize;
        let mut end = after.len();
        for (i, c) in after[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn ident_at(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Every type `epigraph-jobs/src` implements `JobHandler` for, outside tests.
fn defined_handlers(src_dir: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    rust_files(src_dir, &mut files);
    let mut found = BTreeSet::new();
    for file in files {
        let src = without_test_modules(&std::fs::read_to_string(&file).expect("read source"));
        for line in src.lines() {
            let line = line.trim_start();
            if line.starts_with("//") || !line.starts_with("impl") {
                continue;
            }
            if let Some(at) = line.find("JobHandler for ") {
                let name = ident_at(&line[at + "JobHandler for ".len()..]);
                assert!(!name.is_empty(), "unparsed impl line: {line}");
                found.insert(name);
            }
        }
    }
    found
}

/// Every type `build_job_runner` registers.
fn registered_handlers(jobs_drain: &str) -> BTreeSet<String> {
    let start = jobs_drain
        .find("pub fn build_job_runner(")
        .expect("jobs_drain.rs must still define build_job_runner");
    let body = &jobs_drain[start..];
    let end = body.find("\n}\n").expect("end of build_job_runner");
    let flat: String = body[..end].split_whitespace().collect();
    let needle = "register_handler(Arc::new(";
    flat.match_indices(needle)
        .map(|(at, _)| ident_at(&flat[at + needle.len()..]))
        .collect()
}

#[test]
fn every_handler_the_crate_defines_is_registered_by_the_drain() {
    let jobs_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let drain = Path::new(env!("CARGO_MANIFEST_DIR")).join("../epigraph-api/src/jobs_drain.rs");
    let defined = defined_handlers(&jobs_src);
    let registered = registered_handlers(&std::fs::read_to_string(drain).expect("read jobs_drain"));

    // Non-vacuity: both scans must see the handlers that are known to exist,
    // or a broken parser would pass by finding nothing on either side.
    for known in [
        "ClusterGraphHandler",
        "PrivatizationApplyHandler",
        "PrivatizationRevertHandler",
        "PrivatizationResealHandler",
        "ConfigurableEmbeddingHandler",
    ] {
        assert!(defined.contains(known), "scan missed {known}: {defined:?}");
        assert!(
            registered.contains(known),
            "build_job_runner scan missed {known}: {registered:?}"
        );
    }

    let unregistered: Vec<_> = defined.difference(&registered).collect();
    assert!(
        unregistered.is_empty(),
        "epigraph-jobs defines job handlers that drain_jobs never registers, so no job can \
         reach them. Register each in epigraph-api's jobs_drain::build_job_runner, or delete \
         it (and retire its EpiGraphJob kind, see EpiGraphJob::is_retired). \
         Unregistered: {unregistered:?}"
    );
}

#[test]
fn the_test_module_strip_keeps_production_impls() {
    let src = "impl JobHandler for Before {}\n\
               #[cfg(test)]\nmod tests { struct Fake; impl JobHandler for Fake { fn f() { if x {} } } }\n\
               impl<S: X + 'static> JobHandler for After<S> {}\n";
    let stripped = without_test_modules(src);
    assert!(stripped.contains("Before") && stripped.contains("After<S>"));
    assert!(!stripped.contains("Fake"));
}
