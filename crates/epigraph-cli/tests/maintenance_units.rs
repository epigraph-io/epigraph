//! The maintenance jobs' systemd units (`deploy/systemd/`, backlog 21be383b):
//! templates the operator copies and installs by hand, beside the Atlas
//! nightly's. Request processes refuse to apply cascades or run jobs and name
//! the timers that do (`epigraph-cascade-replay.timer`,
//! `epigraph-jobs-drain.timer`); those names must exist here.
//!
//! * `every_timer_the_code_names_ships`: every `<name>.timer` named anywhere
//!   under `crates/*/src` has a timer file here whose `Unit=` service also
//!   ships. A refusal that names a unit nobody can find is the defect this
//!   closes.
//! * `the_units_run_what_deploy_md_promises`: each service runs its binary
//!   with the flags and exit-code handling `docs/deploy.md` step 10 gives it;
//!   each timer fires (a monotonic timer needs a first trigger too).
//! * `the_units_carry_only_placeholders`: the repository is public.
//! * `deploy_md_points_at_the_units`: the runbook names the directory and
//!   every timer, and no longer says no unit files ship.
//! * `systemd_analyze_verifies_the_units` (when `systemd-analyze` is on the
//!   host): every file, with `ExecStart=` pointed at `/bin/true`, passes
//!   `systemd-analyze verify` with no complaint about any of them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

type Unit = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// (unit stem, binary) for each maintenance job this file covers.
const JOBS: &[(&str, &str)] = &[
    ("epigraph-cascade-replay", "replay_deferred_cascades"),
    ("epigraph-jobs-drain", "drain_jobs"),
    ("epigraph-embed-backfill", "embed_backfill"),
    ("epigraph-prune-recall-events", "prune_recall_events"),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn units_dir() -> PathBuf {
    repo_root().join("deploy/systemd")
}

/// `section -> key -> values` of a unit file (comments and blanks skipped).
fn parse(name: &str, text: &str) -> Unit {
    let mut out = Unit::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.to_string();
            out.entry(section.clone()).or_default();
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{name}: not a key=value line: {line:?}"));
        assert!(!section.is_empty(), "{name}: a key outside any section");
        out.entry(section.clone())
            .or_default()
            .entry(k.trim().to_string())
            .or_default()
            .push(v.trim().to_string());
    }
    out
}

fn read(name: &str) -> String {
    std::fs::read_to_string(units_dir().join(name))
        .unwrap_or_else(|e| panic!("deploy/systemd/{name}: {e}"))
}

fn unit(name: &str) -> Unit {
    parse(name, &read(name))
}

fn get<'a>(unit: &'a Unit, section: &str, key: &str) -> Option<&'a str> {
    let v = unit.get(section)?.get(key)?;
    assert_eq!(v.len(), 1, "[{section}] {key}= is set {} times", v.len());
    Some(v[0].as_str())
}

fn one<'a>(unit: &'a Unit, name: &str, section: &str, key: &str) -> &'a str {
    get(unit, section, key).unwrap_or_else(|| panic!("{name}: [{section}] {key}= is missing"))
}

/// Every `<stem>.timer` token in a text: the run of `[a-z0-9-]` before `.timer`.
fn timer_names(text: &str, out: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(i) = text[from..].find(".timer") {
        let end = from + i;
        let after = end + ".timer".len();
        from = after;
        if bytes
            .get(after)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            continue; // `.timers`, `.timer_x`: not a unit name
        }
        let mut start = end;
        while start > 0 && {
            let b = bytes[start - 1];
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
        } {
            start -= 1;
        }
        let stem = &text[start..end];
        if stem.contains('-') {
            out.insert(format!("{stem}.timer"));
        }
    }
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_timer_the_code_names_ships() {
    let mut files = Vec::new();
    for krate in std::fs::read_dir(repo_root().join("crates"))
        .unwrap()
        .flatten()
    {
        rust_sources(&krate.path().join("src"), &mut files);
    }
    let mut named = BTreeSet::new();
    for f in &files {
        timer_names(&std::fs::read_to_string(f).unwrap(), &mut named);
    }
    // Not vacuous: the two the request-path refusals name are found.
    for must in ["epigraph-cascade-replay.timer", "epigraph-jobs-drain.timer"] {
        assert!(
            named.contains(must),
            "the scan no longer finds {must}: {named:?}"
        );
    }
    let missing: Vec<&String> = named
        .iter()
        .filter(|t| !units_dir().join(t.as_str()).is_file())
        .collect();
    assert!(
        missing.is_empty(),
        "timers named under crates/*/src with no file in deploy/systemd/: {missing:?}"
    );
    for t in &named {
        let timer = unit(t);
        let service = one(&timer, t, "Timer", "Unit");
        assert!(
            units_dir().join(service).is_file(),
            "{t}: Unit={service} does not ship"
        );
    }
}

/// The program and arguments of a service's single `ExecStart=`.
fn exec(service: &Unit, name: &str) -> (String, Vec<String>) {
    let line = one(service, name, "Service", "ExecStart");
    let mut words = line.split_whitespace().map(str::to_string);
    let program = words.next().unwrap();
    (program, words.collect())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter()
        .any(|a| a == flag || a.starts_with(&format!("{flag}=")))
}

fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).map(String::as_str)
}

/// systemd time span in seconds: `90s`, `5min`, `1h`, `55min`, `1h 5min`.
fn span_secs(s: &str) -> u64 {
    let mut total = 0;
    for part in s.split_whitespace() {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        let n: u64 = digits.parse().unwrap_or_else(|_| panic!("span {s:?}"));
        total += n * match &part[digits.len()..] {
            "" | "s" | "sec" => 1,
            "m" | "min" => 60,
            "h" | "hr" => 3600,
            "d" => 86400,
            other => panic!("span unit {other:?} in {s:?}"),
        };
    }
    total
}

fn ok_codes(service: &Unit) -> Vec<String> {
    get(service, "Service", "SuccessExitStatus")
        .map(|v| v.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

#[test]
fn the_units_run_what_deploy_md_promises() {
    for (stem, binary) in JOBS {
        let sname = format!("{stem}.service");
        let tname = format!("{stem}.timer");
        let service = unit(&sname);
        let timer = unit(&tname);

        assert_eq!(
            one(&service, &sname, "Service", "Type"),
            "oneshot",
            "{sname}"
        );
        let (program, args) = exec(&service, &sname);
        assert!(
            program.ends_with(&format!("/{binary}")),
            "{sname}: ExecStart runs {program}, not {binary}"
        );
        let env = one(&service, &sname, "Service", "EnvironmentFile");
        assert!(
            env.starts_with("/etc/epigraph/"),
            "{sname}: EnvironmentFile={env}"
        );
        assert!(
            get(&service, "Service", "User").is_some(),
            "{sname}: no User="
        );
        assert!(
            get(&service, "Service", "TimeoutStartSec").is_some(),
            "{sname}: no TimeoutStartSec= (a hung run would hold its slot forever)"
        );

        assert_eq!(one(&timer, &tname, "Timer", "Unit"), sname, "{tname}");
        assert_eq!(one(&timer, &tname, "Install", "WantedBy"), "timers.target");
        let calendar = get(&timer, "Timer", "OnCalendar");
        let monotonic = get(&timer, "Timer", "OnUnitActiveSec")
            .or_else(|| get(&timer, "Timer", "OnUnitInactiveSec"));
        match (calendar, monotonic) {
            (Some(_), None) => assert_eq!(
                one(&timer, &tname, "Timer", "Persistent"),
                "true",
                "{tname}: a missed calendar run should catch up"
            ),
            // OnUnit*Sec= counts from the service's last run: without a first
            // trigger the timer never fires at all.
            (None, Some(_)) => assert!(
                get(&timer, "Timer", "OnBootSec").is_some()
                    || get(&timer, "Timer", "OnActiveSec").is_some(),
                "{tname}: a monotonic timer with no OnBootSec=/OnActiveSec= never fires"
            ),
            other => panic!("{tname}: want one OnCalendar= or one OnUnit*Sec=, got {other:?}"),
        }

        match *binary {
            "replay_deferred_cascades" => {
                assert_eq!(flag_value(&args, "--max-failures"), Some("20"), "{sname}");
                for f in ["--report-only", "--retire", "--sweep-withdrawn-edge-bbas"] {
                    assert!(!has_flag(&args, f), "{sname}: {f} is not for the timer");
                }
                // Exit 2 (a stuck cascade) must surface as a failed unit.
                assert!(!ok_codes(&service).contains(&"2".into()), "{sname}");
                let every = span_secs(monotonic.expect("the replay runs on an interval"));
                assert_eq!(every, 90, "{tname}: the binary documents every 90 s");
            }
            "drain_jobs" => {
                // 3 is out of time with work pending: success. 4 (pending
                // jobs no handler claims) and 5 (a stranded privatization
                // plan) are failures, as is 1.
                let codes = ok_codes(&service);
                assert!(codes.contains(&"3".into()), "{sname}: {codes:?}");
                for bad in ["1", "4", "5"] {
                    assert!(!codes.contains(&bad.into()), "{sname}: {bad} in {codes:?}");
                }
                assert!(!has_flag(&args, "--cancel-pending"), "{sname}");
                // The drain stops itself at --max-runtime (default 50 min):
                // the unit's timeout must leave it room to.
                let runtime = flag_value(&args, "--max-runtime").map_or(50 * 60, span_secs);
                let timeout = span_secs(one(&service, &sname, "Service", "TimeoutStartSec"));
                assert!(
                    timeout > runtime,
                    "{sname}: TimeoutStartSec {timeout}s <= --max-runtime {runtime}s"
                );
            }
            "embed_backfill" => {
                assert!(
                    !has_flag(&args, "--allow-mock"),
                    "{sname}: mock vectors in a real database"
                );
                assert!(!has_flag(&args, "--dry-run"), "{sname}");
            }
            "prune_recall_events" => {
                assert!(!has_flag(&args, "--dry-run"), "{sname}");
            }
            other => panic!("no checks for {other}"),
        }
    }
}

/// A dotted quad not inside a longer dotted run (a version string).
fn has_ipv4(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|tok| {
            let parts: Vec<&str> = tok.split('.').collect();
            parts.len() == 4
                && parts.iter().all(|p| {
                    !p.is_empty() && p.len() <= 3 && p.parse::<u16>().is_ok_and(|n| n < 256)
                })
        })
}

#[test]
fn the_units_carry_only_placeholders() {
    let mut seen = 0;
    for entry in std::fs::read_dir(units_dir()).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let text = std::fs::read_to_string(entry.path()).unwrap();
        seen += 1;
        for bad in [
            "/home/",
            "/Users/",
            "/root/",
            "epiclaw",
            "postgres://",
            "postgresql://",
        ] {
            assert!(!text.contains(bad), "{name} contains {bad:?}");
        }
        assert!(!has_ipv4(&text), "{name} contains an IPv4 address");
        for line in text.lines().map(str::trim) {
            if let Some(v) = line.strip_prefix("Environment=") {
                let lower = v.to_ascii_lowercase();
                for secret in ["password", "secret", "token", "api_key", "database_url"] {
                    assert!(
                        !lower.contains(secret),
                        "{name}: {secret} belongs in the EnvironmentFile, not the unit"
                    );
                }
            }
        }
    }
    assert!(
        seen >= 2 * JOBS.len(),
        "deploy/systemd/ holds only {seen} files"
    );
}

#[test]
fn deploy_md_points_at_the_units() {
    let doc = std::fs::read_to_string(repo_root().join("docs/deploy.md")).unwrap();
    let flat = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !flat.contains("No unit files"),
        "docs/deploy.md still says no unit files ship"
    );
    assert!(
        flat.contains("deploy/systemd/"),
        "docs/deploy.md never names deploy/systemd/"
    );
    for (stem, _) in JOBS {
        assert!(
            flat.contains(&format!("{stem}.timer")),
            "docs/deploy.md never names {stem}.timer"
        );
    }
}

#[test]
fn systemd_analyze_verifies_the_units() {
    let Ok(probe) = Command::new("systemd-analyze").arg("--version").output() else {
        eprintln!("systemd-analyze is not on this host; the syntax tests still ran");
        return;
    };
    if !probe.status.success() {
        eprintln!("systemd-analyze does not run here; the syntax tests still ran");
        return;
    }
    let dir = std::env::temp_dir().join(format!("maintenance-units-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut paths = Vec::new();
    for (stem, _) in JOBS {
        for name in [format!("{stem}.service"), format!("{stem}.timer")] {
            let text: String = read(&name)
                .lines()
                .map(|l| match l.strip_prefix("ExecStart=") {
                    Some(rest) => {
                        let program = rest.split_whitespace().next().unwrap();
                        format!("ExecStart={}\n", rest.replacen(program, "/bin/true", 1))
                    }
                    None => format!("{l}\n"),
                })
                .collect();
            std::fs::write(dir.join(&name), text).unwrap();
            paths.push(dir.join(&name));
        }
    }
    let out = Command::new("systemd-analyze")
        .arg("verify")
        .args(&paths)
        .current_dir(&dir)
        .output()
        .expect("run systemd-analyze");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The host's own units can be unreadable to a test user; only a line
    // about one of these files counts.
    let ours: Vec<&str> = text
        .lines()
        .filter(|l| JOBS.iter().any(|(stem, _)| l.contains(stem)))
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    assert!(ours.is_empty(), "systemd-analyze verify: {ours:#?}");
}
