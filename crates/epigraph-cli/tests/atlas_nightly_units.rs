//! The nightly's systemd units (`deploy/systemd/`, Atlas W9): templates the
//! operator installs by hand. Two checks:
//!
//! * `the_units_say_what_the_runbook_promises` (always): the service is a
//!   oneshot that runs `atlas_nightly --apply` with an `OnFailure=` alert
//!   whose template ships beside it, a start timeout (the window), no
//!   `ProtectHome=` (the naming CLI signs in from the user's home); the timer
//!   is persistent, nightly, and names the service.
//! * `systemd_analyze_verifies_the_units` (when `systemd-analyze` is on the
//!   host): the three files, copied to a scratch directory with only the
//!   `ExecStart=` programs pointed at executables that exist here (the built
//!   binary, `/bin/true`), pass `systemd-analyze verify` with no complaint
//!   about any of them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const SERVICE: &str = "epigraph-atlas-nightly.service";
const TIMER: &str = "epigraph-atlas-nightly.timer";
const ALERT: &str = "epigraph-atlas-nightly-alert@.service";

fn units_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/systemd")
}

/// `section -> key -> values` of a unit file (comments and blanks skipped).
fn parse(text: &str) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut out: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
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
            .unwrap_or_else(|| panic!("not a key=value line: {line:?}"));
        assert!(!section.is_empty(), "a key outside any section: {line:?}");
        out.entry(section.clone())
            .or_default()
            .entry(k.trim().to_string())
            .or_default()
            .push(v.trim().to_string());
    }
    out
}

fn read(name: &str) -> String {
    std::fs::read_to_string(units_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn one<'a>(
    unit: &'a BTreeMap<String, BTreeMap<String, Vec<String>>>,
    section: &str,
    key: &str,
) -> &'a str {
    let v = unit
        .get(section)
        .and_then(|s| s.get(key))
        .unwrap_or_else(|| panic!("[{section}] {key}= is missing"));
    assert_eq!(v.len(), 1, "[{section}] {key}= is set {} times", v.len());
    &v[0]
}

#[test]
fn the_units_say_what_the_runbook_promises() {
    let service = parse(&read(SERVICE));
    assert_eq!(one(&service, "Service", "Type"), "oneshot");
    let exec = one(&service, "Service", "ExecStart");
    let program = exec.split_whitespace().next().unwrap();
    assert!(program.ends_with("/atlas_nightly"), "{exec}");
    assert!(exec.split_whitespace().any(|a| a == "--apply"), "{exec}");
    assert!(one(&service, "Service", "EnvironmentFile").starts_with('/'));
    assert!(!one(&service, "Service", "TimeoutStartSec").is_empty());
    assert!(
        !service["Service"].contains_key("ProtectHome"),
        "the naming CLI signs in from the service user's home"
    );
    // A copy that found the nightly lock held exits 75 having done nothing
    // (the binary's EXIT_LOCKED): not a failure, so no alert.
    let ok_codes: Vec<&str> = one(&service, "Service", "SuccessExitStatus")
        .split_whitespace()
        .collect();
    assert!(ok_codes.contains(&"75"), "{ok_codes:?}");
    let on_failure = one(&service, "Unit", "OnFailure");
    assert_eq!(on_failure, "epigraph-atlas-nightly-alert@%n.service");
    let alert = parse(&read(ALERT));
    assert_eq!(one(&alert, "Service", "Type"), "oneshot");
    assert!(one(&alert, "Service", "ExecStart").contains("%i"));

    let timer = parse(&read(TIMER));
    assert_eq!(one(&timer, "Timer", "Unit"), SERVICE);
    assert_eq!(one(&timer, "Timer", "Persistent"), "true");
    let when = one(&timer, "Timer", "OnCalendar");
    assert!(when.starts_with("*-*-* "), "nightly: {when}");
    assert_eq!(one(&timer, "Install", "WantedBy"), "timers.target");
}

#[test]
fn systemd_analyze_verifies_the_units() {
    let Ok(probe) = Command::new("systemd-analyze").arg("--version").output() else {
        eprintln!("systemd-analyze is not on this host; the syntax test still ran");
        return;
    };
    if !probe.status.success() {
        eprintln!("systemd-analyze does not run here; the syntax test still ran");
        return;
    }
    let dir = std::env::temp_dir().join(format!("atlas-nightly-units-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let nightly = env!("CARGO_BIN_EXE_atlas_nightly");
    for (name, program) in [(SERVICE, nightly), (TIMER, ""), (ALERT, "/bin/true")] {
        let mut text = read(name);
        if !program.is_empty() {
            let line = text
                .lines()
                .find(|l| l.starts_with("ExecStart="))
                .unwrap()
                .to_string();
            let old = line["ExecStart=".len()..]
                .split_whitespace()
                .next()
                .unwrap();
            text = text.replace(&line, &line.replacen(old, program, 1));
        }
        std::fs::write(dir.join(name), text).unwrap();
    }
    let out = Command::new("systemd-analyze")
        .arg("verify")
        .arg(dir.join(SERVICE))
        .arg(dir.join(TIMER))
        .arg(dir.join(ALERT))
        .current_dir(&dir)
        .output()
        .expect("run systemd-analyze");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The host's own units can be unreadable to a test user; only a line
    // about one of these three files counts.
    let ours: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("epigraph-atlas-nightly"))
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    assert!(ours.is_empty(), "systemd-analyze verify: {ours:#?}");
}
