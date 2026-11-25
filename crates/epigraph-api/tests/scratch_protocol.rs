//! The `epigraph-scratch` binary over its real stdio (DESIGN §4.2, task E1).
//!
//! Every test spawns the built binary exactly as the runner will: a snapshot
//! path, a scope and an epoch on the command line, `PATH` as the whole
//! environment, and JSON lines on stdin/stdout.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-scratch");
const SCOPE: &str = "3f9a1c07be52";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "scratch-protocol-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn graph(&self) -> PathBuf {
        self.0.join("graph.json")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(snapshot: &Path, scope: &str, epoch: &str) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.arg("--snapshot")
        .arg(snapshot)
        .args(["--scope", scope, "--epoch", epoch])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

struct Scratch {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Scratch {
    fn spawn(snapshot: &Path, epoch: u64) -> Self {
        let mut child = command(snapshot, SCOPE, &epoch.to_string())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }

    /// Send one raw line, read one response line.
    fn raw(&mut self, line: &str) -> Value {
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.write_all(b"\n").unwrap();
        self.stdin.flush().unwrap();
        let mut out = String::new();
        let n = self.stdout.read_line(&mut out).unwrap();
        assert!(n > 0, "the child closed stdout after: {line}");
        serde_json::from_str(&out).unwrap()
    }

    fn call(&mut self, request: Value) -> Value {
        self.raw(&request.to_string())
    }

    fn ok(&mut self, request: Value) -> Value {
        let id = request["id"].clone();
        let response = self.call(request);
        assert_eq!(response["id"], id, "response id echoes the request id");
        assert_eq!(response["ok"], true, "{response}");
        response
    }

    /// Close stdin and wait for a clean exit.
    fn finish(mut self) {
        drop(self.stdin);
        let status = self.child.wait().unwrap();
        assert!(status.success(), "exit status {status}");
    }
}

fn uuid(n: u32) -> String {
    format!("00000000-0000-5000-8000-{n:012x}")
}

fn sha() -> String {
    "ab".repeat(32)
}

fn atom(n: u32, turn: u64, text: &str) -> Value {
    json!({
        "id": uuid(n), "text": text, "kind": "decision", "speaker": "user",
        "turn": turn, "epoch": 0, "quote": "anchor",
        "evidence": [{"path": format!("turns/{turn}.json"), "sha256": sha(), "span": "user:0"}],
        "seed": {"confidence": 0.71, "reliability": 0.75},
    })
}

#[test]
fn a_session_of_ops_round_trips_over_stdio() {
    let dir = TempDir::new("session");
    let mut s = Scratch::spawn(&dir.graph(), 0);

    let health = s.ok(json!({"id": 1, "op": "health"}));
    assert_eq!(health["status"], "ok");
    assert_eq!(
        (health["scope"].clone(), health["epoch"].clone()),
        (json!(SCOPE), json!(0))
    );
    assert_eq!(health["restored_from"], "empty");
    assert_eq!(health["restore_degraded"], false);
    assert!(!dir.graph().exists(), "a read op writes nothing");

    let put = s.ok(json!({"id": "put-1", "op": "put_atoms", "atoms": [
        atom(1, 3, "The operator decided the greenhouse rollout uses v2 probes only."),
        atom(2, 4, "The operator wants weekly summaries on Fridays."),
        atom(3, 5, "The pilot site has 40 beds."),
    ]}));
    assert_eq!(
        (put["inserted"].clone(), put["existing"].clone()),
        (json!(3), json!(0))
    );
    assert!(
        dir.graph().exists(),
        "a mutating op snapshots before it answers"
    );
    let replay = s.ok(json!({"id": 3, "op": "put_atoms", "atoms": [atom(1, 3, "changed text")]}));
    assert_eq!(
        (replay["inserted"].clone(), replay["existing"].clone()),
        (json!(0), json!(1))
    );

    // A misspelt or mis-cased key is refused, never silently dropped.
    let refused = s.call(
        json!({"id": 4, "op": "corroborate", "corroborationId": uuid(100),
        "target": uuid(2), "seed": {"confidence": 0.6, "reliability": 0.75}}),
    );
    assert_eq!(refused["error"], "bad_request", "{refused}");
    let corroborate = json!({"op": "corroborate", "id": 5, "corroboration_id": uuid(100), "target": uuid(2),
        "seed": {"confidence": 0.6, "reliability": 0.75}, "evidence": [{"path": "turns/9.json", "sha256": sha()}]});
    assert_eq!(s.ok(corroborate.clone())["applied"], true);
    // The replay (same corroboration_id) is acknowledged and not combined again.
    assert_eq!(s.ok(corroborate)["applied"], false);

    let edges = s.ok(json!({"id": 6, "op": "add_edges", "edges": [
        {"id": uuid(50), "source": uuid(1), "target": uuid(2), "rel": "supports"}]}));
    assert_eq!(edges["inserted"], 1);
    let sup = s.ok(json!({"id": 7, "op": "supersede", "old": uuid(3), "new": uuid(1), "reason": "corrected in t9"}));
    assert_eq!(sup["changed"], true);
    assert_eq!(
        s.ok(json!({"id": 8, "op": "mark_applied", "turn": 5}))["changed"],
        true
    );

    let cands = s.ok(json!({"id": 9, "op": "candidates", "text": "greenhouse probes rollout", "k": 5, "recent": 5}));
    let list = cands["candidates"].as_array().unwrap();
    assert_eq!(list[0]["id"], uuid(1));
    assert_eq!(list[0]["via"], "bm25");
    assert!(
        list.iter().all(|c| c["id"] != uuid(3)),
        "a superseded atom is never a candidate"
    );
    assert_eq!(
        list.len(),
        2,
        "one BM25 hit plus the one other current atom: {cands}"
    );

    let a = s.ok(json!({"id": 10, "op": "atom", "atom_id": uuid(2)}));
    assert_eq!(a["atom"]["bbas"].as_array().unwrap().len(), 2);
    assert_eq!(a["atom"]["evidence"][0]["quote"], "anchor");
    let n = s.ok(json!({"id": 11, "op": "neighbors", "atom_id": uuid(2)}));
    assert_eq!(
        n["neighbors"],
        json!([{"edge": uuid(50), "relationship": "supports", "direction": "in",
        "atom": {"id": uuid(1), "text": "The operator decided the greenhouse rollout uses v2 probes only.",
                 "kind": "decision", "speaker": "user", "turn": 3, "is_current": true}}])
    );

    let stats = s.ok(json!({"id": 12, "op": "stats"}));
    assert_eq!(
        stats,
        json!({"id": 12, "ok": true, "atoms": 3, "current_atoms": 2, "edges": 1,
        "applied_turns": 1, "max_applied_turn": 5})
    );
    let snap = s.ok(json!({"id": 13, "op": "snapshot"}));
    assert_eq!(
        snap["bytes"].as_u64().unwrap(),
        fs::metadata(dir.graph()).unwrap().len()
    );
    s.finish();
}

#[test]
fn the_envelope_id_is_never_read_as_an_op_parameter() {
    // `id` is the request id. An atom id in that slot must not be taken as
    // `atom`'s argument: the op still needs its own `atom_id`.
    let dir = TempDir::new("idkey");
    let mut s = Scratch::spawn(&dir.graph(), 0);
    s.ok(json!({"id": 1, "op": "put_atoms", "atoms": [atom(1, 1, "alpha fact")]}));
    let r = s.call(json!({"id": uuid(1), "op": "atom"}));
    assert_eq!(
        (r["id"].clone(), r["ok"].clone(), r["error"].clone()),
        (json!(uuid(1)), json!(false), json!("bad_request")),
        "{r}"
    );
    let r = s.ok(json!({"id": uuid(1), "op": "atom", "atom_id": uuid(1)}));
    assert_eq!(r["atom"]["text"], "alpha fact");
    let r = s.call(json!({"id": 3, "op": "atom", "atom_id": uuid(9)}));
    assert_eq!(r["error"], "unknown_atom");
    s.finish();
}

#[test]
fn bad_lines_get_an_error_and_the_child_keeps_serving() {
    let dir = TempDir::new("bad");
    let mut s = Scratch::spawn(&dir.graph(), 0);
    let cases: Vec<(&str, &str)> = vec![
        ("this is not json", "bad_json"),
        ("{\"id\": 1, \"op\": ", "bad_json"),
        ("[1, 2, 3]", "bad_request"),
        ("{\"id\": 2}", "bad_request"),
        ("{\"id\": 3, \"op\": 7}", "bad_request"),
        ("{\"id\": 4, \"op\": \"drop_tables\"}", "unknown_op"),
        ("{\"id\": 5, \"op\": \"digest\", \"query\": \"x\"}", "not_implemented"),
        ("{\"id\": 6, \"op\": \"update_belief\", \"verbose\": 1}", "bad_request"),
        ("{\"id\": 7, \"op\": \"health\", \"verbose\": true}", "bad_request"),
        ("{\"id\": 8, \"op\": \"put_atoms\", \"atoms\": [{\"id\": \"nope\"}]}", "bad_request"),
        ("{\"id\": 9, \"op\": \"supersede\", \"old\": \"00000000-0000-5000-8000-000000000001\", \"new\": \"00000000-0000-5000-8000-000000000002\"}", "unknown_atom"),
        ("{\"id\": 10, \"op\": \"mark_applied\", \"turn\": -1}", "bad_request"),
        ("{\"id\": 11, \"op\": \"candidates\", \"text\": \"x\", \"k\": 1000}", "bad_request"),
    ];
    for (line, code) in &cases {
        let r = s.raw(line);
        assert_eq!(r["ok"], false, "{line} -> {r}");
        assert_eq!(r["error"], *code, "{line} -> {r}");
        assert!(r["detail"].is_string(), "{line} -> {r}");
    }
    // A bad line yields id null; a parseable one echoes its id.
    assert_eq!(s.raw("garbage")["id"], Value::Null);
    assert_eq!(s.raw("{\"id\": \"q\", \"op\": \"nope\"}")["id"], "q");

    // Blank lines are skipped without a response: the next response is for
    // the next real request.
    s.stdin.write_all(b"\n   \n").unwrap();
    let after = s.ok(json!({"id": 99, "op": "health"}));
    assert_eq!(after["id"], 99);
    // Nothing above changed the graph or wrote a snapshot.
    assert_eq!(s.ok(json!({"id": 100, "op": "stats"}))["atoms"], 0);
    assert!(!dir.graph().exists());
    s.finish();
}

#[test]
fn a_seed_must_carry_confidence_and_reliability_apart() {
    // Critic finding X6: a caller following DESIGN §4.2's old sketch sends a
    // pre-multiplied `{"supported": c×r}`. It must be refused, not stored as
    // a confidence that belief would then discount by the reliability again.
    let dir = TempDir::new("seed");
    let mut s = Scratch::spawn(&dir.graph(), 0);
    let with_seed = |n: u32, seed: Value| {
        let mut a = atom(n, 1, "The pilot uses v2 probes.");
        a["seed"] = seed;
        json!({"id": n, "op": "put_atoms", "atoms": [a]})
    };
    for (n, seed) in [
        (1, json!({"supported": 0.71})),
        (2, json!({"supported": 0.71, "reliability": 0.75})),
        (3, json!({"confidence": 0.71})),
        (4, json!({"reliability": 0.75})),
    ] {
        let r = s.call(with_seed(n, seed.clone()));
        assert_eq!(r["ok"], false, "{seed} -> {r}");
        assert_eq!(r["error"], "bad_request", "{seed} -> {r}");
    }
    assert_eq!(s.ok(json!({"id": 9, "op": "stats"}))["atoms"], 0);

    // The accepted shape stores both factors as sent.
    s.ok(with_seed(
        10,
        json!({"confidence": 0.8, "reliability": 0.95}),
    ));
    let stored = s.ok(json!({"id": 11, "op": "atom", "atom_id": uuid(10)}));
    assert_eq!(
        stored["atom"]["bbas"],
        json!([{"source": uuid(10), "confidence": 0.8, "reliability": 0.95}])
    );
    s.finish();
}

#[test]
fn update_belief_writes_nothing_and_atom_reports_belief() {
    let dir = TempDir::new("belief");
    let mut s = Scratch::spawn(&dir.graph(), 0);
    let empty = s.ok(json!({"id": 1, "op": "update_belief"}));
    assert_eq!(
        (empty["current_atoms"].clone(), empty["contested"].clone()),
        (json!(0), json!(0))
    );
    let seeded = |n: u32, c: f64, r: f64| {
        let mut a = atom(n, n.into(), "A seeded atom.");
        a["seed"] = json!({"confidence": c, "reliability": r});
        a
    };
    s.ok(json!({"id": 2, "op": "put_atoms", "atoms": [seeded(1, 0.8, 0.95), seeded(2, 0.6, 0.5)]}));
    s.ok(
        json!({"id": 3, "op": "corroborate", "corroboration_id": uuid(90), "target": uuid(1),
        "seed": {"confidence": 0.5, "reliability": 0.75}}),
    );
    s.ok(json!({"id": 4, "op": "add_edges", "edges": [
        {"id": uuid(50), "source": uuid(2), "target": uuid(1), "rel": "contradicts"}]}));
    let snapshot_before = fs::read(dir.graph()).unwrap();

    let summary = s.ok(json!({"id": 5, "op": "update_belief"}));
    assert_eq!(
        (
            summary["current_atoms"].clone(),
            summary["contested"].clone(),
            summary["seeds"].clone()
        ),
        (json!(2), json!(2), json!(3))
    );
    assert_eq!(
        fs::read(dir.graph()).unwrap(),
        snapshot_before,
        "belief is derived: update_belief rewrites no snapshot"
    );

    // 0.8 × 0.95 = 0.76 restated by 0.5 × 0.75 = 0.375:
    // 1 − 0.24 × 0.625 = 0.85; BetP 0.85 + 0.15 / 2 = 0.925.
    let a = s.ok(json!({"id": 6, "op": "atom", "atom_id": uuid(1)}));
    let b = &a["belief"];
    assert!((b["bel"].as_f64().unwrap() - 0.85).abs() < 1e-12, "{b}");
    assert!((b["pl"].as_f64().unwrap() - 1.0).abs() < 1e-12, "{b}");
    assert!((b["betp"].as_f64().unwrap() - 0.925).abs() < 1e-12, "{b}");
    assert_eq!(b["contested"], true);
    assert_eq!(b["contested_with"], json!([uuid(2)]));
    s.finish();
}

#[test]
fn error_details_never_echo_request_text() {
    let dir = TempDir::new("detail");
    let mut s = Scratch::spawn(&dir.graph(), 0);
    let secret = "SECRET-CHAT-TEXT-7f3a";
    let probes = vec![
        json!({"id": 1, "op": "put_atoms", "atoms": [{"id": uuid(1), "text": secret, "kind": secret,
            "speaker": "user", "turn": 1, "epoch": 0, "seed": {"confidence": 0.5, "reliability": 0.75}}]}),
        json!({"id": 2, "op": "candidates", "text": 17}),
        json!({"id": 3, "op": "put_atoms", "atoms": [{"id": uuid(1), "text": secret, "kind": "fact",
            "speaker": "user", "turn": 1, "epoch": 3, "seed": {"confidence": 0.5, "reliability": 0.75}}]}),
        json!({"id": 4, "op": "mark_applied", "turn": secret}),
    ];
    for p in probes {
        let r = s.call(p.clone());
        assert_eq!(r["ok"], false, "{r}");
        assert!(
            !r.to_string().contains(secret),
            "detail leaks request text: {r}"
        );
        assert!(!r.to_string().contains("17"), "detail leaks a value: {r}");
    }
    s.finish();
}

#[test]
fn an_acknowledged_write_survives_sigkill_and_restores_on_respawn() {
    let dir = TempDir::new("kill");
    let mut s = Scratch::spawn(&dir.graph(), 0);
    s.ok(json!({"id": 1, "op": "put_atoms", "atoms": [atom(1, 1, "first"), atom(2, 2, "second")]}));
    s.ok(json!({"id": 2, "op": "add_edges", "edges": [
        {"id": uuid(50), "source": uuid(1), "target": uuid(2), "rel": "contradicts"}]}));
    s.ok(json!({"id": 3, "op": "mark_applied", "turn": 2}));
    // No graceful shutdown: the acknowledged writes must already be on disk.
    s.child.kill().unwrap();
    s.child.wait().unwrap();

    let mut again = Scratch::spawn(&dir.graph(), 0);
    let health = again.ok(json!({"id": 1, "op": "health"}));
    assert_eq!(health["restored_from"], "snapshot");
    let stats = again.ok(json!({"id": 2, "op": "stats"}));
    assert_eq!(
        (
            stats["atoms"].clone(),
            stats["edges"].clone(),
            stats["max_applied_turn"].clone()
        ),
        (json!(2), json!(1), json!(2))
    );
    // The second write moved the first snapshot to .prev.
    assert!(PathBuf::from(format!("{}.prev", dir.graph().display())).exists());
    again.finish();
}

#[test]
fn a_damaged_snapshot_restores_from_prev_and_reports_degraded() {
    let dir = TempDir::new("prev");
    let mut s = Scratch::spawn(&dir.graph(), 0);
    s.ok(json!({"id": 1, "op": "put_atoms", "atoms": [atom(1, 1, "kept in prev")]}));
    s.ok(json!({"id": 2, "op": "mark_applied", "turn": 1}));
    s.finish();
    let bytes = fs::read(dir.graph()).unwrap();
    fs::write(dir.graph(), &bytes[..bytes.len() / 2]).unwrap();

    let mut again = Scratch::spawn(&dir.graph(), 0);
    let health = again.ok(json!({"id": 1, "op": "health"}));
    assert_eq!(
        (
            health["restored_from"].clone(),
            health["restore_degraded"].clone()
        ),
        (json!("prev"), json!(true))
    );
    let stats = again.ok(json!({"id": 2, "op": "stats"}));
    assert_eq!(
        (stats["atoms"].clone(), stats["applied_turns"].clone()),
        (json!(1), json!(0)),
        "prev predates mark_applied, so the runner sees turn 1 as unapplied and replays it"
    );
    again.finish();
}

#[test]
fn the_first_write_after_a_prev_restore_never_rotates_damage_over_prev() {
    let dir = TempDir::new("keep-prev");
    let prev = PathBuf::from(format!("{}.prev", dir.graph().display()));
    let tmp = PathBuf::from(format!("{}.tmp", dir.graph().display()));
    let mut s = Scratch::spawn(&dir.graph(), 0);
    s.ok(json!({"id": 1, "op": "put_atoms", "atoms": [atom(1, 1, "kept in prev")]}));
    s.ok(json!({"id": 2, "op": "mark_applied", "turn": 1}));
    s.finish();
    let good_prev = fs::read(&prev).unwrap();
    let bytes = fs::read(dir.graph()).unwrap();
    fs::write(dir.graph(), &bytes[..bytes.len() / 2]).unwrap();

    let mut again = Scratch::spawn(&dir.graph(), 0);
    assert_eq!(
        again.ok(json!({"id": 1, "op": "health"}))["restored_from"],
        "prev"
    );
    // The first write fails; the retry must still not rotate.
    fs::create_dir(&tmp).unwrap();
    let r = again.call(json!({"id": 2, "op": "mark_applied", "turn": 1}));
    assert_eq!(r["error"], "snapshot_failed", "{r}");
    fs::remove_dir(&tmp).unwrap();
    again.ok(json!({"id": 3, "op": "snapshot"}));
    assert_eq!(
        fs::read(&prev).unwrap(),
        good_prev,
        "the damaged graph.json was rotated over the only good .prev"
    );
    let replaced = fs::read(dir.graph()).unwrap();
    assert_ne!(
        replaced,
        &bytes[..bytes.len() / 2],
        "graph.json was replaced"
    );
    // Only the first write skips the rotation.
    again.ok(json!({"id": 4, "op": "put_atoms", "atoms": [atom(2, 2, "second")]}));
    assert_eq!(
        fs::read(&prev).unwrap(),
        replaced,
        "later writes rotate as usual"
    );
    again.finish();

    let mut third = Scratch::spawn(&dir.graph(), 0);
    let health = third.ok(json!({"id": 1, "op": "health"}));
    assert_eq!(
        (
            health["restored_from"].clone(),
            health["restore_degraded"].clone()
        ),
        (json!("snapshot"), json!(false))
    );
    let stats = third.ok(json!({"id": 2, "op": "stats"}));
    assert_eq!(
        (stats["atoms"].clone(), stats["max_applied_turn"].clone()),
        (json!(2), json!(1))
    );
    third.finish();
}

#[test]
fn a_snapshot_write_failure_is_reported_and_retried() {
    let dir = TempDir::new("fail");
    let mut s = Scratch::spawn(&dir.graph(), 0);
    // A directory where the tmp file must go makes the snapshot write fail.
    fs::create_dir(format!("{}.tmp", dir.graph().display())).unwrap();
    let r = s.call(json!({"id": 1, "op": "put_atoms", "atoms": [atom(1, 1, "unsaved")]}));
    assert_eq!(
        (r["ok"].clone(), r["error"].clone()),
        (json!(false), json!("snapshot_failed")),
        "{r}"
    );
    assert!(!dir.graph().exists());
    fs::remove_dir(format!("{}.tmp", dir.graph().display())).unwrap();
    // The replay finds the atom present (in memory) and, because the graph is
    // still unsaved, writes the snapshot this time.
    let r = s.ok(json!({"id": 2, "op": "put_atoms", "atoms": [atom(1, 1, "unsaved")]}));
    assert_eq!(
        (r["inserted"].clone(), r["existing"].clone()),
        (json!(0), json!(1))
    );
    assert!(
        dir.graph().exists(),
        "the retried write persisted the earlier change"
    );
    s.finish();
    let mut again = Scratch::spawn(&dir.graph(), 0);
    assert_eq!(again.ok(json!({"id": 1, "op": "stats"}))["atoms"], 1);
    again.finish();
}

#[test]
fn usage_errors_and_foreign_snapshots_exit_nonzero_without_serving() {
    let dir = TempDir::new("usage");
    let run = |args: &[&str]| {
        Command::new(BIN)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let graph = dir.graph();
    let g = graph.to_str().unwrap();
    for (args, why) in [
        (vec!["--scope", SCOPE, "--epoch", "0"], "no snapshot"),
        (vec!["--snapshot", g, "--epoch", "0"], "no scope"),
        (vec!["--snapshot", g, "--scope", SCOPE], "no epoch"),
        (
            vec!["--snapshot", g, "--scope", "XYZ", "--epoch", "0"],
            "scope not hex",
        ),
        (
            vec!["--snapshot", g, "--scope", "abc", "--epoch", "0"],
            "scope too short",
        ),
        (
            vec!["--snapshot", g, "--scope", SCOPE, "--epoch", "-1"],
            "negative epoch",
        ),
        (
            vec![
                "--snapshot",
                g,
                "--scope",
                SCOPE,
                "--epoch",
                "0",
                "--listen",
                "x",
            ],
            "unknown flag",
        ),
        (
            vec![
                "--snapshot",
                g,
                "--scope",
                SCOPE,
                "--epoch",
                "0",
                "--epoch",
                "1",
            ],
            "repeated flag",
        ),
        (
            vec![
                "--snapshot",
                "/nonexistent-dir-for-scratch/graph.json",
                "--scope",
                SCOPE,
                "--epoch",
                "0",
            ],
            "missing dir",
        ),
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{why}");
        assert!(out.stdout.is_empty(), "{why}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !err.contains("nonexistent-dir"),
            "stderr never echoes a path: {err}"
        );
    }

    // A whole snapshot from epoch 0, opened as epoch 1: refused, file kept.
    let mut s = Scratch::spawn(&graph, 0);
    s.ok(json!({"id": 1, "op": "put_atoms", "atoms": [atom(1, 1, "epoch zero")]}));
    s.finish();
    let before = fs::read(&graph).unwrap();
    let out = command(&graph, SCOPE, "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert_eq!(fs::read(&graph).unwrap(), before);
}
