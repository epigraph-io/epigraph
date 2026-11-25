//! `epigraph-scratch` needs no database and opens no connection (DESIGN §4.1,
//! task E1; operator ruling 9854c563's carve-out from R-39).
//!
//! "No database" means no CONNECTION: epigraph-engine depends on epigraph-db
//! and sqlx unconditionally, so they are linked. Three checks, from the
//! strongest down:
//!
//! 1. Behaviour. The binary runs a full session with a database address in
//!    its environment that points at a listener this test owns. Any attempt
//!    to read that address and connect would land on the listener; none does.
//!    While the session is open, the child's file descriptors are listed: it
//!    holds no socket at all, so it neither listens (no `/api` route is
//!    reachable) nor holds a pool connection.
//! 2. Source. The scratch module and the binary contain no environment read,
//!    no sqlx or pool use, and never build the router.
//! 3. Manifest. The binary is gated on `scratch` alone, and `server` is still
//!    gated on `db` (that last part is `server_bin_requires_db.rs`'s job; it
//!    is unchanged).

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-scratch");
const SCOPE: &str = "3f9a1c07be52";

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("scratch-no-db-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// The kinds of open file descriptor of `pid`, e.g. `["pipe", "pipe",
/// "file", "socket"]`, from `/proc/<pid>/fd`.
#[cfg(target_os = "linux")]
fn fd_kinds(pid: u32) -> Vec<String> {
    let mut kinds = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
        let Ok(target) = fs::read_link(entry.unwrap().path()) else {
            continue; // closed between the listing and the readlink
        };
        let target = target.to_string_lossy().into_owned();
        let kind = if target.starts_with("socket:") {
            "socket"
        } else if target.starts_with("pipe:") {
            "pipe"
        } else if target.starts_with("anon_inode:") {
            "anon_inode"
        } else {
            "file"
        };
        kinds.push(kind.to_string());
    }
    kinds
}

#[test]
fn a_full_session_never_dials_the_database_address_and_holds_no_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    // Built at run time from host and port: no credential-shaped literal.
    let dsn = format!("postgres://127.0.0.1:{port}/scratch_probe");

    let dir = temp_dir();
    let graph = dir.join("graph.json");
    let mut child = Command::new(BIN)
        .arg("--snapshot")
        .arg(&graph)
        .args(["--scope", SCOPE, "--epoch", "0"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("DATABASE_URL", &dsn)
        .env("MIGRATION_DATABASE_URL", &dsn)
        .env("EPIGRAPH_DATABASE_URL", &dsn)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut call = |line: &str| -> serde_json::Value {
        stdin.write_all(line.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
        let mut out = String::new();
        stdout.read_line(&mut out).unwrap();
        serde_json::from_str(&out).unwrap()
    };

    let sha = "cd".repeat(32);
    let session = [
        r#"{"id":1,"op":"health"}"#.to_string(),
        format!(
            r#"{{"id":2,"op":"put_atoms","atoms":[{{"id":"00000000-0000-5000-8000-000000000001","text":"The pilot uses v2 probes.","kind":"decision","speaker":"user","turn":1,"epoch":0,"evidence":[{{"path":"turns/1.json","sha256":"{sha}"}}],"seed":{{"supported":0.7}}}}]}}"#
        ),
        r#"{"id":3,"op":"candidates","text":"probes"}"#.to_string(),
        r#"{"id":4,"op":"mark_applied","turn":1}"#.to_string(),
        r#"{"id":5,"op":"stats"}"#.to_string(),
        r#"{"id":6,"op":"snapshot"}"#.to_string(),
    ];
    for line in &session {
        let r = call(line);
        assert_eq!(r["ok"], true, "{line} -> {r}");
    }

    // The child is alive and idle, its graph written: list what it holds.
    #[cfg(target_os = "linux")]
    {
        let kinds = fd_kinds(child.id());
        assert!(
            !kinds.iter().any(|k| k == "socket"),
            "the scratch child holds a socket (a listener or a database connection): {kinds:?}"
        );
        assert!(
            kinds.iter().filter(|k| *k == "pipe").count() >= 3,
            "stdio pipes: {kinds:?}"
        );
    }

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    // Give a stray asynchronous dial time to arrive, then check nothing came.
    std::thread::sleep(Duration::from_millis(200));
    match listener.accept() {
        Ok((_, peer)) => panic!("the scratch binary connected to the database address from {peer}"),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
    }

    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert!(
        stderr.is_empty(),
        "a clean session writes nothing to stderr: {stderr}"
    );
    assert!(graph.exists());
    let _ = fs::remove_dir_all(&dir);
}

/// Every Rust source under `src/scratch/` plus the binary, with its path.
fn scratch_sources() -> Vec<(PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("src/bin/epigraph-scratch.rs")];
    let mut dirs = vec![root.join("src/scratch")];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let text = fs::read_to_string(&p).unwrap();
            (p, text)
        })
        .collect()
}

/// Code only: `//` comments (and so `//!` / `///` docs) removed.
fn code_of(text: &str) -> String {
    text.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_scratch_sources_read_no_environment_and_touch_no_database_or_router() {
    let sources = scratch_sources();
    let names: Vec<String> = sources
        .iter()
        .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    // Calibration: the walk found the files E1 adds, so an empty scan cannot pass.
    for expected in [
        "epigraph-scratch.rs",
        "mod.rs",
        "protocol.rs",
        "store.rs",
        "bm25.rs",
        "snapshot.rs",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "scan missed {expected}: {names:?}"
        );
    }
    const FORBIDDEN: &[&str] = &[
        "env::var",
        "var_os(",
        "vars()",
        "dotenv",
        "sqlx",
        "PgPool",
        "ScopedPool",
        "PgConnection",
        "epigraph_db::pool",
        "create_router",
        "AppState",
        "TcpListener",
        "TcpStream",
        "UnixListener",
        "UnixStream",
        "std::net",
        "tokio",
        "reqwest",
        "axum",
    ];
    let mut hits = Vec::new();
    for (path, text) in &sources {
        let code = code_of(text);
        for needle in FORBIDDEN {
            if code.contains(needle) {
                hits.push(format!("{}: {needle}", path.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the scratch path must stay database- and network-free: {hits:#?}"
    );

    // Calibration of the matcher itself: a source with these reads is caught.
    let probe =
        code_of("let u = std::env::var(\"DATABASE_URL\"); // fine\nlet p = PgPool::connect(&u);");
    assert!(probe.contains("env::var") && probe.contains("PgPool"));
    assert!(!code_of("// std::env::var in a comment").contains("env::var"));
}

#[test]
fn the_binary_is_gated_on_scratch_alone() {
    let manifest = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let block = manifest
        .split("[[bin]]")
        .skip(1)
        .find(|chunk| chunk.contains("name = \"epigraph-scratch\""))
        .map(|chunk| &chunk[..chunk.find("\n[").unwrap_or(chunk.len())])
        .expect("an epigraph-scratch [[bin]] block");
    let gate: Vec<&str> = block
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| l.starts_with("required-features"))
        .collect();
    assert_eq!(gate, vec!["required-features = [\"scratch\"]"], "{block}");

    let features = manifest.split("[features]").nth(1).unwrap();
    let features = &features[..features.find("\n[").unwrap()];
    let scratch: Vec<&str> = features
        .lines()
        .filter(|l| l.trim_start().starts_with("scratch"))
        .collect();
    assert_eq!(
        scratch,
        vec!["scratch = [\"dep:epigraph-db\"]"],
        "scratch must not pull in `db`"
    );
}
