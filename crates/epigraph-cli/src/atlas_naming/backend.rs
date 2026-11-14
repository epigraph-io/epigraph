//! The model behind the naming step, as an injectable backend.
//!
//! [`ClaudeCliBackend`] is the only production backend: it spawns the Claude
//! CLI (`claude -p`) on the box, the path `scripts/lib/claude_cli.py` uses,
//! so the CLI's own sign-in serves the call. It never uses the Anthropic SDK
//! or an API key: `ANTHROPIC_API_KEY` is removed from the child's
//! environment. Claim text leaves the box only to the model, through that
//! CLI. Tests use [`RecordingBackend`], which never calls a model.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A model call that produced no usable reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendError(pub String);

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BackendError {}

/// One prompt in, the model's reply text out.
pub trait NameBackend {
    /// Ask the model. An error is a failed reply: the group keeps its
    /// placeholder and is named on a later run.
    ///
    /// # Errors
    /// The call failed or returned nothing usable.
    fn complete(&self, prompt: &str) -> Result<String, BackendError>;
}

/// The model `scripts/label_themes_llm.py` labels themes with.
pub const DEFAULT_MODEL: &str = "claude-haiku-4-5-20251001";
/// How long one call may take, its output included, before the CLI's
/// process group is killed.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Environment variables removed from the CLI's environment: an API key
/// would switch the CLI off its own sign-in (never an API key), and
/// `CLAUDECODE` marks a nested session.
pub const REMOVED_ENV: &[&str] = &["ANTHROPIC_API_KEY", "CLAUDECODE"];

/// What the CLI is told to leave out, after `-p --output-format json
/// --max-turns 1 --model M`. The prompt carries claim text, which is
/// untrusted, and the call needs no tool, setting or memory:
///
/// * `--safe-mode`: no CLAUDE.md or memory discovery, skills, plugins, hooks
///   or MCP servers, while the CLI's own sign-in still serves the call
///   (`--bare` would turn the sign-in off and require an API key);
/// * `--restricted`: no command-running tools or WebFetch, and no user,
///   project or local settings files;
/// * `--tools ""`: no tool at all;
/// * `--strict-mcp-config` with no `--mcp-config`: no MCP server;
/// * `--setting-sources ""`: no settings source;
/// * `--disable-slash-commands`: no skill;
/// * `--no-session-persistence`: no session written to disk.
///
/// A CLI that does not know one of these flags fails the call, so the group
/// keeps its placeholder: it never runs with fewer guards.
pub const LOCKDOWN_FLAGS: &[&str] = &[
    "--safe-mode",
    "--restricted",
    "--tools",
    "",
    "--strict-mcp-config",
    "--setting-sources",
    "",
    "--disable-slash-commands",
    "--no-session-persistence",
];

/// The arguments one call runs the CLI with; the prompt goes on stdin.
#[must_use]
pub fn cli_args(model: &str) -> Vec<String> {
    let mut args: Vec<String> = [
        "-p",
        "--output-format",
        "json",
        "--max-turns",
        "1",
        "--model",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    args.push(model.to_string());
    args.extend(LOCKDOWN_FLAGS.iter().map(|s| (*s).to_string()));
    args
}

fn refuse(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
}

/// Where the working directories live: `$XDG_RUNTIME_DIR/atlas-naming` when
/// that is set, otherwise `$HOME/.cache/epigraph/atlas-naming`. Never the
/// system temp dir: the CLI may look for instruction files in the working
/// directory's ancestors, and anyone can write to a temp dir.
///
/// # Errors
/// Neither variable names an absolute directory.
pub fn workdir_base(
    xdg_runtime_dir: Option<&OsStr>,
    home: Option<&OsStr>,
) -> std::io::Result<PathBuf> {
    let absolute = |v: Option<&OsStr>| {
        v.filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if let Some(x) = absolute(xdg_runtime_dir) {
        return Ok(x.join("atlas-naming"));
    }
    if let Some(h) = absolute(home) {
        return Ok(h.join(".cache").join("epigraph").join("atlas-naming"));
    }
    Err(refuse(
        "neither XDG_RUNTIME_DIR nor HOME names an absolute directory for the Claude CLI's \
         working directory"
            .into(),
    ))
}

/// `dir` is a real directory (not a link) owned by this process's user with
/// no group or other permission bits.
fn check_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() {
        return Err(refuse(format!("{} is not a directory", dir.display())));
    }
    let me = rustix::process::geteuid().as_raw();
    if meta.uid() != me {
        return Err(refuse(format!(
            "{} is owned by uid {}, not this user ({me})",
            dir.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(refuse(format!(
            "{} has mode {:o}; it must be 0700",
            dir.display(),
            meta.mode() & 0o7777
        )));
    }
    Ok(())
}

/// No ancestor of `dir` may be writable by anyone but this user or root: an
/// instruction file planted in one would reach every call.
fn check_ancestors(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let me = rustix::process::geteuid().as_raw();
    for a in dir.ancestors().skip(1) {
        let meta = std::fs::metadata(a)?;
        if (meta.uid() != me && meta.uid() != 0) || meta.mode() & 0o022 != 0 {
            return Err(refuse(format!(
                "{} (uid {}, mode {:o}) is writable by another user; the Claude CLI's working \
                 directory must not sit under it",
                a.display(),
                meta.uid(),
                meta.mode() & 0o7777
            )));
        }
    }
    Ok(())
}

/// Create `base` (0700) if it is missing and check it is private: owned by
/// this user with no group or other bits, and under no directory another
/// user may write.
///
/// # Errors
/// It could not be created, or a check failed.
pub fn ensure_private_base(base: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(base)?;
    check_private(base)?;
    check_ancestors(base)
}

/// `claude -p` (see [`cli_args`]), the prompt on stdin, run in its own
/// process group in an empty owner-only directory, and the whole group
/// killed at the timeout.
#[derive(Debug)]
pub struct ClaudeCliBackend {
    program: PathBuf,
    model: String,
    timeout: Duration,
    workdir: PathBuf,
    env: Vec<(String, String)>,
}

impl ClaudeCliBackend {
    /// A backend running `program` (normally `claude` on `PATH`), its
    /// working directory under [`workdir_base`] of this process's
    /// environment, checked by [`ensure_private_base`].
    ///
    /// # Errors
    /// No private base directory, or the working directory could not be
    /// created.
    pub fn new(program: PathBuf, model: String, timeout: Duration) -> std::io::Result<Self> {
        let base = workdir_base(
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )?;
        ensure_private_base(&base)?;
        Self::in_base(&base, program, model, timeout)
    }

    /// A backend whose working directory is a fresh 0700 directory in
    /// `base`, which must exist and be private ([`check_private`]: owned by
    /// this user, no group or other bits). [`ClaudeCliBackend::new`] also
    /// checks `base`'s ancestors.
    ///
    /// # Errors
    /// `base` is not private, or the working directory could not be created.
    pub fn in_base(
        base: &Path,
        program: PathBuf,
        model: String,
        timeout: Duration,
    ) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        check_private(base)?;
        let workdir = base.join(format!("atlas-naming-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&workdir)?;
        Ok(Self {
            program,
            model,
            timeout,
            workdir,
            env: Vec::new(),
        })
    }

    /// The directory the CLI runs in.
    #[must_use]
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// Set `key` on the child. [`REMOVED_ENV`] is applied after, so a removed
    /// variable never reaches the CLI however it was set (the tests set them
    /// here instead of on this process).
    #[must_use]
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }
}

impl Drop for ClaudeCliBackend {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

/// The `result` of the CLI's JSON envelope.
fn envelope_result(stdout: &str) -> Result<String, BackendError> {
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| BackendError(format!("the CLI printed no JSON envelope: {e}")))?;
    let result = v
        .get("result")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if v.get("is_error").and_then(serde_json::Value::as_bool) == Some(true) {
        let head: String = result.chars().take(200).collect();
        return Err(BackendError(format!("the CLI reported an error: {head}")));
    }
    if result.is_empty() {
        return Err(BackendError("the CLI returned an empty result".into()));
    }
    Ok(result)
}

/// Kill the process group this call started (its leader is the CLI, whose
/// pid is the group id).
fn kill_group(pgid: rustix::process::Pid) {
    let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
}

impl NameBackend for ClaudeCliBackend {
    fn complete(&self, prompt: &str) -> Result<String, BackendError> {
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new(&self.program);
        cmd.args(cli_args(&self.model))
            .current_dir(&self.workdir)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        for k in REMOVED_ENV {
            cmd.env_remove(k);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| BackendError(format!("spawn {}: {e}", self.program.display())))?;
        let pgid = rustix::process::Pid::from_child(&child);
        let deadline = Instant::now() + self.timeout;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let body = prompt.to_string();
        // Detached: it ends when the prompt is written or the pipe closes.
        std::thread::spawn(move || {
            let _ = stdin.write_all(body.as_bytes());
        });
        let mut stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stdout.read_to_string(&mut s);
            let _ = tx.send(s);
        });
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    // The child is not reaped yet, so its group id is still
                    // this call's.
                    kill_group(pgid);
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BackendError(format!(
                        "the CLI did not answer within {:?}",
                        self.timeout
                    )));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => {
                    kill_group(pgid);
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BackendError(format!("wait for the CLI: {e}")));
                }
            }
        };
        // The output may still be held open by a process the CLI started;
        // it gets what is left of the same deadline.
        let out = match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(s) => s,
            Err(_) => {
                // Something in the group still holds the pipe, so the group
                // still exists and its id is still this call's.
                kill_group(pgid);
                return Err(BackendError(format!(
                    "the CLI's output was still open after {:?}",
                    self.timeout
                )));
            }
        };
        if !status.success() {
            return Err(BackendError(format!("the CLI exited with {status}")));
        }
        envelope_result(&out)
    }
}

type ReplyFn = dyn Fn(&str) -> Result<String, BackendError> + Send + Sync;

/// A test backend: a scripted reply, a call counter and every prompt it
/// received. It never calls a model.
pub struct RecordingBackend {
    reply: Box<ReplyFn>,
    prompts: Mutex<Vec<String>>,
}

impl RecordingBackend {
    pub fn new(
        reply: impl Fn(&str) -> Result<String, BackendError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            reply: Box::new(reply),
            prompts: Mutex::new(Vec::new()),
        }
    }

    /// How many calls it answered.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.prompts.lock().expect("prompts lock").len()
    }

    /// Every prompt it received, in order.
    #[must_use]
    pub fn prompts(&self) -> Vec<String> {
        self.prompts.lock().expect("prompts lock").clone()
    }
}

impl NameBackend for RecordingBackend {
    fn complete(&self, prompt: &str) -> Result<String, BackendError> {
        self.prompts
            .lock()
            .expect("prompts lock")
            .push(prompt.to_string());
        (self.reply)(prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stub `claude`: records its argument count, each argument on its own
    /// line and its working directory in `<dir>/argv`, then prints `body` as
    /// its envelope only if it was called with `-p` and neither removed
    /// variable reached it.
    fn stub(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("claude");
        let rec = dir.join("argv");
        let script = format!(
            "#!/bin/sh\n\
             cat > /dev/null\n\
             {{ echo \"$#\"; for a in \"$@\"; do printf '%s\\n' \"$a\"; done; pwd; }} > '{rec}'\n\
             if [ -n \"${{ANTHROPIC_API_KEY+x}}\" ]; then echo '{{\"is_error\":true,\"result\":\"api key seen\"}}'; exit 0; fi\n\
             if [ -n \"${{CLAUDECODE+x}}\" ]; then echo '{{\"is_error\":true,\"result\":\"nested\"}}'; exit 0; fi\n\
             if [ \"$1\" != \"-p\" ]; then echo '{{\"is_error\":true,\"result\":\"no -p\"}}'; exit 0; fi\n\
             {body}\n",
            rec = rec.display()
        );
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    /// A fresh 0700 directory for one test (it holds the stub and is the
    /// backend's base).
    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("atlas-naming-stub-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn backend(d: &Path, program: PathBuf, timeout: Duration) -> ClaudeCliBackend {
        ClaudeCliBackend::in_base(d, program, DEFAULT_MODEL.into(), timeout).unwrap()
    }

    const OK_BODY: &str =
        r#"echo '{"type":"result","is_error":false,"result":"{\"name\": \"Stub name\"}"}'"#;

    /// The CLI runs without an API key or the nested-session marker, even
    /// when both are set for it, and the envelope's result comes back.
    #[test]
    fn the_cli_runs_without_an_api_key() {
        let d = dir();
        let p = stub(&d, OK_BODY);
        let got = backend(&d, p, Duration::from_secs(10))
            .with_env("ANTHROPIC_API_KEY", "sk-test-not-a-key")
            .with_env("CLAUDECODE", "1")
            .complete("prompt");
        assert_eq!(got, Ok("{\"name\": \"Stub name\"}".to_string()));
        let _ = std::fs::remove_dir_all(d);
    }

    /// The exact argv, written out here rather than read from the constants
    /// the backend builds it from: every tool, setting source, MCP server,
    /// skill and instruction file is switched off, and the CLI runs in the
    /// backend's private working directory.
    #[test]
    fn the_cli_is_called_with_every_guard() {
        let d = dir();
        let p = stub(&d, OK_BODY);
        let b = backend(&d, p, Duration::from_secs(10));
        assert_eq!(
            b.complete("prompt"),
            Ok("{\"name\": \"Stub name\"}".to_string())
        );
        let rec = std::fs::read_to_string(d.join("argv")).unwrap();
        let lines: Vec<&str> = rec.lines().collect();
        let expected = [
            "16",
            "-p",
            "--output-format",
            "json",
            "--max-turns",
            "1",
            "--model",
            "claude-haiku-4-5-20251001",
            "--safe-mode",
            "--restricted",
            "--tools",
            "",
            "--strict-mcp-config",
            "--setting-sources",
            "",
            "--disable-slash-commands",
            "--no-session-persistence",
        ];
        assert_eq!(&lines[..lines.len() - 1], &expected[..]);
        let cwd = PathBuf::from(lines[lines.len() - 1]);
        assert_eq!(
            std::fs::canonicalize(&cwd).unwrap(),
            std::fs::canonicalize(b.workdir()).unwrap()
        );
        assert_eq!(cwd.parent(), Some(d.as_path()), "{}", cwd.display());
        drop(b);
        let _ = std::fs::remove_dir_all(d);
    }

    /// The working directory's base comes from XDG_RUNTIME_DIR, else HOME,
    /// and never from the system temp dir.
    #[test]
    fn the_workdir_base_is_the_users_own() {
        let os = |s: &str| std::ffi::OsString::from(s);
        assert_eq!(
            workdir_base(Some(&os("/run/user/1000")), Some(&os("/home/u"))).unwrap(),
            PathBuf::from("/run/user/1000/atlas-naming")
        );
        for xdg in [None, Some(os("")), Some(os("relative/dir"))] {
            assert_eq!(
                workdir_base(xdg.as_deref(), Some(&os("/home/u"))).unwrap(),
                PathBuf::from("/home/u/.cache/epigraph/atlas-naming")
            );
        }
        assert!(workdir_base(None, None).is_err());
        assert!(workdir_base(Some(&os("")), Some(&os("rel"))).is_err());
        let tmp = std::env::temp_dir();
        assert!(!workdir_base(None, Some(&os("/home/u")))
            .unwrap()
            .starts_with(&tmp));
    }

    /// A base with group or other bits is refused, and so is a base under a
    /// directory another user may write, even when the base itself is 0700.
    #[test]
    fn a_shared_base_or_ancestor_is_refused() {
        let d = dir();
        let p = stub(&d, OK_BODY);
        let open = d.join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = ClaudeCliBackend::in_base(
            &open,
            p.clone(),
            DEFAULT_MODEL.into(),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(ensure_private_base(&open).is_err());

        let shared = d.join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        let base = shared.join("base");
        let err = ensure_private_base(&base).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        // The nearest offending ancestor is the one named.
        assert!(
            err.to_string().contains(&shared.display().to_string()),
            "{err}"
        );
        // The base itself was made 0700 and passes the base check alone.
        assert!(
            ClaudeCliBackend::in_base(&base, p, DEFAULT_MODEL.into(), Duration::from_secs(1))
                .is_ok()
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn an_error_envelope_an_empty_result_and_a_bad_exit_are_errors() {
        let d = dir();
        for body in [
            r#"echo '{"is_error":true,"result":"rate limited"}'"#,
            r#"echo '{"is_error":false,"result":""}'"#,
            "echo not-json",
            r#"echo '{"is_error":false,"result":"x"}'; exit 3"#,
        ] {
            let p = stub(&d, body);
            assert!(
                backend(&d, p, Duration::from_secs(10))
                    .complete("prompt")
                    .is_err(),
                "{body}"
            );
        }
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_hung_cli_is_killed_at_the_timeout() {
        let d = dir();
        let p = stub(&d, "exec sleep 30");
        let t = Instant::now();
        let got = backend(&d, p, Duration::from_millis(500)).complete("prompt");
        assert!(got.is_err());
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        let _ = std::fs::remove_dir_all(d);
    }

    /// A process the CLI leaves behind holding its output open does not
    /// stretch the call past the timeout, and is killed with the group.
    #[test]
    fn a_process_left_holding_the_output_is_killed_at_the_timeout() {
        let d = dir();
        let pidfile = d.join("grandchild");
        let p = stub(
            &d,
            &format!(
                "sleep 30 &\necho $! > '{}'\n{OK_BODY}\nexit 0",
                pidfile.display()
            ),
        );
        let t = Instant::now();
        let got = backend(&d, p, Duration::from_millis(1500)).complete("prompt");
        let took = t.elapsed();
        assert!(got.is_err(), "{got:?}");
        assert!(took < Duration::from_secs(10), "{took:?}");
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        let stat = format!("/proc/{}/stat", pid.trim());
        // Killed: gone, or a zombie waiting for whoever adopted it.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match std::fs::read_to_string(&stat) {
                Err(_) => break,
                Ok(s)
                    if s.rsplit(')')
                        .next()
                        .unwrap_or("")
                        .trim_start()
                        .starts_with('Z') =>
                {
                    break
                }
                Ok(s) => assert!(Instant::now() < deadline, "still running: {s}"),
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = std::fs::remove_dir_all(d);
    }
}
