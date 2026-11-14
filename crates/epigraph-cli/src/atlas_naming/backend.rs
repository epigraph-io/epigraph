//! The model behind the naming step, as an injectable backend.
//!
//! [`ClaudeCliBackend`] is the only production backend: it spawns the Claude
//! CLI (`claude -p`) on the box, the path `scripts/lib/claude_cli.py` uses,
//! so the CLI's own sign-in serves the call. It never uses the Anthropic SDK
//! or an API key: `ANTHROPIC_API_KEY` is removed from the child's
//! environment. Claim text leaves the box only to the model, through that
//! CLI. Tests use [`RecordingBackend`], which never calls a model.

use std::io::{Read, Write};
use std::path::PathBuf;
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
/// How long one call may take before the child is killed.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Environment variables removed from the CLI's environment: an API key
/// would switch the CLI off its own sign-in (never an API key), and
/// `CLAUDECODE` marks a nested session.
pub const REMOVED_ENV: &[&str] = &["ANTHROPIC_API_KEY", "CLAUDECODE"];

/// `claude -p --output-format json --max-turns 1 --model M`, the prompt on
/// stdin, run in an empty owner-only directory and killed at the timeout.
#[derive(Debug)]
pub struct ClaudeCliBackend {
    program: PathBuf,
    model: String,
    timeout: Duration,
    workdir: PathBuf,
    env: Vec<(String, String)>,
}

impl ClaudeCliBackend {
    /// A backend running `program` (normally `claude` on `PATH`).
    ///
    /// # Errors
    /// The empty working directory could not be created.
    pub fn new(program: PathBuf, model: String, timeout: Duration) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let workdir = std::env::temp_dir().join(format!("atlas-naming-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&workdir)?;
        Ok(Self {
            program,
            model,
            timeout,
            workdir,
            env: Vec::new(),
        })
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

impl NameBackend for ClaudeCliBackend {
    fn complete(&self, prompt: &str) -> Result<String, BackendError> {
        let mut cmd = Command::new(&self.program);
        cmd.args([
            "-p",
            "--output-format",
            "json",
            "--max-turns",
            "1",
            "--model",
            &self.model,
        ])
        .current_dir(&self.workdir)
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
        let mut stdin = child.stdin.take().expect("piped stdin");
        let body = prompt.to_string();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(body.as_bytes());
        });
        let mut stdout = child.stdout.take().expect("piped stdout");
        let reader = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stdout.read_to_string(&mut s);
            s
        });
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    // Only the child this call spawned.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BackendError(format!(
                        "the CLI did not answer within {:?}",
                        self.timeout
                    )));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(BackendError(format!("wait for the CLI: {e}"))),
            }
        };
        let _ = writer.join();
        let out = reader.join().unwrap_or_default();
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

    /// A stub `claude`: prints `body` as its envelope only if it was called
    /// with `-p` and neither removed variable reached it.
    fn stub(dir: &std::path::Path, body: &str) -> PathBuf {
        let p = dir.join("claude");
        let script = format!(
            "#!/bin/sh\n\
             cat > /dev/null\n\
             if [ -n \"${{ANTHROPIC_API_KEY+x}}\" ]; then echo '{{\"is_error\":true,\"result\":\"api key seen\"}}'; exit 0; fi\n\
             if [ -n \"${{CLAUDECODE+x}}\" ]; then echo '{{\"is_error\":true,\"result\":\"nested\"}}'; exit 0; fi\n\
             if [ \"$1\" != \"-p\" ]; then echo '{{\"is_error\":true,\"result\":\"no -p\"}}'; exit 0; fi\n\
             {body}\n"
        );
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("atlas-naming-stub-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&d).unwrap();
        d
    }

    fn backend(program: PathBuf, timeout: Duration) -> ClaudeCliBackend {
        ClaudeCliBackend::new(program, DEFAULT_MODEL.into(), timeout).unwrap()
    }

    /// The CLI runs without an API key or the nested-session marker, even
    /// when both are set for it, and the envelope's result comes back.
    #[test]
    fn the_cli_runs_without_an_api_key() {
        let d = dir();
        let p = stub(
            &d,
            r#"echo '{"type":"result","is_error":false,"result":"{\"name\": \"Stub name\"}"}'"#,
        );
        let got = backend(p, Duration::from_secs(10))
            .with_env("ANTHROPIC_API_KEY", "sk-test-not-a-key")
            .with_env("CLAUDECODE", "1")
            .complete("prompt");
        assert_eq!(got, Ok("{\"name\": \"Stub name\"}".to_string()));
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
                backend(p, Duration::from_secs(10))
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
        let got = backend(p, Duration::from_millis(500)).complete("prompt");
        assert!(got.is_err());
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        let _ = std::fs::remove_dir_all(d);
    }
}
