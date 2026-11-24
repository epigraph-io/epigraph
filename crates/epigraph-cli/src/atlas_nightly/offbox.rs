//! The nightly's off-box hook (backlog 691d283a): the clustering the box does
//! not run (no UMAP here) goes through ONE operator-configured command, the
//! same off-box step the operator tools use, on ids and embeddings only.
//!
//! ```text
//! <command> theme-cap     <export-dir> <result-file>   # W1's theme_cap_core compute
//! <command> atlas-meaning <export-dir> <result-file>   # W4's atlas_meaning_core compute
//! ```
//!
//! The command reads the export directory (claim ids and embeddings, plus
//! W4's per-theme attachment integers: no text, no agent or evidence id, no
//! tenancy), writes the result file and exits 0. `scripts/atlas_offbox_compute.py`
//! is a reference command that computes in place; a real one copies the
//! directory to a compute host, runs the same compute there and copies the
//! result back.
//!
//! What the box keeps to itself:
//! * the command runs with a CLEARED environment (only `PATH`, `HOME` and
//!   `LANG`), so it never receives `DATABASE_URL`,
//!   `MAINTENANCE_DATABASE_URL` or any other credential of the nightly;
//! * it runs in its own process group with no stdin and its stdout discarded
//!   (the nightly's stdout is the JSON summary); at the timeout the whole
//!   group is killed;
//! * the export directory is created owner-only inside the configured work
//!   directory (which must itself be owner-only) and DELETED once the command
//!   returns, whatever it returned;
//! * nothing is exported or run without `--apply`.
//!
//! Every result is checked on the box as an operator's result is: W4's
//! `check_tree` for a meaning tree (ids minted from the members, leaves exactly
//! the members now), and `theme_cap_split.py`'s apply for a theme split (parts
//! exactly the live members, under the cap, one transaction, a manifest that
//! `reverse` restores from).

use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use epigraph_db::repos::atlas_map::AtlasMap;
use epigraph_db::Viewer;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::atlas_meaning::build::{export_map, ExportOptions};
use crate::atlas_meaning::files::{read_result, ResultDoc};
use crate::atlas_meaning::tree::map_key;

/// The first argument of a theme-split call.
pub const KIND_THEME_CAP: &str = "theme-cap";
/// The first argument of a meaning-tree call.
pub const KIND_ATLAS_MEANING: &str = "atlas-meaning";

/// The environment variables the command keeps; every other one is cleared.
pub const KEPT_ENV: [&str; 3] = ["PATH", "HOME", "LANG"];

/// The seed the meaning export records (`atlas_meaning export`'s default).
const MEANING_SEED: u64 = 42;

/// W1's split, run through `theme_cap_split.py offbox` (its export, the
/// command, and its apply, which writes a `reverse` manifest).
#[derive(Debug, Clone)]
pub struct ThemeCapSplit {
    /// The Python interpreter.
    pub python: PathBuf,
    /// `scripts/theme_cap_split.py`.
    pub script: PathBuf,
}

/// The configured hook.
#[derive(Debug, Clone)]
pub struct OffBox {
    /// The off-box command (one program; see the module documentation).
    pub command: PathBuf,
    /// Where exports, results and manifests go; must be an owner-only
    /// directory.
    pub work_dir: PathBuf,
    /// How long one call may take before its process group is killed.
    pub timeout: Duration,
    /// W1's split of the themes over the member cap; without it they are
    /// only reported.
    pub theme_cap_split: Option<ThemeCapSplit>,
}

/// Refuse a work directory that is missing, not a directory (a symlink
/// included), or readable by anyone but its owner: the exports hold
/// embeddings, which approximate claim text.
///
/// # Errors
/// Any of the above, or an I/O error.
pub fn check_work_dir(dir: &Path) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(dir)
        .with_context(|| format!("the off-box work directory {}", dir.display()))?;
    ensure!(
        meta.is_dir(),
        "the off-box work directory {} is not a directory (a symlink is refused too)",
        dir.display()
    );
    let mode = meta.permissions().mode() & 0o777;
    ensure!(
        mode & 0o077 == 0,
        "the off-box work directory {} has mode {mode:o}: it holds embeddings, so it must be \
         owner-only (chmod 700)",
        dir.display()
    );
    Ok(())
}

/// A new owner-only directory for one call under `work_dir`.
fn run_dir(work_dir: &Path, kind: &str) -> anyhow::Result<PathBuf> {
    check_work_dir(work_dir)?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let dir = work_dir.join(format!("{kind}-{stamp}-{}", Uuid::new_v4().simple()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

/// The environment the off-box command gets: [`KEPT_ENV`] from ours.
fn kept_env() -> Vec<(&'static str, OsString)> {
    KEPT_ENV
        .iter()
        .filter_map(|k| std::env::var_os(k).map(|v| (*k, v)))
        .collect()
}

/// Run `cmd` (already given its program and arguments) in its own process
/// group with no stdin, killing the group at `timeout`. Returns its stdout
/// when `capture`, else discards it. Its stderr goes to ours (the journal).
async fn run(
    mut cmd: tokio::process::Command,
    what: &str,
    timeout: Duration,
    capture: bool,
) -> anyhow::Result<Vec<u8>> {
    cmd.process_group(0)
        .stdin(Stdio::null())
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = cmd.spawn().with_context(|| format!("start {what}"))?;
    let pgid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(rustix::process::Pid::from_raw);
    let mut stdout = child.stdout.take();
    let finished = tokio::time::timeout(timeout, async {
        let mut buf = Vec::new();
        let read = async {
            if let Some(s) = stdout.as_mut() {
                tokio::io::AsyncReadExt::read_to_end(s, &mut buf).await?;
            }
            Ok::<(), std::io::Error>(())
        };
        let ((), status) = tokio::try_join!(read, child.wait())?;
        Ok::<_, std::io::Error>((status, buf))
    })
    .await;
    match finished {
        Ok(out) => {
            let (status, buf) = out.with_context(|| format!("wait for {what}"))?;
            if !status.success() {
                bail!("{what} exited with {status}");
            }
            Ok(buf)
        }
        Err(_) => {
            // The leader is not reaped yet, so the group id is still this
            // call's: kill the whole group, then reap the leader.
            if let Some(pgid) = pgid {
                let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
            }
            let _ = child.kill().await;
            bail!("{what} did not finish within {timeout:?}; its process group was killed")
        }
    }
}

impl OffBox {
    /// Run the command once: `<command> <kind> <export> <result>`, with the
    /// cleared environment.
    async fn call(&self, kind: &str, export: &Path, result: &Path) -> anyhow::Result<()> {
        let mut cmd = tokio::process::Command::new(&self.command);
        cmd.arg(kind).arg(export).arg(result).env_clear();
        for (k, v) in kept_env() {
            cmd.env(k, v);
        }
        run(
            cmd,
            &format!("the off-box command {}", self.command.display()),
            self.timeout,
            false,
        )
        .await
        .map(|_| ())
    }

    /// W4's meaning trees of `themes` on `map`, computed off the box:
    /// export them (owner-only, ids and embeddings), run the command, delete
    /// the export, and read the result back. The result must be for this
    /// map and hierarchy, at most this `cap`, and name exactly these themes
    /// (each tree is checked against the live members when the caller builds
    /// it).
    ///
    /// # Errors
    /// A work directory [`check_work_dir`] refuses, an export or database
    /// error, a failed or timed-out command, or a result that is not for
    /// these themes.
    pub async fn meaning_trees(
        &self,
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        themes: &[Uuid],
        cap: usize,
    ) -> anyhow::Result<ResultDoc> {
        let dir = run_dir(&self.work_dir, KIND_ATLAS_MEANING)?;
        let export = dir.join("export");
        let result = dir.join("result.json");
        let opts = ExportOptions {
            map,
            themes: Some(themes.to_vec()),
            cap,
            seed: MEANING_SEED,
        };
        let called = async {
            export_map(conn, viewer, &opts, &export).await?;
            self.call(KIND_ATLAS_MEANING, &export, &result).await
        }
        .await;
        // The embeddings never outlive the call, whatever it returned.
        if export.exists() {
            std::fs::remove_dir_all(&export)
                .with_context(|| format!("delete the export {}", export.display()))?;
        }
        called?;
        let doc = read_result(&result)?;
        ensure!(
            doc.map == map_key(map) && doc.hierarchy == "meaning",
            "the off-box result is for map {:?}, hierarchy {:?}",
            doc.map,
            doc.hierarchy
        );
        ensure!(
            doc.cap <= cap,
            "the off-box result was computed for a cap of {}, over the nightly's {cap}",
            doc.cap
        );
        let mut got: Vec<Uuid> = doc.themes.iter().map(|t| t.theme_id).collect();
        got.sort_unstable();
        let mut want = themes.to_vec();
        want.sort_unstable();
        want.dedup();
        ensure!(
            got == want,
            "the off-box result names themes {got:?}, not the exported {want:?}"
        );
        Ok(doc)
    }

    /// W1's split of `themes` (all over `theme_cap`) through
    /// `theme_cap_split.py offbox`: its export, this command, and its apply
    /// (which writes a manifest `reverse` restores from). The script runs on
    /// the box with the nightly's environment (it needs the maintenance
    /// DSN); it gives the command the same cleared environment. Returns the
    /// script's JSON report.
    ///
    /// # Errors
    /// No split configured, a work directory [`check_work_dir`] refuses, or
    /// a failed, timed-out or unreadable script run.
    pub async fn split_themes(&self, themes: &[Uuid], theme_cap: i64) -> anyhow::Result<Value> {
        let Some(split) = &self.theme_cap_split else {
            bail!("no theme split is configured");
        };
        let dir = run_dir(&self.work_dir, KIND_THEME_CAP)?;
        let mut cmd = tokio::process::Command::new(&split.python);
        cmd.arg(&split.script)
            .arg("offbox")
            .arg("--command")
            .arg(&self.command)
            .arg("--work-dir")
            .arg(&dir)
            .arg("--cap")
            .arg(theme_cap.to_string())
            .arg("--timeout")
            .arg(self.timeout.as_secs().max(1).to_string())
            .arg("--manifest")
            .arg(dir.join("manifest.json"));
        for t in themes {
            cmd.arg("--theme-id").arg(t.to_string());
        }
        // The script's own export, compute and apply all fit in the timeout,
        // plus the apply's margin.
        let out = run(
            cmd,
            &format!("{} offbox", split.script.display()),
            self.timeout.saturating_mul(2),
            true,
        )
        .await?;
        serde_json::from_slice(&out).context("the theme split's report is not JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!("atlas-offbox-{}", Uuid::new_v4()))
    }

    #[test]
    fn the_work_directory_must_be_an_owner_only_directory() {
        let d = scratch();
        assert!(check_work_dir(&d).is_err(), "a missing directory");
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o750)).unwrap();
        let err = check_work_dir(&d).unwrap_err().to_string();
        assert!(err.contains("owner-only"), "{err}");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        check_work_dir(&d).unwrap();
        let link = scratch();
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(check_work_dir(&link).is_err(), "a symlink");
        let run = run_dir(&d, KIND_THEME_CAP).unwrap();
        let mode = std::fs::metadata(&run).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::remove_file(&link).ok();
        std::fs::remove_dir_all(&d).ok();
    }

    /// A command that outlives the timeout is killed with what it started,
    /// and the call fails.
    #[tokio::test]
    async fn a_command_past_the_timeout_is_killed_with_its_group() {
        let d = scratch();
        std::fs::create_dir(&d).unwrap();
        let marker = d.join("survived");
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("(sleep 2; touch {}) & sleep 30", marker.display()));
        let started = std::time::Instant::now();
        let err = run(cmd, "the sleeper", Duration::from_millis(300), false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not finish"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!marker.exists(), "a process of the group outlived the kill");
        std::fs::remove_dir_all(&d).ok();
    }
}
