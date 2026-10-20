//! `plan_label_dedup`, `apply_label_dedup` and `probe_label_dedup`: thin MCP
//! tools over the pure `epigraph_engine::label_dedup` planner.
//!
//! # The profile
//!
//! Every family rule comes from a `label-dedup-profile/v1` document pinned by
//! `profile_hash` (BLAKE3 of its exact bytes). How it may arrive depends on
//! the transport:
//!
//! * **stdio**: `profile_path` only, resolved under the profile root this
//!   process was started with ([`PROFILE_ROOT_ENV`]). Every component below
//!   the root is checked with `lstat` (a symlink anywhere is refused), the
//!   file is opened `O_NOFOLLOW | O_NONBLOCK` (a symlink swapped in, or a
//!   FIFO, is refused rather than followed or waited on) and must be a
//!   regular file. When the process was also given a pin
//!   ([`PROFILE_PIN_ENV`]), `profile_hash` must equal it, so the agent
//!   talking to the process cannot pick another profile. `profile_json` is
//!   refused.
//! * **HTTP**: `profile_json` only.
//!
//! A missing file and an unreadable one give the same `PROFILE_NOT_FOUND`
//! answer. `profile_claim_id` (a stored profile claim) is reserved and
//! refused until stamped private reads exist for it.
//!
//! # Reads
//!
//! Every family read is [`ClaimRepository::list_all_by_labels_ordered_by_id`]
//! on ONE connection stamped from the caller's viewer (`ScopedPool::read_as`),
//! so a caller sees exactly the rows it may read: its own group-private rows
//! included (an unstamped session would lose them under row security), other
//! groups' private rows never. `max_claims` (default and server cap
//! [`DEFAULT_MAX_CLAIMS`]) caps each read; a larger request is clamped and the
//! clamp reported, and a read that hit the cap is reported truncated.
//!
//! # Writes
//!
//! `apply_label_dedup` re-plans from live state, refuses a truncated read
//! (`TRUNCATED`) or a changed plan (`PLAN_DRIFT`) before writing anything,
//! then writes each unit in ONE transaction stamped from the write identity,
//! every claim through `update_labels`' own per-claim path
//! ([`crate::tools::claims::relabel_claim`]). The profile's closed label is
//! gated like `resolved`. A refused claim fails its whole unit; later units
//! continue. The response's `applied_units` lists the labels each committed
//! write actually changed: the revert input
//! (`epigraph_engine::label_dedup::revert_writes`).

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use epigraph_engine::label_dedup::{
    self as engine, AppliedLabelChange, DedupClaim, LabelDedupError, LabelDedupProfile, PlanInputs,
    PlanRequest, ProbeCandidate, ReadPurpose, ReadSpec, Section, Snapshot, WriteUnit,
};
use rmcp::model::{CallToolResult, Content, ErrorCode};
use serde_json::{json, Value};

use crate::errors::{db_caller_error, internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::claims::OwnershipGrant;
use crate::types::{ApplyLabelDedupParams, PlanLabelDedupParams, ProbeLabelDedupParams};

/// The default and the server cap of `max_claims`.
pub const DEFAULT_MAX_CLAIMS: usize = 5000;

/// The largest profile accepted, from a file or inline.
pub const MAX_PROFILE_BYTES: usize = 1 << 20;

/// The environment variable naming the directory stdio `profile_path` must
/// resolve under.
pub const PROFILE_ROOT_ENV: &str = "EPIGRAPH_MCP_PROFILE_ROOT";
/// The environment variable carrying the profile hash a stdio caller must pin.
pub const PROFILE_PIN_ENV: &str = "EPIGRAPH_MCP_PROFILE_PIN";

/// Refusal codes this module adds to the engine's (`LabelDedupError::code`).
pub mod codes {
    pub const PROFILE_PATH_REFUSED: &str = "PROFILE_PATH_REFUSED";
    pub const PROFILE_JSON_REFUSED: &str = "PROFILE_JSON_REFUSED";
    pub const PROFILE_NOT_FOUND: &str = "PROFILE_NOT_FOUND";
    pub const PROFILE_TOO_LARGE: &str = "PROFILE_TOO_LARGE";
    pub const PROFILE_SOURCE_REQUIRED: &str = "PROFILE_SOURCE_REQUIRED";
    pub const PROFILE_CLAIM_DEFERRED: &str = "PROFILE_CLAIM_DEFERRED";
    pub const PROFILE_HASH_MISMATCH: &str = "PROFILE_HASH_MISMATCH";
    pub const INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";
    pub const PLAN_DRIFT: &str = "PLAN_DRIFT";
}

/// Per-process label-dedup settings, read once at startup.
#[derive(Debug, Clone)]
pub struct LabelDedupConfig {
    /// Where stdio `profile_path` must resolve. `None`: path mode refused.
    pub profile_root: Option<PathBuf>,
    /// The hash a stdio `profile_hash` must equal. `None`: no pin.
    pub profile_pin: Option<String>,
    /// The server cap on `max_claims`.
    pub max_claims_cap: usize,
}

impl Default for LabelDedupConfig {
    fn default() -> Self {
        Self {
            profile_root: None,
            profile_pin: None,
            max_claims_cap: DEFAULT_MAX_CLAIMS,
        }
    }
}

impl LabelDedupConfig {
    /// Read [`PROFILE_ROOT_ENV`] and [`PROFILE_PIN_ENV`]; an empty value is
    /// unset.
    #[must_use]
    pub fn from_env() -> Self {
        let var = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        Self {
            profile_root: var(PROFILE_ROOT_ENV).map(PathBuf::from),
            profile_pin: var(PROFILE_PIN_ENV),
            max_claims_cap: DEFAULT_MAX_CLAIMS,
        }
    }
}

// ── Errors and output ───────────────────────────────────────────────────────

fn refusal(code: &str, detail: impl std::fmt::Display) -> McpError {
    McpError {
        code: ErrorCode::INVALID_PARAMS,
        message: format!("{code}: {detail}").into(),
        data: Some(json!({ "code": code })),
    }
}

fn engine_refusal(e: &LabelDedupError) -> McpError {
    McpError {
        code: ErrorCode::INVALID_PARAMS,
        message: e.to_string().into(),
        data: Some(json!({ "code": e.code() })),
    }
}

fn success_json(value: &Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// A hash as the pin and the plan hash are compared: trimmed, lowercase.
fn canonical_hash(h: &str) -> String {
    h.trim().to_ascii_lowercase()
}

// ── The profile ─────────────────────────────────────────────────────────────

struct ProfileArgs<'a> {
    path: Option<&'a str>,
    json: Option<&'a str>,
    claim_id: Option<&'a str>,
    hash: &'a str,
}

/// Load and verify the profile for this transport. Returns the profile and
/// its canonical hash.
fn load_profile(
    server: &EpiGraphMcpFull,
    auth: Option<&epigraph_auth::AuthContext>,
    args: &ProfileArgs<'_>,
) -> Result<(LabelDedupProfile, String), McpError> {
    if args.claim_id.is_some() {
        return Err(refusal(
            codes::PROFILE_CLAIM_DEFERRED,
            "reading the profile from a stored claim is not available yet; pass profile_path \
             (stdio) or profile_json (HTTP)",
        ));
    }
    let http = auth.is_some();
    let cfg = &server.label_dedup;
    let bytes = match (args.path, args.json) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(refusal(
                codes::PROFILE_SOURCE_REQUIRED,
                "pass exactly one of profile_path (stdio) or profile_json (HTTP)",
            ))
        }
        (Some(_), None) if http => {
            return Err(refusal(
                codes::PROFILE_PATH_REFUSED,
                "profile_path is read only on stdio; over HTTP pass profile_json",
            ))
        }
        (None, Some(_)) if !http => {
            return Err(refusal(
                codes::PROFILE_JSON_REFUSED,
                "on stdio the profile is read from profile_path under this server's profile \
                 root, never inline",
            ))
        }
        (Some(path), None) => {
            check_pin(cfg.profile_pin.as_deref(), args.hash)?;
            read_profile_file(cfg.profile_root.as_deref(), path)?
        }
        (None, Some(text)) => {
            if text.len() > MAX_PROFILE_BYTES {
                return Err(refusal(
                    codes::PROFILE_TOO_LARGE,
                    format!("the profile is larger than {MAX_PROFILE_BYTES} bytes"),
                ));
            }
            text.as_bytes().to_vec()
        }
    };
    let (profile, hash) =
        LabelDedupProfile::load_pinned(&bytes, args.hash).map_err(|e| engine_refusal(&e))?;
    Ok((profile, canonical_hash(&hash)))
}

/// On stdio with a pin, the caller's hash must be the pin.
fn check_pin(pin: Option<&str>, hash: &str) -> Result<(), McpError> {
    match pin {
        Some(pin) if canonical_hash(pin) != canonical_hash(hash) => Err(refusal(
            codes::PROFILE_HASH_MISMATCH,
            "profile_hash is not the profile this server was pinned to",
        )),
        _ => Ok(()),
    }
}

fn path_refused(path: &str, why: &str) -> McpError {
    refusal(
        codes::PROFILE_PATH_REFUSED,
        format!("profile_path {path:?}: {why}"),
    )
}

/// The one answer for a profile that is absent or that this process cannot
/// read: the two are indistinguishable to the caller.
fn profile_not_found(path: &str) -> McpError {
    refusal(
        codes::PROFILE_NOT_FOUND,
        format!("profile_path {path:?}: no readable profile at this path under the profile root"),
    )
}

/// Read the profile at `path` under `root`. See the module doc.
fn read_profile_file(root: Option<&Path>, path: &str) -> Result<Vec<u8>, McpError> {
    let Some(root) = root else {
        return Err(path_refused(
            path,
            "this server has no profile root (EPIGRAPH_MCP_PROFILE_ROOT is unset), so path \
             mode is off",
        ));
    };
    let given = Path::new(path);
    if given
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(path_refused(path, "`..` is not allowed"));
    }
    let relative = if given.is_absolute() {
        given
            .strip_prefix(root)
            .map_err(|_| path_refused(path, "outside the profile root"))?
    } else {
        given
    };
    let names: Vec<&std::ffi::OsStr> = relative
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        return Err(path_refused(path, "names no file under the profile root"));
    }

    // lstat every component below the root: a symlink anywhere is refused,
    // every intermediate must be a directory and the last a regular file.
    let mut full = root.to_path_buf();
    for (i, name) in names.iter().enumerate() {
        full.push(name);
        let meta = std::fs::symlink_metadata(&full).map_err(|_| profile_not_found(path))?;
        if meta.file_type().is_symlink() {
            return Err(path_refused(path, "a symlink is never followed"));
        }
        let last = i + 1 == names.len();
        if !last && !meta.is_dir() {
            return Err(profile_not_found(path));
        }
        if last && !meta.is_file() {
            return Err(path_refused(path, "not a regular file"));
        }
    }

    // O_NOFOLLOW: a symlink swapped in after the lstat fails the open (ELOOP).
    // O_NONBLOCK: a FIFO swapped in never blocks the open.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&full)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                path_refused(path, "a symlink is never followed")
            } else {
                profile_not_found(path)
            }
        })?;
    let meta = file.metadata().map_err(|_| profile_not_found(path))?;
    if !meta.is_file() {
        return Err(path_refused(path, "not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_PROFILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| profile_not_found(path))?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(refusal(
            codes::PROFILE_TOO_LARGE,
            format!("the profile is larger than {MAX_PROFILE_BYTES} bytes"),
        ));
    }
    Ok(bytes)
}

// ── Arguments ───────────────────────────────────────────────────────────────

/// `max_claims` as requested and as served.
#[derive(Debug, Clone, Copy)]
struct MaxClaims {
    requested: Option<i64>,
    effective: usize,
    clamped: bool,
}

impl MaxClaims {
    fn resolve(cap: usize, requested: Option<i64>) -> Result<Self, McpError> {
        let cap = cap.max(1);
        match requested {
            None => Ok(Self {
                requested: None,
                effective: DEFAULT_MAX_CLAIMS.min(cap),
                clamped: false,
            }),
            Some(n) if n < 1 => Err(refusal(
                codes::INVALID_ARGUMENT,
                format!("max_claims must be at least 1, got {n}"),
            )),
            Some(n) => {
                let n = usize::try_from(n).unwrap_or(usize::MAX);
                Ok(Self {
                    requested,
                    effective: n.min(cap),
                    clamped: n > cap,
                })
            }
        }
    }

    fn json(self) -> Value {
        json!({
            "requested": self.requested,
            "effective": self.effective,
            "clamped": self.clamped,
        })
    }
}

fn parse_sections(raw: &[String]) -> Result<Vec<Section>, McpError> {
    raw.iter()
        .map(|s| {
            serde_json::from_value::<Section>(Value::String(s.trim().to_string())).map_err(|_| {
                refusal(
                    codes::INVALID_ARGUMENT,
                    format!(
                        "unknown section {s:?}; expected hygiene, dedup, closeout, lifecycle or \
                         signal_dedup"
                    ),
                )
            })
        })
        .collect()
}

fn parse_as_of(raw: Option<&str>) -> Result<Option<NaiveDate>, McpError> {
    raw.map(|s| {
        NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").map_err(|_| {
            refusal(
                codes::INVALID_ARGUMENT,
                format!("as_of must be YYYY-MM-DD, got {s:?}"),
            )
        })
    })
    .transpose()
}

/// Everything a plan needs, validated.
struct Prepared {
    profile: LabelDedupProfile,
    profile_hash: String,
    run_tag: String,
    as_of: Option<NaiveDate>,
    sections: Vec<Section>,
    max: MaxClaims,
}

fn prepare(
    server: &EpiGraphMcpFull,
    auth: Option<&epigraph_auth::AuthContext>,
    profile: &ProfileArgs<'_>,
    run_tag: &str,
    as_of: Option<&str>,
    sections: &[String],
    max_claims: Option<i64>,
) -> Result<Prepared, McpError> {
    let max = MaxClaims::resolve(server.label_dedup.max_claims_cap, max_claims)?;
    let sections = parse_sections(sections)?;
    let as_of = parse_as_of(as_of)?;
    let (profile, profile_hash) = load_profile(server, auth, profile)?;
    Ok(Prepared {
        profile,
        profile_hash,
        run_tag: run_tag.to_string(),
        as_of,
        sections,
        max,
    })
}

// ── Reads ───────────────────────────────────────────────────────────────────

/// Perform `specs` on one connection stamped from `viewer`.
async fn read_family(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    specs: &[ReadSpec],
    cap: usize,
) -> Result<(Vec<(ReadPurpose, Snapshot)>, DateTime<Utc>), McpError> {
    let scoped = server.scoped.as_ref().ok_or_else(|| {
        internal_error(
            "label-dedup reads need a ScopedPool (EpiGraphMcpFull::with_scoped_pool): an \
             unstamped read would silently drop the caller's own group-private rows",
        )
    })?;
    let cap_i64 = i64::try_from(cap).unwrap_or(i64::MAX);
    let mut read = scoped.read_as(viewer).await.map_err(db_caller_error)?;
    let snapshot_at = Utc::now();
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let rows = ClaimRepository::list_all_by_labels_ordered_by_id(
            &mut *read,
            viewer,
            &spec.include,
            &spec.exclude,
            spec.current_only,
            cap_i64,
        )
        .await
        .map_err(db_caller_error)?;
        let claims = rows
            .into_iter()
            .map(|r| DedupClaim {
                id: r.id,
                content: r.content,
                labels: r.labels,
                created_at: Some(r.created_at),
            })
            .collect();
        out.push((spec.purpose, Snapshot::from_capped(claims, cap)));
    }
    read.commit().await.map_err(db_caller_error)?;
    Ok((out, snapshot_at))
}

/// Read the family as `viewer` and plan.
async fn compute_plan(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    p: &Prepared,
) -> Result<(engine::Plan, DateTime<Utc>), McpError> {
    let specs = p
        .profile
        .reads(&p.sections)
        .map_err(|e| engine_refusal(&e))?;
    let (snaps, at) = read_family(server, viewer, &specs, p.max.effective).await?;
    let mut inputs = PlanInputs::default();
    for (purpose, snap) in snaps {
        match purpose {
            ReadPurpose::Members => inputs.members = snap,
            ReadPurpose::LifecycleSignals => inputs.lifecycle_signals = Some(snap),
            ReadPurpose::LifecycleTargets => inputs.lifecycle_targets = Some(snap),
            ReadPurpose::SignalMembers => inputs.signal_members = Some(snap),
            ReadPurpose::ClosedSignals => {}
        }
    }
    let req = PlanRequest {
        profile: &p.profile,
        profile_hash: &p.profile_hash,
        run_tag: &p.run_tag,
        as_of: p.as_of,
        sections: &p.sections,
    };
    let plan = engine::plan(&req, &inputs).map_err(|e| engine_refusal(&e))?;
    Ok((plan, at))
}

/// The plan as the tools return it: the engine's plan plus the snapshot time,
/// the `max_claims` report and the write units apply would run.
fn plan_json(plan: &engine::Plan, at: DateTime<Utc>, max: MaxClaims) -> Result<Value, McpError> {
    let mut v = serde_json::to_value(plan).map_err(internal_error)?;
    v["coverage"]["snapshot_at"] = json!(at.to_rfc3339());
    v["max_claims"] = max.json();
    v["write_units"] = serde_json::to_value(plan.write_units()).map_err(internal_error)?;
    Ok(v)
}

/// Labels this profile treats as retirement, beyond `resolved`: the closed
/// labels of both passes. Adding or removing one takes the ownership gate.
fn retirement_labels(profile: &LabelDedupProfile) -> Vec<String> {
    let mut out: Vec<String> = profile
        .pass
        .closed_label
        .iter()
        .chain(
            profile
                .signal_dedup
                .iter()
                .flat_map(|p| p.closed_label.iter()),
        )
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

// ── write_check: a prediction, never a write ────────────────────────────────

/// Predict, per write target, whether the write identity may write it: the
/// same non-writing gates `update_labels` runs (ownership over HTTP, the
/// retirement-label gate, the owner group in the writer's set or the admin
/// path). Row-security refusals the database alone decides (an operator
/// binding, a revoked membership raced in) are not modelled; apply reports
/// those per unit.
async fn write_check(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    units: &[WriteUnit],
    retirement: &[String],
) -> Result<Vec<Value>, McpError> {
    if units.is_empty() {
        return Ok(Vec::new());
    }
    let caller = match server.write_identity(auth, viewer).await {
        Ok(c) => c,
        Err(e) => {
            return Ok(units
                .iter()
                .flat_map(|u| u.writes.iter().map(move |w| (u, w)))
                .map(|(u, w)| {
                    json!({
                        "unit": u.unit, "claim_id": w.claim_id, "writable": false,
                        "resolved_gate": "n/a", "admin_path": false,
                        "reason": format!("no write identity: {}", e.message),
                    })
                })
                .collect())
        }
    };
    let scoped = server
        .scoped
        .as_ref()
        .ok_or_else(|| internal_error("label-dedup write_check needs a ScopedPool"))?;
    let mut read = scoped.read_as(viewer).await.map_err(db_caller_error)?;
    let mut out = Vec::new();
    for unit in units {
        for w in &unit.writes {
            let target = ClaimRepository::write_target_of(&mut *read, viewer, w.claim_id)
                .await
                .map_err(db_caller_error)?;
            let Some((author, group)) = target else {
                out.push(json!({
                    "unit": unit.unit, "claim_id": w.claim_id, "writable": false,
                    "resolved_gate": "n/a", "admin_path": false, "reason": "not found",
                }));
                continue;
            };
            let mut reason: Option<String> = None;
            let grant = if auth.is_some() {
                match crate::tools::claims::require_owner_or_admin(server, auth, caller, author)
                    .await
                {
                    Ok(g) => Some(g),
                    Err(e) => {
                        reason = Some(format!("not_owner: {}", e.message));
                        None
                    }
                }
            } else {
                None
            };
            let touches = w
                .add
                .iter()
                .chain(&w.remove)
                .any(|l| l == crate::tools::claims::RETIREMENT_LABEL || retirement.contains(l));
            let (gate, retire_grant) = if touches {
                match crate::tools::claims::require_owner_or_admin(server, auth, caller, author)
                    .await
                {
                    Ok(OwnershipGrant::UndeclaredSigner) => {
                        reason.get_or_insert_with(|| {
                            "the retirement label needs a decided owner".to_string()
                        });
                        ("refused", None)
                    }
                    Ok(g) => ("ok", Some(g)),
                    Err(e) => {
                        reason.get_or_insert_with(|| format!("retirement gate: {}", e.message));
                        ("refused", None)
                    }
                }
            } else {
                ("n/a", None)
            };
            let admin_path =
                crate::tools::admin_write::takes_admin_path(grant.or(retire_grant), viewer, group);
            let group_writable = viewer.writable_groups().contains(&group) || admin_path;
            if !group_writable {
                reason.get_or_insert_with(|| {
                    "the claim's owner group is not writable by this identity".to_string()
                });
            }
            let ownership_ok = auth.is_none() || grant.is_some();
            let writable = ownership_ok && gate != "refused" && group_writable;
            out.push(json!({
                "unit": unit.unit, "claim_id": w.claim_id, "writable": writable,
                "resolved_gate": gate, "admin_path": admin_path, "reason": reason,
            }));
        }
    }
    read.commit().await.map_err(db_caller_error)?;
    Ok(out)
}

// ── The tools ───────────────────────────────────────────────────────────────

/// Plan a label-family dedup pass. Read-only.
///
/// # Errors
/// A refusal carrying `data.code`: a profile refusal (see the module doc),
/// `INVALID_ARGUMENT`, or an engine refusal (`AS_OF_REQUIRED`,
/// `SECTION_NOT_CONFIGURED`, `INVALID_RUN_TAG`, `PROFILE_SCHEMA_INVALID`, ...).
pub async fn plan_label_dedup(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: PlanLabelDedupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let prepared = prepare(
        server,
        auth,
        &ProfileArgs {
            path: params.profile_path.as_deref(),
            json: params.profile_json.as_deref(),
            claim_id: params.profile_claim_id.as_deref(),
            hash: &params.profile_hash,
        },
        &params.run_tag,
        params.as_of.as_deref(),
        &params.sections,
        params.max_claims,
    )?;
    let (plan, at) = compute_plan(server, viewer, &prepared).await?;
    let mut out = plan_json(&plan, at, prepared.max)?;
    let checks = write_check(
        server,
        viewer,
        auth,
        &plan.write_units(),
        &retirement_labels(&prepared.profile),
    )
    .await?;
    out["write_check"] = Value::Array(checks);
    success_json(&out)
}

/// Re-plan from live state and apply the plan the caller reviewed.
///
/// # Errors
/// As [`plan_label_dedup`], plus the read-only refusal and a missing write
/// identity. A truncated read and a drifted plan are NOT errors: they are a
/// `refused` status with nothing written.
pub async fn apply_label_dedup(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ApplyLabelDedupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    server.reject_if_read_only()?;
    let prepared = prepare(
        server,
        auth,
        &ProfileArgs {
            path: params.profile_path.as_deref(),
            json: params.profile_json.as_deref(),
            claim_id: params.profile_claim_id.as_deref(),
            hash: &params.profile_hash,
        },
        &params.run_tag,
        params.as_of.as_deref(),
        &params.sections,
        params.max_claims,
    )?;
    let (plan, at) = compute_plan(server, viewer, &prepared).await?;
    let refused = |code: &str, message: String| -> Result<CallToolResult, McpError> {
        success_json(&json!({
            "applied_plan_hash": Value::Null,
            "status": "refused",
            "refusal": {"code": code, "message": message},
            "plan": plan_json(&plan, at, prepared.max)?,
            "results": [],
            "counts": {"units": 0, "ok": 0, "failed": 0, "labels_added": 0, "labels_removed": 0},
            "applied_units": [],
        }))
    };
    if let Some(e) = plan.apply_refusal() {
        return refused(e.code(), e.to_string());
    }
    if canonical_hash(&plan.plan_hash) != canonical_hash(&params.plan_hash) {
        return refused(
            codes::PLAN_DRIFT,
            "the live family no longer plans to the reviewed plan_hash; review the fresh plan \
             and apply its plan_hash"
                .to_string(),
        );
    }
    let units = plan.write_units();
    if units.is_empty() {
        return success_json(&json!({
            "applied_plan_hash": plan.plan_hash,
            "status": "nothing_to_do",
            "results": [],
            "counts": {"units": 0, "ok": 0, "failed": 0, "labels_added": 0, "labels_removed": 0},
            "applied_units": [],
            "coverage": plan_json(&plan, at, prepared.max)?["coverage"].clone(),
        }));
    }

    let caller = server.write_identity(auth, viewer).await?;
    let retirement = retirement_labels(&prepared.profile);
    let mut results = Vec::with_capacity(units.len());
    let mut applied: Vec<AppliedLabelChange> = Vec::new();
    let mut failed = 0usize;
    for unit in &units {
        match apply_unit(server, viewer, auth, caller, unit, &retirement).await {
            Ok((changes, admin_path)) => {
                results.push(json!({"unit": unit.unit, "ok": true, "admin_path": admin_path}));
                applied.extend(changes);
            }
            Err(e) => {
                failed += 1;
                results.push(json!({
                    "unit": unit.unit, "ok": false, "admin_path": false,
                    "error": e.message,
                }));
            }
        }
    }
    let added: usize = applied.iter().map(|c| c.labels_added.len()).sum();
    let removed: usize = applied.iter().map(|c| c.labels_removed.len()).sum();
    success_json(&json!({
        "applied_plan_hash": plan.plan_hash,
        "status": "applied",
        "results": results,
        "counts": {
            "units": units.len(),
            "ok": units.len() - failed,
            "failed": failed,
            "labels_added": added,
            "labels_removed": removed,
        },
        "applied_units": serde_json::to_value(&applied).map_err(internal_error)?,
        "coverage": plan_json(&plan, at, prepared.max)?["coverage"].clone(),
        "max_claims": prepared.max.json(),
    }))
}

/// One unit, one transaction stamped from the write identity. Every claim
/// goes through `update_labels`' per-claim path; any refusal drops the
/// transaction, so nothing of the unit lands.
async fn apply_unit(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: crate::write_identity::WriteIdentity,
    unit: &WriteUnit,
    retirement: &[String],
) -> Result<(Vec<AppliedLabelChange>, bool), McpError> {
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "apply_label_dedup").await?;
    let mut changes = Vec::with_capacity(unit.writes.len());
    let mut admin_path = false;
    for w in &unit.writes {
        let (_, before) = ClaimRepository::get_by_id_with_labels(
            &mut *tx,
            viewer,
            ClaimId::from_uuid(w.claim_id),
        )
        .await
        .map_err(internal_error)?
        .ok_or_else(|| {
            refusal(
                codes::INVALID_ARGUMENT,
                format!("claim {} not found", w.claim_id),
            )
        })?;
        let out = crate::tools::claims::relabel_claim(
            server, &mut tx, viewer, auth, caller, w.claim_id, &w.add, &w.remove, retirement,
        )
        .await?;
        admin_path |= out.admin_path;
        changes.push(AppliedLabelChange::from_write(
            &unit.unit,
            w,
            &before,
            &out.labels,
        ));
    }
    tx.commit().await.map_err(internal_error)?;
    changes.retain(|c| !c.is_empty());
    Ok((changes, admin_path))
}

/// Classify would-be claims against the family index. Read-only.
///
/// # Errors
/// A profile refusal, `TOO_MANY_CANDIDATES`, `SECTION_NOT_CONFIGURED` (closed
/// signals asked of a profile without lifecycle), or `TRUNCATED`: a read that
/// hit `max_claims` is refused, never answered `new`.
pub async fn probe_label_dedup(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ProbeLabelDedupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    if params.candidates.len() > engine::PROBE_MAX_CANDIDATES {
        return Err(engine_refusal(&LabelDedupError::TooManyCandidates {
            got: params.candidates.len(),
            max: engine::PROBE_MAX_CANDIDATES,
        }));
    }
    let max = MaxClaims::resolve(server.label_dedup.max_claims_cap, params.max_claims)?;
    let (profile, _hash) = load_profile(
        server,
        auth,
        &ProfileArgs {
            path: params.profile_path.as_deref(),
            json: params.profile_json.as_deref(),
            claim_id: params.profile_claim_id.as_deref(),
            hash: &params.profile_hash,
        },
    )?;
    let specs = profile
        .probe_reads(params.include_closed_signals)
        .map_err(|e| engine_refusal(&e))?;
    let (snaps, at) = read_family(server, viewer, &specs, max.effective).await?;
    let mut index = Snapshot::default();
    let mut closed: Option<Snapshot> = None;
    for (purpose, snap) in snaps {
        match purpose {
            ReadPurpose::ClosedSignals => closed = Some(snap),
            _ => index = snap,
        }
    }
    let candidates: Vec<ProbeCandidate> = params
        .candidates
        .into_iter()
        .map(|c| ProbeCandidate {
            key: c.key,
            content: c.content,
            labels: c.labels,
        })
        .collect();
    let verdicts = engine::probe(&profile, &index, closed.as_ref(), &candidates)
        .map_err(|e| engine_refusal(&e))?;
    success_json(&json!({
        "verdicts": verdicts,
        "coverage": {
            "members": index.claims.len(),
            "closed_signals": closed.as_ref().map(|s| s.claims.len()),
            "truncated": false,
            "snapshot_at": at.to_rfc3339(),
        },
        "max_claims": max.json(),
    }))
}
