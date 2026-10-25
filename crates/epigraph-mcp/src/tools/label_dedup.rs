//! `plan_label_dedup`, `apply_label_dedup`, `probe_label_dedup`,
//! `revert_label_dedup` and `label_dedup_index_view`: thin MCP tools over the
//! pure `epigraph_engine::label_dedup` planner.
//!
//! Label dedup is bookkeeping on an operational INDEX family (a lead list, a
//! tracker), never a merge of knowledge claims: duplicates of those are marked
//! one by one with `mark_duplicate`. Every family a profile names must be
//! declared `family_kind: "index"` (`FAMILY_NOT_INDEX`) and be on this
//! server's allowlist, [`INDEX_FAMILIES_ENV`] (`FAMILY_NOT_ALLOWED`; empty
//! refuses every family), decided from the profile alone, before any read.
//!
//! # The profile
//!
//! Every family rule comes from a `label-dedup-profile/v2` document pinned by
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
//! The reads are of CURRENT claims, so a marked duplicate leaves the family
//! without a label write. Each claim read carries the duplicates marked onto
//! it ([`ClaimRepository::marked_duplicates_of`], the index view), whose
//! fields the engine reads where the claim's own are (a later deadline holds
//! off close-out). They are read through the same viewer: a duplicate the
//! caller cannot read is invisible to its plan, as it is to
//! `label_dedup_index_view`.
//!
//! # Writes
//!
//! `apply_label_dedup` re-plans from live state, refuses a truncated read
//! (`TRUNCATED`) or a changed plan (`PLAN_DRIFT`) before writing anything,
//! then runs each unit in ONE transaction stamped from the write identity:
//! a cluster's marks first, each through the dedup act
//! (`ClaimRepository::mark_duplicate_act_attributed_conn`, the caller's own
//! authority, provenance [`MARK_TOOL`] + tier + run tag + plan hash on the
//! identity edge; the cascade runs after the commit on the administrative
//! connection, or is deferred on the same transaction), then every label
//! write through `update_labels`' own per-claim path
//! ([`crate::tools::claims::relabel_claim`]). The profile's closed label is
//! gated like `resolved`. A refused claim fails its whole unit; later units
//! continue. The response's `applied_marks` and `applied_units` (the labels
//! each committed write actually changed) are `revert_label_dedup`'s input:
//! the label writes are undone first, then the marks, newest first.
//!
//! # Ownership
//!
//! The family read admits every claim the caller can read, other authors'
//! public claims included, and the engine has no notion of an owner. So:
//!
//! * every member of a cluster unit (the survivor included, written or not),
//!   and every target of any other unit, must be the write identity's own:
//!   its author, an agent of the author's operator, or (HTTP) a
//!   `claims:admin` caller. A server with no declared signer cannot decide
//!   that for another agent's claim, and undecided is not owned
//!   (`CROSS_OWNER_MEMBER` for a member, `TARGET_NOT_OWNED` for a target);
//! * a cluster whose members have more than ONE owner is never marked,
//!   WHATEVER the caller's grant, however it was joined (a shared id, or one
//!   owner's revision label naming another's claim): it fails
//!   `CROSS_OWNER_MEMBER` and is listed in `review` for a human
//!   ([`cross_owner`]; a claim's owner is its author's operator, else the
//!   author);
//! * a mark is the caller's own act, so a `claims:admin` caller still cannot
//!   mark inside a group it cannot write.
//!
//! `plan_label_dedup`'s `unit_check` predicts each from the same check, and
//! each mark from the act's own write predicates
//! ([`ClaimRepository::session_may_mark_conn`]). For the same reason probe
//! never answers `match` (or `match_only`) on a claim the caller does not
//! own: that verdict becomes `review`, keeping `matched_id` for the human.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, DuplicateProvenance};
use epigraph_engine::admin_cascade::{self, CascadeCause, CascadeTrigger};
use epigraph_engine::label_dedup::{
    self as engine, AppliedLabelChange, AppliedMark, DedupClaim, LabelDedupError,
    LabelDedupProfile, PlanInputs, PlanRequest, ProbeCandidate, ProbeVerdict, ProbeVerdictKind,
    ReadPurpose, ReadSpec, Section, Snapshot, WriteUnit,
};
use epigraph_engine::retraction_cascade::CascadeReport;
use rmcp::model::{CallToolResult, ContentBlock, ErrorCode};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::errors::{db_caller_error, internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::claims::OwnershipGrant;
use crate::types::{
    ApplyLabelDedupParams, LabelDedupIndexViewParams, PlanLabelDedupParams, ProbeLabelDedupParams,
    RevertLabelDedupParams,
};

/// The default and the server cap of `max_claims`.
pub const DEFAULT_MAX_CLAIMS: usize = 5000;

/// The largest profile accepted, from a file or inline.
pub const MAX_PROFILE_BYTES: usize = 1 << 20;

/// The environment variable naming the directory stdio `profile_path` must
/// resolve under.
pub const PROFILE_ROOT_ENV: &str = "EPIGRAPH_MCP_PROFILE_ROOT";
/// The environment variable carrying the profile hash a stdio caller must pin.
pub const PROFILE_PIN_ENV: &str = "EPIGRAPH_MCP_PROFILE_PIN";
/// The environment variable listing (comma-separated) the family labels this
/// server lets label dedup run on: the operator's index families. Read once at
/// startup. Empty or unset refuses every family.
pub const INDEX_FAMILIES_ENV: &str = "EPIGRAPH_LABEL_DEDUP_INDEX_FAMILIES";

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
    pub const CROSS_OWNER_MEMBER: &str = "CROSS_OWNER_MEMBER";
    pub const FAMILY_NOT_ALLOWED: &str = "FAMILY_NOT_ALLOWED";
    pub const FAMILY_NOT_INDEX: &str = "FAMILY_NOT_INDEX";
    pub const TARGET_NOT_OWNED: &str = "TARGET_NOT_OWNED";
    pub const MARK_REFUSED: &str = "MARK_REFUSED";
    pub const ADMIN_CONNECTION_REQUIRED: &str = "ADMIN_CONNECTION_REQUIRED";
    pub const UNMARK_REFUSED: &str = "UNMARK_REFUSED";
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
    /// The family labels label dedup may run on ([`INDEX_FAMILIES_ENV`]).
    /// Empty: every family is refused.
    pub index_families: std::collections::BTreeSet<String>,
}

impl Default for LabelDedupConfig {
    fn default() -> Self {
        Self {
            profile_root: None,
            profile_pin: None,
            max_claims_cap: DEFAULT_MAX_CLAIMS,
            index_families: std::collections::BTreeSet::new(),
        }
    }
}

impl LabelDedupConfig {
    /// Read [`PROFILE_ROOT_ENV`] and [`PROFILE_PIN_ENV`]; an empty value is
    /// unset.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// [`Self::from_env`] over any variable lookup: each value is trimmed,
    /// and an empty or all-whitespace one is unset.
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let var = |k: &str| {
            lookup(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        Self {
            profile_root: var(PROFILE_ROOT_ENV).map(PathBuf::from),
            profile_pin: var(PROFILE_PIN_ENV),
            max_claims_cap: DEFAULT_MAX_CLAIMS,
            index_families: var(INDEX_FAMILIES_ENV)
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|f| !f.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
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

/// The engine's code for a pass over its pairwise bound
/// (`LabelDedupError::ResourceCap`).
const RESOURCE_CAP: &str = "RESOURCE_CAP";

/// The `data.code` a refusal carries, if any.
fn refusal_code(e: &McpError) -> Option<&str> {
    e.data
        .as_ref()
        .and_then(|d| d.get("code"))
        .and_then(Value::as_str)
}

fn success_json(value: &Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
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
    check_families(&profile, &server.label_dedup.index_families)?;
    Ok(Prepared {
        profile,
        profile_hash,
        run_tag: run_tag.to_string(),
        as_of,
        sections,
        max,
    })
}

/// Every family the profile names must be declared an index and be on this
/// server's allowlist, decided from the profile alone, before any read: label
/// dedup is bookkeeping on an operational index and must never be pointed at
/// a family of knowledge claims.
fn check_families(
    profile: &LabelDedupProfile,
    allowed: &std::collections::BTreeSet<String>,
) -> Result<(), McpError> {
    let mut families = vec![(profile.pass.family_label.as_str(), profile.pass.family_kind)];
    families.extend(
        profile
            .signal_dedup
            .iter()
            .map(|p| (p.family_label.as_str(), p.family_kind)),
    );
    families.extend(
        profile
            .lifecycle
            .iter()
            .map(|l| (l.signal_family_label.as_str(), l.signal_family_kind)),
    );
    for (label, kind) in families {
        if kind != engine::FamilyKind::Index {
            return Err(refusal(
                codes::FAMILY_NOT_INDEX,
                format!(
                    "the profile declares the {label:?} family {kind:?}; label dedup runs only \
                     on an index family (duplicates of knowledge claims are marked one by one \
                     with mark_duplicate)"
                ),
            ));
        }
        if !allowed.contains(label) {
            return Err(refusal(
                codes::FAMILY_NOT_ALLOWED,
                format!(
                    "the {label:?} family is not on this server's index-family allowlist \
                     ({INDEX_FAMILIES_ENV}); an empty allowlist refuses every family"
                ),
            ));
        }
    }
    Ok(())
}

// ── Reads ───────────────────────────────────────────────────────────────────

/// Perform `specs` on one connection stamped from `viewer`. Every claim read
/// carries its marked duplicates ([`ClaimRepository::marked_duplicates_of`],
/// the `index_view`), read on the same connection and capped like the family
/// read: a member whose duplicates did not all fit marks the read truncated.
/// A duplicate of another owner than its canonical's is left out (and
/// reported), so it cannot move the canonical's dates.
async fn read_family(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    specs: &[ReadSpec],
    cap: usize,
) -> Result<FamilyRead, McpError> {
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
    let mut owners = OwnerCache::default();
    let mut foreign = Vec::new();
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
        let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        let dups = ClaimRepository::marked_duplicates_of(&mut *read, viewer, &ids, cap_i64)
            .await
            .map_err(db_caller_error)?;
        // Over the cap, or a chain deeper than the walk follows: either way
        // some duplicate (and its dates) is missing from the read.
        let dups_truncated = dups.rows.len() > cap || dups.chain_truncated;
        let mut by_canonical: BTreeMap<Uuid, Vec<DedupClaim>> = BTreeMap::new();
        for d in dups.rows.into_iter().take(cap) {
            // Only the canonical's own owner's duplicates feed the plan: a
            // stranger who marked a claim onto a public member must not move
            // its dates (a far deadline would hold off its close-out).
            if is_foreign_duplicate(&mut owners, &mut read, &d).await? {
                foreign.push(json!({"canonical": d.canonical, "id": d.id}));
                continue;
            }
            by_canonical
                .entry(d.canonical)
                .or_default()
                .push(DedupClaim {
                    id: d.id,
                    content: d.content,
                    labels: d.labels,
                    created_at: Some(d.created_at),
                    duplicates: Vec::new(),
                });
        }
        let claims = rows
            .into_iter()
            .map(|r| DedupClaim {
                duplicates: by_canonical.remove(&r.id).unwrap_or_default(),
                id: r.id,
                content: r.content,
                labels: r.labels,
                created_at: Some(r.created_at),
            })
            .collect();
        let mut snapshot = Snapshot::from_capped(claims, cap);
        snapshot.truncated |= dups_truncated;
        out.push((spec.purpose, snapshot));
    }
    read.commit().await.map_err(db_caller_error)?;
    foreign.sort_by_key(Value::to_string);
    foreign.dedup();
    Ok(FamilyRead {
        snapshots: out,
        at: snapshot_at,
        foreign_duplicates: foreign,
    })
}

/// One read of a profile's families.
struct FamilyRead {
    snapshots: Vec<(ReadPurpose, Snapshot)>,
    at: DateTime<Utc>,
    /// Duplicates marked onto a member by another owner, left out of the plan.
    foreign_duplicates: Vec<Value>,
}

/// Read the family as `viewer` and plan.
async fn compute_plan(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    p: &Prepared,
) -> Result<Planned, McpError> {
    let specs = p
        .profile
        .reads(&p.sections)
        .map_err(|e| engine_refusal(&e))?;
    let read = read_family(server, viewer, &specs, p.max.effective).await?;
    let mut inputs = PlanInputs::default();
    for (purpose, snap) in read.snapshots {
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
    Ok(Planned {
        plan,
        at: read.at,
        foreign_duplicates: read.foreign_duplicates,
    })
}

/// A plan and what its read saw.
struct Planned {
    plan: engine::Plan,
    at: DateTime<Utc>,
    foreign_duplicates: Vec<Value>,
}

/// The plan as the tools return it: the engine's plan plus the snapshot time,
/// the `max_claims` report and the write units apply would run.
fn plan_json(planned: &Planned, max: MaxClaims) -> Result<Value, McpError> {
    let plan = &planned.plan;
    let mut v = serde_json::to_value(plan).map_err(internal_error)?;
    v["coverage"]["snapshot_at"] = json!(planned.at.to_rfc3339());
    v["coverage"]["foreign_duplicates_ignored"] = json!(planned.foreign_duplicates);
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

// ── Ownership of a unit's claims ────────────────────────────────────────────

/// The claims a cluster unit's decision joins, keyed by unit name: its
/// survivor and every loser. Built from the plan's cluster records, NOT from
/// the unit's writes: a survivor with nothing to write is dropped from the
/// writes, yet it is the claim the losers are marked onto.
fn unit_members(plan: &engine::Plan) -> BTreeMap<String, Vec<Uuid>> {
    let mut out = BTreeMap::new();
    let mut add = |kind: &str, clusters: &[engine::Cluster]| {
        for c in clusters {
            let mut ids = Vec::with_capacity(c.members.len() + 1);
            ids.push(c.survivor);
            ids.extend(c.members.iter().map(|m| m.id));
            // The same unit name `Plan::write_units` gives the cluster.
            out.insert(format!("{kind}:{}", c.survivor), ids);
        }
    };
    add("cluster", &plan.clusters);
    if let Some(sd) = &plan.signal_dedup {
        add("signal_cluster", &sd.clusters);
    }
    out
}

/// The claims of `unit` that are not among `members` but that it writes: a
/// hygiene, close-out, lifecycle or signal target. Each takes the ownership
/// check a member takes (A4), refused as `TARGET_NOT_OWNED`.
fn other_targets(unit: &WriteUnit, members: &[Uuid]) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = unit
        .writes
        .iter()
        .map(|w| w.claim_id)
        .filter(|id| !members.contains(id))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Why the claims `ids` are not ONE owner's, or `None` when they are. A
/// claim's owner is its author's operator, or the author itself when it has
/// none: an operator's own claims and its agents' claims, and two agents of
/// one operator, are one owner. Decided for EVERY caller, `claims:admin`
/// included (A7, decision D4): label dedup never marks across owners, however
/// the cluster was joined (a shared id or one owner's revision label); such a
/// unit is left for a human (`review`). The ONE check behind `unit_check` and
/// apply, read on `conn`.
async fn cross_owner(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    ids: &[Uuid],
) -> Result<Option<String>, McpError> {
    let mut first: Option<(Uuid, Uuid)> = None;
    let mut owners = OwnerCache::default();
    for id in ids {
        // An unreadable member is not a cross-owner verdict: the ownership
        // check refuses it on its own.
        let Some((author, _)) = ClaimRepository::write_target_of(&mut *conn, viewer, *id)
            .await
            .map_err(db_caller_error)?
        else {
            continue;
        };
        let owner = owners.owner_of(&mut *conn, author).await?;
        match first {
            None => first = Some((*id, owner)),
            // The owner ids stay out of the text: an operator link is not
            // something a reader of these claims may otherwise learn.
            Some((other, other_owner)) if other_owner != owner => {
                return Ok(Some(format!(
                    "claims {other} and {id} have different owners; label dedup never marks \
                     across owners, whatever the caller's grant: review the cluster"
                )));
            }
            Some(_) => {}
        }
    }
    Ok(None)
}

/// A claim author's owner (its operator, else itself), read once per author.
#[derive(Default)]
struct OwnerCache(BTreeMap<Uuid, Uuid>);

impl OwnerCache {
    async fn owner_of(
        &mut self,
        conn: &mut sqlx::PgConnection,
        author: Uuid,
    ) -> Result<Uuid, McpError> {
        if let Some(owner) = self.0.get(&author) {
            return Ok(*owner);
        }
        let owner = epigraph_db::AgentRepository::operator_of_author(&mut *conn, author)
            .await
            .map_err(internal_error)?
            .map_or(author, |o| o.operator_id);
        self.0.insert(author, owner);
        Ok(owner)
    }
}

/// Whether `d`'s author has another owner than its canonical's author. The
/// ONE owner rule behind the plan's `coverage.foreign_duplicates_ignored` and
/// the index view's, so the two cannot drift apart: a stranger who marked a
/// claim onto a public member must not move its dates.
async fn is_foreign_duplicate(
    owners: &mut OwnerCache,
    conn: &mut sqlx::PgConnection,
    d: &epigraph_db::MarkedDuplicateRow,
) -> Result<bool, McpError> {
    Ok(owners.owner_of(&mut *conn, d.agent_id).await?
        != owners.owner_of(&mut *conn, d.canonical_agent_id).await?)
}

/// Why the write identity does not own claim `id`, or `None` when it does:
/// its author, an agent of the author's operator, or (HTTP) a `claims:admin`
/// caller. The ONE check behind `unit_check`, apply's `CROSS_OWNER_MEMBER` /
/// `TARGET_NOT_OWNED` and probe's downgrade, so prediction and enforcement
/// cannot drift apart. The author is read on `conn` (apply: the unit's own
/// stamped transaction).
async fn member_not_owned(
    server: &EpiGraphMcpFull,
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: crate::write_identity::WriteIdentity,
    id: Uuid,
) -> Result<Option<String>, McpError> {
    let Some((author, _group)) = ClaimRepository::write_target_of(&mut *conn, viewer, id)
        .await
        .map_err(db_caller_error)?
    else {
        return Ok(Some(format!("claim {id} is not readable by this identity")));
    };
    Ok(
        match crate::tools::claims::require_owner_or_admin(server, auth, caller, author).await {
            Ok(OwnershipGrant::UndeclaredSigner) => Some(format!(
                "claim {id} is authored by agent {author}; this server has no declared signer, \
                 so whether it may act for that agent is undecided"
            )),
            Ok(_) => None,
            Err(e) => Some(format!("claim {id}: {}", e.message)),
        },
    )
}

/// How [`canonical_refusal`] reads whether the canonical is still current.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CanonicalCheck {
    /// The plan's prediction: a plain read, no row lock.
    Predict,
    /// Apply's check before marking onto the canonical: a locking read held
    /// to the unit's commit.
    HoldForMark,
}

/// Why the write identity may not mark a duplicate onto `canonical`, or
/// `None`: `mark_duplicate`'s own rule for the canonical (its owning group
/// must be one the caller writes, since the cascade moves other writers'
/// edges and mass functions onto it), and the canonical must still be
/// current (a mark onto a retired claim would build a chain the plan never
/// showed). Without it a label-dedup apply could make a mark that
/// `mark_duplicate` refuses, and that `unmark_duplicate` (the revert) then
/// refuses too.
///
/// `check` says how currency is read. [`CanonicalCheck::Predict`] (the
/// plan's `write_check`) reads it plainly: a prediction takes no row lock, so
/// a read-scoped plan never blocks a concurrent write to a canonical nor
/// waits behind one. [`CanonicalCheck::HoldForMark`] (apply, on the unit's
/// transaction) reads it under a row lock held to the unit's commit, so the
/// canonical cannot be retired between this check and the mark.
async fn canonical_refusal(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    canonical: Uuid,
    check: CanonicalCheck,
) -> Result<Option<String>, McpError> {
    let Some((_, group)) = ClaimRepository::write_target_of(&mut *conn, viewer, canonical)
        .await
        .map_err(db_caller_error)?
    else {
        return Ok(Some(format!(
            "canonical {canonical} is not readable by this identity"
        )));
    };
    if !viewer.writable_groups().contains(&group) {
        return Ok(Some(format!(
            "this identity does not write the group that owns canonical {canonical}, so \
             mark_duplicate (and its un-mark) would refuse the mark"
        )));
    }
    if check == CanonicalCheck::Predict {
        return Ok(
            (!ClaimRepository::are_all_current(&mut *conn, viewer, &[canonical])
                .await
                .map_err(db_caller_error)?)
            .then(|| format!("canonical {canonical} is no longer current")),
        );
    }
    // Locked on the unit's transaction, so the canonical cannot be retired
    // (marked, superseded, deprecated) between this check and the mark: a
    // retirement in flight is waited for and read, a later one waits for this
    // unit's commit.
    match ClaimRepository::current_state_locked(&mut *conn, viewer, &[canonical])
        .await
        .map_err(db_caller_error)?
        .first()
    {
        Some((_, true)) => Ok(None),
        Some((_, false)) => Ok(Some(format!("canonical {canonical} is no longer current"))),
        None => Ok(Some(format!(
            "canonical {canonical} could not be locked by this identity's write session"
        ))),
    }
}

// ── write_check: a prediction, never a write ────────────────────────────────

/// Predict, per write target, whether the write identity may write it: the
/// ownership check every target takes (A4), the same non-writing gates
/// `update_labels` runs (ownership over HTTP, the retirement-label gate, the
/// owner group in the writer's set or the admin path). Row-security refusals
/// the database alone decides (an operator binding, a revoked membership raced
/// in) are not modelled; apply reports those per unit.
///
/// Returns the per-write entries and, per unit, `unit_check`: whether the
/// unit is predicted to apply, every member of a cluster unit (survivor
/// included, written or not) and whether the write identity owns it, the
/// cross-owner verdict (`review`), and per mark whether the act's own write
/// predicates admit it on the write identity's stamped transaction
/// ([`ClaimRepository::session_may_mark_conn`], asked and rolled back).
async fn write_check(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    units: &[WriteUnit],
    members: &BTreeMap<String, Vec<Uuid>>,
    retirement: &[String],
) -> Result<(Vec<Value>, Vec<Value>), McpError> {
    if units.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let caller = match server.write_identity(auth, viewer).await {
        Ok(c) => c,
        Err(e) => {
            let reason = format!("no write identity: {}", e.message);
            let writes = units
                .iter()
                .flat_map(|u| u.writes.iter().map(move |w| (u, w)))
                .map(|(u, w)| {
                    json!({
                        "unit": u.unit, "claim_id": w.claim_id, "writable": false,
                        "resolved_gate": "n/a", "admin_path": false, "reason": reason,
                    })
                })
                .collect();
            let unit_check = units
                .iter()
                .map(|u| {
                    let ms: Vec<Value> = members
                        .get(&u.unit)
                        .into_iter()
                        .flatten()
                        .map(|id| json!({"claim_id": id, "owned": false, "reason": reason}))
                        .collect();
                    let marks: Vec<Value> = u
                        .marks
                        .iter()
                        .map(|m| {
                            json!({"dup": m.dup, "canonical": m.canonical, "may_mark": false,
                                   "reason": reason})
                        })
                        .collect();
                    json!({
                        "unit": u.unit, "applies": false, "members": ms, "marks": marks,
                        "cross_owner": Value::Null, "review": false,
                    })
                })
                .collect();
            return Ok((writes, unit_check));
        }
    };
    let scoped = server
        .scoped
        .as_ref()
        .ok_or_else(|| internal_error("label-dedup write_check needs a ScopedPool"))?;
    let mut read = scoped.read_as(viewer).await.map_err(db_caller_error)?;
    // The act's authority is the write identity's: asked on ITS stamped
    // transaction, which writes nothing and is rolled back.
    let mut act_refusal = None;
    let mut act = if units.iter().any(|u| !u.marks.is_empty()) {
        // A reader with no writable group cannot open one: every mark is then
        // predicted refused, and the plan (a read) still answers.
        match crate::claim_helper::begin_author_stamped_tx(server, caller, "plan_label_dedup").await
        {
            Ok(tx) => Some(tx),
            Err(e) => {
                act_refusal = Some(format!(
                    "no write transaction for this identity: {}",
                    e.message
                ));
                None
            }
        }
    } else {
        None
    };
    let mut out = Vec::new();
    let mut unit_check = Vec::with_capacity(units.len());
    for unit in units {
        let mut applies = true;
        let unit_ids: &[Uuid] = members.get(&unit.unit).map_or(&[], Vec::as_slice);
        let mut member_checks = Vec::new();
        for id in unit_ids {
            let why = member_not_owned(server, &mut read, viewer, auth, caller, *id).await?;
            applies &= why.is_none();
            member_checks.push(json!({"claim_id": id, "owned": why.is_none(), "reason": why}));
        }
        let cross = cross_owner(&mut read, viewer, unit_ids).await?;
        applies &= cross.is_none();
        let mut mark_checks = Vec::with_capacity(unit.marks.len());
        for m in &unit.marks {
            let why = match act.as_mut() {
                None => act_refusal.clone(),
                Some(tx) => {
                    match canonical_refusal(tx, viewer, m.canonical, CanonicalCheck::Predict)
                        .await?
                    {
                        Some(why) => Some(why),
                        None => (!ClaimRepository::session_may_mark_conn(
                            tx,
                            ClaimId::from_uuid(m.dup),
                            ClaimId::from_uuid(m.canonical),
                        )
                        .await
                        .map_err(db_caller_error)?)
                        .then(|| {
                            "this identity's own write predicates refuse the dedup act (it must \
                         write the duplicate)"
                                .to_string()
                        }),
                    }
                }
            };
            applies &= why.is_none();
            mark_checks.push(json!({
                "dup": m.dup, "canonical": m.canonical, "may_mark": why.is_none(),
                "reason": why,
            }));
        }
        for w in &unit.writes {
            let target = ClaimRepository::write_target_of(&mut *read, viewer, w.claim_id)
                .await
                .map_err(db_caller_error)?;
            let Some((author, group)) = target else {
                applies = false;
                out.push(json!({
                    "unit": unit.unit, "claim_id": w.claim_id, "writable": false,
                    "resolved_gate": "n/a", "admin_path": false, "reason": "not found",
                }));
                continue;
            };
            let mut reason: Option<String> =
                member_not_owned(server, &mut read, viewer, auth, caller, w.claim_id)
                    .await?
                    .map(|why| format!("not_owner: {why}"));
            let owned = reason.is_none();
            let grant = if auth.is_some() {
                crate::tools::claims::require_owner_or_admin(server, auth, caller, author)
                    .await
                    .ok()
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
            let writable = owned && gate != "refused" && group_writable;
            applies &= writable;
            out.push(json!({
                "unit": unit.unit, "claim_id": w.claim_id, "writable": writable,
                "resolved_gate": gate, "admin_path": admin_path, "reason": reason,
            }));
        }
        unit_check.push(json!({
            "unit": unit.unit, "applies": applies, "members": member_checks,
            "marks": mark_checks, "review": cross.is_some(), "cross_owner": cross,
        }));
    }
    read.commit().await.map_err(db_caller_error)?;
    if let Some(tx) = act {
        tx.rollback().await.map_err(db_caller_error)?;
    }
    Ok((out, unit_check))
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
    let planned = compute_plan(server, viewer, &prepared).await?;
    let mut out = plan_json(&planned, prepared.max)?;
    let plan = &planned.plan;
    let (checks, unit_check) = write_check(
        server,
        viewer,
        auth,
        &plan.write_units(),
        &unit_members(plan),
        &retirement_labels(&prepared.profile),
    )
    .await?;
    out["write_check"] = Value::Array(checks);
    out["unit_check"] = Value::Array(unit_check);
    success_json(&out)
}

/// An apply's answer that wrote nothing.
fn nothing_applied(status: &str) -> Value {
    json!({
        "status": status,
        "results": [],
        "counts": {"units": 0, "ok": 0, "failed": 0, "marks": 0, "labels_added": 0,
                   "labels_removed": 0},
        "applied_units": [],
        "applied_marks": [],
        "review": [],
    })
}

/// Re-plan from live state and apply the plan the caller reviewed.
///
/// # Errors
/// As [`plan_label_dedup`], plus the read-only refusal and a missing write
/// identity. A truncated read, a family over the engine's pairwise bound
/// (`RESOURCE_CAP`) and a drifted plan are NOT errors: they are a `refused`
/// status with nothing written.
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
    let planned = match compute_plan(server, viewer, &prepared).await {
        Ok(planned) => planned,
        // The family read fit `max_claims` but not the engine's pairwise
        // bound: a refusal of the pass, like TRUNCATED, with no plan to show.
        Err(e) if refusal_code(&e) == Some(RESOURCE_CAP) => {
            let mut v = nothing_applied("refused");
            v["applied_plan_hash"] = Value::Null;
            v["refusal"] = json!({"code": RESOURCE_CAP, "message": e.message});
            v["plan"] = Value::Null;
            v["max_claims"] = prepared.max.json();
            return success_json(&v);
        }
        Err(e) => return Err(e),
    };
    let refused = |code: &str, message: String| -> Result<CallToolResult, McpError> {
        let mut v = nothing_applied("refused");
        v["applied_plan_hash"] = Value::Null;
        v["refusal"] = json!({"code": code, "message": message});
        v["plan"] = plan_json(&planned, prepared.max)?;
        success_json(&v)
    };
    let plan = &planned.plan;
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
        let mut v = nothing_applied("nothing_to_do");
        v["applied_plan_hash"] = json!(plan.plan_hash);
        v["coverage"] = plan_json(&planned, prepared.max)?["coverage"].clone();
        return success_json(&v);
    }

    let caller = server.write_identity(auth, viewer).await?;
    let ctx = UnitContext {
        server,
        viewer,
        auth,
        caller,
        retirement: retirement_labels(&prepared.profile),
        run_tag: &prepared.run_tag,
        plan_hash: &plan.plan_hash,
    };
    let members = unit_members(plan);
    let mut results = Vec::with_capacity(units.len());
    let mut applied: Vec<AppliedLabelChange> = Vec::new();
    let mut applied_marks: Vec<Value> = Vec::new();
    let mut review = Vec::new();
    let mut failed = 0usize;
    for unit in &units {
        let unit_ids = members.get(&unit.unit).map_or(&[][..], Vec::as_slice);
        match apply_unit(&ctx, unit, unit_ids).await {
            Ok(done) => {
                results.push(json!({"unit": unit.unit, "ok": true, "admin_path": done.admin_path}));
                applied.extend(done.changes);
                applied_marks.extend(done.marks);
            }
            Err(UnitRefusal { error, review: why }) => {
                failed += 1;
                if let Some(why) = why {
                    review.push(json!({"unit": unit.unit, "reason": why}));
                }
                results.push(json!({
                    "unit": unit.unit, "ok": false, "admin_path": false,
                    "code": refusal_code(&error), "error": error.message,
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
            "marks": applied_marks.len(),
            "labels_added": added,
            "labels_removed": removed,
        },
        "applied_units": serde_json::to_value(&applied).map_err(internal_error)?,
        "applied_marks": applied_marks,
        "review": review,
        "coverage": plan_json(&planned, prepared.max)?["coverage"].clone(),
        "max_claims": prepared.max.json(),
    }))
}

/// What every unit of one apply shares.
struct UnitContext<'a> {
    server: &'a EpiGraphMcpFull,
    viewer: &'a epigraph_db::visibility::Viewer,
    auth: Option<&'a epigraph_auth::AuthContext>,
    caller: crate::write_identity::WriteIdentity,
    retirement: Vec<String>,
    run_tag: &'a str,
    plan_hash: &'a str,
}

/// A committed unit.
struct UnitApplied {
    changes: Vec<AppliedLabelChange>,
    /// Each [`AppliedMark`] with its cascade's status.
    marks: Vec<Value>,
    admin_path: bool,
}

/// A refused unit (nothing of it written), and the reason it is for a human
/// when it is a cross-owner cluster.
struct UnitRefusal {
    error: McpError,
    review: Option<String>,
}

impl From<McpError> for UnitRefusal {
    fn from(error: McpError) -> Self {
        Self {
            error,
            review: None,
        }
    }
}

/// The tool a label-dedup mark names in its identity edge's provenance.
pub const MARK_TOOL: &str = "label_dedup";

/// One unit, one transaction stamped from the write identity:
///
/// 1. a cluster of more than one owner is refused for EVERY caller and left
///    for review (`CROSS_OWNER_MEMBER`, [`cross_owner`]); every member must
///    be the write identity's own (`CROSS_OWNER_MEMBER`) and every other
///    target too (`TARGET_NOT_OWNED`), all before any write;
/// 2. each mark through the dedup act on this transaction (the caller's own
///    authority; provenance: this tool, the matching tier, what it matched
///    on, the run tag and the plan hash), with the cascade deferred on the
///    same transaction when this server holds no administrative connection;
/// 3. every label write through `update_labels`' per-claim path.
///
/// Any refusal drops the transaction, so nothing of the unit lands. After the
/// commit, each mark's cascade runs on the administrative connection.
async fn apply_unit(
    ctx: &UnitContext<'_>,
    unit: &WriteUnit,
    members: &[Uuid],
) -> Result<UnitApplied, UnitRefusal> {
    let UnitContext {
        server,
        viewer,
        auth,
        caller,
        ..
    } = *ctx;
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, caller, "apply_label_dedup").await?;
    if let Some(why) = cross_owner(&mut tx, viewer, members).await? {
        return Err(UnitRefusal {
            error: refusal(
                codes::CROSS_OWNER_MEMBER,
                format!("{}: {why}. Nothing of the unit was written", unit.unit),
            ),
            review: Some(why),
        });
    }
    for id in members {
        if let Some(why) = member_not_owned(server, &mut tx, viewer, auth, caller, *id).await? {
            return Err(refusal(
                codes::CROSS_OWNER_MEMBER,
                format!(
                    "{}: every member of a cluster must be the write identity's own; {why}. \
                     Nothing of the unit was written",
                    unit.unit
                ),
            )
            .into());
        }
    }
    for id in other_targets(unit, members) {
        if let Some(why) = member_not_owned(server, &mut tx, viewer, auth, caller, id).await? {
            return Err(refusal(
                codes::TARGET_NOT_OWNED,
                format!(
                    "{}: a label-dedup write target must be the write identity's own; {why}. \
                     Nothing of the unit was written",
                    unit.unit
                ),
            )
            .into());
        }
    }

    let mut canonicals: Vec<Uuid> = unit.marks.iter().map(|m| m.canonical).collect();
    canonicals.sort();
    canonicals.dedup();
    for canonical in canonicals {
        if let Some(why) =
            canonical_refusal(&mut tx, viewer, canonical, CanonicalCheck::HoldForMark).await?
        {
            return Err(refusal(
                codes::MARK_REFUSED,
                format!("{}: {why}. Nothing of the unit was written", unit.unit),
            )
            .into());
        }
    }

    // The cascade's administrative session, taken once for the unit; without
    // one, each mark's cascade is deferred on this transaction.
    let (mut session, deferral) = if unit.marks.is_empty() {
        (None, None)
    } else {
        match crate::maintenance::admin_cascade_session(server).await {
            Ok(s) => (Some(s), None),
            Err(reason) => (None, Some(reason)),
        }
    };
    let actor = caller.agent_id();
    let mut marked = Vec::with_capacity(unit.marks.len());
    for m in &unit.marks {
        let provenance = DuplicateProvenance::new(MARK_TOOL, tier_name(m.rule))
            .matched_on(json!(m.matched_on))
            .run_tag(ctx.run_tag)
            .plan_hash(ctx.plan_hash)
            .marked_by(Some(actor));
        let edge = ClaimRepository::mark_duplicate_act_attributed_conn(
            &mut tx,
            ClaimId::from_uuid(m.dup),
            ClaimId::from_uuid(m.canonical),
            &provenance,
        )
        .await
        .map_err(|e| {
            refusal(
                codes::MARK_REFUSED,
                format!(
                    "{}: marking {} a duplicate of {}: {e}. Nothing of the unit was written",
                    unit.unit, m.dup, m.canonical
                ),
            )
        })?;
        let trigger = CascadeTrigger::new(
            CascadeCause::Dedup,
            Some(actor),
            crate::tools::supersede::oauth_principal(auth),
            m.dup,
            Some(m.canonical),
        );
        let deferred = match &deferral {
            Some(reason) => Some(
                admin_cascade::record_deferral(&mut *tx, &trigger, reason)
                    .await
                    .map_err(internal_error)?,
            ),
            None => None,
        };
        marked.push((
            AppliedMark::from_mark(&unit.unit, m, Some(edge)),
            trigger,
            deferred,
        ));
    }

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
            server,
            &mut tx,
            viewer,
            auth,
            caller,
            w.claim_id,
            &w.add,
            &w.remove,
            &ctx.retirement,
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

    // THE CASCADE of each committed mark (migration 117), as mark_duplicate
    // runs it: best-effort, audited, filtered to the caller.
    let mut marks = Vec::with_capacity(marked.len());
    for (mark, trigger, deferred) in marked {
        let (cascade, belief_cascade) = match (session.as_mut(), deferred) {
            (Some(s), _) => {
                let (conn, v) = s.split();
                admin_cascade::apply_after_dedup(
                    conn,
                    v,
                    viewer,
                    &trigger,
                    mark.dup,
                    mark.canonical,
                )
                .await
            }
            (None, status) => (status.unwrap_or_default(), CascadeReport::default()),
        };
        let mut v = serde_json::to_value(&mark).map_err(internal_error)?;
        v["cascade"] = serde_json::to_value(&cascade).map_err(internal_error)?;
        v["belief_cascade"] = serde_json::to_value(&belief_cascade).map_err(internal_error)?;
        marks.push(v);
    }
    Ok(UnitApplied {
        changes,
        marks,
        admin_path,
    })
}

/// A tier as a mark's provenance names it (its serialized name).
fn tier_name(tier: engine::Tier) -> String {
    serde_json::to_value(tier)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{tier:?}"))
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
    check_families(&profile, &server.label_dedup.index_families)?;
    let specs = profile
        .probe_reads(params.include_closed_signals)
        .map_err(|e| engine_refusal(&e))?;
    let read = read_family(server, viewer, &specs, max.effective).await?;
    let at = read.at;
    let mut index = Snapshot::default();
    let mut closed: Option<Snapshot> = None;
    for (purpose, snap) in read.snapshots {
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
    let verdicts = review_foreign_matches(server, viewer, auth, verdicts).await?;
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

/// A `match` or `match_only` verdict tells the caller not to file its item.
/// On a claim the caller does not own (see the module doc) it becomes
/// `review` instead, keeping `matched_id`: the caller could neither merge
/// into that claim nor rely on it tracking the caller's item.
async fn review_foreign_matches(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    mut verdicts: Vec<ProbeVerdict>,
) -> Result<Vec<ProbeVerdict>, McpError> {
    let skips = |v: &ProbeVerdict| {
        matches!(
            v.verdict,
            ProbeVerdictKind::Match | ProbeVerdictKind::MatchOnly
        ) && v.matched_id.is_some()
    };
    if !verdicts.iter().any(skips) {
        return Ok(verdicts);
    }
    let caller = server.write_identity(auth, viewer).await;
    let scoped = server
        .scoped
        .as_ref()
        .ok_or_else(|| internal_error("probe_label_dedup needs a ScopedPool"))?;
    let mut read = scoped.read_as(viewer).await.map_err(db_caller_error)?;
    for v in verdicts.iter_mut().filter(|v| skips(v)) {
        let Some(id) = v.matched_id else { continue };
        let why = match &caller {
            Ok(c) => member_not_owned(server, &mut read, viewer, auth, *c, id).await?,
            Err(e) => Some(format!("no write identity: {}", e.message)),
        };
        if let Some(why) = why {
            let was = if v.verdict == ProbeVerdictKind::Match {
                "match"
            } else {
                "match_only"
            };
            v.verdict = ProbeVerdictKind::Review;
            v.reason = format!(
                "{}; review rather than {was}: the matched claim is not the caller's own ({why})",
                v.reason
            );
        }
    }
    read.commit().await.map_err(db_caller_error)?;
    Ok(verdicts)
}

// ── Revert and the index view ───────────────────────────────────────────────

/// The most label changes, and the most marks, one revert takes.
pub const REVERT_MAX_ITEMS: usize = 2 * DEFAULT_MAX_CLAIMS;

/// Undo one apply from its own response (A6): the label writes first, each
/// inverse through `update_labels`' per-claim path, newest first
/// ([`engine::revert_writes`]); then every mark, newest first
/// ([`engine::revert_marks`]), each through `unmark_duplicate` with the
/// canonical and identity edge the apply recorded (a claim marked since onto
/// another claim, or marked again, is refused). Every step takes the gates
/// the single-claim tool takes, so a revert grants nothing `update_labels`
/// and `unmark_duplicate` would not.
///
/// Nothing is written until every un-mark is proved admissible: the server's
/// administrative connection (an un-mark has no deferred form;
/// `ADMIN_CONNECTION_REQUIRED`) and each un-mark's own gate, read-only, in
/// order, a canonical still marked a duplicate itself being admissible only
/// when this revert un-marks it first (`UNMARK_REFUSED`). Otherwise the label
/// half alone would leave the marks without the labels they were applied
/// with. After that, each step is reported; a step that still fails (a race)
/// does not stop the others, and `status` is then `partial`.
///
/// # Errors
/// The read-only refusal, a malformed or oversized input,
/// `ADMIN_CONNECTION_REQUIRED`, `UNMARK_REFUSED`, or a missing write identity.
pub async fn revert_label_dedup(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: RevertLabelDedupParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    server.reject_if_read_only()?;
    if params.applied_units.len() > REVERT_MAX_ITEMS
        || params.applied_marks.len() > REVERT_MAX_ITEMS
    {
        return Err(refusal(
            codes::INVALID_ARGUMENT,
            format!("a revert takes at most {REVERT_MAX_ITEMS} label changes and as many marks"),
        ));
    }
    let changes = params
        .applied_units
        .iter()
        .map(|c| {
            Ok(AppliedLabelChange {
                unit: c.unit.clone(),
                claim_id: parse_id(&c.claim_id)?,
                labels_added: c.labels_added.clone(),
                labels_removed: c.labels_removed.clone(),
            })
        })
        .collect::<Result<Vec<_>, McpError>>()?;
    let marks = params
        .applied_marks
        .iter()
        .map(|m| {
            let rule: engine::Tier = serde_json::from_value(json!(m.rule)).map_err(|e| {
                refusal(
                    codes::INVALID_ARGUMENT,
                    format!("{:?} is not a dedup tier: {e}", m.rule),
                )
            })?;
            Ok(AppliedMark {
                unit: m.unit.clone(),
                dup: parse_id(&m.dup)?,
                canonical: parse_id(&m.canonical)?,
                rule,
                matched_on: m.matched_on.clone(),
                identity_edge: m.identity_edge.as_deref().map(parse_id).transpose()?,
            })
        })
        .collect::<Result<Vec<_>, McpError>>()?;
    let unmarks = engine::revert_marks(&marks);
    if !unmarks.is_empty() {
        // Proved usable, then released: each un-mark takes its own session.
        crate::maintenance::admin_cascade_session(server)
            .await
            .map_err(|reason| {
                refusal(
                    codes::ADMIN_CONNECTION_REQUIRED,
                    format!(
                        "this revert un-marks {} duplicate(s), and an un-mark needs this \
                         server's administrative (maintenance) connection ({reason}); nothing \
                         was written",
                        unmarks.len()
                    ),
                )
            })?;
        preflight_unmarks(server, viewer, auth, &unmarks).await?;
    }
    let caller = server.write_identity(auth, viewer).await?;

    let mut steps = Vec::new();
    for w in engine::revert_writes(&changes) {
        let done: Result<(), McpError> = async {
            let mut tx =
                crate::claim_helper::begin_author_stamped_tx(server, caller, "revert_label_dedup")
                    .await?;
            crate::tools::claims::relabel_claim(
                server,
                &mut tx,
                viewer,
                auth,
                caller,
                w.claim_id,
                &w.add,
                &w.remove,
                &[],
            )
            .await?;
            tx.commit().await.map_err(internal_error)
        }
        .await;
        steps.push(json!({
            "step": "labels", "claim_id": w.claim_id, "add": w.add, "remove": w.remove,
            "ok": done.is_ok(), "error": done.err().map(|e| e.message),
        }));
    }
    for m in &unmarks {
        let done = crate::tools::supersede::unmark_duplicate_expecting(
            server,
            viewer,
            auth,
            m.dup,
            expectation(m),
        )
        .await;
        steps.push(json!({
            "step": "unmark", "unit": m.unit, "claim_id": m.dup, "canonical": m.canonical,
            "ok": done.is_ok(),
            "error": done.as_ref().err().map(|e| e.message.clone()),
            "result": done.ok(),
        }));
    }
    let all_ok = steps.iter().all(|s| s["ok"] == true);
    success_json(&json!({
        "status": if all_ok { "reverted" } else { "partial" },
        "steps": steps,
    }))
}

fn expectation(m: &AppliedMark) -> crate::tools::supersede::UnmarkExpectation {
    crate::tools::supersede::UnmarkExpectation {
        canonical: Some(m.canonical),
        identity_edge: m.identity_edge,
    }
}

/// Every un-mark of a revert, proved admissible before anything is written:
/// its own gate (read-only), and a current canonical to restore it against
/// (its canonical, or the claim that replaced it since: the gate's chain), or
/// its canonical un-marked earlier by this same revert (the un-mark act
/// refuses a duplicate whose canonical is itself still a marked duplicate).
/// `UNMARK_REFUSED` names every one that is not.
async fn preflight_unmarks(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    unmarks: &[AppliedMark],
) -> Result<(), McpError> {
    let mut refused = Vec::new();
    let mut undone_first = std::collections::BTreeSet::new();
    for m in unmarks {
        match crate::tools::supersede::unmark_gate(server, viewer, auth, m.dup, expectation(m))
            .await
        {
            Err(e) => refused.push(format!("{}: {}", m.dup, e.message)),
            Ok(_) if undone_first.contains(&m.canonical) => {}
            Ok(gate) => {
                if let Err(why) = gate.chain {
                    refused.push(format!("{}: claim {} {why}", m.dup, m.dup));
                }
            }
        }
        undone_first.insert(m.dup);
    }
    if refused.is_empty() {
        return Ok(());
    }
    Err(refusal(
        codes::UNMARK_REFUSED,
        format!(
            "{} of {} un-mark(s) would be refused; nothing was written: {}",
            refused.len(),
            unmarks.len(),
            refused.join("; ")
        ),
    ))
}

/// The most canonicals one `label_dedup_index_view` call reads.
pub const INDEX_VIEW_MAX_IDS: usize = 100;

/// The index view (decision D3): each canonical with every claim marked a
/// duplicate of it (down a chain), so a reader of an index family reads the
/// fields a duplicate kept (a later deadline) where the canonical is. Read on
/// one connection stamped from the caller's viewer: a canonical or a duplicate
/// the caller cannot read is not returned (a canonical is listed in
/// `missing`), so a caller that must see every duplicate needs a viewer that
/// reads them all. Like the plan, it leaves out (and lists in
/// `foreign_duplicates_ignored`) a duplicate of another owner than its
/// canonical's, unless `same_owner_only` is `false`. Read-only.
///
/// # Errors
/// `INVALID_ARGUMENT` (no id, more than [`INDEX_VIEW_MAX_IDS`], a malformed
/// id, a bad `max_claims`), or a failed read.
pub async fn label_dedup_index_view(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: LabelDedupIndexViewParams,
    _auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    if params.claim_ids.is_empty() || params.claim_ids.len() > INDEX_VIEW_MAX_IDS {
        return Err(refusal(
            codes::INVALID_ARGUMENT,
            format!(
                "claim_ids takes 1 to {INDEX_VIEW_MAX_IDS} ids, got {}",
                params.claim_ids.len()
            ),
        ));
    }
    let ids = params
        .claim_ids
        .iter()
        .map(|id| parse_id(id))
        .collect::<Result<Vec<_>, McpError>>()?;
    let max = MaxClaims::resolve(server.label_dedup.max_claims_cap, params.max_claims)?;
    let scoped = server
        .scoped
        .as_ref()
        .ok_or_else(|| internal_error("label_dedup_index_view needs a ScopedPool"))?;
    let mut read = scoped.read_as(viewer).await.map_err(db_caller_error)?;
    let mut found = Vec::with_capacity(ids.len());
    let mut missing = Vec::new();
    for id in ids {
        match ClaimRepository::get_by_id_with_labels(&mut *read, viewer, ClaimId::from_uuid(id))
            .await
            .map_err(db_caller_error)?
        {
            Some((claim, labels)) => found.push((id, claim.content, labels)),
            None => missing.push(id),
        }
    }
    let canonicals: Vec<Uuid> = found.iter().map(|(id, _, _)| *id).collect();
    let dups = ClaimRepository::marked_duplicates_of(
        &mut *read,
        viewer,
        &canonicals,
        i64::try_from(max.effective).unwrap_or(i64::MAX),
    )
    .await
    .map_err(db_caller_error)?;
    let truncated = dups.rows.len() > max.effective || dups.chain_truncated;
    // The plan's owner rule, after the cap (so `truncated` keeps its meaning).
    let same_owner_only = params.same_owner_only.unwrap_or(true);
    let mut owners = OwnerCache::default();
    let mut kept = Vec::with_capacity(dups.rows.len().min(max.effective));
    let mut foreign = Vec::new();
    for d in dups.rows.iter().take(max.effective) {
        if same_owner_only && is_foreign_duplicate(&mut owners, &mut read, d).await? {
            foreign.push(json!({"canonical": d.canonical, "id": d.id}));
        } else {
            kept.push(d);
        }
    }
    read.commit().await.map_err(db_caller_error)?;
    let views: Vec<Value> = found
        .into_iter()
        .map(|(id, content, labels)| {
            let duplicates: Vec<Value> = kept
                .iter()
                .filter(|d| d.canonical == id)
                .map(|d| {
                    json!({"id": d.id, "content": d.content, "labels": d.labels,
                           "agent_id": d.agent_id, "created_at": d.created_at.to_rfc3339()})
                })
                .collect();
            json!({
                "canonical": {"id": id, "content": content, "labels": labels},
                "duplicates": duplicates,
            })
        })
        .collect();
    success_json(&json!({
        "views": views,
        "missing": missing,
        "truncated": truncated,
        "foreign_duplicates_ignored": foreign,
        "max_claims": max.json(),
    }))
}

fn parse_id(raw: &str) -> Result<Uuid, McpError> {
    Uuid::parse_str(raw.trim()).map_err(|e| {
        refusal(
            codes::INVALID_ARGUMENT,
            format!("{raw:?} is not a claim id: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from(vars: &[(&str, &str)]) -> LabelDedupConfig {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        LabelDedupConfig::from_lookup(|k| {
            vars.iter()
                .find(|(name, _)| name == k)
                .map(|(_, v)| v.clone())
        })
    }

    /// The host forwards these exact names into the stdio server's
    /// environment; a renamed variable would silently turn path mode off and
    /// drop the pin.
    #[test]
    fn the_profile_root_and_pin_are_read_from_their_exact_names_and_trimmed() {
        assert_eq!(PROFILE_ROOT_ENV, "EPIGRAPH_MCP_PROFILE_ROOT");
        assert_eq!(PROFILE_PIN_ENV, "EPIGRAPH_MCP_PROFILE_PIN");
        let cfg = config_from(&[
            ("EPIGRAPH_MCP_PROFILE_ROOT", " /profiles "),
            ("EPIGRAPH_MCP_PROFILE_PIN", "\tabc123\n"),
        ]);
        assert_eq!(cfg.profile_root, Some(PathBuf::from("/profiles")));
        assert_eq!(cfg.profile_pin.as_deref(), Some("abc123"));
        assert_eq!(cfg.max_claims_cap, DEFAULT_MAX_CLAIMS);
    }

    /// The allowlist is read from its exact name, comma-separated and trimmed;
    /// unset or blank is the empty list, which refuses every family.
    #[test]
    fn the_index_family_allowlist_is_read_comma_separated() {
        assert_eq!(INDEX_FAMILIES_ENV, "EPIGRAPH_LABEL_DEDUP_INDEX_FAMILIES");
        let cfg = config_from(&[(INDEX_FAMILIES_ENV, " a-list , b-list,, ")]);
        assert_eq!(
            cfg.index_families.into_iter().collect::<Vec<_>>(),
            vec!["a-list".to_string(), "b-list".to_string()]
        );
        for blank in ["", " , ", "\t"] {
            assert!(config_from(&[(INDEX_FAMILIES_ENV, blank)])
                .index_families
                .is_empty());
        }
        assert!(config_from(&[]).index_families.is_empty());
    }

    #[test]
    fn an_empty_or_blank_profile_variable_is_unset() {
        for blank in ["", "   ", "\t\n"] {
            let cfg = config_from(&[
                ("EPIGRAPH_MCP_PROFILE_ROOT", blank),
                ("EPIGRAPH_MCP_PROFILE_PIN", blank),
            ]);
            assert_eq!(cfg.profile_root, None, "{blank:?}");
            assert_eq!(cfg.profile_pin, None, "{blank:?}");
        }
        // Absent entirely, and set only under other names: unset too.
        let cfg = config_from(&[
            ("EPIGRAPH_PROFILE_ROOT", "/profiles"),
            ("PROFILE_PIN", "abc123"),
        ]);
        assert_eq!(cfg.profile_root, None);
        assert_eq!(cfg.profile_pin, None);
    }
}
