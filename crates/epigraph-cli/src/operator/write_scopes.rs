//! `reprovision-write-scopes`: the audited bulk grant of `edges:write` and
//! `evidence:write` to every ACTIVE OAuth client that already holds
//! `claims:write`, and to those clients' LIVE refresh chains, with its exact
//! reverse from a manifest (backlog c841b15f, migration 362).
//!
//! # Why this exists
//!
//! The MCP scope remap (backlog c2dbcf27) moves the edge and evidence writers
//! from `claims:write` to `edges:write` / `evidence:write`. Shipping it before
//! the clients that write today hold those scopes would cut them off, so the
//! remap is gated on this verb having run (`docs/deploy.md`).
//!
//! A grant on `oauth_clients` alone is not enough. The refresh grant issues
//! the presented token's STORED scopes narrowed to the client's
//! `granted_scopes` (`epigraph-api`'s `token.rs::refresh_scopes`, and the
//! rotation definer, migrations 140/172), so an agent connected before the
//! grant would keep minting its old scope set for as long as its chain
//! rotates. This verb is therefore the one audited exception to "a grant
//! never widens an existing chain" (see `client_scope`'s module doc): it adds
//! the two scopes to each live refresh token of the client that holds
//! `claims:write`, as well as to both scope arrays of the client.
//!
//! # The rules (enforced by the definers, migration 362)
//!
//! * **Maintenance DSN only**, through [`super::connect`]; both definers also
//!   refuse a non-maintenance session (42501).
//! * **Exactly the two scopes.** [`SCOPES`] is the whole set; the definer
//!   refuses any other scope (an admin-only one included), so no input can
//!   make this verb grant authority beyond them.
//! * **Active clients only.** A candidate is `status = 'active'` with
//!   `claims:write` in `granted_scopes`. Suspended, revoked and pending
//!   clients are never touched.
//! * **Only chains that consented to `claims:write`.** A live refresh token
//!   (`revoked_at IS NULL AND expires_at > now()`) is widened only when its
//!   stored scopes hold `claims:write`.
//! * **Append, never reorder.** Each missing scope is appended; every other
//!   element keeps its place, so the reverse can restore the exact arrays.
//! * **Audited.** One `oauth.write_scopes_reprovisioned` `security_events` row
//!   per changed client, written by the definer in the same transaction.
//! * **Dry run by default.** Without `--apply` the same definer call runs,
//!   audit rows included, in a transaction that is rolled back.
//! * **Counted.** `--apply` needs `--confirm-count N`, the dry run's client
//!   count repeated back; a different count rolls everything back.
//! * **Reversible.** `--apply` needs `--manifest-out`: a new JSONL file
//!   (header, then one line per client with both arrays before and after and
//!   each widened token's family, before and after), written and fsynced
//!   BEFORE the commit. `--reverse --manifest F` undoes it client by client,
//!   compare-and-swap: a client whose arrays changed since is HELD (exit 3),
//!   and a chain is restored by family, so a successor minted by a rotation
//!   since is restored too.
//!
//! A rotation in flight during the run can mint a successor the run did not
//! see; the verb is idempotent, so the runbook re-runs the dry run after an
//! apply and expects zero clients.

use super::client_scope::Operator;
use super::manifest::Writer;
use anyhow::{bail, Context};
use serde_json::{json, Value};
use sqlx::{Acquire, PgConnection};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The scopes this verb grants, in the order they are appended. The definer
/// closes the same set; [`tests::the_scopes_are_ordinary_write_scopes`] pins
/// that neither is admin-only.
pub const SCOPES: [&str; 2] = ["edges:write", "evidence:write"];

/// The manifest header's `kind`.
pub const MANIFEST_KIND: &str = "reprovision-write-scopes";

/// The forward run's options.
#[derive(Debug, Clone)]
pub struct Options {
    pub apply: bool,
    pub confirm_count: Option<usize>,
    pub manifest_out: Option<PathBuf>,
    pub reason: String,
}

/// Refuse incomplete options before any connection is made.
///
/// # Errors
/// A blank reason; under `--apply`, no `--confirm-count` or no
/// `--manifest-out`, or a manifest path that already exists.
pub fn validate(o: &Options) -> anyhow::Result<()> {
    if o.reason.trim().is_empty() {
        bail!("--reason must say why (it is recorded in every audit row); nothing was changed");
    }
    if o.apply {
        if o.confirm_count.is_none() {
            bail!(
                "--apply needs --confirm-count N: the number of clients the dry run reported, \
                 repeated back"
            );
        }
        let Some(path) = &o.manifest_out else {
            bail!("--apply needs --manifest-out FILE (the undo manifest; it must not exist)");
        };
        if path.exists() {
            bail!(
                "manifest {} exists; a manifest is never overwritten (choose a new path)",
                path.display()
            );
        }
    }
    Ok(())
}

/// One widened refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub token: Uuid,
    pub family: Uuid,
    pub before: Vec<String>,
    pub after: Vec<String>,
}

/// One client a forward run changed (or would change).
#[derive(Debug, Clone)]
pub struct Changed {
    pub client: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub client_type: String,
    pub agent_id: Option<Uuid>,
    pub allowed_before: Vec<String>,
    pub granted_before: Vec<String>,
    pub allowed_after: Vec<String>,
    pub granted_after: Vec<String>,
    pub chains: Vec<Chain>,
    pub audit_event_id: Uuid,
}

impl Changed {
    /// Its manifest line.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "client": self.client,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "client_type": self.client_type,
            "agent_id": self.agent_id,
            "allowed_before": self.allowed_before,
            "granted_before": self.granted_before,
            "allowed_after": self.allowed_after,
            "granted_after": self.granted_after,
            "chains": self.chains.iter().map(|c| json!({
                "id": c.token,
                "family": c.family,
                "before": c.before,
                "after": c.after,
            })).collect::<Vec<_>>(),
            "audit_event_id": self.audit_event_id,
        })
    }
}

/// What a forward run found and did.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub changed: Vec<Changed>,
    /// `false` for a dry run: nothing was committed.
    pub applied: bool,
    pub manifest: Option<PathBuf>,
}

/// The operator facts recorded in each audit row (the database records
/// `session_user` itself).
fn operator_json(op: &Operator) -> Value {
    json!({
        "os_user": op.os_user,
        "os_user_source": "environment (SUDO_USER, USER, LOGNAME): advisory, settable by the \
                           caller",
        "process_uid": op.process_uid,
        "process_user": op.process_user,
        "login_uid": op.login_uid,
        "login_user": op.login_user,
    })
}

fn strings(v: &Value) -> anyhow::Result<Vec<String>> {
    v.as_array()
        .context("expected an array of scopes")?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_string)
                .context("expected a scope string")
        })
        .collect()
}

fn parse_chains(v: &Value) -> anyhow::Result<Vec<Chain>> {
    v.as_array()
        .context("expected an array of chains")?
        .iter()
        .map(|c| {
            Ok(Chain {
                token: c["id"]
                    .as_str()
                    .context("chain id")?
                    .parse()
                    .context("chain id")?,
                family: c["family"]
                    .as_str()
                    .context("chain family")?
                    .parse()
                    .context("chain family")?,
                before: strings(&c["before"])?,
                after: strings(&c["after"])?,
            })
        })
        .collect()
}

type ForwardRow = (
    Uuid,
    String,
    String,
    String,
    Option<Uuid>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Value,
    Uuid,
);

/// Run the forward verb: one definer call in one transaction on `conn`,
/// committed only under `apply` and only when the changed-client count equals
/// `confirm_count`, after the manifest is written and fsynced.
///
/// # Errors
/// Invalid options; the definer refuses (not a maintenance session, a scope
/// outside the closed set); the count differs from `--confirm-count`; the
/// manifest cannot be written; a statement fails. Nothing is committed then.
pub async fn run(
    conn: &mut PgConnection,
    opts: &Options,
    operator: &Operator,
) -> anyhow::Result<Outcome> {
    validate(opts)?;
    let scopes: Vec<String> = SCOPES.iter().map(|s| (*s).to_string()).collect();
    let mut tx = conn.begin().await.context("beginning the transaction")?;
    let rows: Vec<ForwardRow> = sqlx::query_as(
        "SELECT out_client, out_client_key, out_client_name, out_client_type, out_agent_id, \
                out_allowed_before, out_granted_before, out_allowed_after, out_granted_after, \
                out_chains, out_audit_event_id \
           FROM public.epigraph_reprovision_write_scopes($1, $2, $3)",
    )
    .bind(&scopes)
    .bind(&opts.reason)
    .bind(operator_json(operator))
    .fetch_all(&mut *tx)
    .await
    .context("calling epigraph_reprovision_write_scopes (is migration 362 applied?)")?;

    let mut changed = Vec::with_capacity(rows.len());
    for r in rows {
        changed.push(Changed {
            client: r.0,
            client_id: r.1,
            client_name: r.2,
            client_type: r.3,
            agent_id: r.4,
            allowed_before: r.5,
            granted_before: r.6,
            allowed_after: r.7,
            granted_after: r.8,
            chains: parse_chains(&r.9)?,
            audit_event_id: r.10,
        });
    }

    if !opts.apply {
        tx.rollback().await.context("rolling back the dry run")?;
        return Ok(Outcome {
            changed,
            applied: false,
            manifest: None,
        });
    }

    let want = opts.confirm_count.expect("validated");
    if changed.len() != want {
        tx.rollback().await.context("rolling back")?;
        bail!(
            "--confirm-count {want} does not match the {} client(s) this run would change; \
             everything was rolled back. Re-run the dry run and confirm its count.",
            changed.len()
        );
    }
    let path = opts.manifest_out.as_ref().expect("validated");
    let mut w = Writer::create_new(
        path,
        &json!({
            "kind": MANIFEST_KIND,
            "version": 1,
            "scopes": SCOPES,
            "reason": opts.reason,
            "session_user": operator.session_user,
            "clients": changed.len(),
            "created_at": chrono::Utc::now(),
        }),
    )?;
    w.append_values(&changed.iter().map(Changed::to_json).collect::<Vec<_>>())?;
    tx.commit().await.context("committing")?;
    Ok(Outcome {
        changed,
        applied: true,
        manifest: Some(path.clone()),
    })
}

/// The forward run's report lines.
#[must_use]
pub fn describe(o: &Outcome) -> Vec<String> {
    let mode = if o.applied { "APPLIED" } else { "DRY RUN" };
    let tokens: usize = o.changed.iter().map(|c| c.chains.len()).sum();
    let mut out = vec![format!(
        "{mode}: reprovision-write-scopes {}: {} client(s), {tokens} live refresh token(s)",
        SCOPES.join(" "),
        o.changed.len()
    )];
    for c in &o.changed {
        out.push(format!(
            "CLIENT\t{}\t{}\t{:?}\ttype={}\tallowed_scopes {:?} -> {:?}\tgranted_scopes {:?} -> \
             {:?}\taudit {}{}",
            c.client,
            c.client_id,
            c.client_name,
            c.client_type,
            c.allowed_before,
            c.allowed_after,
            c.granted_before,
            c.granted_after,
            c.audit_event_id,
            if o.applied { "" } else { " (rolled back)" }
        ));
        let mut families: Vec<Uuid> = c.chains.iter().map(|ch| ch.family).collect();
        families.sort_unstable();
        families.dedup();
        for f in families {
            let n = c.chains.iter().filter(|ch| ch.family == f).count();
            let added: Vec<&str> = c
                .chains
                .iter()
                .filter(|ch| ch.family == f)
                .flat_map(|ch| {
                    ch.after
                        .get(ch.before.len()..)
                        .unwrap_or_default()
                        .iter()
                        .map(String::as_str)
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            out.push(format!(
                "  CHAIN\tfamily {f}\t{n} live token(s)\tadds {}",
                added.join(" ")
            ));
        }
    }
    match (&o.manifest, o.applied) {
        (Some(m), true) => out.push(format!(
            "manifest {} (reverse: reprovision-write-scopes --reverse --manifest {} --reason \
             TEXT --apply)",
            m.display(),
            m.display()
        )),
        _ => out.push(format!(
            "re-run with --apply --confirm-count {} --manifest-out FILE --reason TEXT",
            o.changed.len()
        )),
    }
    out
}

/// One client's reverse result.
#[derive(Debug, Clone)]
pub struct Reversed {
    pub client: Uuid,
    /// `restored`, `already`, `held` or `missing`.
    pub state: String,
    pub tokens_restored: i32,
    pub tokens_held: i32,
    pub audit_event_id: Uuid,
}

/// What a reverse run did.
#[derive(Debug, Clone)]
pub struct ReverseOutcome {
    pub clients: Vec<Reversed>,
    pub applied: bool,
}

impl ReverseOutcome {
    /// Whether anything was left un-restored (a held client or token, or a
    /// client that no longer exists): exit 3.
    #[must_use]
    pub fn incomplete(&self) -> bool {
        self.clients
            .iter()
            .any(|c| c.state == "held" || c.state == "missing" || c.tokens_held > 0)
    }
}

/// Read a forward manifest: its client lines.
///
/// # Errors
/// The file cannot be read, has no `reprovision-write-scopes` header, or a
/// line is malformed.
pub fn read_manifest(path: &Path) -> anyhow::Result<Vec<Changed>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: Value = serde_json::from_str(lines.next().context("the manifest is empty")?)
        .context("the manifest header is not JSON")?;
    if header["kind"] != MANIFEST_KIND {
        bail!(
            "{} is not a {MANIFEST_KIND} manifest (header kind {})",
            path.display(),
            header["kind"]
        );
    }
    let mut out = Vec::new();
    for (n, line) in lines.enumerate() {
        let v: Value = serde_json::from_str(line)
            .with_context(|| format!("manifest line {} is not JSON", n + 2))?;
        let uuid = |k: &str| -> anyhow::Result<Uuid> {
            v[k].as_str()
                .with_context(|| format!("line {}: {k}", n + 2))?
                .parse()
                .with_context(|| format!("line {}: {k}", n + 2))
        };
        out.push(Changed {
            client: uuid("client")?,
            client_id: v["client_id"].as_str().unwrap_or_default().to_string(),
            client_name: v["client_name"].as_str().unwrap_or_default().to_string(),
            client_type: v["client_type"].as_str().unwrap_or_default().to_string(),
            agent_id: v["agent_id"].as_str().and_then(|s| s.parse().ok()),
            allowed_before: strings(&v["allowed_before"])?,
            granted_before: strings(&v["granted_before"])?,
            allowed_after: strings(&v["allowed_after"])?,
            granted_after: strings(&v["granted_after"])?,
            chains: parse_chains(&v["chains"])?,
            audit_event_id: uuid("audit_event_id")?,
        });
    }
    Ok(out)
}

/// Reverse a forward run from its manifest, one definer call per client, in
/// one transaction committed only under `apply`.
///
/// # Errors
/// A blank reason; the manifest cannot be read; the definer refuses a line
/// (not a re-provision's shape, not a maintenance session); a statement fails.
pub async fn reverse(
    conn: &mut PgConnection,
    manifest: &Path,
    reason: &str,
    apply: bool,
    operator: &Operator,
) -> anyhow::Result<ReverseOutcome> {
    if reason.trim().is_empty() {
        bail!("--reason must say why (it is recorded in every audit row); nothing was changed");
    }
    let lines = read_manifest(manifest)?;
    let mut tx = conn.begin().await.context("beginning the transaction")?;
    let mut clients = Vec::with_capacity(lines.len());
    for c in &lines {
        let chains: Vec<Value> = c
            .chains
            .iter()
            .map(|ch| {
                json!({ "id": ch.token, "family": ch.family, "before": ch.before,
                              "after": ch.after })
            })
            .collect();
        let (state, tokens_restored, tokens_held, audit_event_id): (String, i32, i32, Uuid) =
            sqlx::query_as(
                "SELECT out_client_state, out_tokens_restored, out_tokens_held, \
                        out_audit_event_id \
                   FROM public.epigraph_reprovision_write_scopes_reverse(\
                        $1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(c.client)
            .bind(&c.allowed_before)
            .bind(&c.granted_before)
            .bind(&c.allowed_after)
            .bind(&c.granted_after)
            .bind(Value::Array(chains))
            .bind(reason)
            .bind(operator_json(operator))
            .fetch_one(&mut *tx)
            .await
            .with_context(|| format!("reversing client {}", c.client))?;
        clients.push(Reversed {
            client: c.client,
            state,
            tokens_restored,
            tokens_held,
            audit_event_id,
        });
    }
    if apply {
        tx.commit().await.context("committing")?;
    } else {
        tx.rollback().await.context("rolling back the dry run")?;
    }
    Ok(ReverseOutcome {
        clients,
        applied: apply,
    })
}

/// The reverse run's report lines.
#[must_use]
pub fn describe_reverse(o: &ReverseOutcome) -> Vec<String> {
    let mode = if o.applied { "APPLIED" } else { "DRY RUN" };
    let mut out = vec![format!(
        "{mode}: reprovision-write-scopes --reverse: {} client(s)",
        o.clients.len()
    )];
    for c in &o.clients {
        out.push(format!(
            "{}\t{}\ttokens_restored={}\ttokens_held={}\taudit {}{}",
            c.state.to_uppercase(),
            c.client,
            c.tokens_restored,
            c.tokens_held,
            c.audit_event_id,
            if o.applied { "" } else { " (rolled back)" }
        ));
    }
    if o.incomplete() {
        out.push(
            "INCOMPLETE: at least one client or chain changed since the run and was left \
             alone (HELD), or no longer exists (MISSING)"
                .to_string(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_core::canonical_scopes::{ADMIN_ONLY_SCOPES, PLATFORM_ADMIN_SCOPE, WRITE_SCOPES};

    #[test]
    fn the_scopes_are_ordinary_write_scopes() {
        for s in SCOPES {
            assert!(
                !ADMIN_ONLY_SCOPES.contains(&s),
                "{s} must not be admin-only"
            );
            assert_ne!(s, PLATFORM_ADMIN_SCOPE);
            assert!(
                WRITE_SCOPES.contains(&s),
                "{s} must be a canonical write scope"
            );
        }
    }

    fn opts(apply: bool, count: Option<usize>, out: Option<&str>, reason: &str) -> Options {
        Options {
            apply,
            confirm_count: count,
            manifest_out: out.map(PathBuf::from),
            reason: reason.to_string(),
        }
    }

    #[test]
    fn apply_needs_a_count_a_new_manifest_and_a_reason() {
        let fresh = std::env::temp_dir().join(format!("rws-{}.jsonl", Uuid::new_v4()));
        let fresh = fresh.to_str().expect("utf-8");
        assert!(validate(&opts(false, None, None, "gate the remap")).is_ok());
        assert!(validate(&opts(false, None, None, "  ")).is_err());
        assert!(validate(&opts(true, None, Some(fresh), "r")).is_err());
        assert!(validate(&opts(true, Some(3), None, "r")).is_err());
        assert!(validate(&opts(true, Some(3), Some(fresh), "r")).is_ok());
        let existing = std::env::temp_dir();
        assert!(validate(&opts(true, Some(3), existing.to_str(), "r")).is_err());
    }
}
