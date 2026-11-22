//! Operator CLI for the canonical hierarchical `ingest_document` pipeline.
//!
//! This is intentionally a thin wrapper around
//! `epigraph_mcp::tools::ingestion::do_ingest_document`: it gives operators a
//! per-invocation database target without forking the ingestion logic away from
//! the MCP tool.
//!
//! It signs every claim it writes, so it needs a real key: `--agent-key-file`,
//! `EPIGRAPH_INGEST_AGENT_KEY` or `--agent-key` (backlog bfc2eff8). There is
//! no default signer: the old one, the `document-ingest-cli` name-derived key,
//! was `BLAKE3("author:document-ingest-cli")`, which anyone can compute, and
//! is refused even when given explicitly.
//!
//! The claims it creates take `--visibility` / `--group-id` exactly as the MCP
//! tools take `visibility` / `group_id`, resolved for the acting agent (the
//! signer). Omitted, they resolve D-V1 (team, else private), so
//! an operator ingest's claims are never public unless `--visibility public`
//! says so. Where they landed is printed on stderr. The setting scopes the
//! claims and, since migration 246, the `papers` row (title, DOI, journal)
//! with its `processed_by` stamp and every edge onto it; the author agents
//! stay world-readable whatever it is (docs/tenancy/papers-tenancy-followup.md).

use std::path::PathBuf;

use anyhow::{anyhow, Context};
use clap::Parser;
use epigraph_crypto::AgentSigner;
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::ingestion::{do_ingest_document_reporting, IngestTenancy};
use epigraph_mcp::EpiGraphMcpFull;

#[derive(Parser, Debug)]
#[command(
    name = "ingest-document",
    about = "Ingest a DocumentExtraction JSON into a target EpiGraph database"
)]
struct Cli {
    /// PostgreSQL connection URL for the target graph.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Path to a hierarchical DocumentExtraction JSON file.
    #[arg(long)]
    file: PathBuf,

    /// The signer's Ed25519 secret key as 64 hex chars. Prefer
    /// `--agent-key-file` or the environment: a value on the command line is
    /// visible to every local user in the process list. One of the three is
    /// REQUIRED (there is no default signer), and the publicly computable
    /// `document-ingest-cli` key is refused. Make one with
    /// `openssl rand -hex 32`, and keep it: the key IS the acting agent.
    #[arg(
        long,
        env = "EPIGRAPH_INGEST_AGENT_KEY",
        hide_env_values = true,
        conflicts_with = "agent_key_file"
    )]
    agent_key: Option<String>,

    /// A file holding the signer's Ed25519 secret key (64 hex chars;
    /// surrounding whitespace is ignored). Alternative to `--agent-key`.
    #[arg(long)]
    agent_key_file: Option<PathBuf>,

    /// OpenAI API key for embedding generation. If omitted, embeddings use the
    /// MCP embedder's mock/no-provider behavior.
    #[arg(long, env = "OPENAI_API_KEY", hide_env_values = true)]
    openai_api_key: Option<String>,

    /// Who reads the claims this ingest creates: `team`, `private` or
    /// `public`. Omitted, the acting agent's D-V1 default applies: its default
    /// team if still writable, else its human's under the same condition, else
    /// its only writable team, else private. Never public unless asked
    /// (operator ruling, 2026-11-10). Claims only: the paper's own record
    /// (title, DOI), its author agents and its processed-by stamp stay
    /// world-readable. The outcome is printed on stderr.
    #[arg(long)]
    visibility: Option<String>,

    /// The team to write into, with `--visibility team` or no `--visibility`.
    /// The acting agent (or its human) must hold a writer membership in it.
    #[arg(long)]
    group_id: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "epigraph_cli=info,epigraph_mcp=info".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    // Refused before any connection, with the MCP tools' own wording.
    let choice = epigraph_core::VisibilityChoice::parse_str(
        cli.visibility.as_deref(),
        cli.group_id.as_deref(),
    )
    .map_err(|e| anyhow!("invalid --visibility / --group-id: {e}"))?;

    // CLI maintenance bin: the operator is the authority and the work is
    // corpus-wide. See `epigraph_cli::MaintenancePool`.
    //
    // Before PR-15 the bypass viewer came from a `ScopedPool` that was then
    // discarded, while the `EpiGraphMcpFull` this bin drives was built on a
    // separate ordinary pool. Under FORCE the pool is what filters, so the
    // privileged viewer did not save it. The whole ingest now runs on the
    // maintenance pool.
    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "ingest-document")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::TenancyBackfill)
        .await
        .context("mint maintenance viewer")?;
    let viewer = session.viewer();

    run(cli, choice, maint.pool().clone(), viewer).await
}

async fn run(
    cli: Cli,
    choice: epigraph_core::VisibilityChoice,
    pool: sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> anyhow::Result<()> {
    let data = tokio::fs::read_to_string(&cli.file)
        .await
        .with_context(|| format!("cannot read {}", cli.file.display()))?;
    let extraction: DocumentExtraction =
        serde_json::from_str(&data).context("invalid DocumentExtraction JSON")?;

    let key_text = agent_key_text(cli.agent_key.as_deref(), cli.agent_key_file.as_deref())?;
    let signer = signer_from_cli(key_text.as_deref())?;
    // `on_a_privileged_pool`, not `with_scoped_pool`: `pool` here is
    // `MaintenancePool::pool()` — see the comment in `main` above, which records
    // that this bin's whole ingest deliberately runs on the maintenance pool
    // because under FORCE it is the pool that filters, not the viewer. That role
    // holds BYPASSRLS, so `epigraph_bypass()` is true, the tier-A `WITH CHECK`
    // admits the embedding UPDATE, and there is no tenancy context to stamp. The
    // declaration is required rather than defaulted so that a future bin built on
    // an ORDINARY pool cannot acquire an unstamped embedding writer by omission —
    // it would get `StorePath::Undeclared` and a loud refusal instead.
    let embedder = McpEmbedder::new(pool.clone(), cli.openai_api_key).on_a_privileged_pool(
        "epigraph-cli ingest_document runs entirely on MaintenancePool, whose role bypasses RLS",
    );
    // Declared on the SERVER too, for the same reason: `do_ingest_document` now
    // runs its walk in one transaction stamped from the ingesting agent, and a
    // server with neither a `ScopedPool` nor this declaration refuses rather
    // than write on an unstamped connection. On `MaintenancePool` there is
    // nothing to stamp, and the declaration selects a plain transaction.
    let server = EpiGraphMcpFull::new(pool, signer, embedder, false).on_a_privileged_pool(
        "epigraph-cli ingest_document runs entirely on MaintenancePool, whose role bypasses RLS",
    );

    // The acting agent is this server's signer (no `auth`), so `choice`
    // resolves against IT: an omitted `--visibility` is D-V1 for that agent,
    // never public.
    let (result, tenancy) =
        do_ingest_document_reporting(&server, viewer, &extraction, None, choice)
            .await
            .map_err(|e| anyhow!("ingest_document failed: {}", e.message))?;
    // The walk returns once its transaction commits, with its embedding loop
    // still running on the server's `BackgroundTasks`. Exiting here would drop
    // that loop and leave the new claims with no vector, so wait for it, with
    // the stdio server's bound (`EPIGRAPH_MCP_STDIO_DRAIN_SECS`).
    let background = server.background_tasks();
    if background.active() > 0 {
        let limit = epigraph_mcp::background::exit_drain_timeout();
        if !background.wait_idle(limit).await {
            eprintln!(
                "ingest-document: the embedding loop did not finish within {} s; claims it had \
                 not reached carry no vector until the maintenance backfill (embed_backfill) \
                 runs",
                limit.as_secs()
            );
        }
    }
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .ok_or_else(|| anyhow!("ingest_document returned no text content"))?;

    // stdout stays the ingest's JSON; where the claims landed goes to stderr,
    // because a default ingest by a teamless agent (a fresh key with no team)
    // lands PRIVATE, and an operator must not have to guess.
    eprintln!("{}", tenancy_line(&tenancy));
    println!("{text}");
    Ok(())
}

/// The one stderr line that says where this run's new claims landed.
fn tenancy_line(t: &IngestTenancy) -> String {
    let mut line = format!(
        "ingest-document: new claims written {} (owner group {}); claims it converged onto \
         keep their own visibility; the paper record itself is not tenanted",
        t.visibility.to_uppercase(),
        t.owner_group_id
    );
    if let Some(note) = &t.note {
        line.push_str("; ");
        line.push_str(note);
    }
    line
}

/// The key text from `--agent-key` / `EPIGRAPH_INGEST_AGENT_KEY`, or read
/// from `--agent-key-file` (clap refuses both at once). The read error names
/// the path, never the content.
fn agent_key_text(
    agent_key: Option<&str>,
    agent_key_file: Option<&std::path::Path>,
) -> anyhow::Result<Option<String>> {
    match (agent_key, agent_key_file) {
        (Some(raw), _) => Ok(Some(raw.to_string())),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map(Some)
            .with_context(|| format!("cannot read --agent-key-file {}", path.display())),
        (None, None) => Ok(None),
    }
}

/// The name the pre-bfc2eff8 default signer was derived from. Its key is
/// `BLAKE3("author:document-ingest-cli")`, so anyone can compute it.
const LEGACY_DEFAULT_SIGNER_NAME: &str = "document-ingest-cli";

/// The signer for `agent_key` (the key text, from whichever source).
///
/// # Errors
/// No key (there is no default signer), a malformed key, or the legacy
/// default's publicly computable key. No message echoes the key.
fn signer_from_cli(agent_key: Option<&str>) -> anyhow::Result<AgentSigner> {
    let Some(raw) = agent_key else {
        return Err(anyhow!(
            "ingest-document signs every claim it writes and needs a real key: pass \
             --agent-key-file <path> (a file holding 64 hex chars, e.g. from \
             `openssl rand -hex 32`), set EPIGRAPH_INGEST_AGENT_KEY, or pass --agent-key. \
             There is no default signer: the old one (the {LEGACY_DEFAULT_SIGNER_NAME:?} \
             name-derived key) is computable by anyone and is refused"
        ));
    };
    let key = parse_agent_key(raw)?;
    let signer = AgentSigner::from_bytes(&key).context("invalid --agent-key")?;
    if signer.public_key()
        == epigraph_crypto::did_key::keypair_from_name(LEGACY_DEFAULT_SIGNER_NAME).public_key()
    {
        return Err(anyhow!(
            "--agent-key is the {LEGACY_DEFAULT_SIGNER_NAME:?} name-derived key, whose private \
             half anyone can compute from that name; refusing to sign with it. Use a random key \
             (`openssl rand -hex 32`)"
        ));
    }
    Ok(signer)
}

/// Parse an `--agent-key` value into its 32 bytes.
///
/// Surrounding whitespace is trimmed first (a value pasted from a file or a
/// shell variable can carry a trailing space, CR or newline). What is left must
/// be exactly 64 ASCII hex characters. Every other input is a named error,
/// never a panic — the byte-pair slicing this replaces (`&key_hex[i..i + 2]`)
/// panicked on an odd length and on a multi-byte character — and never
/// some other signer, because the operator asked for one specific
/// key. No message echoes any part of the value: it is a secret, and `main`
/// prints the error. Same rules as epigraph-mcp's `--agent-key` parsing
/// (PR #516).
fn parse_agent_key(raw: &str) -> anyhow::Result<[u8; 32]> {
    const EXPECTED: &str = "expected exactly 64 hex chars (32 bytes); the value is not shown";
    let key_hex = raw.trim();
    if !key_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "invalid --agent-key: it contains a non-hex character; {EXPECTED}"
        ));
    }
    if !key_hex.len().is_multiple_of(2) {
        return Err(anyhow!(
            "invalid --agent-key: odd number of hex chars ({}); {EXPECTED}",
            key_hex.len()
        ));
    }
    if key_hex.len() != 64 {
        return Err(anyhow!(
            "--agent-key must be exactly 32 bytes: got {} hex chars; {EXPECTED}",
            key_hex.len()
        ));
    }
    let mut key = [0u8; 32];
    // Cannot fail after the checks above; mapped to a fixed message anyway,
    // because `FromHexError`'s Display names the offending character.
    hex::decode_to_slice(key_hex, &mut key)
        .map_err(|_| anyhow!("invalid --agent-key hex; {EXPECTED}"))?;
    Ok(key)
}

#[cfg(test)]
mod agent_key_tests {
    use super::*;

    const KEY_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    /// Backlog bfc2eff8: there is no default signer. No key is an error that
    /// says how to supply one, and the old default's key (the
    /// `document-ingest-cli` name-derived key, computable by anyone) is
    /// refused even when given explicitly, padded or in upper case.
    /// Mutation caught: restoring the default, or dropping the literal-seed
    /// check.
    #[test]
    fn no_key_and_the_literal_seeded_key_are_refused() {
        let Err(err) = signer_from_cli(None) else {
            panic!("no key must be refused: the old default signs with a public key");
        };
        let msg = format!("{err:?}");
        for named in [
            "--agent-key-file",
            "EPIGRAPH_INGEST_AGENT_KEY",
            "--agent-key",
        ] {
            assert!(msg.contains(named), "the refusal must name {named}: {msg}");
        }

        // The legacy default's SECRET, recomputed from the public name: what
        // an attacker (or an operator copying old docs) would pass.
        let legacy =
            epigraph_crypto::did_key::keypair_from_name("document-ingest-cli").secret_key();
        let legacy_hex = hex::encode(legacy);
        for given in [
            legacy_hex.clone(),
            format!("{legacy_hex}\n"),
            legacy_hex.to_uppercase(),
        ] {
            let Err(err) = signer_from_cli(Some(&given)) else {
                panic!("the publicly computable document-ingest-cli key must be refused");
            };
            let msg = format!("{err:?}");
            assert!(msg.contains("anyone can compute"), "{msg}");
            assert!(
                !msg.contains(&legacy_hex[..16]),
                "the refusal must not echo the key: {msg}"
            );
        }
    }

    /// The clean key gives the signer for exactly those 32 bytes, and a key
    /// with surrounding whitespace gives the SAME signer: not merely `Ok`.
    #[test]
    fn well_formed_key_is_that_signer_even_when_padded() {
        let expected = AgentSigner::from_bytes(&[1u8; 32]).unwrap().public_key();
        for key in [
            KEY_HEX.to_string(),
            format!("{KEY_HEX} "),
            format!("{KEY_HEX}\r"),
            format!("{KEY_HEX}\n"),
            format!("{KEY_HEX}\r\n"),
            format!(" \t{KEY_HEX}"),
            KEY_HEX.to_uppercase(),
        ] {
            let signer =
                signer_from_cli(Some(&key)).unwrap_or_else(|e| panic!("{key:?} must parse: {e}"));
            assert_eq!(signer.public_key(), expected, "{key:?}");
        }
    }

    /// Inputs the old byte-pair slicing PANICKED on (odd length, a multi-byte
    /// character inside 64 bytes), plus the other malformed shapes, are each
    /// a clean `Err`: no panic, and never some other signer.
    #[test]
    fn malformed_keys_are_errors_not_panics_or_the_default() {
        let odd = &KEY_HEX[..63];
        let multibyte = format!("{}\u{e9}", &KEY_HEX[..62]); // 64 bytes, 63 chars
        assert_eq!(multibyte.len(), 64);
        let internal_space = format!("{} {}", &KEY_HEX[..32], &KEY_HEX[33..]);
        let short = &KEY_HEX[..62];
        let long = format!("{KEY_HEX}01");
        let non_hex = format!("{}zz", &KEY_HEX[..62]);
        for bad in [
            odd,
            multibyte.as_str(),
            internal_space.as_str(),
            short,
            long.as_str(),
            non_hex.as_str(),
            "",
            "   ",
            "\r\n",
        ] {
            let outcome = std::panic::catch_unwind(|| signer_from_cli(Some(bad)));
            let result = outcome.unwrap_or_else(|_| panic!("{bad:?} must not panic"));
            assert!(result.is_err(), "{bad:?} must be refused, not defaulted");
        }
    }

    /// No error message, including its full cause chain, echoes any part of
    /// the key: it is a secret, and `main` prints the error.
    #[test]
    fn errors_never_echo_the_value() {
        let secret = "0123456789abcdef".repeat(4);
        let non_hex = format!("{}g", &secret[..63]);
        let odd = secret[..63].to_string();
        let wrong_len = secret[..62].to_string();
        for bad in [non_hex, odd, wrong_len] {
            let Err(err) = signer_from_cli(Some(&bad)) else {
                panic!("{bad:?} must be refused");
            };
            let msg = format!("{err:?}");
            assert!(
                msg.contains("--agent-key"),
                "error must name the flag: {msg}"
            );
            for window in bad.as_bytes().windows(16) {
                let run = std::str::from_utf8(window).unwrap();
                assert!(
                    !msg.contains(run),
                    "the error must not echo the key (found {run:?}): {msg}"
                );
            }
            assert!(
                !msg.contains("'g'"),
                "the error must not name the bad char: {msg}"
            );
        }
    }
}
