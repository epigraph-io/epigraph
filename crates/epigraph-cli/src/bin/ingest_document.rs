//! Operator CLI for the canonical hierarchical `ingest_document` pipeline.
//!
//! This is intentionally a thin wrapper around
//! `epigraph_mcp::tools::ingestion::do_ingest_document`: it gives operators a
//! per-invocation database target without forking the ingestion logic away from
//! the MCP tool.

use std::path::PathBuf;

use anyhow::{anyhow, Context};
use clap::Parser;
use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::ingestion::do_ingest_document;
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

    /// Ed25519 secret key as 64 hex chars. If omitted, uses a deterministic
    /// document-ingest-cli signer so repeated operator runs share attribution.
    #[arg(long)]
    agent_key: Option<String>,

    /// OpenAI API key for embedding generation. If omitted, embeddings use the
    /// MCP embedder's mock/no-provider behavior.
    #[arg(long, env = "OPENAI_API_KEY", hide_env_values = true)]
    openai_api_key: Option<String>,
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

    run(cli, maint.pool().clone(), viewer).await
}

async fn run(
    cli: Cli,
    pool: sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> anyhow::Result<()> {
    let data = tokio::fs::read_to_string(&cli.file)
        .await
        .with_context(|| format!("cannot read {}", cli.file.display()))?;
    let extraction: DocumentExtraction =
        serde_json::from_str(&data).context("invalid DocumentExtraction JSON")?;

    let signer = signer_from_cli(cli.agent_key.as_deref())?;
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

    let result = do_ingest_document(&server, viewer, &extraction)
        .await
        .map_err(|e| anyhow!("ingest_document failed: {}", e.message))?;
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .ok_or_else(|| anyhow!("ingest_document returned no text content"))?;

    println!("{text}");
    Ok(())
}

fn signer_from_cli(agent_key: Option<&str>) -> anyhow::Result<AgentSigner> {
    if let Some(raw) = agent_key {
        let key = parse_agent_key(raw)?;
        return AgentSigner::from_bytes(&key).context("invalid --agent-key");
    }

    Ok(epigraph_crypto::did_key::keypair_from_name(
        "document-ingest-cli",
    ))
}

/// Parse an `--agent-key` value into its 32 bytes.
///
/// Surrounding whitespace is trimmed first (a value pasted from a file or a
/// shell variable can carry a trailing space, CR or newline). What is left must
/// be exactly 64 ASCII hex characters. Every other input is a named error,
/// never a panic — the byte-pair slicing this replaces (`&key_hex[i..i + 2]`)
/// panicked on an odd length and on a multi-byte character — and never the
/// deterministic default signer, because the operator asked for one specific
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

    /// The clean key gives the signer for exactly those 32 bytes, and a key
    /// with surrounding whitespace gives the SAME signer: not merely `Ok`,
    /// which the deterministic default would also be.
    #[test]
    fn well_formed_key_is_that_signer_even_when_padded() {
        let expected = AgentSigner::from_bytes(&[1u8; 32]).unwrap().public_key();
        let default = signer_from_cli(None).unwrap().public_key();
        assert_ne!(expected, default, "fixture must differ from the default");
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
    /// a clean `Err`: no panic, and never the deterministic default signer.
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
