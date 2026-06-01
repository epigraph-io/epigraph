//! LLM-based theme naming via the claude CLI (OAuth, project convention).
//!
//! Fetches the 10 claims nearest to a theme's centroid, sends them to
//! claude-haiku, and writes the response as the theme label. Falls back
//! to the existing label on any error so a claude outage never blocks
//! theme building.

use sqlx::PgPool;
use std::io::Write;
use std::process::{Command, Stdio};
use uuid::Uuid;

/// Build the naming prompt. Public for testing.
pub fn build_naming_prompt(claims: &[String]) -> String {
    let mut p = String::from(
        "You are naming a semantic cluster in a scientific knowledge graph.\n\
         Below are the 10 claims closest to this cluster's centroid — \
         the most representative statements in the cluster.\n\n\
         Claims:\n",
    );
    for (i, c) in claims.iter().enumerate() {
        p.push_str(&format!("{}. {}\n", i + 1, c));
    }
    p.push_str(
        "\nRespond with ONLY the theme name — 4 to 8 words, Title Case, \
         no quotes, no punctuation, no explanation.\n\
         Theme name:",
    );
    p
}

/// Parse raw LLM output into a clean single-line theme name.
/// Returns `""` when the output is empty (caller uses fallback label).
/// Public for testing.
pub fn parse_theme_name(raw: &str) -> String {
    let line = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let stripped = line.trim_matches('"').trim_matches('\'');
    let clean = stripped.trim_end_matches(['.', ',', ';', ':']);
    clean.trim().to_string()
}

/// Fetch the 10 claims nearest to `theme_id`'s centroid.
async fn nearest_claims(pool: &PgPool, theme_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT c.content \
         FROM claims c \
         JOIN claim_themes ct ON ct.id = $1 \
         WHERE c.embedding IS NOT NULL AND ct.centroid IS NOT NULL \
         ORDER BY c.embedding <=> ct.centroid \
         LIMIT 10",
    )
    .bind(theme_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(s,)| s).collect())
}

/// Invoke the claude CLI synchronously with `prompt` on stdin.
/// Returns stdout as a String on success.
fn invoke_claude(prompt: &str) -> anyhow::Result<String> {
    let mut child = Command::new("claude")
        .args([
            "-p",
            "--output-format",
            "text",
            "--model",
            "claude-haiku-4-5-20251001",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn claude CLI: {e}"))?;
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(prompt.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!("claude exited non-zero: {stderr}"));
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// Name a theme using the LLM. Returns the generated label, or
/// `fallback_label` if the CLI is unavailable or returns unusable output.
pub async fn name_theme(pool: &PgPool, theme_id: Uuid, fallback_label: &str) -> String {
    let claims = match nearest_claims(pool, theme_id).await {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => {
            tracing::debug!(%theme_id, "namer: no nearest claims, using fallback");
            return fallback_label.to_string();
        }
        Err(e) => {
            tracing::warn!(%theme_id, error = %e, "namer: DB error fetching nearest claims");
            return fallback_label.to_string();
        }
    };

    let prompt = build_naming_prompt(&claims);
    let raw = match tokio::task::spawn_blocking(move || invoke_claude(&prompt)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(%theme_id, error = %e, "namer: claude CLI failed, using fallback");
            return fallback_label.to_string();
        }
        Err(e) => {
            tracing::warn!(%theme_id, error = %e, "namer: spawn_blocking panicked, using fallback");
            return fallback_label.to_string();
        }
    };

    let name = parse_theme_name(&raw);
    if name.is_empty() {
        tracing::warn!(%theme_id, raw = %raw, "namer: empty parse result, using fallback");
        return fallback_label.to_string();
    }

    tracing::info!(%theme_id, label = %name, "namer: named theme");
    name
}
