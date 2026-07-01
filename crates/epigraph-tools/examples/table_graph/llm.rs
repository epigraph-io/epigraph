//! Claude CLI driver. Builds a per-table prompt and invokes `claude` (OAuth)
//! to produce a structured Markdown narrative. No SDK fallback per project convention.

use crate::types::*;
use anyhow::{anyhow, Context, Result};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MD_INSTRUCTIONS: &str = r#"
Produce a Markdown document with EXACTLY this structure (no preamble, no postamble):

# Table `<name>` (`<repo>`)

## Purpose

<one paragraph: what this table stores, why it exists, who reads/writes it>

## Call sites

- Crate `<crate>` writes to via function `<fn>`: `<grep-able snippet>`
- Crate `<crate>` reads from via function `<fn>`: `<grep-able snippet>`
... (one bullet per discovered call site)

## Foreign key relationships

- References table `<target>`: `<DDL excerpt>`
... (one bullet per FK; omit section if none)

## DDL

```sql
<concatenated CREATE/ALTER>
```

## Git context

- <SHA-prefix> <date>: <subject>
... (one bullet per commit, most recent first)

Notes:
- Use the call sites and FK targets exactly as provided in the dossier; do not invent.
- Snippets must be grep-able strings that appear verbatim in the source code.
- The "Purpose" paragraph is your own synthesis from the dossier.
"#;

pub fn build_prompt(d: &Dossier) -> String {
    let mut p = String::new();
    p.push_str(&format!(
        "Build a Tier-1 hierarchical narrative for database table `{}` in repo `{}`.\n\n",
        d.table.name, d.table.repo
    ));
    p.push_str("# Dossier\n\n## DDL\n```sql\n");
    p.push_str(&d.ddl);
    p.push_str("\n```\n\n## Git context\n");
    for c in &d.commits {
        p.push_str(&format!(
            "- {} {}: {}\n",
            &c.sha[..8.min(c.sha.len())],
            c.date,
            c.subject
        ));
        if !c.body.is_empty() {
            p.push_str(&format!("  {}\n", c.body.lines().next().unwrap_or("")));
        }
    }
    p.push_str("\n## Call sites (deterministically extracted)\n");
    for s in &d.call_sites {
        p.push_str(&format!(
            "- crate=`{}` fn=`{}` kind={:?}\n  snippet: `{}`\n",
            s.crate_name, s.function, s.kind, s.snippet
        ));
    }
    p.push_str("\n## FK targets (deterministically extracted)\n");
    for t in &d.fk_targets {
        p.push_str(&format!("- {}\n", t));
    }
    p.push_str("\n");
    p.push_str(MD_INSTRUCTIONS);
    p
}

/// Strip an optional ```markdown ... ``` code fence and any leading prose.
pub fn extract_md(text: &str) -> Result<String> {
    if let Some(start) = text.find("```markdown") {
        let after = &text[start + "```markdown".len()..];
        let end = after
            .find("```")
            .ok_or_else(|| anyhow!("unterminated code fence"))?;
        return Ok(after[..end].trim().to_string());
    }
    // Check for # Table header before generic fence (avoids matching inner ```sql blocks)
    if let Some(start) = text.find("# Table") {
        return Ok(text[start..].trim().to_string());
    }
    // Fallback: bare fence (only if no # Table header found)
    if let Some(start) = text.find("```") {
        let after = &text[start + 3..];
        let end = after
            .find("```")
            .ok_or_else(|| anyhow!("unterminated code fence"))?;
        return Ok(after[..end].trim().to_string());
    }
    Err(anyhow!("no '# Table' header or code fence"))
}

/// Invoke `claude -p` and read its narrative output from a result file.
///
/// Nested `claude` sessions suppress text in the `--output-format json` `result`
/// field (see `feedback_nested_cli.md`), so we instead instruct Claude to Write
/// the narrative to `result_path` and poll for that file.
pub fn invoke_claude(prompt: &str, result_path: &std::path::Path) -> Result<String> {
    if let Some(parent) = result_path.parent() {
        std::fs::create_dir_all(parent).context("create result_path parent")?;
    }
    if result_path.exists() {
        std::fs::remove_file(result_path).ok();
    }

    let wrapped = format!(
        "{prompt}\n\n---\n\nWhen you have produced the Markdown document, use the Write tool to save it to:\n\n    {path}\n\nWrite ONLY the Markdown document to that file (no preamble, no postamble, no surrounding code fence). Do not print the document to the chat.\n",
        prompt = prompt,
        path = result_path.display(),
    );

    let status = Command::new("claude")
        .args([
            "-p",
            "--dangerously-skip-permissions",
            "--model",
            "claude-sonnet-5",
        ])
        .arg(&wrapped)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("spawn claude CLI")?;
    if !status.success() {
        return Err(anyhow!("claude CLI exited non-zero (status {})", status));
    }

    // Result file is written by the Write tool inside the subprocess, but tool
    // execution can complete slightly after process exit. Poll briefly.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !result_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    if !result_path.exists() {
        return Err(anyhow!(
            "claude exited successfully but did not write {}",
            result_path.display()
        ));
    }
    std::fs::read_to_string(result_path)
        .with_context(|| format!("read result file {}", result_path.display()))
}

pub fn extract(d: &Dossier) -> Result<String> {
    let result_dir = std::path::PathBuf::from(
        "docs/superpowers/artifacts/2026-04-30-table-graph/staging/llm-out",
    );
    let result_path = result_dir.join(format!("{}.{}.md", d.table.repo, d.table.name));

    let prompt = build_prompt(d);
    let raw = invoke_claude(&prompt, &result_path)?;
    if let Ok(md) = extract_md(&raw) {
        return Ok(md);
    }
    // Some models wrap the doc in extra prose; ask for a strict re-emission.
    let strict = format!(
        "Respond with ONLY the Markdown document (no prose, no fences).\n\n{}",
        prompt
    );
    let raw = invoke_claude(&strict, &result_path)?;
    extract_md(&raw)
}
