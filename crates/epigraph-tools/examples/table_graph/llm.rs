//! Claude CLI driver. Builds a per-table prompt and invokes `claude` (OAuth)
//! to produce a structured Markdown narrative. No SDK fallback per project convention.

use crate::types::*;
use anyhow::{anyhow, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

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
    p.push_str(&format!("Build a Tier-1 hierarchical narrative for database table `{}` in repo `{}`.\n\n",
        d.table.name, d.table.repo));
    p.push_str("# Dossier\n\n## DDL\n```sql\n");
    p.push_str(&d.ddl);
    p.push_str("\n```\n\n## Git context\n");
    for c in &d.commits {
        p.push_str(&format!("- {} {}: {}\n", &c.sha[..8.min(c.sha.len())], c.date, c.subject));
        if !c.body.is_empty() {
            p.push_str(&format!("  {}\n", c.body.lines().next().unwrap_or("")));
        }
    }
    p.push_str("\n## Call sites (deterministically extracted)\n");
    for s in &d.call_sites {
        p.push_str(&format!("- crate=`{}` fn=`{}` kind={:?}\n  snippet: `{}`\n",
            s.crate_name, s.function, s.kind, s.snippet));
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
        let end = after.find("```").ok_or_else(|| anyhow!("unterminated code fence"))?;
        return Ok(after[..end].trim().to_string());
    }
    if let Some(start) = text.find("```") {
        let after = &text[start + 3..];
        let end = after.find("```").ok_or_else(|| anyhow!("unterminated code fence"))?;
        return Ok(after[..end].trim().to_string());
    }
    let start = text.find("# Table").ok_or_else(|| anyhow!("no '# Table' header"))?;
    Ok(text[start..].trim().to_string())
}

pub fn invoke_claude(prompt: &str) -> Result<String> {
    let mut child = Command::new("claude")
        .args(["-p", "--output-format", "json", "--model", "claude-sonnet-4-6"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn claude CLI")?;
    child.stdin.as_mut().expect("stdin").write_all(prompt.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!("claude CLI failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let stdout = String::from_utf8(out.stdout)?;
    let envelope: serde_json::Value = serde_json::from_str(&stdout)
        .context("claude CLI stdout not JSON")?;
    let text = envelope.get("result").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("empty result; stdout: {}", stdout))?;
    Ok(text.to_string())
}

pub fn extract(d: &Dossier) -> Result<String> {
    let prompt = build_prompt(d);
    let raw = invoke_claude(&prompt)?;
    if let Ok(md) = extract_md(&raw) { return Ok(md); }
    let strict = format!("Respond with ONLY the Markdown document (no prose, no fences).\n\n{}", prompt);
    let raw = invoke_claude(&strict)?;
    extract_md(&raw)
}
