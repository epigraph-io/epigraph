# PR-hierarchical commit ingestion (core) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a PR-hierarchical ingestion mode to `ingest_git` that, given one merged PR's metadata + commits, writes a `repo → PR → commit` claim hierarchy with datestamped edges, attributes the PR to the orchestrator agent and commits to their (stable) git authors, and links the PR to the backlog/resolution claims it resolves.

**Architecture:** Extend the existing `crates/epigraph-cli/src/bin/ingest_git.rs` (hand-rolled CLI, reqwest → epigraph-api HTTP). Reuse `parse_commit_message`, `build_packet`, `register_agent`, `create_prov_edge`. Find-or-create nodes via `/api/v1/submit/packet` with stable `idempotency_key`s. All structural + resolution edges go through the **generic** `POST /api/v1/edges` (it carries `valid_from` + `if_not_exists`; the hierarchical endpoint does not). Linking uses the **existing** `RESOLVED_BY` relationship — no server change. This plan is the CLI logic only; the GitHub Actions wiring and the historical backfill are separate plans.

**Tech stack:** Rust, reqwest, serde_json, uuid, `epigraph_crypto` (`AgentSigner`, `ContentHasher`, `to_canonical_bytes`), blake3 (deterministic author seed), chrono. Tests: `#[sqlx::test]` + axum `tower::ServiceExt::oneshot` against `epigraph_db_repo_test`.

**Scope decisions baked in (from the design + recon):**
- Linking relationship = **`RESOLVED_BY`** (`backlog/resolution claim → PR claim`); already in `VALID_RELATIONSHIPS`, non-evidential. *No `resolves` server change.*
- All edges via `POST /api/v1/edges` with `valid_from` + `if_not_exists:true`.
- Packet signature: reuse existing behavior (per-author signer signs evidence bullets; packet-level signature is the existing placeholder). Valid because prod runs `require_signatures=false`. Proper canonical packet signing + the broader DID system are explicitly **out of scope** (tracked in the spec §6.3).
- Find-or-create = `submit` with stable `idempotency_key`.

**Conventions:** Run all `git`/`cargo` with absolute paths in the worktree. Test DB: `export DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test` (superuser per CLAUDE.md). Pre-commit gate every task: `cargo fmt --check` + `cargo clippy -p epigraph-cli --bin ingest_git --locked -- -D warnings`.

---

## File structure

- **Modify** `crates/epigraph-cli/src/bin/ingest_git.rs` — add: PR-mode args; `resolve_author_agent`; `resolve_orchestrator_agent`; `parse_orchestrator_trailer`; `ensure_repo_node`; `build_pr_packet`; `submit_find_or_create`; `link_edge`; `extract_references`; `link_resolutions`; `run_pr_ingest` (the mode entry); a `#[cfg(test)]` block for the new pure functions.
- **Create** `crates/epigraph-cli/tests/pr_hierarchical_ingest_test.rs` — end-to-end `#[sqlx::test]` using an in-process axum router (submit + edges + claims-query routes) via `oneshot`.

Everything new lives in the one bin file (matching the existing layout — the bin is already self-contained with its API structs). The integration test is a new file under the crate's existing `tests/` dir.

---

## Task 0: Spike — confirm registration route, agent idempotency, and submit dedup

**Files:** none (investigation; record findings in the commit message of Task 1).

- [ ] **Step 1: Confirm the agent-registration route + whether it dedups on public_key**

Run:
```bash
cd /home/jeremy/epigraph-wt-commitspec
grep -rn "/agents\"\|route(\"/agents\|fn create_agent\|public_key" crates/epigraph-api/src/routes/agents.rs crates/epigraph-api/src/lib.rs | head -40
```
Determine: (a) the exact path (`/agents` vs `/api/v1/agents`), (b) whether POSTing an existing `public_key` returns the existing agent (idempotent) or errors/creates a duplicate.

- [ ] **Step 2: Confirm submit dedup on `idempotency_key`**

Run:
```bash
grep -rn "idempotency_key\|was_duplicate\|ON CONFLICT" crates/epigraph-api/src/routes/submit.rs crates/epigraph-db/src/repos/claim.rs | head -40
```
Confirm a second submit with the same `idempotency_key` returns `was_duplicate:true` and the same `claim_id` (this is the find-or-create primitive).

- [ ] **Step 3: Record the two answers.** If `/agents` is NOT idempotent on `public_key`, Task 1 must add a GET-existing-by-public-key lookup before POST; note which route serves that. If no lookup route exists, Task 1 registers once and relies on the deterministic key making re-registration a no-op or tolerated duplicate (acceptable: same public_key, the deterministic id derivation in Step 1 of Task 1 keeps attribution stable regardless of duplicate agent rows). No commit (investigation only).

---

## Task 1: Deterministic per-author agent resolver

**Files:**
- Modify: `crates/epigraph-cli/src/bin/ingest_git.rs`
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test for a deterministic author signer**

Add to the test module:
```rust
#[test]
fn author_signer_is_deterministic_per_email() {
    let a = author_signer("Jeremy Barton", "jeremy.barton@gmail.com");
    let b = author_signer("J. Barton", "jeremy.barton@gmail.com"); // name differs, email same
    let c = author_signer("Someone", "other@example.com");
    assert_eq!(a.public_key(), b.public_key(), "same email => same key");
    assert_ne!(a.public_key(), c.public_key(), "different email => different key");
}

#[test]
fn author_email_is_normalized() {
    let a = author_signer("x", "Jeremy.Barton@Gmail.com  ");
    let b = author_signer("x", "jeremy.barton@gmail.com");
    assert_eq!(a.public_key(), b.public_key(), "case/space-insensitive email");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/jeremy/epigraph-wt-commitspec && cargo test -p epigraph-cli --bin ingest_git author_signer -- --nocapture`
Expected: FAIL — `author_signer` not found.

- [ ] **Step 3: Implement the deterministic signer**

Add near `AgentRegistry` (blake3 is already a crate dep):
```rust
/// Derive a STABLE Ed25519 signer for a git author from their email, so the same
/// human maps to the same agent identity across every run and repo. Email is
/// normalized (trimmed + lowercased). This is the interim author-DID scheme
/// pending the project's real DID system.
fn author_signer(_display_name: &str, email: &str) -> AgentSigner {
    let normalized = email.trim().to_ascii_lowercase();
    let seed = blake3::hash(format!("epigraph-git-author-v1:{normalized}").as_bytes());
    let key: [u8; 32] = *seed.as_bytes();
    AgentSigner::from_bytes(&key).expect("32-byte blake3 hash is a valid Ed25519 seed")
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p epigraph-cli --bin ingest_git author_signer -- --nocapture`
Expected: PASS (both tests).

- [ ] **Step 5: Add the registration-backed resolver (find-or-create author agent)**

Add (uses the existing `AgentRegistry::register_agent` associated fn; per Task 0, registration of a repeated public_key is tolerated):
```rust
/// Resolve (and register if needed) the stable agent id for a git author.
/// Caches per email within a run to avoid duplicate POSTs.
async fn resolve_author_agent(
    client: &reqwest::Client,
    endpoint: &str,
    cache: &mut std::collections::HashMap<String, (AgentSigner, Uuid)>,
    display_name: &str,
    email: &str,
) -> Result<(AgentSigner, Uuid), String> {
    let key = email.trim().to_ascii_lowercase();
    if let Some(hit) = cache.get(&key) {
        return Ok((hit.0.clone(), hit.1));
    }
    let signer = author_signer(display_name, email);
    let agent_id = AgentRegistry::register_agent(client, endpoint, &signer, display_name).await?;
    cache.insert(key, (signer.clone(), agent_id));
    Ok((signer, agent_id))
}
```
> If `AgentSigner` is not `Clone`, store the 32-byte key in the cache and rebuild the signer via `author_signer` on hit (it is deterministic). Adjust accordingly.

- [ ] **Step 6: Commit**

```bash
cd /home/jeremy/epigraph-wt-commitspec
cargo fmt && cargo clippy -p epigraph-cli --bin ingest_git --locked -- -D warnings
git add crates/epigraph-cli/src/bin/ingest_git.rs
git commit -m "feat(cli): deterministic per-author agent identity for git ingest

**Evidence:**
- per-author mode minted a fresh Uuid::new_v4()+key per run, proliferating duplicate
  author agents; Task 0 confirmed registration/idempotency behavior <record finding>.

**Reasoning:**
- Derive the author's Ed25519 key from blake3(namespace||lowercased email) so the same
  committer maps to one stable identity across runs/repos; interim DID scheme per spec §6.3.

**Verification:**
- cargo test author_signer (determinism + email normalization) passes; fmt+clippy clean."
```

---

## Task 2: Orchestrator-agent resolver (trailer + fallback)

**Files:** Modify + test in `ingest_git.rs`.

- [ ] **Step 1: Write the failing test for trailer parsing**

```rust
#[test]
fn parses_orchestrator_trailer() {
    let body = "fix(api): x\n\nEvidence:\n- y\n\nEpigraph-Orchestrator-Id: 7b3a0c1e-0000-4000-8000-000000000001\nCo-Authored-By: Claude <a@b>";
    assert_eq!(
        parse_orchestrator_trailer(body),
        Some("7b3a0c1e-0000-4000-8000-000000000001".parse().unwrap())
    );
    assert_eq!(parse_orchestrator_trailer("no trailer here"), None);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p epigraph-cli --bin ingest_git orchestrator_trailer -- --nocapture`
Expected: FAIL — `parse_orchestrator_trailer` not found.

- [ ] **Step 3: Implement trailer parsing**

```rust
/// Parse an `Epigraph-Orchestrator-Id: <uuid>` trailer from a PR body or commit message.
/// Case-insensitive key match; last occurrence wins (trailers live at the bottom).
fn parse_orchestrator_trailer(text: &str) -> Option<Uuid> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("Epigraph-Orchestrator-Id") {
                v.trim().parse::<Uuid>().ok()
            } else {
                None
            }
        })
        .last()
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p epigraph-cli --bin ingest_git orchestrator_trailer -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Add the resolver with env fallback**

```rust
/// Resolve the implementing orchestrator agent id for a PR:
/// 1) `Epigraph-Orchestrator-Id:` trailer in the PR body or any commit message;
/// 2) else `EPIGRAPH_DEFAULT_ORCHESTRATOR_ID` env var.
/// Returns an error if neither is present (the PR claim MUST have an author).
fn resolve_orchestrator_agent(pr_body: &str, commit_msgs: &[String]) -> Result<Uuid, String> {
    if let Some(id) = parse_orchestrator_trailer(pr_body) {
        return Ok(id);
    }
    for m in commit_msgs {
        if let Some(id) = parse_orchestrator_trailer(m) {
            return Ok(id);
        }
    }
    std::env::var("EPIGRAPH_DEFAULT_ORCHESTRATOR_ID")
        .ok()
        .and_then(|s| s.trim().parse::<Uuid>().ok())
        .ok_or_else(|| {
            "no Epigraph-Orchestrator-Id trailer and EPIGRAPH_DEFAULT_ORCHESTRATOR_ID unset".to_string()
        })
}
```
> The orchestrator agent must already exist in `agents`. The caller (Task 8) verifies via `GET /api/v1/agents/{id}` (or the route confirmed in Task 0) and, if missing, falls back to the env default; if that is also missing/unregistered, the run fails fast with a clear message rather than minting a junk agent.

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy -p epigraph-cli --bin ingest_git --locked -- -D warnings
git add crates/epigraph-cli/src/bin/ingest_git.rs
git commit -m "feat(cli): resolve PR orchestrator agent from trailer + env fallback

**Evidence:**
- PR claims must be attributed to the implementing orchestrator agent (design §6.1).

**Reasoning:**
- Read Epigraph-Orchestrator-Id trailer (PR body, then commits); fall back to
  EPIGRAPH_DEFAULT_ORCHESTRATOR_ID; never mint a junk agent on an unknown DID.

**Verification:**
- cargo test orchestrator_trailer passes; fmt+clippy clean."
```

---

## Task 3: Find-or-create primitive + repo node

**Files:** Modify + test in `ingest_git.rs`.

- [ ] **Step 1: Write the failing test for the repo-node packet shape**

```rust
#[test]
fn repo_node_packet_has_stable_idempotency_and_label() {
    let signer = AgentSigner::generate();
    let p = build_repo_packet("epigraph-io/epiclaw-host", signer.public_key_uuid_stub(), &signer);
    assert_eq!(p.claim.idempotency_key.as_deref(), Some("repo:epigraph-io/epiclaw-host"));
    assert!(p.claim.content.contains("epigraph-io/epiclaw-host"));
    let props = p.claim.properties.as_ref().unwrap();
    assert_eq!(props["source"], "git-history");
    assert_eq!(props["node"], "repo");
    assert_eq!(props["repo"], "epigraph-io/epiclaw-host");
}
```
> `public_key_uuid_stub()` is not real; replace with a literal `Uuid::nil()` for the test — the packet builder takes an explicit `agent_id`. Rewrite the call as `build_repo_packet("epigraph-io/epiclaw-host", Uuid::nil(), &signer)`.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p epigraph-cli --bin ingest_git repo_node_packet -- --nocapture`
Expected: FAIL — `build_repo_packet` not found.

- [ ] **Step 3: Implement `build_repo_packet`**

```rust
/// Build the find-or-create packet for a repository's root node.
fn build_repo_packet(repo_slug: &str, agent_id: Uuid, signer: &AgentSigner) -> EpistemicPacket {
    let content = format!("Repository {repo_slug} — development history (commits and PRs).");
    let evidence_text = format!("Repository slug: {repo_slug}");
    let ev = EvidenceSubmission {
        content_hash: hex::encode(ContentHasher::hash(evidence_text.as_bytes())),
        evidence_type: EvidenceTypeSubmission::Document { source_url: Some(format!("repo://{repo_slug}")), mime_type: "text/plain".into() },
        raw_content: Some(evidence_text.clone()),
        signature: Some(hex::encode(signer.sign(evidence_text.as_bytes()))),
    };
    EpistemicPacket {
        claim: ClaimSubmission {
            content,
            initial_truth: Some(0.95),
            agent_id,
            idempotency_key: Some(format!("repo:{repo_slug}")),
            properties: Some(serde_json::json!({
                "source": "git-history", "node": "repo", "repo": repo_slug
            })),
        },
        evidence: vec![ev],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: "heuristic".into(),
            inputs: vec![TraceInputSubmission::Evidence { index: 0 }],
            confidence: 0.95,
            explanation: format!("Root node for repository {repo_slug}"),
            signature: None,
        },
        signature: "0".repeat(128),
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p epigraph-cli --bin ingest_git repo_node_packet -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Add the `submit_find_or_create` helper and `ensure_repo_node`**

```rust
/// Submit a packet and return its claim id. Because the packet carries a stable
/// idempotency_key, a second call returns the same claim_id (was_duplicate=true).
async fn submit_find_or_create(
    client: &reqwest::Client, endpoint: &str, packet: &EpistemicPacket, labels: &[&str],
) -> Result<Uuid, String> {
    let url = format!("{endpoint}/api/v1/submit/packet");
    let resp = client.post(&url).json(packet).timeout(Duration::from_secs(30)).send().await
        .map_err(|e| format!("submit failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("submit {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    let parsed: SubmitResponse = resp.json().await.map_err(|e| format!("decode submit resp: {e}"))?;
    // Labels are applied via PATCH /api/v1/claims/{id} (labels field) — see Task 8 helper `apply_labels`.
    if !labels.is_empty() {
        apply_labels(client, endpoint, parsed.claim_id, labels).await?;
    }
    Ok(parsed.claim_id)
}

async fn ensure_repo_node(
    client: &reqwest::Client, endpoint: &str, repo_slug: &str, agent_id: Uuid, signer: &AgentSigner,
) -> Result<Uuid, String> {
    let packet = build_repo_packet(repo_slug, agent_id, signer);
    let label = format!("repo:{repo_slug}");
    submit_find_or_create(client, endpoint, &packet, &["source:git-history", "node:repo", &label]).await
}
```
> `apply_labels` is defined in Task 8 (PATCH `/api/v1/claims/{id}` with `{"labels": {"add": [...]}}` — confirm the exact label-patch body against `routes/claims.rs` during Task 8; the CLAUDE.md backlog section shows `add=[...]` semantics).

- [ ] **Step 6: Commit**

```bash
cargo fmt && cargo clippy -p epigraph-cli --bin ingest_git --locked -- -D warnings
git add crates/epigraph-cli/src/bin/ingest_git.rs
git commit -m "feat(cli): find-or-create repo root node via stable idempotency_key

**Evidence:**
- The hierarchy needs one persistent root per repo (design §4.2); submit idempotency_key
  is the find-or-create primitive (Task 0 confirmed dedup returns same claim_id).

**Reasoning:**
- build_repo_packet keys on repo:{slug}; submit_find_or_create returns the stable id and
  applies source:git-history/node:repo/repo:<slug> labels.

**Verification:**
- cargo test repo_node_packet passes; fmt+clippy clean."
```

---

## Task 4: PR node builder + find-or-create

**Files:** Modify + test in `ingest_git.rs`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn pr_packet_keys_on_repo_and_number_and_carries_properties() {
    let signer = AgentSigner::generate();
    let meta = PrMeta {
        repo_slug: "epigraph-io/epigraph".into(), number: 252,
        title: "fix(api): stop auto-enqueueing cluster jobs".into(),
        body: "## Summary\nResolves d531c585".into(),
        merge_sha: "2a31f8d".into(), merged_at: "2026-06-02T15:10:01Z".into(),
        author_login: "tylorsama".into(),
    };
    let p = build_pr_packet(&meta, Uuid::nil());
    assert_eq!(p.claim.idempotency_key.as_deref(), Some("pr:epigraph-io/epigraph#252"));
    assert!(p.claim.content.contains("stop auto-enqueueing cluster jobs"));
    let props = p.claim.properties.as_ref().unwrap();
    assert_eq!(props["node"], "pr");
    assert_eq!(props["pr_number"], 252);
    assert_eq!(props["merge_sha"], "2a31f8d");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p epigraph-cli --bin ingest_git pr_packet -- --nocapture`
Expected: FAIL — `PrMeta` / `build_pr_packet` not found.

- [ ] **Step 3: Implement `PrMeta` + `build_pr_packet`**

```rust
#[derive(Debug, Clone)]
struct PrMeta {
    repo_slug: String,
    number: u64,
    title: String,
    body: String,
    merge_sha: String,
    merged_at: String,   // ISO-8601
    author_login: String,
}

/// Build the find-or-create packet for a PR node. agent_id = orchestrator agent.
fn build_pr_packet(meta: &PrMeta, orchestrator_id: Uuid) -> EpistemicPacket {
    let content = format!("[PR #{}] {}", meta.number, meta.title);
    let body = if meta.body.trim().is_empty() { meta.title.clone() } else { meta.body.clone() };
    let ev = EvidenceSubmission {
        content_hash: hex::encode(ContentHasher::hash(body.as_bytes())),
        evidence_type: EvidenceTypeSubmission::Document {
            source_url: Some(format!("https://github.com/{}/pull/{}", meta.repo_slug, meta.number)),
            mime_type: "text/markdown".into(),
        },
        raw_content: Some(body),
        signature: None,
    };
    EpistemicPacket {
        claim: ClaimSubmission {
            content,
            initial_truth: Some(0.8),
            agent_id: orchestrator_id,
            idempotency_key: Some(format!("pr:{}#{}", meta.repo_slug, meta.number)),
            properties: Some(serde_json::json!({
                "source": "git-history", "node": "pr",
                "repo": meta.repo_slug, "pr_number": meta.number,
                "merge_sha": meta.merge_sha, "merged_at": meta.merged_at,
                "url": format!("https://github.com/{}/pull/{}", meta.repo_slug, meta.number),
                "author_login": meta.author_login, "orchestrator_agent_id": orchestrator_id,
            })),
        },
        evidence: vec![ev],
        reasoning_trace: ReasoningTraceSubmission {
            methodology: "heuristic".into(),
            inputs: vec![TraceInputSubmission::Evidence { index: 0 }],
            confidence: 0.8,
            explanation: format!("PR #{} merged at {}", meta.number, meta.merged_at),
            signature: None,
        },
        signature: "0".repeat(128),
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p epigraph-cli --bin ingest_git pr_packet -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy -p epigraph-cli --bin ingest_git --locked -- -D warnings
git add crates/epigraph-cli/src/bin/ingest_git.rs
git commit -m "feat(cli): build PR node packet attributed to orchestrator agent

**Evidence:**
- PR is the unit of work/merge/resolution (design §4.1); attributed to orchestrator (§6.1).

**Reasoning:**
- build_pr_packet keys on pr:{slug}#{n}, content from PR title, body as evidence,
  pr_number/merge_sha/merged_at/url in properties for downstream linking + datestamps.

**Verification:**
- cargo test pr_packet passes; fmt+clippy clean."
```

---

## Task 5: Datestamped edge helper

**Files:** Modify + test in `ingest_git.rs`.

- [ ] **Step 1: Write the failing test for the edge request body**

```rust
#[test]
fn edge_body_uses_generic_endpoint_fields() {
    let body = edge_body(Uuid::nil(), Uuid::nil(), "decomposes_to", Some("2026-06-02T15:10:01Z"));
    assert_eq!(body["source_type"], "claim");
    assert_eq!(body["target_type"], "claim");
    assert_eq!(body["relationship"], "decomposes_to");
    assert_eq!(body["valid_from"], "2026-06-02T15:10:01Z");
    assert_eq!(body["if_not_exists"], true);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p epigraph-cli --bin ingest_git edge_body -- --nocapture`
Expected: FAIL — `edge_body` not found.

- [ ] **Step 3: Implement `edge_body` + `link_edge`**

```rust
/// Build a generic POST /api/v1/edges body. Uses the generic endpoint (not
/// /edges/hierarchical) because only this one accepts valid_from + if_not_exists.
fn edge_body(source_id: Uuid, target_id: Uuid, relationship: &str, valid_from: Option<&str>) -> serde_json::Value {
    let mut b = serde_json::json!({
        "source_id": source_id, "target_id": target_id,
        "source_type": "claim", "target_type": "claim",
        "relationship": relationship,
        "if_not_exists": true,
        "properties": { "source": "git-history" },
    });
    if let Some(ts) = valid_from {
        b["valid_from"] = serde_json::json!(ts);
    }
    b
}

/// Create an idempotent, datestamped edge. 200/201 both mean success.
async fn link_edge(
    client: &reqwest::Client, endpoint: &str,
    source_id: Uuid, target_id: Uuid, relationship: &str, valid_from: Option<&str>,
) -> Result<(), String> {
    let url = format!("{endpoint}/api/v1/edges");
    let resp = client.post(&url).json(&edge_body(source_id, target_id, relationship, valid_from))
        .timeout(Duration::from_secs(30)).send().await.map_err(|e| format!("edge POST failed: {e}"))?;
    let status = resp.status();
    if status.is_success() { Ok(()) }
    else { Err(format!("edge {}: {}", status, resp.text().await.unwrap_or_default())) }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p epigraph-cli --bin ingest_git edge_body -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy -p epigraph-cli --bin ingest_git --locked -- -D warnings
git add crates/epigraph-cli/src/bin/ingest_git.rs
git commit -m "feat(cli): idempotent datestamped edge helper via generic /edges

**Evidence:**
- Hierarchy + resolution edges must carry valid_from; LinkHierarchicalRequest lacks it,
  CreateEdgeRequest has valid_from + if_not_exists and allows decomposes_to/RESOLVED_BY.

**Reasoning:**
- Single edge_body/link_edge over POST /api/v1/edges with if_not_exists=true for
  re-run safety; valid_from stamps the relationship with merge/commit time.

**Verification:**
- cargo test edge_body passes; fmt+clippy clean."
```

---

## Task 6: Reference resolver (UUID trailers/free-text + PR-number)

**Files:** Modify + test in `ingest_git.rs`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn extracts_uuid_and_pr_references() {
    let text = "Resolves d531c585-0214-4fad-972b-10c7aa039984\n\
                Resolves-Claim: 9699e396-380b-4105-99c3-e4938dc3e156\n\
                see also PR #219 and #237";
    let refs = extract_references(text);
    assert!(refs.claim_uuids.contains(&"d531c585-0214-4fad-972b-10c7aa039984".parse().unwrap()));
    assert!(refs.claim_uuids.contains(&"9699e396-380b-4105-99c3-e4938dc3e156".parse().unwrap()));
    assert!(refs.pr_numbers.contains(&219));
    assert!(refs.pr_numbers.contains(&237));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p epigraph-cli --bin ingest_git references -- --nocapture`
Expected: FAIL — `extract_references` not found.

- [ ] **Step 3: Implement extraction (regex-free, std-only)**

```rust
#[derive(Debug, Default, PartialEq)]
struct References {
    claim_uuids: Vec<Uuid>,
    pr_numbers: Vec<u64>,
}

/// Extract resolution references from PR body + commit text:
/// - any token parseable as a UUID that appears after "Resolves" or in a
///   "Resolves-Claim:" trailer;
/// - any `#<n>` token (PR/issue numbers).
fn extract_references(text: &str) -> References {
    let mut r = References::default();
    for raw in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let tok = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '#');
        if let Ok(id) = tok.parse::<Uuid>() {
            if !r.claim_uuids.contains(&id) { r.claim_uuids.push(id); }
        } else if let Some(num) = tok.strip_prefix('#').and_then(|n| n.parse::<u64>().ok()) {
            if !r.pr_numbers.contains(&num) { r.pr_numbers.push(num); }
        }
    }
    r
}
```
> This deliberately treats *any* UUID in the text as a candidate claim reference (the `Resolves`/`Resolves-Claim:` context is human convention; the resolver validates existence before linking, so a stray UUID that isn't a claim is simply dropped in Task 7's lookup).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p epigraph-cli --bin ingest_git references -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy -p epigraph-cli --bin ingest_git --locked -- -D warnings
git add crates/epigraph-cli/src/bin/ingest_git.rs
git commit -m "feat(cli): extract claim-UUID and PR-number references from PR text

**Evidence:**
- PRs link to backlog/resolution claims they resolve (design §7) via Resolves-Claim
  trailer / free-text UUID / PR-number citations.

**Reasoning:**
- std-only tokenizer collects candidate UUIDs and #N numbers; existence is validated
  before any edge is created (Task 7), so stray tokens are harmless.

**Verification:**
- cargo test references passes; fmt+clippy clean."
```

---

## Task 7: Resolve references to claim ids and link RESOLVED_BY edges

**Files:** Modify in `ingest_git.rs`. (Network behavior is covered by the Task 9 integration test, not a unit test.)

- [ ] **Step 1: Implement claim-existence check + PR-number search + linking**

```rust
/// Confirm a claim exists (GET returns 200). properties are not exposed by the
/// read endpoint, but existence is all we need.
async fn claim_exists(client: &reqwest::Client, endpoint: &str, id: Uuid) -> bool {
    let url = format!("{endpoint}/api/v1/claims/{id}");
    matches!(client.get(&url).timeout(Duration::from_secs(15)).send().await, Ok(r) if r.status().is_success())
}

/// Find existing resolution/backlog claims whose CONTENT cites "PR #<n>".
async fn find_claims_citing_pr(client: &reqwest::Client, endpoint: &str, n: u64) -> Vec<Uuid> {
    let needle = format!("PR #{n}");
    let url = format!("{endpoint}/api/v1/claims");
    let resp = client.get(&url)
        .query(&[("content_contains", needle.as_str()), ("is_current", "true"), ("limit", "25")])
        .timeout(Duration::from_secs(20)).send().await;
    let Ok(resp) = resp else { return vec![] };
    if !resp.status().is_success() { return vec![]; }
    let Ok(v) = resp.json::<serde_json::Value>().await else { return vec![] };
    v["claims"].as_array().map(|a| {
        a.iter().filter_map(|c| c["id"].as_str()?.parse::<Uuid>().ok()).collect()
    }).unwrap_or_default()
}

/// For each resolved target, create `target --RESOLVED_BY--> PR`, datestamped at merge time.
/// RESOLVED_BY is in VALID_RELATIONSHIPS and is non-evidential (no DS recompute).
async fn link_resolutions(
    client: &reqwest::Client, endpoint: &str,
    pr_claim_id: Uuid, refs: &References, merged_at: &str,
) -> Result<usize, String> {
    let mut linked = 0;
    for uuid in &refs.claim_uuids {
        if *uuid != pr_claim_id && claim_exists(client, endpoint, *uuid).await {
            link_edge(client, endpoint, *uuid, pr_claim_id, "RESOLVED_BY", Some(merged_at)).await?;
            linked += 1;
        }
    }
    for n in &refs.pr_numbers {
        for target in find_claims_citing_pr(client, endpoint, *n).await {
            if target != pr_claim_id {
                link_edge(client, endpoint, target, pr_claim_id, "RESOLVED_BY", Some(merged_at)).await?;
                linked += 1;
            }
        }
    }
    Ok(linked)
}
```
> Direction is `backlog/resolution claim → RESOLVED_BY → PR claim` (read: "X was resolved by this PR"). Self-references and the PR's own number are skipped.

- [ ] **Step 2: Build (no unit test for network code here)**

Run: `cargo build -p epigraph-cli --bin ingest_git`
Expected: compiles.

- [ ] **Step 3: Commit**

```bash
cargo fmt && cargo clippy -p epigraph-cli --bin ingest_git --locked -- -D warnings
git add crates/epigraph-cli/src/bin/ingest_git.rs
git commit -m "feat(cli): link PR node to resolved backlog claims via RESOLVED_BY

**Evidence:**
- Connect the commit ledger to the ad-hoc dev subgraph (design §1, §7); RESOLVED_BY
  already exists in the allowed relationship set, so no server change.

**Reasoning:**
- Validate UUID refs via GET claim; match PR-number refs via ?content_contains=PR%20%23n;
  create datestamped target->RESOLVED_BY->PR edges (merge time).

**Verification:**
- compiles; behavior asserted end-to-end in Task 9; fmt+clippy clean."
```

---

## Task 8: PR-mode args, `apply_labels`, and `run_pr_ingest` orchestration

**Files:** Modify `Args`, `Args::parse`, `main`, and add `run_pr_ingest` in `ingest_git.rs`.

- [ ] **Step 1: Confirm the label-patch route, then implement `apply_labels`**

Run:
```bash
grep -rn "labels\|fn .*label\|/labels\|patch_claim\|update_labels" crates/epigraph-api/src/routes/claims.rs | head -30
```
Implement against the confirmed route (expected `PATCH /api/v1/claims/{id}` or `/api/v1/claims/{id}/labels` with an `add` list):
```rust
async fn apply_labels(client: &reqwest::Client, endpoint: &str, id: Uuid, labels: &[&str]) -> Result<(), String> {
    // Adjust path/body to the route confirmed above.
    let url = format!("{endpoint}/api/v1/claims/{id}/labels");
    let resp = client.patch(&url).json(&serde_json::json!({ "add": labels }))
        .timeout(Duration::from_secs(15)).send().await.map_err(|e| format!("label PATCH: {e}"))?;
    if resp.status().is_success() { Ok(()) } else {
        Err(format!("label PATCH {}: {}", resp.status(), resp.text().await.unwrap_or_default()))
    }
}
```

- [ ] **Step 2: Add PR-mode fields to `Args` and parse them**

Add to `struct Args`: `pr_mode: bool`, `repo_slug: Option<String>`, `pr_number: Option<u64>`, `pr_title: Option<String>`, `pr_body: Option<String>`, `merge_sha: Option<String>`, `merged_at: Option<String>`, `pr_author: Option<String>`, `rev_range: Option<String>`, `orchestrator_id: Option<Uuid>`.
In `Args::parse`, add flags: `--pr-ingest` (sets `pr_mode=true`), `--repo-slug`, `--pr-number`, `--pr-title`, `--pr-body`, `--merge-sha`, `--merged-at`, `--pr-author`, `--rev-range`, `--orchestrator-id`. Update `--help` text. (Match the existing hand-rolled `while let Some(arg) = iter.next()` pattern.)

- [ ] **Step 3: Add `--rev-range` support to commit parsing**

Extend `parse_git_log` to accept an optional rev-range that, when present, replaces `--since`:
```rust
fn parse_git_log_range(repo: &std::path::Path, rev_range: &str) -> Result<Vec<ParsedCommit>, String> {
    // Same format string as parse_git_log, but pass `rev_range` (e.g. "A..B") and
    // `--no-merges` as the revision argument instead of --since/-n.
    // Reuse parse_git_log_output on the captured stdout.
}
```
Use `--no-merges` so merge commits never become claims (design §4.2).

- [ ] **Step 4: Implement `run_pr_ingest`**

```rust
async fn run_pr_ingest(args: &Args) -> Result<(), String> {
    let client = /* build_client closure result */;
    let repo_slug = args.repo_slug.clone().ok_or("--repo-slug required")?;
    let meta = PrMeta {
        repo_slug: repo_slug.clone(),
        number: args.pr_number.ok_or("--pr-number required")?,
        title: args.pr_title.clone().ok_or("--pr-title required")?,
        body: args.pr_body.clone().unwrap_or_default(),
        merge_sha: args.merge_sha.clone().ok_or("--merge-sha required")?,
        merged_at: args.merged_at.clone().ok_or("--merged-at required")?,
        author_login: args.pr_author.clone().unwrap_or_default(),
    };
    let rev_range = args.rev_range.clone().ok_or("--rev-range required")?;
    let commits = parse_git_log_range(&args.repo, &rev_range)?;
    let commit_msgs: Vec<String> = commits.iter()
        .map(|c| format!("[{}][{}] {}", c.commit_type, c.scope, c.claim_text)).collect();

    // 1) orchestrator agent (trailer/flag/env), verified to exist.
    let orchestrator_id = match args.orchestrator_id {
        Some(id) => id,
        None => resolve_orchestrator_agent(&meta.body, &commit_msgs)?,
    };
    // verify existence; fall back to env default already handled by resolver.

    // 2) repo node (use orchestrator as author of the root node).
    let repo_signer = author_signer("repo-root", &format!("repo+{repo_slug}@git"));
    let _ = AgentRegistry::register_agent(&client, &args.endpoint, &repo_signer, "git-ingester").await;
    let repo_id = ensure_repo_node(&client, &args.endpoint, &repo_slug, orchestrator_id, &repo_signer).await?;

    // 3) PR node.
    let pr_packet = build_pr_packet(&meta, orchestrator_id);
    let pr_label = format!("repo:{repo_slug}");
    let pr_id = submit_find_or_create(&client, &args.endpoint, &pr_packet,
        &["source:git-history", "node:pr", &pr_label]).await?;
    // repo --decomposes_to--> PR, stamped at merge time.
    link_edge(&client, &args.endpoint, repo_id, pr_id, "decomposes_to", Some(&meta.merged_at)).await?;

    // 4) commit children, attributed to git authors.
    let mut author_cache = std::collections::HashMap::new();
    for commit in &commits {
        let (signer, author_id) = resolve_author_agent(&client, &args.endpoint, &mut author_cache,
            &commit.author_name, &commit.author_email).await?;
        let packet = build_packet(commit, &signer, author_id, None);
        let commit_label = format!("repo:{repo_slug}");
        let commit_id = submit_find_or_create(&client, &args.endpoint, &packet,
            &["source:git-history", "node:commit", &commit_label]).await?;
        // PR --decomposes_to--> commit, stamped at commit time.
        link_edge(&client, &args.endpoint, pr_id, commit_id, "decomposes_to", Some(&commit.date)).await?;
    }

    // 5) resolution links (PR-level).
    let mut ref_text = meta.body.clone();
    for c in &commits { ref_text.push('\n'); ref_text.push_str(&c.claim_text); }
    let refs = extract_references(&ref_text);
    let linked = link_resolutions(&client, &args.endpoint, pr_id, &refs, &meta.merged_at).await?;
    println!("PR #{}: repo={repo_id} pr={pr_id} commits={} resolved_links={linked}",
        meta.number, commits.len());
    Ok(())
}
```
> The repo-root signer is a fixed synthetic identity (`git-ingester`); the repo node's `agent_id` is the orchestrator for consistency with PR attribution. Commit children use their git-author agents (design §6.2).

- [ ] **Step 5: Dispatch from `main`**

At the top of `main` (after `Args::parse`), branch:
```rust
if args.pr_mode {
    if let Err(e) = run_pr_ingest(&args).await { eprintln!("pr-ingest failed: {e}"); std::process::exit(1); }
    return;
}
```

- [ ] **Step 6: Build + clippy + commit**

```bash
cd /home/jeremy/epigraph-wt-commitspec
cargo build -p epigraph-cli --bin ingest_git
cargo fmt && cargo clippy -p epigraph-cli --bin ingest_git --locked -- -D warnings
git add crates/epigraph-cli/src/bin/ingest_git.rs
git commit -m "feat(cli): wire --pr-ingest mode assembling repo->PR->commit hierarchy

**Evidence:**
- The PR-hierarchical ingestion path (design §4) needs an entry point taking PR metadata
  + a rev-range and orchestrating node/edge/resolution creation.

**Reasoning:**
- run_pr_ingest: ensure repo node, PR node (orchestrator), commit children (git authors),
  decomposes_to edges datestamped at merge/commit time, RESOLVED_BY resolution links;
  --rev-range with --no-merges so merge commits aren't claims.

**Verification:**
- compiles; fmt+clippy clean; behavior asserted in Task 9."
```

---

## Task 9: End-to-end integration test

**Files:**
- Create: `crates/epigraph-cli/tests/pr_hierarchical_ingest_test.rs`

Because `run_pr_ingest` talks HTTP, the test builds an in-process axum router (submit + edges + claims routes) and points a `reqwest`-free shim at it — OR, simpler and matching the established pattern, the test exercises the **pure assembly** by calling the API handlers directly via `oneshot` with the exact JSON bodies the CLI produces (`build_pr_packet`, `edge_body`). Use the latter: it validates the contracts the CLI depends on without spawning a server.

- [ ] **Step 1: Write the failing end-to-end test**

```rust
#![cfg(feature = "db")]
use axum::{body::Body, http::{Request, StatusCode}, routing::{post, get}, Router};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

// Mirror the routes the CLI hits.
fn app(pool: PgPool) -> Router {
    use epigraph_api::state::{ApiConfig, AppState};
    let state = AppState::with_db(pool, ApiConfig::default());
    Router::new()
        .route("/api/v1/submit/packet", post(epigraph_api::routes::submit::submit_packet))
        .route("/api/v1/edges", post(epigraph_api::routes::edges::create_edge))
        .route("/api/v1/claims/:id", get(epigraph_api::routes::claims::get_claim))
        .route("/api/v1/claims", get(epigraph_api::routes::claims_query::list_claims_query))
        .with_state(state)
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&b).unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn pr_ingest_builds_hierarchy_and_resolution_edge(pool: PgPool) {
    // Seed an agent + a backlog claim that cites "PR #999".
    let agent = /* ensure_system_agent(&pool) — copy the helper from edges.rs db_tests */;
    let backlog = /* seed_claim(&pool, agent, "Backlog X. Fixed by PR #999.") */;

    let router = app(pool.clone());

    // 1) submit PR node (idempotency_key pr:org/repo#999).
    let pr_body = serde_json::json!({
        "claim": { "content": "[PR #999] fix(api): thing", "initial_truth": 0.8,
                   "agent_id": agent, "idempotency_key": "pr:org/repo#999",
                   "properties": {"node":"pr","pr_number":999} },
        "evidence": [], "reasoning_trace": {"methodology":"heuristic","inputs":[],
                   "confidence":0.8,"explanation":"x"}, "signature": "0".repeat(128)
    });
    let r = router.clone().oneshot(Request::builder().method("POST").uri("/api/v1/submit/packet")
        .header("content-type","application/json").body(Body::from(pr_body.to_string())).unwrap()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let pr_id: Uuid = json(r).await["claim_id"].as_str().unwrap().parse().unwrap();

    // 2) re-submit same PR -> same id (idempotent find-or-create).
    let r2 = router.clone().oneshot(Request::builder().method("POST").uri("/api/v1/submit/packet")
        .header("content-type","application/json").body(Body::from(pr_body.to_string())).unwrap()).await.unwrap();
    let pr_id2: Uuid = json(r2).await["claim_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(pr_id, pr_id2, "stable idempotency_key returns same claim");

    // 3) RESOLVED_BY edge backlog -> PR, datestamped.
    let edge = serde_json::json!({"source_id": backlog, "target_id": pr_id,
        "source_type":"claim","target_type":"claim","relationship":"RESOLVED_BY",
        "valid_from":"2026-06-02T15:10:01Z","if_not_exists":true,"properties":{"source":"git-history"}});
    let re = router.clone().oneshot(Request::builder().method("POST").uri("/api/v1/edges")
        .header("content-type","application/json").body(Body::from(edge.to_string())).unwrap()).await.unwrap();
    assert!(re.status().is_success(), "RESOLVED_BY edge accepted");
    let edge_json = json(re).await;
    assert_eq!(edge_json["valid_from"], "2026-06-02T15:10:01Z");

    // 4) content_contains finds the backlog claim citing PR #999.
    let q = router.clone().oneshot(Request::builder().method("GET")
        .uri("/api/v1/claims?content_contains=PR%20%23999&is_current=true").body(Body::empty()).unwrap()).await.unwrap();
    let found = json(q).await;
    let ids: Vec<String> = found["claims"].as_array().unwrap().iter()
        .map(|c| c["id"].as_str().unwrap().to_string()).collect();
    assert!(ids.contains(&backlog.to_string()), "PR-number search finds the backlog claim");
}
```
> Copy `ensure_system_agent` / `seed_claim` helpers verbatim from `edges.rs`'s `db_tests`. Confirm the exact handler paths (`epigraph_api::routes::...`) are `pub` and re-exported; if not, add minimal `pub use` in `epigraph-api` or call via the crate's existing `create_router` test helper.

- [ ] **Step 2: Run to verify it fails (compile/route wiring first), then passes**

Run:
```bash
export DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test
cargo test -p epigraph-cli --test pr_hierarchical_ingest_test -- --nocapture
```
Expected: first FAIL (handlers not `pub`/path mismatch) → fix exports/paths → PASS: idempotent PR id, accepted datestamped `RESOLVED_BY` edge, PR-number search hit.

- [ ] **Step 3: Commit**

```bash
cargo fmt && cargo clippy -p epigraph-cli --tests --locked -- -D warnings
git add crates/epigraph-cli/tests/pr_hierarchical_ingest_test.rs
git commit -m "test(cli): end-to-end PR-hierarchical ingest contracts against test DB

**Evidence:**
- The CLI depends on submit-idempotency, RESOLVED_BY+valid_from acceptance, and
  content_contains PR-number search; these must be asserted against real routes.

**Reasoning:**
- oneshot the actual submit/edges/claims handlers (edges.rs db_tests pattern) on
  epigraph_db_repo_test; assert stable id on re-submit, datestamped edge, search hit.

**Verification:**
- cargo test --test pr_hierarchical_ingest_test passes; fmt+clippy clean."
```

---

## Task 10: `--dry-run` for PR mode + final gate

**Files:** Modify `run_pr_ingest` / `main` in `ingest_git.rs`.

- [ ] **Step 1: Honor `--dry-run` in PR mode**

In `run_pr_ingest`, when `args.dry_run`, parse + print the planned hierarchy and resolution targets and **return before any POST**:
```rust
if args.dry_run {
    println!("[dry-run] repo={} pr=#{} commits={} refs={:?}",
        meta.repo_slug, meta.number, commits.len(), extract_references(&ref_text));
    return Ok(());
}
```
(Compute `ref_text`/`refs` before the submit section so dry-run can show them.)

- [ ] **Step 2: Manual dry-run smoke test against this repo**

Run (no server needed; dry-run must not POST):
```bash
cd /home/jeremy/epigraph-wt-commitspec
cargo run -p epigraph-cli --bin ingest_git -- --pr-ingest --dry-run \
  --repo-slug epigraph-io/epigraph --pr-number 252 \
  --pr-title "fix(api): stop auto-enqueueing cluster jobs" \
  --pr-body "Resolves d531c585-0214-4fad-972b-10c7aa039984" \
  --merge-sha 2a31f8d --merged-at 2026-06-02T15:10:01Z --pr-author tylorsama \
  --rev-range 'b72e271..2a31f8d'
```
Expected: prints the planned repo/PR/commit counts + extracted refs (the `d531c585` UUID); makes no network calls.

- [ ] **Step 3: Full gate**

Run:
```bash
export DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test
cargo fmt --check
cargo clippy -p epigraph-cli --bin ingest_git --tests --locked -- -D warnings
cargo test -p epigraph-cli --bin ingest_git
cargo test -p epigraph-cli --test pr_hierarchical_ingest_test
```
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-cli/src/bin/ingest_git.rs
git commit -m "feat(cli): --dry-run for PR-ingest mode (parse + plan, no writes)

**Evidence:**
- The GitHub Actions workflow (separate plan) runs a pre-merge dry-run for early signal.

**Reasoning:**
- In pr_mode, --dry-run prints the planned hierarchy + extracted references and returns
  before any POST, so it is safe to run on untrusted/unmerged PRs.

**Verification:**
- dry-run smoke test makes no network calls; full fmt/clippy/test gate green."
```

---

## Self-review

**Spec coverage (design §):** §3 trigger — N/A here (CI plan); §4.1/4.2 hierarchy nodes — Tasks 3,4,5,8; §4.3 datestamped decomposes_to edges — Tasks 5,8; §6.1 orchestrator PR attribution — Tasks 2,8; §6.2 commit→git-author — Tasks 1,8; §6.3 require_signatures dependency / interim author DID — Task 1 (placeholder sig retained; deterministic author key); §7 linking — Tasks 6,7; §8 idempotency (git-hash, find-or-create, edge if_not_exists) — Tasks 3,4,5,7; `repo:<slug>` label — Tasks 3,4,5,8. **Gap intentionally deferred:** semantic/LLM enrichment + the `fix→challenges→feat` edges (greenfield per recon) are not in this core plan; not a design requirement for the hierarchy.

**Placeholder scan:** the few `> notes` flag real verify-at-implementation points (label-patch route body in Task 8 Step 1; `/agents` idempotency in Task 0; handler `pub`/re-export in Task 9) — each carries the command to resolve it, not a blank TODO. `public_key_uuid_stub()` in Task 3 Step 1 is explicitly corrected to `Uuid::nil()` in the same step.

**Type consistency:** `PrMeta`, `References`, `edge_body`, `link_edge`, `submit_find_or_create`, `build_pr_packet`, `build_repo_packet`, `resolve_author_agent`, `resolve_orchestrator_agent`, `apply_labels`, `run_pr_ingest` names are used identically across tasks. API structs (`EpistemicPacket`, `ClaimSubmission`, `EvidenceSubmission`, `ReasoningTraceSubmission`, `SubmitResponse`) match the verbatim definitions in `ingest_git.rs`. Edge JSON matches `CreateEdgeRequest`; relationships (`decomposes_to`, `RESOLVED_BY`) are confirmed members of `VALID_RELATIONSHIPS`.

**Open items carried from the spec:** none block this plan. `RESOLVED_BY` replaces the `resolves`-vs-`supports` decision (§9.1) and removes the separate server-change plan. `require_signatures=false` dependency and the DID system remain noted, not resolved here.
