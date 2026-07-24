-- 056: Label the pre-identity legacy orphan agents.
--
-- Before deterministic LLM-agent identity landed (fix/llm-agent-identity), every
-- unconfigured MCP process minted a fresh AgentSigner::generate() keypair and
-- registered under the generic display_name 'mcp-agent'. That produced ~1,198
-- one-shot orphan agents that collapse to no shared identity — each is a distinct
-- key with no OPERATED_BY lineage. The new (model, system_prompt) derivation makes
-- identical configs collapse to ONE agent going forward, but the historical orphans
-- remain and must stay untouched by the crypto change (backward-compatible fallback).
--
-- This migration only *labels* them so audits and future consolidation can select
-- them by the `legacy-orphan-identity` label rather than brittle display_name matching.
-- DATA-ONLY: no schema change.
--
-- Idempotent: the NOT (... = ANY(labels)) guard skips rows already carrying the
-- label, so a second apply is a no-op and appends the label exactly once.
UPDATE agents
SET    labels = array_append(labels, 'legacy-orphan-identity')
WHERE  display_name = 'mcp-agent'
  AND  NOT ('legacy-orphan-identity' = ANY(labels));
