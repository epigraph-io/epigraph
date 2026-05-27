"""Tiered enrichment utility for EpiGraph claim evidence.

Provides enrich_tier1/2/3() and auto_tier() router. Uses claude CLI for LLM calls.
Constrains methodology output to canonical Rust vocabulary (cdst.rs methodology_profile keys).

Can be imported as a library or invoked as a CLI:
    python3 scripts/lib/tiered_enrichment.py --tier 1 --claim-text "..." --evidence-text "..."
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass, asdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.claude_cli import claude_cli_call

log = logging.getLogger(__name__)

# ── Canonical vocabulary (must match Rust cdst.rs methodology_profile keys) ──

CANONICAL_METHODOLOGIES = {
    "deductive_logic",
    "meta_analysis",
    "statistical_analysis",
    "bayesian_inference",
    "inductive_generalization",
    "expert_elicitation",
    "extraction",
}

METHODOLOGY_ALIASES = {
    "deductive": "deductive_logic",
    "deductive_reasoning": "deductive_logic",
    "meta-analysis": "meta_analysis",
    "statistical": "statistical_analysis",
    "statistical_inference": "statistical_analysis",
    "bayesian": "bayesian_inference",
    "inductive": "inductive_generalization",
    "expert": "expert_elicitation",
    "testimonial": "expert_elicitation",
    "llm_extraction": "extraction",
    "instrumental": "inductive_generalization",
    "experimental_observation": "inductive_generalization",
    "instrumental_measurement": "inductive_generalization",
    "computational": "statistical_analysis",
    "computational_simulation": "statistical_analysis",
    "visual_inspection": "extraction",
    "negative_result": "inductive_generalization",
    "theoretical_derivation": "deductive_logic",
    "literature_synthesis": "meta_analysis",
}

DEFAULT_METHODOLOGY = "extraction"


def normalize_methodology(raw: str) -> str:
    """Normalize a methodology string to canonical vocabulary."""
    low = raw.strip().lower()
    if low in CANONICAL_METHODOLOGIES:
        return low
    if low in METHODOLOGY_ALIASES:
        return METHODOLOGY_ALIASES[low]
    log.warning("Unknown methodology '%s', falling back to '%s'", raw, DEFAULT_METHODOLOGY)
    return DEFAULT_METHODOLOGY


# ── Result type ──

@dataclass
class EnrichmentResult:
    methodology: str
    confidence: float
    supports_claim: bool
    instruments_used: list[str]
    reagents_involved: list[str]
    conditions: list[str]
    evidence_type: str
    tier: int
    reasoning: str | None = None


# ── Prompt templates ──

_METHODOLOGY_LIST = ", ".join(sorted(CANONICAL_METHODOLOGIES))

TIER1_PROMPT = """\
Analyze this scientific evidence and classify its methodology.

Claim: {claim_text}
Evidence: {evidence_text}

Return a JSON object with these fields:
- "methodology": one of [{methodologies}]
- "confidence": float 0.0-1.0, how confident the evidence supports/refutes the claim
- "supports_claim": boolean, does the evidence support (true) or refute (false) the claim
- "instruments_used": list of instruments/tools mentioned
- "reagents_involved": list of chemicals/reagents mentioned
- "conditions": list of experimental conditions
- "evidence_type": one of ["empirical", "statistical", "logical", "testimonial", "circumstantial"]

Respond with ONLY a JSON object. No markdown, no explanation.""".format(
    methodologies=_METHODOLOGY_LIST,
    claim_text="{claim_text}",
    evidence_text="{evidence_text}",
)

TIER2_PROMPT = """\
Analyze this scientific evidence with full paper context and classify its methodology.

Claim: {claim_text}
Evidence: {evidence_text}

Paper abstract: {abstract}
Surrounding sentences: {surrounding_sentences}

Given the broader paper context, reconsider the methodology classification carefully.
Double-negatives and indirect evidence relationships are common — assess direction precisely.

Return a JSON object with these fields:
- "methodology": one of [{methodologies}]
- "confidence": float 0.0-1.0
- "supports_claim": boolean
- "instruments_used": list of instruments/tools
- "reagents_involved": list of chemicals/reagents
- "conditions": list of experimental conditions
- "evidence_type": one of ["empirical", "statistical", "logical", "testimonial", "circumstantial"]
- "reasoning": string explaining why you chose this methodology given the paper context

Respond with ONLY a JSON object. No markdown, no explanation.""".format(
    methodologies=_METHODOLOGY_LIST,
    claim_text="{claim_text}",
    evidence_text="{evidence_text}",
    abstract="{abstract}",
    surrounding_sentences="{surrounding_sentences}",
)

TIER3_PROMPT = """\
Analyze this scientific evidence in the context of cross-source corroboration and conflict.

Claim: {claim_text}
Evidence: {evidence_text}
Paper abstract: {abstract}

Cross-source history (other sources that reference this claim):
{cross_source_history}

Current Dempster-Shafer belief state:
{ds_belief_state}

Assess whether conflicting evidence reflects genuine scientific disagreement or
methodological artifacts (e.g., different measurement conditions, scope differences).

Return a JSON object with these fields:
- "methodology": one of [{methodologies}]
- "confidence": float 0.0-1.0
- "supports_claim": boolean
- "instruments_used": list of instruments/tools
- "reagents_involved": list of chemicals/reagents
- "conditions": list of experimental conditions
- "evidence_type": one of ["empirical", "statistical", "logical", "testimonial", "circumstantial"]
- "reasoning": string explaining your assessment in light of the cross-source evidence

Respond with ONLY a JSON object. No markdown, no explanation.""".format(
    methodologies=_METHODOLOGY_LIST,
    claim_text="{claim_text}",
    evidence_text="{evidence_text}",
    abstract="{abstract}",
    cross_source_history="{cross_source_history}",
    ds_belief_state="{ds_belief_state}",
)


def _parse_enrichment(raw_json: str, tier: int) -> EnrichmentResult:
    """Parse LLM JSON response into EnrichmentResult with normalization."""
    start = raw_json.find("{")
    end = raw_json.rfind("}") + 1
    if start < 0 or end <= start:
        raise ValueError(f"No JSON object found in response: {raw_json[:200]}")

    data = json.loads(raw_json[start:end])
    return EnrichmentResult(
        methodology=normalize_methodology(data.get("methodology", DEFAULT_METHODOLOGY)),
        confidence=float(data.get("confidence", 0.5)),
        supports_claim=bool(data.get("supports_claim", True)),
        instruments_used=data.get("instruments_used", []),
        reagents_involved=data.get("reagents_involved", []),
        conditions=data.get("conditions", []),
        evidence_type=data.get("evidence_type", "empirical"),
        tier=tier,
        reasoning=data.get("reasoning") if tier >= 2 else None,
    )


# ── Tier functions ──

async def enrich_tier1(claim_text: str, evidence_text: str) -> EnrichmentResult:
    """Tier 1: claim + evidence text only. Cost: ~$0.001/claim."""
    prompt = TIER1_PROMPT.format(claim_text=claim_text, evidence_text=evidence_text)
    raw = await claude_cli_call(prompt, timeout_secs=60)
    return _parse_enrichment(raw, tier=1)


async def enrich_tier2(
    claim_text: str,
    evidence_text: str,
    abstract: str,
    surrounding_sentences: list[str],
) -> EnrichmentResult:
    """Tier 2: + abstract context + surrounding sentences. Cost: ~$0.003/claim."""
    prompt = TIER2_PROMPT.format(
        claim_text=claim_text,
        evidence_text=evidence_text,
        abstract=abstract,
        surrounding_sentences="\n".join(surrounding_sentences),
    )
    raw = await claude_cli_call(prompt, timeout_secs=90)
    return _parse_enrichment(raw, tier=2)


async def enrich_tier3(
    claim_text: str,
    evidence_text: str,
    abstract: str,
    cross_source_history: list[dict],
    ds_belief_state: dict,
) -> EnrichmentResult:
    """Tier 3: + cross-source history + DS belief state. Cost: ~$0.005/claim."""
    prompt = TIER3_PROMPT.format(
        claim_text=claim_text,
        evidence_text=evidence_text,
        abstract=abstract,
        cross_source_history=json.dumps(cross_source_history, indent=2),
        ds_belief_state=json.dumps(ds_belief_state, indent=2),
    )
    raw = await claude_cli_call(prompt, timeout_secs=120)
    return _parse_enrichment(raw, tier=3)


async def auto_tier(
    claim_text: str,
    evidence_text: str,
    tier1_confidence: float | None = None,
    has_conflict: bool = False,
    **context,
) -> EnrichmentResult:
    """Router: picks appropriate tier based on confidence/conflict.

    Context kwargs for higher tiers:
      - abstract: str (Tier 2/3)
      - surrounding_sentences: list[str] (Tier 2)
      - cross_source_history: list[dict] (Tier 3)
      - ds_belief_state: dict (Tier 3)
    """
    # Step 1: Run Tier 1 if no confidence provided
    tier1_result = None
    if tier1_confidence is None:
        tier1_result = await enrich_tier1(claim_text, evidence_text)
        tier1_confidence = tier1_result.confidence

    # Step 2: High confidence + no conflict → return Tier 1 result
    if tier1_confidence >= 0.3 and not has_conflict:
        if tier1_result is not None:
            return tier1_result
        return await enrich_tier1(claim_text, evidence_text)

    # Step 3: Low confidence → Tier 2
    if tier1_confidence < 0.3:
        if "abstract" not in context:
            raise ValueError("Tier 2 enrichment requires 'abstract' in context kwargs")
        return await enrich_tier2(
            claim_text, evidence_text,
            context["abstract"],
            context.get("surrounding_sentences", []),
        )

    # Step 4: has_conflict AND Tier 3 context available → Tier 3
    if has_conflict:
        if "cross_source_history" in context and "ds_belief_state" in context:
            return await enrich_tier3(
                claim_text, evidence_text,
                context.get("abstract", ""),
                context["cross_source_history"],
                context["ds_belief_state"],
            )
        # Step 5: has_conflict but no Tier 3 context → fallback to Tier 2
        if "abstract" not in context:
            raise ValueError("Tier 2 enrichment requires 'abstract' in context kwargs")
        return await enrich_tier2(
            claim_text, evidence_text,
            context["abstract"],
            context.get("surrounding_sentences", []),
        )

    # Fallback: return Tier 1
    if tier1_result is not None:
        return tier1_result
    return await enrich_tier1(claim_text, evidence_text)


# ── CLI interface ──

def main():
    parser = argparse.ArgumentParser(description="Tiered enrichment utility")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3], required=True)
    parser.add_argument("--claim-text", default=None)
    parser.add_argument("--evidence-text", default=None)
    parser.add_argument("--abstract", default="")
    parser.add_argument("--output", choices=["json", "text"], default="json")
    parser.add_argument("--claim-id", type=str, help="Load claim from database by UUID")
    parser.add_argument("--database-url", type=str,
        default="postgres://epigraph_ro:epigraph_ro@localhost:5432/epigraph")
    args = parser.parse_args()

    claim_text = args.claim_text
    evidence_text = args.evidence_text

    if args.claim_id:
        import psycopg2
        import uuid as uuid_mod
        try:
            uuid_mod.UUID(args.claim_id)
        except ValueError:
            print(f"Invalid UUID: {args.claim_id}", file=sys.stderr)
            sys.exit(1)
        conn = psycopg2.connect(args.database_url)
        with conn.cursor() as cur:
            cur.execute("SELECT content FROM claims WHERE id = %s::uuid", (args.claim_id,))
            row = cur.fetchone()
        conn.close()
        if not row:
            print(f"Claim {args.claim_id} not found", file=sys.stderr)
            sys.exit(1)
        claim_text = row[0]

    if not claim_text:
        parser.error("--claim-text or --claim-id is required")
    if not evidence_text:
        evidence_text = claim_text  # Fallback: use claim text as evidence

    async def run():
        if args.tier == 1:
            result = await enrich_tier1(claim_text, evidence_text)
        elif args.tier == 2:
            result = await enrich_tier2(
                claim_text, evidence_text,
                args.abstract, [],
            )
        else:
            result = await enrich_tier3(
                claim_text, evidence_text,
                args.abstract, [], {},
            )
        if args.output == "json":
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"Tier {result.tier}: {result.methodology} (conf={result.confidence:.2f})")

    asyncio.run(run())


if __name__ == "__main__":
    main()
