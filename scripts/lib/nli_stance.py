"""NLI -> Dempster-Shafer BBA stance mapping for the EpiGraph belief path.

This is part 2 of backlog item 97244690 (the canonical, invariant-mandated
deliverable). The NLI cross-encoder service (services/nli) produces a 3-way
{entailment, neutral, contradiction} distribution for a (premise, hypothesis)
pair. This module converts that distribution into a Dempster-Shafer basic
belief assignment (BBA) over a two-hypothesis {support, refute} frame and
submits it as evidence so it feeds the DST/pignistic belief ordering
(BetP) -- NOT the parser-confidence multiplier.

The mapping (a textbook NLI->BBA transfer):

    entailment    -> m({support})          = m({0})
    contradiction -> m({refute})           = m({1})
    neutral       -> m({support, refute})  = m(Theta)   (ignorance)

Because the NLI probabilities already sum to 1.0, this is a valid BBA with
no renormalization: neutral mass becomes uncommitted mass on the whole
frame (Theta), which is exactly TBM's representation of "no evidence for
either side" -- the correct semantics for an NLI "neutral" verdict.

Design notes:
  - The PURE mapping (`nli_to_bba`) imports nothing heavy and is unit-tested
    with no network or service. It is the only part runtime-verifiable on the
    constrained build box.
  - The I/O helpers (`fetch_nli`, `submit_nli_stance`) lazily import requests
    / the shared _api_client so the pure path stays import-light, and submit
    via the EpiGraph HTTP evidence endpoint (POST /api/v1/frames/:id/evidence)
    -- the HTTP surface of the submit_ds_evidence MCP tool -- per
    feedback_no_raw_sql (Python scripts call the API, never raw SQL or MCP
    stdio). Both routes hit the same MassFunctionRepository + belief layer.

The {support, refute} frame is conventionally indexed [support=0, refute=1].
The submitting claim represents the "support" hypothesis, so hypothesis_index
is 0 (the evidence endpoint also defaults an unassigned claim to index 0).
"""
from __future__ import annotations

import os
from typing import Optional

# Frame contract: index 0 = "support", index 1 = "refute". Theta (the full
# frame {support, refute}) is keyed "0,1" in the masses dict, matching the
# epigraph-ds / evidence-endpoint comma-separated-index convention.
# THETA_KEY="0,1" assumes a TWO-hypothesis {support, refute} frame; for a
# larger frame the ignorance key would be all indices joined by commas.
SUPPORT_KEY = "0"
REFUTE_KEY = "1"
THETA_KEY = "0,1"


def nli_to_bba(scores: dict) -> dict[str, float]:
    """Map an NLI {entailment, neutral, contradiction} distribution to a
    Dempster-Shafer BBA over the {support, refute} frame.

    Returns a masses dict keyed by comma-separated hypothesis indices:
      {"0": m(support), "1": m(refute), "0,1": m(Theta)}.

    The three input probabilities are clamped to [0, 1] and renormalized to
    sum to 1.0 (defensive: the service already normalizes, but a caller may
    pass rounded or partial values). A zero-mass focal element is omitted so
    the BBA is minimal. Raises ValueError if all three are zero/missing.
    """
    e = max(0.0, float(scores.get("entailment", 0.0)))
    n = max(0.0, float(scores.get("neutral", 0.0)))
    c = max(0.0, float(scores.get("contradiction", 0.0)))
    total = e + n + c
    if total <= 0.0:
        raise ValueError(
            f"NLI scores sum to {total}; cannot build a BBA from "
            f"{scores!r}"
        )
    e, n, c = e / total, n / total, c / total

    masses: dict[str, float] = {}
    if e > 0.0:
        masses[SUPPORT_KEY] = e
    if c > 0.0:
        masses[REFUTE_KEY] = c
    if n > 0.0:
        masses[THETA_KEY] = n
    return masses


async def fetch_nli(
    premise: str,
    hypothesis: str,
    service_url: Optional[str] = None,
    timeout_secs: float = 30.0,
) -> dict:
    """Call POST /nli on the cross-encoder service and return the raw
    {entailment, neutral, contradiction, model, stub} dict.

    `service_url` defaults to NLI_SERVICE_URL (e.g. http://localhost/nli).
    Lazily imports httpx so the pure mapping path needs no HTTP deps.
    Raises RuntimeError if the service is unconfigured or the call fails.
    """
    url = service_url or os.environ.get("NLI_SERVICE_URL", "")
    if not url:
        raise RuntimeError(
            "NLI service not configured (set NLI_SERVICE_URL or pass "
            "service_url)"
        )
    import httpx  # lazy: only the I/O path needs it

    async with httpx.AsyncClient(timeout=timeout_secs) as http:
        resp = await http.post(
            url, json={"premise": premise, "hypothesis": hypothesis}
        )
        resp.raise_for_status()
        return resp.json()


def submit_nli_stance(
    claim_id: str,
    frame_id: str,
    premise: str,
    hypothesis: str,
    reliability: float = 1.0,
    service_url: Optional[str] = None,
    evidence_type: Optional[str] = "nli_cross_encoder",
):
    """End-to-end: fetch the NLI distribution for (premise, hypothesis), map
    it to a {support, refute} BBA, and submit it to the DST belief path via
    the EpiGraph HTTP evidence endpoint.

    `premise` is the evidence/prior text; `hypothesis` is the claim under
    assessment (entailment of the claim by the evidence -> support). The
    evidence is submitted with `reliability` as the discount factor so the
    frame-function source-reliability machinery can re-weight it per
    perspective at query time.

    Returns the parsed evidence-submission response (belief, plausibility,
    pignistic_prob, ...). Synchronous wrapper around the async fetch; lazily
    imports asyncio + the shared _api_client (which calls the HTTP API, never
    raw SQL or MCP stdio -- feedback_no_raw_sql).
    """
    import asyncio

    scores = asyncio.run(fetch_nli(premise, hypothesis, service_url=service_url))
    masses = nli_to_bba(scores)

    # Lazy import: keep the pure mapping path free of the requests/jwt deps.
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from _api_client import EpiGraphClient  # noqa: E402

    # The /frames/:id/evidence route is guarded by bearer_auth_middleware
    # (valid-JWT, no per-route scope check); claims:write matches the
    # write-path convention used elsewhere by _api_client callers.
    client = EpiGraphClient(scopes=["claims:write"])
    body = {
        "claim_id": claim_id,
        "reliability": reliability,
        "masses": masses,
    }
    if evidence_type is not None:
        body["evidence_type"] = evidence_type
    resp = client.post(f"/api/v1/frames/{frame_id}/evidence", json=body)
    resp.raise_for_status()
    return resp.json()
