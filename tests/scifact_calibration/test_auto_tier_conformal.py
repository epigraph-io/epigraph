"""auto_tier routes on the split-conformal prediction set (backlog 3a6666e9).

auto_tier used to escalate a claim to Tier 2 when the Tier-1 LLM confidence was
below a raw 0.3 cutoff. It now builds the Tier-1 result's BBA, scores it with
the nonconformity scores the offline calibrator fits (score_c = 1 - BetP_c, or
1 - theta for NEI), and escalates when the prediction set
{c : score_c <= q_c} is not a singleton, using the shipped
calibration.toml `[conformal.quantiles]`.

The LLM is stubbed at the `claude_cli_call` boundary only: the Tier-1 stub
returns the fixture's own enrichment JSON, so parsing, methodology
normalisation, the BBA, the set and the routing all run for real. The expected
set comes from scripts/calibrate_conformal.py::prediction_set, the calibrator's
own implementation, not from the routing code under test.
"""
import asyncio
import json
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import calibrate_conformal as cc  # noqa: E402
from lib import tiered_enrichment as te  # noqa: E402

FIXTURES = ROOT / "tests" / "scifact_calibration" / "fixtures"
SHIPPED_Q = tomllib.loads((ROOT / "calibration.toml").read_text())["conformal"]["quantiles"]


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


class StubLLM:
    """Answers each tier's prompt; records which tiers were asked."""

    def __init__(self, enrichment):
        self.enrichment = enrichment
        self.calls = []

    async def __call__(self, prompt, timeout_secs=90, model=None):
        if prompt.startswith("Analyze this scientific evidence and classify"):
            self.calls.append(1)
            return json.dumps(self.enrichment)
        if prompt.startswith("Analyze this scientific evidence with full paper context"):
            self.calls.append(2)
            return json.dumps({"methodology": "extraction", "confidence": 0.5, "supports_claim": True,
                               "evidence_type": "empirical", "reasoning": "tier-2 stub"})
        if prompt.startswith("Analyze this scientific evidence in the context of cross-source"):
            self.calls.append(3)
            return json.dumps({"methodology": "extraction", "confidence": 0.5, "supports_claim": True,
                               "evidence_type": "empirical", "reasoning": "tier-3 stub"})
        raise AssertionError(f"unexpected prompt: {prompt[:80]!r}")


@pytest.fixture(autouse=True)
def shipped_calibration(monkeypatch):
    """Route on the repository's calibration.toml, whatever the shell exports."""
    monkeypatch.delenv("CALIBRATION_PATH", raising=False)
    te.routing_quantiles.cache_clear()
    yield
    te.routing_quantiles.cache_clear()


def route(monkeypatch, f, **kwargs):
    stub = StubLLM(f["enrichment"])
    monkeypatch.setattr(te, "claude_cli_call", stub)
    kwargs.setdefault("abstract", "abstract")
    result = asyncio.run(te.auto_tier(f["claim"], " ".join(f["evidence_sentences"]), **kwargs))
    return result, stub.calls


def test_confident_tier1_with_an_empty_set_escalates_to_tier2(monkeypatch):
    # confidence 0.6 cleared the old 0.3 cutoff, so the old router kept Tier 1;
    # its prediction set is empty (no class conforms), which is not a singleton.
    f = fixture("enriched_1021_9433958.json")
    assert f["enrichment"]["confidence"] >= 0.3
    assert cc.prediction_set(f, SHIPPED_Q) == []
    result, calls = route(monkeypatch, f)
    assert result.tier == 2
    assert calls == [1, 2]


def test_zero_confidence_with_a_confident_nei_set_stays_tier1(monkeypatch):
    # confidence 0.0 fell under the old cutoff (Tier 2), but the set is the
    # singleton {not_enough_info}: the calibrated model is sure it is NEI.
    f = fixture("enriched_114_33872649.json")
    assert f["enrichment"]["confidence"] < 0.3
    assert cc.prediction_set(f, SHIPPED_Q) == ["not_enough_info"]
    result, calls = route(monkeypatch, f)
    assert result.tier == 1
    assert calls == [1]


def test_conflict_still_reaches_tier3_when_the_set_is_a_singleton(monkeypatch):
    f = fixture("enriched_1000_16472469.json")
    assert cc.prediction_set(f, SHIPPED_Q) == ["supported"]
    result, calls = route(monkeypatch, f, has_conflict=True, cross_source_history=[],
                          ds_belief_state={})
    assert result.tier == 3
    assert calls == [1, 3]


def test_routing_agrees_with_the_calibrator_on_every_fixture(monkeypatch):
    tiers = {1: 0, 2: 0}
    fixtures = cc.load_fixtures()
    assert len(fixtures) >= 1100
    for f in fixtures:
        result, calls = route(monkeypatch, f)
        singleton = len(cc.prediction_set(f, SHIPPED_Q)) == 1
        want = 1 if singleton else 2
        assert result.tier == want, (f["scifact_id"], f["enrichment"], cc.prediction_set(f, SHIPPED_Q))
        # exactly one Tier-1 LLM call, then at most the one escalation
        assert calls == ([1] if singleton else [1, 2]), (f["scifact_id"], calls)
        tiers[want] += 1
    # both branches are exercised, so the agreement is not vacuous
    assert tiers[1] > 100 and tiers[2] > 100, tiers


def test_routing_reads_the_shipped_quantiles():
    q = te.routing_quantiles()
    assert q == {c: SHIPPED_Q[c] for c in cc.CLASSES}
    assert all(0.0 < q[c] < 1.0 for c in cc.CLASSES)


def test_calibration_path_without_a_conformal_section_is_refused(monkeypatch, tmp_path):
    # Falling back to include-always quantiles (1.0) would silently send every
    # claim to Tier 2; refuse instead.
    path = tmp_path / "calibration.toml"
    path.write_text("[thresholds]\nsupported = 0.5\n")
    monkeypatch.setenv("CALIBRATION_PATH", str(path))
    te.routing_quantiles.cache_clear()
    with pytest.raises(ValueError, match=r"\[conformal\.quantiles\]"):
        te.routing_quantiles()


def test_calibration_path_is_honoured(monkeypatch, tmp_path):
    path = tmp_path / "calibration.toml"
    path.write_text("[conformal]\nalpha = 0.1\n\n[conformal.quantiles]\n"
                    "supported = 0.9\ncontradicted = 0.9\nnot_enough_info = 0.9\n")
    monkeypatch.setenv("CALIBRATION_PATH", str(path))
    te.routing_quantiles.cache_clear()
    assert te.routing_quantiles() == {"supported": 0.9, "contradicted": 0.9, "not_enough_info": 0.9}
