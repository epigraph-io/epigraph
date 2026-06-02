"""Unit tests for the pure NLI -> DST BBA stance mapping (nli_stance.py).

Run: python -m pytest scripts/lib/test_nli_stance.py
These exercise ONLY the network-free `nli_to_bba` mapping -- the part 2
deliverable's load-bearing logic. The HTTP fetch + evidence submit need the
running NLI service and EpiGraph API and are NOT exercised here (deployment).
"""
import math
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from nli_stance import (  # noqa: E402
    REFUTE_KEY,
    SUPPORT_KEY,
    THETA_KEY,
    nli_to_bba,
)


def _mass_sum(bba):
    return sum(bba.values())


def test_entailment_becomes_support_mass():
    bba = nli_to_bba({"entailment": 0.8, "neutral": 0.15, "contradiction": 0.05})
    # entailment -> m(support)=m({0}); contradiction -> m(refute)=m({1});
    # neutral -> m(Theta)=m({0,1}).
    assert math.isclose(bba[SUPPORT_KEY], 0.8, abs_tol=1e-9)
    assert math.isclose(bba[REFUTE_KEY], 0.05, abs_tol=1e-9)
    assert math.isclose(bba[THETA_KEY], 0.15, abs_tol=1e-9)


def test_contradiction_becomes_refute_mass():
    # A contradiction-dominant distribution must put most mass on refute
    # (index 1), NOT support -- guards the entailment/contradiction column
    # order, the single most damaging wiring bug.
    bba = nli_to_bba({"entailment": 0.05, "neutral": 0.15, "contradiction": 0.80})
    assert bba[REFUTE_KEY] > bba[SUPPORT_KEY]
    assert math.isclose(bba[REFUTE_KEY], 0.80, abs_tol=1e-9)


def test_neutral_becomes_theta_ignorance():
    # Pure-neutral input is total ignorance: ALL mass on Theta (the whole
    # frame), none committed to either singleton. This is the TBM semantics
    # of "no evidence either way" and is what makes neutral != refute.
    bba = nli_to_bba({"entailment": 0.0, "neutral": 1.0, "contradiction": 0.0})
    assert bba == {THETA_KEY: 1.0}
    assert SUPPORT_KEY not in bba
    assert REFUTE_KEY not in bba


def test_masses_sum_to_one():
    for scores in (
        {"entailment": 0.33, "neutral": 0.34, "contradiction": 0.33},
        {"entailment": 0.7, "neutral": 0.2, "contradiction": 0.1},
        {"entailment": 0.0, "neutral": 0.5, "contradiction": 0.5},
    ):
        assert math.isclose(_mass_sum(nli_to_bba(scores)), 1.0, abs_tol=1e-9)


def test_unnormalized_input_is_renormalized():
    # Caller passes values summing to 2.0; mapping must renormalize so the
    # BBA is valid (mass sums to 1.0), preserving ratios.
    bba = nli_to_bba({"entailment": 1.0, "neutral": 0.5, "contradiction": 0.5})
    assert math.isclose(_mass_sum(bba), 1.0, abs_tol=1e-9)
    assert math.isclose(bba[SUPPORT_KEY], 0.5, abs_tol=1e-9)  # 1.0 / 2.0


def test_zero_mass_focal_elements_omitted():
    # No entailment -> no m({0}) key at all (minimal BBA), not a zero entry.
    bba = nli_to_bba({"entailment": 0.0, "neutral": 0.4, "contradiction": 0.6})
    assert SUPPORT_KEY not in bba
    assert set(bba.keys()) == {REFUTE_KEY, THETA_KEY}


def test_all_zero_scores_raise():
    with pytest.raises(ValueError):
        nli_to_bba({"entailment": 0.0, "neutral": 0.0, "contradiction": 0.0})
    with pytest.raises(ValueError):
        nli_to_bba({})
