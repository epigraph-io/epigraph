"""Unit tests for the NLI service in stub mode (no model download).

Run: NLI_STUB=1 pytest services/nli/test_app.py
These assert the HTTP contract the Rust NliClient depends on; they do NOT
claim NLI accuracy (the stub is a lexical stand-in, asserted as such).
"""
import os

os.environ["NLI_STUB"] = "1"  # set before importing app

from fastapi.testclient import TestClient  # noqa: E402

import app as nli_app  # noqa: E402

client = TestClient(nli_app.app)


def _post(premise, hypothesis):
    r = client.post("/nli", json={"premise": premise, "hypothesis": hypothesis})
    assert r.status_code == 200, r.text
    return r.json()


def test_response_has_all_three_labels_and_stub_flag():
    body = _post("the sky is blue", "the sky is blue")
    assert set(["entailment", "neutral", "contradiction"]).issubset(body)
    assert body["stub"] is True
    assert body["model"] == "stub"


def test_probabilities_normalize_to_one():
    body = _post("cells divide by mitosis", "mitosis divides cells")
    total = body["entailment"] + body["neutral"] + body["contradiction"]
    assert abs(total - 1.0) < 1e-9


def test_stub_is_deterministic():
    a = _post("force equals mass times acceleration", "F = m a")
    b = _post("force equals mass times acceleration", "F = m a")
    assert a == b


def test_stub_flags_negation_as_contradiction_dominant():
    # Direction sensitivity: a negated near-restatement must put the most
    # mass on contradiction, NOT entailment. Guards the label wiring so a
    # future label-order regression in app.py is caught.
    body = _post("the reaction is exothermic", "the reaction is not exothermic")
    assert body["contradiction"] > body["entailment"]
    assert body["contradiction"] >= body["neutral"]


def test_unrelated_inputs_are_neutral_dominant():
    body = _post("the stock market rose today", "photosynthesis requires light")
    assert body["neutral"] > body["entailment"]
    assert body["neutral"] > body["contradiction"]


def test_missing_field_is_422():
    r = client.post("/nli", json={"premise": "only premise"})
    assert r.status_code == 422
