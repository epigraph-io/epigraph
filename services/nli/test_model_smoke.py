"""Opt-in real-model smoke test for the NLI service (downloads the checkpoint).

Skipped unless NLI_REAL_MODEL=1. Run it after any change to the pinned
torch / transformers / sentencepiece stack:

    pip install -r services/nli/requirements.txt pytest httpx
    NLI_REAL_MODEL=1 pytest services/nli/test_model_smoke.py

test_app.py runs in stub mode and never imports torch or transformers, so it
cannot detect a dependency bump that breaks the model path. This file loads
the real pipeline through app._get_pipe() (including its id2label guard) and
checks the direction of the 3-way distribution on clear-cut pairs.
"""
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("NLI_REAL_MODEL") != "1",
    reason="set NLI_REAL_MODEL=1 to load the real NLI checkpoint",
)

import app as nli_app  # noqa: E402


def _scores(premise, hypothesis):
    e, n, c = nli_app._model_scores(premise, hypothesis)
    return {"entailment": e, "neutral": n, "contradiction": c}


def test_pipeline_loads_with_pinned_label_order():
    pipe = nli_app._get_pipe()
    id2label = pipe.model.config.id2label
    assert tuple(str(id2label[i]).lower() for i in sorted(id2label)) == nli_app.LABELS


def test_restatement_is_entailment_dominant():
    s = _scores(
        "The committee approved the budget on Tuesday.",
        "The budget was approved.",
    )
    assert abs(sum(s.values()) - 1.0) < 1e-3, s
    assert s["entailment"] > s["neutral"] and s["entailment"] > s["contradiction"], s


def test_negation_is_contradiction_dominant():
    s = _scores(
        "The reaction released heat, so it is exothermic.",
        "The reaction is not exothermic.",
    )
    assert s["contradiction"] > s["entailment"] and s["contradiction"] > s["neutral"], s


def test_unrelated_pair_is_not_entailment():
    s = _scores(
        "The stock market rose sharply today.",
        "Photosynthesis requires light.",
    )
    assert s["entailment"] < 0.5, s
