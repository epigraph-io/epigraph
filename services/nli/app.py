"""Self-hosted CPU NLI cross-encoder microservice.

Exposes a single deterministic-on-fixed-input endpoint that scores a
(premise, hypothesis) pair into a 3-way natural-language-inference
distribution {entailment, neutral, contradiction}. It is an ALTERNATE,
cheap, batchable PRODUCER for the 3-way signal the EpiGraph enrichment
probes (coherence_probe / skeptic_probe in crates/epigraph-cli) already
emit via per-call LLM round-trips -- NOT a new capability. See
backlog item 97244690 and services/nli/README.md.

Model: tasksource / MoritzLaurer DeBERTa-v3-base-MNLI family (~184M).
The model is loaded LAZILY on first /nli call so the process starts
(and `import app` in tests) without pulling weights. Set NLI_STUB=1 to
short-circuit the model entirely and return a deterministic lexical
stub -- the only mode usable on the 2.7GB-free / no-GPU build box.
"""
from __future__ import annotations

import os
import threading
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

# MNLI head label order for the DeBERTa-v3-MNLI family is
# [entailment, neutral, contradiction] (id2label of the published
# checkpoints). Pinned here so the Rust client and tests share one
# contract; verify against the loaded model's config.id2label at startup.
LABELS = ("entailment", "neutral", "contradiction")
MODEL_NAME = os.environ.get(
    "NLI_MODEL", "MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli"
)
MAX_CHARS = int(os.environ.get("NLI_MAX_CHARS", "4000"))

app = FastAPI(title="epigraph-nli", version="0.1.0")


class NliRequest(BaseModel):
    premise: str = Field(..., min_length=1)
    hypothesis: str = Field(..., min_length=1)


class NliResponse(BaseModel):
    entailment: float
    neutral: float
    contradiction: float
    model: str
    stub: bool


_pipe = None
_pipe_lock = threading.Lock()


def _stub_scores(premise: str, hypothesis: str) -> tuple[float, float, float]:
    """Deterministic lexical stand-in used when NLI_STUB=1.

    Pure token-overlap heuristic with an explicit negation flip. It is NOT
    an NLI model and makes no accuracy claim; its ONLY contract is to be a
    deterministic, model-free oracle so the service and its Rust client can
    be wired and tested on a box that cannot host the 184M checkpoint.
    Returns probabilities summing to 1.0.
    """
    p = set(premise.lower().split())
    h = set(hypothesis.lower().split())
    if not h:
        return (0.0, 1.0, 0.0)
    overlap = len(p & h) / len(h)
    negators = {"not", "no", "never", "cannot", "n't", "without"}
    flip = bool((p ^ h) & negators)
    if flip and overlap >= 0.5:
        return (0.05, 0.15, 0.80)
    if overlap >= 0.6:
        return (0.80, 0.15, 0.05)
    if overlap <= 0.1:
        return (0.05, 0.90, 0.05)
    return (0.20, 0.70, 0.10)


def _get_pipe():
    global _pipe
    if _pipe is not None:
        return _pipe
    with _pipe_lock:
        if _pipe is None:
            # Imported lazily so test collection / stub mode never needs torch.
            from transformers import pipeline  # type: ignore

            _pipe = pipeline(
                "text-classification",
                model=MODEL_NAME,
                top_k=None,  # return ALL class scores
                device=-1,  # CPU
            )
            # Deploy-time guard (required_fix #5): a wrong checkpoint with a
            # different head order would silently invert every stance. Verify
            # the loaded model's id2label matches the pinned LABELS contract.
            id2label = getattr(getattr(_pipe, "model", None), "config", None)
            id2label = getattr(id2label, "id2label", None)
            if id2label:
                loaded = tuple(
                    str(id2label[i]).lower() for i in sorted(id2label)
                )
                if loaded != LABELS:
                    raise RuntimeError(
                        "NLI model label order "
                        f"{loaded} does not match the pinned contract "
                        f"{LABELS}; refusing to serve a silently-inverted "
                        "stance. Set NLI_MODEL to a checkpoint whose "
                        "config.id2label is [entailment, neutral, "
                        "contradiction]."
                    )
    return _pipe


def _model_scores(premise: str, hypothesis: str) -> tuple[float, float, float]:
    pipe = _get_pipe()
    # transformers text-pair input; truncate defensively.
    out = pipe(
        {"text": premise[:MAX_CHARS], "text_pair": hypothesis[:MAX_CHARS]},
        truncation=True,
    )
    # Deploy-time guard (required_fix #5): with top_k=None the documented
    # return is a flat list[{label, score}], but some transformers versions
    # wrap a single input in an extra list (list[list[...]]). Unwrap one
    # level so a version bump does not silently produce all-zero scores.
    if out and isinstance(out[0], list):
        out = out[0]
    if not isinstance(out, list):
        raise RuntimeError(
            f"unexpected NLI pipeline output shape: {type(out)!r}"
        )
    # out is a list of {label, score}; map by lowercased label.
    scores = {d["label"].lower(): float(d["score"]) for d in out}
    return (
        scores.get("entailment", 0.0),
        scores.get("neutral", 0.0),
        scores.get("contradiction", 0.0),
    )


def _stub_enabled() -> bool:
    return os.environ.get("NLI_STUB", "0") == "1"


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": MODEL_NAME, "stub": _stub_enabled()}


@app.post("/nli", response_model=NliResponse)
def nli(req: NliRequest) -> NliResponse:
    stub = _stub_enabled()
    if stub:
        e, n, c = _stub_scores(req.premise, req.hypothesis)
    else:
        e, n, c = _model_scores(req.premise, req.hypothesis)
    return NliResponse(
        entailment=e,
        neutral=n,
        contradiction=c,
        model="stub" if stub else MODEL_NAME,
        stub=stub,
    )
