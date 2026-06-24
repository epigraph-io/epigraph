# epigraph-nli — CPU NLI cross-encoder microservice

Alternate, cheap, deterministic, batchable PRODUCER for the 3-way
entail/neutral/contradiction signal used across EpiGraph's stance
machinery. **This is a cost/latency/determinism optimization of an
already-working path, NOT a new capability** (backlog item 97244690).

The item has two halves:

1. **This service + its Rust HTTP client** — the producer of the 3-way
   distribution.
2. **`scripts/lib/nli_stance.py`** — the canonical consumer that maps the
   distribution to a Dempster-Shafer BBA over a `{support, refute}` frame
   (`entailment -> m(support)`, `contradiction -> m(refute)`,
   `neutral -> m(Theta)` = ignorance) and submits it to the DST belief
   path (`submit_ds_evidence`). This is what feeds pignistic/BetP belief
   ordering, the invariant-mandated path.

A secondary (BONUS) consumer wires the same distribution into the Rust
enrichment probes (`coherence_probe` / `skeptic_probe` in
`crates/epigraph-cli/src/enrichment/confidence.rs`), which feed the
parser-confidence multiplier on the commit-ingest path. That is NOT the
DST belief path and is an optional convenience, not the item's deliverable.

## Contract

`POST /nli` `{"premise": str, "hypothesis": str}` ->
`{"entailment": f, "neutral": f, "contradiction": f, "model": str, "stub": bool}`
(probabilities sum to 1.0). Behind Caddy at `http://<host>/nli`.

## Model

`MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli` (~184M), MNLI head label
order `[entailment, neutral, contradiction]`. Loaded lazily on first call.
A startup assertion (`_get_pipe`) refuses to serve if the loaded model's
`config.id2label` does not match this pinned order — a wrong checkpoint
with a transposed head would otherwise silently invert every stance.

## Run

- Stub (no model, for tests / smoke on small boxes):
  `NLI_STUB=1 uvicorn app:app --port 8000` then `NLI_STUB=1 pytest`.
- Real model: `uvicorn app:app --port 8000` (needs ~1.5GB RAM + the
  weights; do NOT run on the 2.7GB-free dev box).
- Container: `docker build -t epigraph-nli services/nli` then run with
  `-p 8000:8000`; front with the `Caddyfile.snippet` stanza.

## Wiring (DST belief path — the canonical consumer)

`scripts/lib/nli_stance.py` is the item's part-2 deliverable:

```python
from lib.nli_stance import nli_to_bba, submit_nli_stance

# Pure mapping (network-free, unit-tested):
masses = nli_to_bba({"entailment": 0.8, "neutral": 0.15, "contradiction": 0.05})
# -> {"0": 0.8, "1": 0.05, "0,1": 0.15}   ({support, refute}; "0,1" = Theta)

# End-to-end (needs the NLI service + the EpiGraph API up):
submit_nli_stance(claim_id, frame_id, premise=evidence, hypothesis=claim,
                  reliability=0.9)
```

`submit_nli_stance` fetches the distribution from `POST /nli`, maps it to
the BBA above, and submits it via the EpiGraph HTTP evidence endpoint
(`POST /api/v1/frames/:id/evidence` through `_api_client.py`), which is the
HTTP surface of the `submit_ds_evidence` MCP tool — both hit the same
`MassFunctionRepository` + belief-query layer. Python scripts call the
HTTP API (per `feedback_no_raw_sql`), not the MCP stdio transport.

## Wiring (Rust probes — BONUS, parser-confidence path)

The Rust client (`crates/epigraph-cli/src/enrichment/nli_client.rs`) is
constructed from `NLI_SERVICE_URL`; pass it to `coherence_probe` /
`skeptic_probe` to route stance classification to this service instead of
an LLM. When the env var is unset the probes use the existing LLM path
unchanged. This adjusts parser confidence (`combined_confidence`), not the
DST belief ordering.
