"""Build-time model pre-cache and smoke check for the NLI image.

The Dockerfile runs this after installing the requirements, so the first
request does not pay for a cold model pull and a broken model path fails the
build instead of shipping an image without a working model:

  * NLI_STUB=1 (a build argument) skips the model entirely, for a stub image.
  * Otherwise the model is loaded through app._get_pipe() (so the id2label
    order guard runs at build time) and one clear-cut pair is scored; the
    scores must sum to 1 and put the most mass on entailment.

Any failure prints a "NLI model pre-cache failed" line and exits 1.
"""
from __future__ import annotations

import os
import sys

PREMISE = "The committee approved the budget on Tuesday."
HYPOTHESIS = "The budget was approved."


def main() -> int:
    if os.environ.get("NLI_STUB") == "1":
        print("NLI_STUB=1: skipping the model pre-cache (stub image)")
        return 0
    try:
        import app  # reads NLI_MODEL; imports transformers lazily

        e, n, c = app._model_scores(PREMISE, HYPOTHESIS)
        if abs(e + n + c - 1.0) > 1e-3 or not (e > n and e > c):
            raise RuntimeError(
                "smoke pair is not entailment-dominant: "
                f"entailment={e:.4f} neutral={n:.4f} contradiction={c:.4f}"
            )
    except Exception as exc:  # noqa: BLE001 - any failure must fail the build
        print(f"NLI model pre-cache failed: {exc!r}", file=sys.stderr)
        return 1
    print(f"NLI model pre-cached: {app.MODEL_NAME} (entailment={e:.3f})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
