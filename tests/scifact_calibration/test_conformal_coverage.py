"""Offline split-conformal coverage + efficiency test (backlog d5ba91a5).

Run: python3 tests/scifact_calibration/test_conformal_coverage.py
(exit 0 = pass). No external deps; reuses scripts/lib/scifact_conformal.py.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from calibrate_conformal import (
    load_fixtures, stratified_split, fit_quantiles, report, ALPHA, CAL_FRACTION, SEED,
)


def main():
    fx = load_fixtures()
    assert len(fx) >= 1100, f"expected ~1189 fixtures, got {len(fx)}"
    cal, val = stratified_split(fx, CAL_FRACTION, SEED)
    q, n_by = fit_quantiles(cal, ALPHA)
    r = report(val, q)

    # (1) COVERAGE: the conformal guarantee. Marginal coverage on the held-out
    # half must be >= 1 - alpha, minus a small finite-sample tolerance.
    target = 1.0 - ALPHA
    tol = 0.03
    assert r["marginal_coverage"] >= target - tol, (
        f"marginal coverage {r['marginal_coverage']:.4f} < {target - tol:.4f}"
    )

    # (2) EFFICIENCY (anti-tautology): the predictor must actually EXCLUDE
    # labels. A trivial always-{all 3} predictor would score coverage 1.0 but
    # mean set size 3.0; require mean set size strictly and meaningfully below
    # the trivial 3 (and below 2 — the BetP triple is highly separable here).
    assert r["mean_set_size"] < 2.0, (
        f"mean set size {r['mean_set_size']:.4f} not < 2.0 — predictor is not "
        f"excluding labels (would pass coverage trivially)"
    )

    # (3) Quantiles are real order statistics in (0, 1), not the include-always
    # degenerate 1.0 (which would make the set trivial and coverage vacuous).
    assert all(0.0 < q[c] < 1.0 for c in ("supported", "contradicted")), (
        f"quantiles collapsed to degenerate values: {q}"
    )

    print("PASS", {
        "marginal_coverage": round(r["marginal_coverage"], 4),
        "mean_set_size": round(r["mean_set_size"], 4),
        "quantiles": {c: round(q[c], 4) for c in q},
    })


if __name__ == "__main__":
    main()
