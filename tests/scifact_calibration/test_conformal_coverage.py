"""Offline split-conformal coverage + efficiency test (backlog d5ba91a5).

Run: python3 tests/scifact_calibration/test_conformal_coverage.py [--check]
(exit 0 = pass). No external deps; reuses scripts/lib/scifact_conformal.py.

--check also asserts that the SHIPPED `[conformal]` section of calibration.toml
(the values the runtime classifier reads) agrees with a refit of the same
fixtures, the way scripts/calibrate_conformal.py fits the production values.
Without it the held-out test below refits its own quantiles and never reads the
shipped ones, so `[conformal.quantiles]` could drift arbitrarily from the data
and every test would still pass (backlog 733df577). `--calibration PATH` checks
another file instead of the repository's calibration.toml.
"""
import argparse
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from calibrate_conformal import (
    load_fixtures, stratified_split, fit_quantiles, report, ALPHA, CAL_FRACTION, SEED,
    CALIBRATION_TOML, CLASSES, CONFORMAL_MARKER, conformal_comment,
)

# The writer formats each quantile with 6 decimals, so a faithful shipped value
# is within 5e-7 of the refit; anything further is drift, not rounding.
QUANTILE_TOL = 1e-6


def held_out(fx):
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
    return q, r


def check_shipped(fx, path):
    """The shipped [conformal] section must be the refit of these fixtures."""
    text = Path(path).read_text()
    conformal = tomllib.loads(text).get("conformal")
    assert conformal is not None, f"{path} has no [conformal] section"
    assert conformal.get("alpha") == ALPHA, (
        f"shipped alpha {conformal.get('alpha')!r} != the calibrator's {ALPHA}"
    )
    shipped = conformal.get("quantiles", {})
    # The production fit: scripts/calibrate_conformal.py refits on ALL fixtures.
    q_full, n_full = fit_quantiles(fx, ALPHA)
    drift = {
        c: (shipped.get(c), round(q_full[c], 6))
        for c in CLASSES
        if shipped.get(c) is None or abs(shipped[c] - q_full[c]) > QUANTILE_TOL
    }
    assert not drift, (
        f"{path} [conformal.quantiles] disagree with a refit of the {len(fx)} "
        f"fixtures (class: (shipped, refit)): {drift}. Re-run "
        f"scripts/calibrate_conformal.py, or restore the shipped values."
    )
    # The comment above [conformal] must state the population the shipped
    # values were fit on: the writer's text for this refit, word for word.
    start = text.find(CONFORMAL_MARKER)
    end = text.find("\n[conformal]\n", start)
    assert start >= 0 and end > start, f"{path}: no {CONFORMAL_MARKER!r} comment above [conformal]"
    shipped_comment = text[start:end + 1]
    expected_comment = conformal_comment(n_full, len(fx))
    assert shipped_comment == expected_comment, (
        f"{path}: the [conformal] comment does not state the fit's population.\n"
        f"--- shipped\n{shipped_comment}--- expected (calibrate_conformal.conformal_comment)\n"
        f"{expected_comment}"
    )
    return q_full


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="also assert the shipped [conformal] section matches a refit")
    ap.add_argument("--calibration", default=str(CALIBRATION_TOML),
                    help="the calibration.toml --check reads (default: the repository's)")
    args = ap.parse_args()

    fx = load_fixtures()
    assert len(fx) >= 1100, f"expected ~1189 fixtures, got {len(fx)}"
    q, r = held_out(fx)
    out = {
        "marginal_coverage": round(r["marginal_coverage"], 4),
        "mean_set_size": round(r["mean_set_size"], 4),
        "quantiles": {c: round(q[c], 4) for c in q},
    }
    if args.check:
        q_full = check_shipped(fx, args.calibration)
        out["shipped_matches_refit"] = {c: round(q_full[c], 6) for c in CLASSES}
    print("PASS", out)


if __name__ == "__main__":
    main()
