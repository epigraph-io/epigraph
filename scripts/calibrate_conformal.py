#!/usr/bin/env python3
"""Split-conformal calibrator for the CDST BetP classifier.

Fits per-class nonconformity quantiles over the labelled SciFact fixtures and
writes a [conformal] section into calibration.toml. Distribution-free split
conformal: for each class c, score_c(x) = 1 - <BetP component for c>, and
q_c is the ceil((n_c+1)(1-alpha))/n_c-th smallest TRUE-label score on the
calibration partition. The runtime includes class c in the prediction set iff
score_c(x) <= q_c, giving marginal (1-alpha) coverage on this distribution.

Nonconformity scores (the ONLY mapping consistent with the runtime, which has
no betp_NEI — supported+contradicted live on one axis, theta is the other):
    score_supported       = 1 - betp_sup
    score_contradicted    = 1 - betp_unsup
    score_not_enough_info = 1 - theta

Reuses lib.scifact_conformal.compute_betp (NOT the threshold_sweep_holdout.py
shortcut, which is buggy under open-world mass). Conflict_k is absent from the
fixtures so it does not enter the score.

Usage:
    python3 scripts/calibrate_conformal.py            # writes [conformal] to calibration.toml
    python3 scripts/calibrate_conformal.py --check     # print quantiles + coverage, do NOT write
"""
import argparse, glob, json, math, sys
from collections import defaultdict
from pathlib import Path
from random import Random

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from lib.scifact_conformal import (
    build_bba_directed, map_legacy_fields, compute_betp, OPEN_WORLD_FRACTIONS,
)

FIXTURES = ROOT / "tests" / "scifact_calibration" / "fixtures"
CALIBRATION_TOML = ROOT / "calibration.toml"
SCIFACT_OWF = OPEN_WORLD_FRACTIONS["peer_reviewed"]
ALPHA = 0.1            # target miscoverage; 1-alpha = 0.90 marginal coverage
SEED = 42
CAL_FRACTION = 0.5     # split-conformal: half calibrate, half validate (the --check report)
GT2LABEL = {"SUPPORT": "supported", "CONTRADICT": "contradicted",
            "NOT_ENOUGH_INFO": "not_enough_info"}
CLASSES = ["supported", "contradicted", "not_enough_info"]


def load_fixtures():
    out = []
    for p in sorted(FIXTURES.glob("enriched_*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except Exception:
            pass
    return out


def masses_for(f):
    e = f.get("enrichment", {})
    meth = e.get("methodology", "extraction")
    conf = e.get("confidence", 0.5)
    et = e.get("evidence_type")
    sup = e.get("supports_claim")
    if et is None or sup is None:
        et, sup, adj = map_legacy_fields(methodology=meth)
        conf *= adj
    return build_bba_directed(evidence_type=et, methodology=meth,
                              confidence=conf, supports=sup,
                              open_world_fraction=SCIFACT_OWF)


def scores(f):
    betp_sup, betp_unsup, theta = compute_betp(masses_for(f))
    return {"supported": 1.0 - betp_sup,
            "contradicted": 1.0 - betp_unsup,
            "not_enough_info": 1.0 - theta}


def stratified_split(fx, cal_frac, seed):
    rng = Random(seed)
    byc = defaultdict(list)
    for f in fx:
        byc[f["ground_truth"]].append(f)
    cal, val = [], []
    for _, items in byc.items():
        s = items[:]
        rng.shuffle(s)
        n = int(len(s) * cal_frac)
        cal.extend(s[:n])
        val.extend(s[n:])
    return cal, val


def fit_quantiles(cal, alpha):
    """Per-class TRUE-label score quantile with finite-sample guard."""
    by_label = defaultdict(list)
    for f in cal:
        lbl = GT2LABEL[f["ground_truth"]]
        by_label[lbl].append(scores(f)[lbl])
    q = {}
    n_by = {}
    for c in CLASSES:
        sc = sorted(by_label.get(c, []))
        n = len(sc)
        n_by[c] = n
        if n == 0:
            q[c] = 1.0
            continue
        k = math.ceil((n + 1) * (1.0 - alpha))
        # Finite-sample guard: if the index exceeds n, the (1-alpha) order
        # statistic does not exist -> include-always (q=1.0).
        q[c] = 1.0 if k > n else sc[k - 1]
    return q, n_by


def prediction_set(f, q):
    s = scores(f)
    return [c for c in CLASSES if s[c] <= q[c]]


def report(val, q):
    hit = tot = 0
    sizes = []
    per = defaultdict(lambda: [0, 0])
    for f in val:
        pset = prediction_set(f, q)
        sizes.append(len(pset))
        true = GT2LABEL[f["ground_truth"]]
        tot += 1
        per[true][1] += 1
        if true in pset:
            hit += 1
            per[true][0] += 1
    return {
        "marginal_coverage": hit / tot if tot else 0.0,
        "mean_set_size": sum(sizes) / len(sizes) if sizes else 0.0,
        "per_class_coverage": {c: (v[0] / v[1] if v[1] else 0.0) for c, v in per.items()},
    }


def write_conformal_section(q, n_by, n_total):
    text = CALIBRATION_TOML.read_text()
    marker = "# ── Split-Conformal Prediction Sets"
    if "[conformal]" in text:
        raise SystemExit("[conformal] already present; remove it before re-fitting.")
    block = (
        f"\n{marker} ────────────────\n"
        f"# Per-class nonconformity quantiles q_c, fit by scripts/calibrate_conformal.py\n"
        f"# over {n_total} labelled SciFact fixtures (split-conformal, alpha={ALPHA},\n"
        f"# seed={SEED}). score_c = 1 - BetP_c (supported/contradicted) or 1 - theta (NEI);\n"
        f"# class c is in the prediction set iff score_c <= q_c. Calibration n per class:\n"
        f"# supported={n_by['supported']} contradicted={n_by['contradicted']} "
        f"not_enough_info={n_by['not_enough_info']}.\n"
        f"[conformal]\n"
        f"alpha = {ALPHA}\n\n"
        f"[conformal.quantiles]\n"
        f"supported        = {q['supported']:.6f}\n"
        f"contradicted     = {q['contradicted']:.6f}\n"
        f"not_enough_info  = {q['not_enough_info']:.6f}\n"
    )
    CALIBRATION_TOML.write_text(text.rstrip() + "\n" + block)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="print quantiles + held-out coverage; do not write calibration.toml")
    args = ap.parse_args()
    fx = load_fixtures()
    print(f"Loaded {len(fx)} fixtures")
    cal, val = stratified_split(fx, CAL_FRACTION, SEED)
    q, n_by = fit_quantiles(cal, ALPHA)
    print(f"Quantiles (cal n/class={n_by}): "
          + ", ".join(f"{c}={q[c]:.4f}" for c in CLASSES))
    r = report(val, q)
    print(f"Held-out marginal coverage: {r['marginal_coverage']:.4f} (target {1-ALPHA})")
    print(f"Held-out mean set size:     {r['mean_set_size']:.4f}")
    print(f"Per-class coverage:         {r['per_class_coverage']}")
    if args.check:
        return
    # Production write: refit on ALL fixtures (no held-out split) for the final q_c.
    q_full, n_full = fit_quantiles(fx, ALPHA)
    write_conformal_section(q_full, n_full, len(fx))
    print(f"Wrote [conformal] to {CALIBRATION_TOML}")


if __name__ == "__main__":
    main()
