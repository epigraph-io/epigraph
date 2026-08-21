"""Offline tests for the generality-direction falsification harness.

No database, no network. These lock in the properties that decide whether the
numbers the script prints can be believed at all:

  * a scrambled-direction corpus scores at chance (the control the whole
    experiment rests on -- an earlier revision regrouped edges by the *flipped*
    endpoint, which made the one-child-per-parent subsample over-represent
    flipped edges and pushed the control to 0.63);
  * a corpus with no role signal scores at chance;
  * a corpus with a planted density signal is found;
  * orientation is fitted on the fit split only;
  * ties are broken by coin flip and counted, not silently credited;
  * the parent-clustered CI is wider than the naive binomial one when a parent
    has many children.

Run: python3 -m unittest scripts.tests.test_generality_direction
"""
import argparse
import sys
import unittest
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import test_generality_direction as gd  # noqa: E402


def _args(**kw):
    base = dict(seed=1234, k=20, radii=[0.20, 0.30, 0.40], chunk=128,
                length_ratio=1.2, boot_reps=200)
    base.update(kw)
    return argparse.Namespace(**base)


def _text(rng):
    """Role-independent text: same length and vocabulary distribution for
    parents and children, so `length_chars` and bag-of-words are genuinely null."""
    return " ".join(f"w{rng.integers(0, 60)}" for _ in range(int(rng.integers(5, 40))))


def _corpus(rng, planted, n_parents=200, n_children=3, dim=32, n_bg=800):
    def unit(x):
        return x / np.linalg.norm(x, axis=-1, keepdims=True)
    core = unit(rng.normal(size=dim))
    bg = np.vstack([unit(core + 0.35 * rng.normal(size=(n_bg // 2, dim))),
                    unit(rng.normal(size=(n_bg - n_bg // 2, dim)))]).astype(np.float32)
    bg_ids = [f"bg{i}" for i in range(n_bg)]
    edges, emb, content, agent = [], {}, {}, {}
    for i in range(n_parents):
        pid = f"p{i}"
        emb[pid] = (unit(core + 0.35 * rng.normal(size=dim)) if planted
                    else unit(rng.normal(size=dim))).astype(np.float32)
        content[pid], agent[pid] = _text(rng), "agent-a"
        for j in range(n_children):
            cid = f"c{i}_{j}"
            emb[cid] = unit(rng.normal(size=dim)).astype(np.float32)
            content[cid], agent[cid] = _text(rng), "agent-a"
            edges.append((pid, cid))
    return edges, emb, content, agent, bg, bg_ids


def _run(planted, seed=1234):
    rng = np.random.default_rng(seed)
    edges, emb, content, agent, bg, bg_ids = _corpus(rng, planted)
    return gd.run_analysis(edges, emb, content, agent, bg, bg_ids,
                           _args(seed=seed), np.random.default_rng(seed))


class ChanceLevelTests(unittest.TestCase):
    """The controls that make every other number interpretable."""

    def assertNearChance(self, rep, label):
        """Within 4 standard errors of 0.50. A 95% CI misses 5% of the time and
        these suites check ~9 proxies at once, so a bare CI-coverage assertion
        would flake; 4 SE is the multiplicity allowance."""
        n = rep["n_edges"]
        self.assertGreater(n, 0, label)
        tol = 4.0 * 0.5 / (n ** 0.5)
        self.assertLessEqual(abs(rep["acc"] - 0.50), tol,
                             f"{label}: acc={rep['acc']:.3f} n={n} tol=+-{tol:.3f}")

    def test_shuffled_control_is_at_chance_even_with_strong_signal(self):
        # The planted corpus has a large real signal; scrambling the direction
        # labels must destroy it completely, for every proxy.
        rep = _run(planted=True)
        for name, r in rep["shuffled_control"].items():
            self.assertNearChance(r, f"{name} shuffled control")

    def test_null_corpus_scores_at_chance(self):
        rep = _run(planted=False)
        for name, r in rep["results"].items():
            self.assertNearChance(r["overall"], f"{name} invented signal")

    def test_random_reference_is_at_chance_on_planted_corpus(self):
        rep = _run(planted=True)
        self.assertNearChance(rep["results"]["random_reference"]["overall"],
                              "random_reference")


class SensitivityTests(unittest.TestCase):
    def test_planted_density_signal_is_found(self):
        rep = _run(planted=True)
        acc = rep["results"]["knn_mean_sim_k20"]["overall"]["acc"]
        self.assertGreater(acc, 0.75, "harness missed a planted density signal")

    def test_verdict_dead_on_null_corpus(self):
        rep = _run(planted=False)
        rep["verdict"] = gd.verdict(rep)
        self.assertEqual(rep["verdict"]["verdict"], "DEAD")


class ScoringTests(unittest.TestCase):
    def test_orientation_fitted_on_fit_split_only(self):
        # "lower = parent" data: the fit split must recover the negative sign.
        values = {"p": 0.0, "c": 1.0, "p2": 0.0, "c2": 1.0}
        fit = [("p", "c", "p")]
        self.assertEqual(gd.fit_orientation(values, fit, np.random.default_rng(0)), -1)

    def test_ties_are_coin_flipped_and_counted(self):
        values = {"a": 1.0, "b": 1.0}
        edges = [("a", "b", "a")] * 400
        correct, ties = gd.score_edges(values, edges, 1, np.random.default_rng(0))
        self.assertEqual(ties, 400)
        self.assertGreater(correct.mean(), 0.40)
        self.assertLess(correct.mean(), 0.60)

    def test_clustered_ci_is_wider_than_binomial_when_children_correlate(self):
        # One parent, 60 perfectly-correlated children: the naive interval would
        # claim 60 independent trials; the clustered one must not.
        correct = np.ones(60, dtype=bool)
        correct[:20] = False
        clusters = ["p0"] * 30 + ["p1"] * 30
        rep = gd.accuracy_report(correct, clusters, np.random.default_rng(0), 500)
        naive = gd.wilson_ci(int(correct.sum()), len(correct))
        clustered = rep["ci_all_edges_clustered"]
        self.assertGreater(clustered[1] - clustered[0], naive[1] - naive[0])

    def test_wilson_ci_bounds(self):
        lo, hi = gd.wilson_ci(50, 100)
        self.assertLess(lo, 0.5)
        self.assertGreater(hi, 0.5)
        self.assertEqual(gd.wilson_ci(0, 0)[0] == gd.wilson_ci(0, 0)[0], False)  # NaN


class DeterminismTests(unittest.TestCase):
    def test_same_seed_same_answer(self):
        a = _run(planted=True, seed=99)["results"]
        b = _run(planted=True, seed=99)["results"]
        for name in a:
            self.assertEqual(a[name]["overall"]["acc"], b[name]["overall"]["acc"])


class ProxyTests(unittest.TestCase):
    def test_participation_ratio_bounds_and_self_exclusion(self):
        rng = np.random.default_rng(0)
        bg = rng.normal(size=(200, 16)).astype(np.float32)
        bg /= np.linalg.norm(bg, axis=1, keepdims=True)
        ids = [f"bg{i}" for i in range(200)]
        out = gd.compute_proxies(bg[:5], ids[:5], bg, ids, k=20, radii=[0.30])
        pr = out["participation_ratio"]
        # PR of a k-point neighbourhood lies in [1, k-1].
        self.assertTrue(np.all(pr >= 1.0) and np.all(pr <= 20.0), pr)
        # A target present in the background must not match itself at sim 1.0.
        self.assertTrue(np.all(out["knn_mean_sim_k20"] < 0.999))


if __name__ == "__main__":
    unittest.main()
