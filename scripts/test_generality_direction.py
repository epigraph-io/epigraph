#!/usr/bin/env python3
"""Falsification test: does embedding-space geometry predict `decomposes_to` direction?

Read-only analysis. Never writes to the database (the connection is pinned
`default_transaction_read_only = on`, so a stray DML would abort rather than
commit).

## The question

An ontology is asymmetric (`decomposes_to` has a direction); a Riemannian
metric is symmetric (`d(a,b) = d(b,a)`). So no learned metric can induce
hierarchy unless some *asymmetric* quantity derived from the geometry
correlates with generality. In the full method that quantity is the volume
element `sqrt(det G(z))`. Training that is weeks of work.

This script asks the cheap prerequisite question: does a **flat-space**
generality proxy, computed in the 1536-d OpenAI space we already have, beat
chance at predicting which endpoint of a `decomposes_to` edge is the parent?
If the flat proxies are at chance, a learned metric has no signal to sharpen
and the ontology-from-curvature programme should be abandoned.

A negative result is a successful outcome of this script.

## Proxies (all computed against a background sample of `is_current` claims)

  nbr_count_r{0.20,0.30,0.40}  # background claims within cosine distance r
  knn_mean_sim_k{K}            # mean cosine sim to the K nearest background claims
  centroid_prox                # cosine sim to the background mean embedding
  participation_ratio          # (sum L)^2 / sum L^2 over eigenvalues L of the
                               # local K-NN covariance -- effective dimensionality
                               # of the neighbourhood

`participation_ratio` is the headline: it is the flat-space analogue of the
volume element, so it is the proxy whose behaviour actually forecasts whether
the learned-metric version can work. It is reported separately even when
another proxy scores higher.

## Metric convention

`claims.embedding` holds OpenAI embeddings, returned at unit L2 norm. This
script does **not** renormalise the stored vectors; it reports the observed
norm distribution as a data check and computes **cosine** similarity
(`cos_dist = 1 - cos_sim`) throughout. On unit vectors cosine and Euclidean
are monotonically related (`d_euc^2 = 2 - 2*cos_sim`), so every rank-based
result here is identical under either metric.

## Methodology guards

* **Held-out orientation.** Whether "higher proxy = parent" or "lower = parent"
  is fitted on a *fit* split and scored only on a disjoint *test* split. Parents
  are split as whole groups, so no parent straddles the split.
* **Length baseline.** `len(content)` is scored as a first-class competitor,
  and every proxy is additionally scored inside length-matched strata where the
  length signal is neutralised by construction.
* **Agent confound.** The parent/child `agent_id` contingency is reported, plus
  accuracy restricted to edges whose endpoints share an agent.
* **Non-independence.** Headline accuracy uses a one-child-per-parent
  subsample (independent trials, Wilson CI); the all-edges figure is reported
  with a parent-clustered bootstrap CI.
* **No temporal / id leakage.** `created_at`, `id` and insertion order are
  never read as features -- `created_at` is not even selected. Hierarchical
  ingest creates parents before children, so any time-derived feature would
  score near-perfectly and mean nothing.
* **Shuffled control.** The whole pipeline is rerun with edge directions
  randomly flipped. It must return ~0.50; if it does not, the harness is broken
  and every other number is suspect.
* **Lexical sanity check.** A bag-of-words and a length-only logistic
  regression are fitted on the same split. If they match the geometric proxies,
  a positive result is lexical (a direction in the ambient space), not
  evidence about manifold curvature.

## Pre-registered decision rule (fixed before any result was seen)

  proceed       best proxy >= 0.70 AND >= 10 points over the length baseline
                AND the margin survives the within-agent restriction
  inconclusive  0.55 - 0.70, or margin over length < 10 points
  dead          <= 0.55, or not separable from the length baseline

## Usage

    DATABASE_URL=postgres://epigraph_ro:epigraph_ro@localhost:5432/epigraph \
        python3 scripts/test_generality_direction.py

    # Smoke test on a slice:
    python3 scripts/test_generality_direction.py --limit 500 --background 5000

    # Machine-readable, plus the paired-distribution plot:
    python3 scripts/test_generality_direction.py --json out.json --plot out.png

    # Validate the harness with no database at all (synthetic null + planted
    # signal; asserts the null lands at chance and the planted signal is found):
    python3 scripts/test_generality_direction.py --self-test

## Memory profile

Background 50k x 1536 float32 = ~307 MB; endpoint embeddings ~123 MB at 20k
unique claims; one similarity chunk (`--chunk` x background) ~100 MB. Peak
around 600 MB. Reduce `--background` on a small host.
"""
import argparse
import json
import math
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from theme_lib import (  # noqa: E402
    connect,
    load_embeddings_for_ids,
    set_statement_timeout,
)

RO_DATABASE_URL = "postgres://epigraph_ro:epigraph_ro@localhost:5432/epigraph"
DEFAULT_RADII = (0.20, 0.30, 0.40)
HEADLINE_PROXY = "participation_ratio"
LENGTH_BASELINE = "length_chars"

# Pre-registered thresholds. Do not adjust after seeing results.
PROCEED_ACC = 0.70
PROCEED_MARGIN = 0.10
DEAD_ACC = 0.55


# --------------------------------------------------------------------------
# statistics
# --------------------------------------------------------------------------

def wilson_ci(successes, n, z=1.96):
    """95% Wilson score interval. Correct at small n and near 0/1, unlike the
    normal-approximation interval."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = successes / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def cluster_bootstrap_ci(parent_sums, parent_counts, rng, reps=2000):
    """95% CI resampling *parents* with replacement, so a parent with 30
    children contributes one draw rather than 30 independent ones."""
    p = len(parent_sums)
    if p == 0:
        return (float("nan"), float("nan"))
    idx = rng.integers(0, p, size=(reps, p))
    num = parent_sums[idx].sum(axis=1)
    den = parent_counts[idx].sum(axis=1)
    accs = np.where(den > 0, num / np.maximum(den, 1), np.nan)
    return (float(np.nanpercentile(accs, 2.5)), float(np.nanpercentile(accs, 97.5)))


# --------------------------------------------------------------------------
# proxy computation
# --------------------------------------------------------------------------

def unit_rows(mat):
    """Row-normalise a copy for cosine arithmetic. The stored vectors are left
    untouched; this only implements the definition of cosine similarity."""
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return mat / norms


def compute_proxies(target_emb, target_ids, bg_emb, bg_ids, k=50,
                    radii=DEFAULT_RADII, chunk=512, verbose=False):
    """Generality proxies for every row of `target_emb` against the background.

    A target that is itself in the background is masked out of its own
    neighbourhood (otherwise every claim scores a free self-match at sim 1.0).
    """
    tgt = unit_rows(target_emb.astype(np.float32))
    bg = unit_rows(bg_emb.astype(np.float32))
    bg_centroid = bg.mean(axis=0)
    bg_centroid /= max(np.linalg.norm(bg_centroid), 1e-12)
    bg_pos = {cid: i for i, cid in enumerate(bg_ids)}

    n = tgt.shape[0]
    k_eff = min(k, bg.shape[0] - 1)
    out = {f"nbr_count_r{r:.2f}": np.zeros(n) for r in radii}
    out[f"knn_mean_sim_k{k_eff}"] = np.zeros(n)
    out["centroid_prox"] = tgt @ bg_centroid
    out["participation_ratio"] = np.zeros(n)

    for start in range(0, n, chunk):
        stop = min(start + chunk, n)
        sims = tgt[start:stop] @ bg.T                      # (chunk, n_bg)
        for local, gi in enumerate(range(start, stop)):
            self_idx = bg_pos.get(target_ids[gi])
            if self_idx is not None:
                sims[local, self_idx] = -np.inf
        for r in radii:
            out[f"nbr_count_r{r:.2f}"][start:stop] = (sims >= 1.0 - r).sum(axis=1)
        top = np.argpartition(-sims, k_eff - 1, axis=1)[:, :k_eff]
        for local, gi in enumerate(range(start, stop)):
            idx = top[local]
            out[f"knn_mean_sim_k{k_eff}"][gi] = float(sims[local, idx].mean())
            nbrs = bg[idx]
            nbrs = nbrs - nbrs.mean(axis=0, keepdims=True)
            # Eigenvalues of the k x k Gram matrix match the nonzero spectrum of
            # the 1536 x 1536 covariance, so PR is exact and ~1e5x cheaper.
            gram = (nbrs @ nbrs.T) / max(k_eff - 1, 1)
            lam = np.linalg.eigvalsh(gram.astype(np.float64))
            lam = np.clip(lam, 0.0, None)
            s1, s2 = lam.sum(), (lam ** 2).sum()
            out["participation_ratio"][gi] = float(s1 * s1 / s2) if s2 > 0 else 0.0
        if verbose:
            print(f"    proxies {stop}/{n}", file=sys.stderr)
    return out


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

def score_edges(values, edges, orientation, rng):
    """Per-edge correctness under `orientation` (+1 => higher value = parent).

    Exact ties carry no information, so they are broken by a seeded coin flip
    and counted; a proxy with a high tie rate is reported as such rather than
    being silently credited with half its trials.
    """
    if len(edges) == 0:
        return np.zeros(0, dtype=bool), 0
    diff = np.array([values[e[0]] - values[e[1]] for e in edges]) * orientation
    ties = int((diff == 0).sum())
    coin = rng.random(len(diff)) < 0.5
    return np.where(diff == 0, coin, diff > 0), ties


def fit_orientation(values, fit_edges, rng):
    """Fix the sign on the fit split only -- never on the test set."""
    correct, _ = score_edges(values, fit_edges, 1, rng)
    return 1 if (len(correct) and correct.mean() >= 0.5) else -1


def accuracy_report(correct, clusters, rng, boot_reps=2000):
    """Headline (one child per parent, Wilson CI) plus all-edges with a
    parent-clustered bootstrap CI.

    `clusters` is the *true* parent of each edge, never the endpoint currently
    being presented as parent -- otherwise the shuffled control would regroup
    the data and stop landing at chance.
    """
    n = len(correct)
    if n == 0:
        return {"n_edges": 0}
    order = {}
    for i, p in enumerate(clusters):
        order.setdefault(p, []).append(i)
    keys = list(order.keys())
    sums = np.array([correct[idx].sum() for idx in order.values()], dtype=float)
    counts = np.array([len(idx) for idx in order.values()], dtype=float)

    # one child per parent, chosen by the seeded rng
    picks = [order[kk][rng.integers(0, len(order[kk]))] for kk in keys]
    sub = correct[np.array(picks)]
    sub_acc = float(sub.mean())
    lo, hi = wilson_ci(int(sub.sum()), len(sub))
    all_acc = float(correct.mean())
    blo, bhi = cluster_bootstrap_ci(sums, counts, rng, reps=boot_reps)
    return {
        "n_edges": n,
        "n_parents": len(keys),
        "acc": sub_acc,              # headline: independent trials
        "ci": [lo, hi],
        "acc_all_edges": all_acc,
        "ci_all_edges_clustered": [blo, bhi],
    }


def evaluate(proxy_values, edges_fit, edges_test, rng, boot_reps=2000, subset=None):
    """Fit orientation on `edges_fit`, score on `edges_test` (optionally a
    subset of it, for the confound restrictions)."""
    orientation = fit_orientation(proxy_values, edges_fit, rng)
    test = edges_test if subset is None else [e for e in edges_test if subset(e)]
    correct, ties = score_edges(proxy_values, test, orientation, rng)
    rep = accuracy_report(correct, [e[2] for e in test], rng, boot_reps)
    rep["orientation"] = "higher=parent" if orientation > 0 else "lower=parent"
    rep["tie_rate"] = (ties / len(test)) if test else 0.0
    return rep


# --------------------------------------------------------------------------
# lexical controls
# --------------------------------------------------------------------------

def pairwise_logreg(featurise, edges_fit, edges_test, rng, label=""):
    """Antisymmetric pairwise classifier: features are f(a) - f(b), no
    intercept, label = 1 iff `a` is the parent. Each pair is presented in a
    random order so the model cannot learn a constant."""
    try:
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        return {"skipped": "scikit-learn not installed"}
    import scipy.sparse as sp

    def build(edges, r):
        if not edges:
            return None, None, None
        flip = r.random(len(edges)) < 0.5
        a = [e[1] if f else e[0] for e, f in zip(edges, flip)]
        b = [e[0] if f else e[1] for e, f in zip(edges, flip)]
        fa, fb = featurise(a), featurise(b)
        x = (fa - fb)
        y = np.where(flip, 0, 1)
        return x, y, [e[2] for e in edges]

    xf, yf, _ = build(edges_fit, rng)
    xt, yt, pt = build(edges_test, rng)
    if xf is None or xt is None or len(set(yf)) < 2:
        return {"skipped": "insufficient data"}
    if sp.issparse(xf):
        xf, xt = sp.csr_matrix(xf), sp.csr_matrix(xt)
    model = LogisticRegression(fit_intercept=False, max_iter=2000, C=1.0)
    model.fit(xf, yf)
    correct = model.predict(xt) == yt
    rep = accuracy_report(np.asarray(correct), pt, rng)
    rep["model"] = label
    return rep


def lexical_controls(edges_fit, edges_test, content, rng):
    ids = sorted({cid for e in edges_fit + edges_test for cid in e[:2]})
    idx = {cid: i for i, cid in enumerate(ids)}
    texts = [content.get(cid, "") for cid in ids]

    lengths = np.array([[len(t), len(t.split())] for t in texts], dtype=float)
    lengths = (lengths - lengths.mean(0)) / np.maximum(lengths.std(0), 1e-9)
    out = {"length_logreg": pairwise_logreg(
        lambda claims: lengths[[idx[c] for c in claims]],
        edges_fit, edges_test, rng, "length (chars, tokens)")}

    try:
        from sklearn.feature_extraction.text import HashingVectorizer
        vec = HashingVectorizer(n_features=2 ** 18, alternate_sign=False,
                                lowercase=True, norm="l2")
        bow = vec.transform(texts)
        out["bag_of_words_logreg"] = pairwise_logreg(
            lambda claims: bow[[idx[c] for c in claims]],
            edges_fit, edges_test, rng, "bag of words (2^18 hashed unigrams)")
    except ImportError:
        out["bag_of_words_logreg"] = {"skipped": "scikit-learn not installed"}
    return out


# --------------------------------------------------------------------------
# database access (read-only)
# --------------------------------------------------------------------------

def open_ro(database_url, timeout_ms):
    conn = connect(database_url or os.environ.get("DATABASE_URL", RO_DATABASE_URL))
    with conn.cursor() as cur:
        cur.execute("SET default_transaction_read_only = on")
    conn.commit()
    set_statement_timeout(conn, timeout_ms)
    return conn


EDGE_PREDICATE = """
      e.relationship = 'decomposes_to'
  AND e.source_type = 'claim' AND e.target_type = 'claim'
  AND p.is_current AND c.is_current
  AND p.embedding IS NOT NULL AND c.embedding IS NOT NULL
"""


def fetch_edges(conn, limit, seed, verbose=False):
    """Sample decomposes_to edges. Source is the parent, target is the child.

    Sampling is a seeded hash of the edge id -- deterministic and reproducible,
    and *not* a feature: no id- or time-derived quantity reaches the scorer.
    """
    salt = str(seed)
    with conn.cursor() as cur:
        cur.execute(f"""
            SELECT count(*) FROM edges e
            JOIN claims p ON p.id = e.source_id
            JOIN claims c ON c.id = e.target_id
            WHERE {EDGE_PREDICATE}""")
        eligible = cur.fetchone()[0]
        # Diagnostics for a small sample: which predicate is the binding one?
        cur.execute("""
            SELECT count(*) FROM edges
            WHERE relationship = 'decomposes_to'
              AND source_type = 'claim' AND target_type = 'claim'""")
        raw = cur.fetchone()[0]
        cur.execute("""
            SELECT count(*) FROM edges WHERE lower(relationship) = 'decomposes_to'""")
        any_case = cur.fetchone()[0]
        if verbose:
            print(f"  edges: {raw} claim->claim, {eligible} with both endpoints "
                  f"current+embedded", file=sys.stderr)
        cur.execute(f"""
            SELECT e.source_id::text, e.target_id::text
            FROM edges e
            JOIN claims p ON p.id = e.source_id
            JOIN claims c ON c.id = e.target_id
            WHERE {EDGE_PREDICATE}
            ORDER BY md5(e.id::text || %s)
            LIMIT %s""", (salt, limit))
        edges = [(r[0], r[1]) for r in cur.fetchall()]
    return edges, {"decomposes_to_claim_claim": raw,
                   "decomposes_to_any_case_any_type": any_case,
                   "eligible_both_current_embedded": eligible,
                   "sampled": len(edges)}


def fetch_background_ids(conn, n, seed, exclude=()):
    """Background reference sample. Endpoint claims are excluded so a claim is
    never scored against a copy of itself."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id::text FROM claims
            WHERE is_current AND embedding IS NOT NULL
              AND NOT (id = ANY(%s::uuid[]))
            ORDER BY md5(id::text || %s)
            LIMIT %s""", (list(exclude), str(seed), n))
        return [r[0] for r in cur.fetchall()]


def detect_dim(conn, default=1536):
    """Read the embedding width off the data rather than assuming it, so a
    schema change surfaces as a clear number instead of a broadcast error."""
    with conn.cursor() as cur:
        cur.execute("SELECT embedding::text FROM claims "
                    "WHERE embedding IS NOT NULL LIMIT 1")
        row = cur.fetchone()
    return len(json.loads(row[0])) if row else default


def fetch_metadata(conn, ids):
    """Content and agent only. `created_at` and `id` are deliberately not read
    as features -- ingest order would leak the answer."""
    content, agent = {}, {}
    for start in range(0, len(ids), 5000):
        sub = ids[start:start + 5000]
        with conn.cursor() as cur:
            cur.execute("SELECT id::text, content, agent_id::text FROM claims "
                        "WHERE id = ANY(%s::uuid[])", (sub,))
            for cid, text, aid in cur.fetchall():
                content[cid], agent[cid] = text, aid
    return content, agent


# --------------------------------------------------------------------------
# analysis core (database-agnostic, so --self-test can drive it directly)
# --------------------------------------------------------------------------

def run_analysis(edges, emb, content, agent, bg_emb, bg_ids, args, rng,
                 verbose=False):
    edges = [(p, c, p) for p, c in edges]   # (presented parent, child, cluster key)
    ids = sorted({cid for e in edges for cid in e[:2]})
    emb_mat = np.stack([emb[cid] for cid in ids])
    norms = np.linalg.norm(emb_mat, axis=1)

    if verbose:
        print(f"  computing proxies for {len(ids)} unique endpoint claims",
              file=sys.stderr)
    proxies = compute_proxies(emb_mat, ids, bg_emb, bg_ids, k=args.k,
                              radii=args.radii, chunk=args.chunk, verbose=verbose)
    proxies = {name: {cid: float(v[i]) for i, cid in enumerate(ids)}
               for name, v in proxies.items()}

    # Baselines: length, and a random reference that must land at chance.
    proxies[LENGTH_BASELINE] = {cid: float(len(content.get(cid, ""))) for cid in ids}
    proxies["length_tokens"] = {cid: float(len(content.get(cid, "").split()))
                                for cid in ids}
    proxies["random_reference"] = {cid: float(rng.random()) for cid in ids}

    # Split by parent group so no parent appears in both fit and test.
    parents = sorted({e[2] for e in edges})
    shuffled = list(parents)
    rng.shuffle(shuffled)
    fit_parents = set(shuffled[:len(shuffled) // 2])
    edges_fit = [e for e in edges if e[2] in fit_parents]
    edges_test = [e for e in edges if e[2] not in fit_parents]

    # Confound subsets, evaluated on the same held-out orientation.
    def same_agent(e):
        return agent.get(e[0]) is not None and agent.get(e[0]) == agent.get(e[1])

    def length_matched(e):
        la, lb = len(content.get(e[0], "")), len(content.get(e[1], ""))
        lo, hi = min(la, lb), max(la, lb)
        return lo > 0 and hi / lo <= args.length_ratio

    results = {}
    for name, values in proxies.items():
        seeded = np.random.default_rng(args.seed)
        results[name] = {
            "overall": evaluate(values, edges_fit, edges_test, seeded, args.boot_reps),
            "same_agent": evaluate(values, edges_fit, edges_test, seeded,
                                   args.boot_reps, subset=same_agent),
            "length_matched": evaluate(values, edges_fit, edges_test, seeded,
                                       args.boot_reps, subset=length_matched),
        }

    # Shuffled control: flip a coin per edge and rerun end to end, orientation
    # fitting included. Must land at ~0.50 or the harness is broken.
    ctl_rng = np.random.default_rng(args.seed + 777)

    def scramble(subset):
        f = ctl_rng.random(len(subset)) < 0.5
        return [(e[1], e[0], e[2]) if flip_it else e
                for e, flip_it in zip(subset, f)]

    shuffled_control = {
        name: evaluate(values, scramble(edges_fit), scramble(edges_test),
                       np.random.default_rng(args.seed + 13), args.boot_reps)
        for name, values in proxies.items()
    }

    # Agent contingency across roles.
    parent_agents, child_agents, same = {}, {}, 0
    for p, c, _ in edges:
        parent_agents[agent.get(p)] = parent_agents.get(agent.get(p), 0) + 1
        child_agents[agent.get(c)] = child_agents.get(agent.get(c), 0) + 1
        if agent.get(p) is not None and agent.get(p) == agent.get(c):
            same += 1
    pair_counts = {}
    for p, c, _ in edges:
        key = f"{agent.get(p)}->{agent.get(c)}"
        pair_counts[key] = pair_counts.get(key, 0) + 1

    lengths_p = np.array([len(content.get(e[0], "")) for e in edges], dtype=float)
    lengths_c = np.array([len(content.get(e[1], "")) for e in edges], dtype=float)

    return {
        "n_edges": len(edges),
        "n_unique_claims": len(ids),
        "n_parents": len(parents),
        "n_edges_fit": len(edges_fit),
        "n_edges_test": len(edges_test),
        "children_per_parent_mean": len(edges) / max(len(parents), 1),
        "embedding_norms": {"mean": float(norms.mean()), "std": float(norms.std()),
                            "min": float(norms.min()), "max": float(norms.max())},
        "metric": "cosine (1 - cos_sim); monotone in Euclidean on unit vectors",
        "results": results,
        "shuffled_control": shuffled_control,
        "agent_confound": {
            "n_same_agent_edges": same,
            "frac_same_agent": same / max(len(edges), 1),
            "n_distinct_parent_agents": len(parent_agents),
            "n_distinct_child_agents": len(child_agents),
            "top_agent_pairs": sorted(pair_counts.items(), key=lambda kv: -kv[1])[:10],
        },
        "length_stats": {
            "parent_mean_chars": float(lengths_p.mean()),
            "child_mean_chars": float(lengths_c.mean()),
            "frac_parent_longer": float((lengths_p > lengths_c).mean()),
            "n_length_matched": sum(1 for e in edges_test if length_matched(e)),
            "length_ratio_threshold": args.length_ratio,
        },
        "lexical_controls": lexical_controls(
            edges_fit, edges_test, content, np.random.default_rng(args.seed + 5)),
        "_plot_data": {
            "parent": [proxies[HEADLINE_PROXY][e[0]] for e in edges],
            "child": [proxies[HEADLINE_PROXY][e[1]] for e in edges],
        },
    }


# --------------------------------------------------------------------------
# verdict
# --------------------------------------------------------------------------

def verdict(report):
    res = report["results"]
    geometric = [n for n in res
                 if n not in (LENGTH_BASELINE, "length_tokens", "random_reference")]
    best = max(geometric, key=lambda n: res[n]["overall"]["acc"])
    best_acc = res[best]["overall"]["acc"]
    length_acc = res[LENGTH_BASELINE]["overall"]["acc"]
    margin = best_acc - length_acc
    within_agent = res[best]["same_agent"]
    wa_margin = (within_agent.get("acc", float("nan"))
                 - res[LENGTH_BASELINE]["same_agent"].get("acc", float("nan")))

    survives = (not math.isnan(wa_margin)) and wa_margin >= PROCEED_MARGIN
    if best_acc >= PROCEED_ACC and margin >= PROCEED_MARGIN and survives:
        call = "PROCEED"
    elif best_acc <= DEAD_ACC or margin <= 0.0:
        call = "DEAD"
    else:
        call = "INCONCLUSIVE"
    return {
        "verdict": call,
        "best_geometric_proxy": best,
        "best_acc": best_acc,
        "length_baseline_acc": length_acc,
        "margin_over_length": margin,
        "within_agent_margin": wa_margin,
        "headline_proxy": HEADLINE_PROXY,
        "headline_proxy_acc": res[HEADLINE_PROXY]["overall"]["acc"],
    }


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def fmt(rep):
    if rep.get("n_edges", 0) == 0:
        return "     n/a (no edges in subset)"
    lo, hi = rep["ci"]
    out = f"{rep['acc']:.3f} [{lo:.3f},{hi:.3f}] n={rep['n_edges']:>5}"
    if "tie_rate" in rep:
        out += f" tie={rep['tie_rate']:.2f} {rep['orientation']}"
    return out


def print_report(report, args):
    r = report["results"]
    print("=" * 78)
    print("GENERALITY-DIRECTION TEST -- does geometry predict decomposes_to direction?")
    print("=" * 78)
    s = report.get("sample_diagnostics")
    if s:
        print(f"\nEdge population: {s['decomposes_to_claim_claim']} claim->claim "
              f"decomposes_to edges; {s['eligible_both_current_embedded']} eligible "
              f"(both endpoints is_current + embedded); {s['sampled']} sampled "
              f"(cap {args.limit}).")
    print(f"Edges scored: {report['n_edges']}  parents: {report['n_parents']}  "
          f"unique endpoint claims: {report['n_unique_claims']}  "
          f"mean children/parent: {report['children_per_parent_mean']:.2f}")
    print(f"Split: {report['n_edges_fit']} fit (orientation) / "
          f"{report['n_edges_test']} test (scored), disjoint by parent.")
    n = report["embedding_norms"]
    print(f"Embedding L2 norms: mean={n['mean']:.4f} sd={n['std']:.4f} "
          f"(not renormalised). Metric: {report['metric']}")

    print("\n-- ACCURACY (headline = one child per parent, Wilson 95% CI) "
          + "-" * 16)
    print(f"{'proxy':<26} {'accuracy [95% CI]':<34} {'all-edges (clustered CI)'}")
    for name in r:
        o = r[name]["overall"]
        tail = ""
        if o.get("n_edges"):
            blo, bhi = o["ci_all_edges_clustered"]
            tail = f"{o['acc_all_edges']:.3f} [{blo:.3f},{bhi:.3f}]"
        mark = " *" if name == HEADLINE_PROXY else ""
        print(f"{name+mark:<26} {fmt(o):<34} {tail}")
    print("  * headline proxy: flat-space analogue of the volume element")

    print("\n-- CONFOUND 1: text length " + "-" * 50)
    ls = report["length_stats"]
    print(f"parent mean {ls['parent_mean_chars']:.0f} chars, child mean "
          f"{ls['child_mean_chars']:.0f}; parent longer in "
          f"{ls['frac_parent_longer']:.1%} of edges")
    print(f"length baseline accuracy: {fmt(r[LENGTH_BASELINE]['overall'])}")
    print(f"length-matched strata (ratio <= {ls['length_ratio_threshold']}, "
          f"n={ls['n_length_matched']} test edges):")
    for name in r:
        print(f"  {name:<26} {fmt(r[name]['length_matched'])}")

    print("\n-- CONFOUND 2: authoring agent " + "-" * 46)
    a = report["agent_confound"]
    print(f"same-agent edges: {a['n_same_agent_edges']} ({a['frac_same_agent']:.1%}); "
          f"{a['n_distinct_parent_agents']} distinct parent agents, "
          f"{a['n_distinct_child_agents']} child agents")
    print("top parent->child agent pairs:")
    for key, cnt in a["top_agent_pairs"][:5]:
        print(f"  {cnt:>6}  {key}")
    print("accuracy restricted to same-agent edges:")
    for name in r:
        print(f"  {name:<26} {fmt(r[name]['same_agent'])}")

    print("\n-- CONFOUND 3: non-independence " + "-" * 45)
    print("headline accuracy uses one child per parent (independent trials, "
          "Wilson CI);")
    print("the all-edges column carries a parent-clustered bootstrap CI "
          f"({args.boot_reps} reps).")

    print("\n-- CONFOUND 4: temporal / id leakage " + "-" * 40)
    print("created_at, id and insertion order are never read as features "
          "(created_at is not selected at all).")

    print("\n-- SHUFFLED CONTROL (directions randomly flipped; expect ~0.50) "
          + "-" * 14)
    for name, rep in report["shuffled_control"].items():
        print(f"  {name:<26} {fmt(rep)}")

    print("\n-- LEXICAL SANITY CHECK " + "-" * 53)
    for name, rep in report["lexical_controls"].items():
        if "skipped" in rep:
            print(f"  {name:<26} skipped: {rep['skipped']}")
        else:
            print(f"  {name:<26} {fmt(rep)}   [{rep['model']}]")
    print("  If these match the geometric proxies, a positive result is lexical")
    print("  (a direction in the ambient space), not evidence about curvature.")

    v = report["verdict"]
    print("\n" + "=" * 78)
    print(f"VERDICT: {v['verdict']}")
    print("=" * 78)
    print(f"best geometric proxy : {v['best_geometric_proxy']} = {v['best_acc']:.3f}")
    print(f"length baseline      : {v['length_baseline_acc']:.3f}")
    print(f"margin over length   : {v['margin_over_length']:+.3f} "
          f"(threshold +{PROCEED_MARGIN:.2f})")
    print(f"within-agent margin  : {v['within_agent_margin']:+.3f}")
    print(f"headline ({HEADLINE_PROXY}) : {v['headline_proxy_acc']:.3f}")
    print("\nPre-registered rule: PROCEED if best >= 0.70 AND margin >= +0.10 AND "
          "the margin\nsurvives within-agent; DEAD if best <= 0.55 or not separable "
          "from length;\notherwise INCONCLUSIVE. Thresholds were fixed before "
          "results were seen.")


def make_plot(report, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print(f"(plot skipped: matplotlib not installed)", file=sys.stderr)
        return None
    p = np.array(report["_plot_data"]["parent"])
    c = np.array(report["_plot_data"]["child"])
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.5))
    ax[0].violinplot([c, p], showmedians=True)
    ax[0].set_xticks([1, 2])
    ax[0].set_xticklabels(["child\n(specific)", "parent\n(general)"])
    ax[0].set_ylabel(HEADLINE_PROXY)
    ax[0].set_title(f"{HEADLINE_PROXY} by role (paired endpoints)")
    d = p - c
    ax[1].hist(d, bins=60, color="#4477aa")
    ax[1].axvline(0, color="crimson", lw=1.5)
    ax[1].set_xlabel(f"{HEADLINE_PROXY}(parent) - {HEADLINE_PROXY}(child)")
    ax[1].set_ylabel("edges")
    ax[1].set_title(f"within-edge difference "
                    f"(parent higher in {float((d > 0).mean()):.1%} of edges)")
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    return path


# --------------------------------------------------------------------------
# self-test (no database)
# --------------------------------------------------------------------------

def self_test(args):
    """Validate the harness on synthetic corpora whose answer is known.

    null    -- embeddings independent of role; every proxy must land at chance.
    planted -- parents drawn from a dense core, children from a sparse shell;
               the density proxies must find it.

    This exercises the same scoring, splitting, orientation-fitting, CI and
    shuffled-control code that the live run uses.
    """
    rng = np.random.default_rng(args.seed)
    dim, n_par, n_child, n_bg = 64, 300, 3, 4000

    def unit(x):
        return x / np.linalg.norm(x, axis=-1, keepdims=True)

    def build(planted):
        core = unit(rng.normal(size=dim))
        bg_ids = [f"bg{i}" for i in range(n_bg)]
        # A dense core plus a diffuse halo, so density genuinely varies.
        dense = unit(core + 0.35 * rng.normal(size=(n_bg // 2, dim)))
        halo = unit(rng.normal(size=(n_bg - n_bg // 2, dim)))
        bg = np.vstack([dense, halo]).astype(np.float32)
        edges, emb, content, agent = [], {}, {}, {}
        for i in range(n_par):
            pid = f"p{i}"
            emb[pid] = (unit(core + 0.35 * rng.normal(size=dim)) if planted
                        else unit(rng.normal(size=dim))).astype(np.float32)
            content[pid] = " ".join(f"w{rng.integers(0, 50)}" for _ in range(20))
            agent[pid] = "a0"
            for j in range(n_child):
                cid = f"c{i}_{j}"
                emb[cid] = unit(rng.normal(size=dim)).astype(np.float32)
                content[cid] = " ".join(f"w{rng.integers(0, 50)}" for _ in range(20))
                agent[cid] = "a0"
                edges.append((pid, cid))
        return edges, emb, content, agent, bg, bg_ids

    ok = True
    for planted in (False, True):
        label = "planted" if planted else "null"
        edges, emb, content, agent, bg, bg_ids = build(planted)
        sub = argparse.Namespace(**vars(args))
        sub.k, sub.chunk, sub.boot_reps = 50, 256, 400
        rep = run_analysis(edges, emb, content, agent, bg, bg_ids, sub,
                           np.random.default_rng(args.seed))
        rep["verdict"] = verdict(rep)
        res = rep["results"]
        dens = res[f"knn_mean_sim_k{min(sub.k, len(bg_ids) - 1)}"]["overall"]["acc"]
        ctl = rep["shuffled_control"][HEADLINE_PROXY]["acc"]
        rnd = res["random_reference"]["overall"]["acc"]
        print(f"\n[self-test: {label}]")
        print(f"  density proxy (knn_mean_sim) acc = {dens:.3f}")
        print(f"  {HEADLINE_PROXY} acc            = "
              f"{res[HEADLINE_PROXY]['overall']['acc']:.3f}")
        print(f"  random_reference acc           = {rnd:.3f}  (expect ~0.50)")
        print(f"  shuffled control acc           = {ctl:.3f}  (expect ~0.50)")
        print(f"  verdict                        = {rep['verdict']['verdict']}")
        if not 0.40 <= rnd <= 0.60:
            print("  FAIL: random reference is not at chance"); ok = False
        if not 0.35 <= ctl <= 0.65:
            print("  FAIL: shuffled control is not at chance"); ok = False
        if planted and dens < 0.75:
            print("  FAIL: harness missed a planted density signal"); ok = False
        if not planted and not 0.35 <= dens <= 0.65:
            print("  FAIL: harness invented signal on a null corpus"); ok = False
    print("\nself-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Falsification test: does embedding geometry predict "
                    "decomposes_to edge direction?",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Read-only. Pre-registered decision rule: PROCEED >= 0.70 with a "
               "+0.10 margin\nover the length baseline surviving the within-agent "
               "restriction; DEAD <= 0.55.")
    ap.add_argument("--database-url", default=None,
                    help=f"defaults to $DATABASE_URL, else {RO_DATABASE_URL}")
    ap.add_argument("--limit", type=int, default=10000,
                    help="max decomposes_to edges to sample (default 10000)")
    ap.add_argument("--background", type=int, default=50000,
                    help="background claim sample for neighbourhood stats "
                         "(default 50000)")
    ap.add_argument("--seed", type=int, default=20260821,
                    help="seed for sampling, splitting, tie-breaks and bootstrap")
    ap.add_argument("--k", type=int, default=50, help="k for k-NN proxies")
    ap.add_argument("--radii", type=float, nargs="+", default=list(DEFAULT_RADII),
                    help="cosine-distance radii for neighbourhood counts")
    ap.add_argument("--length-ratio", type=float, default=1.2,
                    help="max longer/shorter char ratio for the length-matched "
                         "stratum (default 1.2)")
    ap.add_argument("--chunk", type=int, default=512,
                    help="similarity-matrix chunk size (memory knob)")
    ap.add_argument("--boot-reps", type=int, default=2000,
                    help="parent-clustered bootstrap replicates")
    ap.add_argument("--timeout-ms", type=int, default=900000,
                    help="server-side statement_timeout")
    ap.add_argument("--json", default=None, help="write the full report as JSON")
    ap.add_argument("--plot", default=None,
                    help="write the paired parent/child distribution plot here")
    ap.add_argument("--self-test", action="store_true",
                    help="validate the harness on synthetic data; no database")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test(args)

    rng = np.random.default_rng(args.seed)
    conn = open_ro(args.database_url, args.timeout_ms)
    try:
        if args.verbose:
            print("fetching edges...", file=sys.stderr)
        edges, diag = fetch_edges(conn, args.limit, args.seed, args.verbose)
        if not edges:
            print("No eligible decomposes_to edges found. Diagnostics:")
            print(json.dumps(diag, indent=2))
            print("\nVERDICT: cannot be issued -- no data.")
            return 2
        ids = sorted({cid for e in edges for cid in e})
        if args.verbose:
            print(f"fetching metadata for {len(ids)} claims...", file=sys.stderr)
        content, agent = fetch_metadata(conn, ids)
        dim = detect_dim(conn)
        if args.verbose:
            print(f"embedding dimension: {dim}", file=sys.stderr)
        emb_mat = load_embeddings_for_ids(conn, ids, dim=dim)
        emb = {cid: emb_mat[i] for i, cid in enumerate(ids)}
        if args.verbose:
            print(f"fetching {args.background} background claims...", file=sys.stderr)
        bg_ids = fetch_background_ids(conn, args.background, args.seed, exclude=ids)
        bg_emb = load_embeddings_for_ids(conn, bg_ids, dim=dim)
    finally:
        conn.close()

    report = run_analysis(edges, emb, content, agent, bg_emb, bg_ids, args, rng,
                          args.verbose)
    report["sample_diagnostics"] = diag
    report["config"] = {k: v for k, v in vars(args).items()}
    report["verdict"] = verdict(report)
    print_report(report, args)

    if diag["sampled"] < args.limit:
        print(f"\nNOTE: only {diag['sampled']} eligible edges exist "
              f"(requested {args.limit}). Every CI above is correspondingly wide; "
              f"treat the verdict as provisional.")
    if args.plot:
        p = make_plot(report, args.plot)
        if p:
            print(f"\nplot: {p}")
    if args.json:
        out = {k: v for k, v in report.items() if k != "_plot_data"}
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2, default=str)
        print(f"json: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
