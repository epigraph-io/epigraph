#!/usr/bin/env python3
"""Theme maintenance: assign, reassign, split, recompute — all via EpiGraph API.

Ported from EpigraphV2/scripts/maintain_themes.py. Public exposes all the
underlying endpoints (`/api/v1/themes/*` plus `/api/v1/clusters/boundary-claims`)
so the pipeline runs unchanged; only the auth helper differs.

Operations (run in order):
  1.   Assign unthemed claims to nearest existing theme
  1.5  Reassign misplaced claims (boundary_ratio + centroid_distance detection)
  2.   Detect and auto-split high-variance themes (k-means client-side)
  3.   Recompute centroids (only for affected themes)
  4.   Report remaining high-variance themes
  5.   Detect new theme candidates

Usage:
    python3 scripts/maintain_themes.py [--dry-run] [--api-url URL]

Environment:
    EPIGRAPH_API_URL  - API base URL (default: http://127.0.0.1:8080)
    EPIGRAPH_TOKEN    - Bearer token for write endpoints. Mint via
                        scripts/mint_epigraph_token.py (requires claims:write,
                        and claims:admin for reassign flows that cross owners).
                        Read-only endpoints work without a token.
"""

import json
import os
import subprocess
import sys

try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "requests"])
    import requests

API_URL = os.environ.get("EPIGRAPH_API_URL", "http://127.0.0.1:8080")
# Allow --api-url override
for i, arg in enumerate(sys.argv):
    if arg == "--api-url" and i + 1 < len(sys.argv):
        API_URL = sys.argv[i + 1]

DRY_RUN = "--dry-run" in sys.argv

# Public-repo auth convention: bearer token in EPIGRAPH_TOKEN env var
# (mint with scripts/mint_epigraph_token.py — see header docstring).
# V2 shelled out to epigraph-login.py; that script doesn't ship with public.
TOKEN = os.environ.get("EPIGRAPH_TOKEN")


def get_auth_headers():
    """Build request headers, attaching bearer token when available."""
    headers = {"Content-Type": "application/json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    return headers


def api_get(path, params=None, timeout=60):
    """GET request to the API."""
    resp = requests.get(f"{API_URL}{path}", params=params, headers=get_auth_headers(), timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def api_post(path, body=None, timeout=1800):
    """POST request to the API."""
    resp = requests.post(f"{API_URL}{path}", json=body or {}, headers=get_auth_headers(), timeout=timeout)
    resp.raise_for_status()
    return resp.json()


# ── Phase 1: Assign unthemed claims ──────────────────────────────────────────

def assign_unthemed_claims():
    """Assign claims with embeddings but no theme to nearest theme centroid.

    The server loops internally until all unthemed claims are assigned —
    on a fresh DB with ~425k unthemed rows this can take many minutes.
    The default requests timeout (120s) is too short; bump to 30 min.
    """
    if DRY_RUN:
        print("  [DRY] Skipping assignment", file=sys.stderr)
        return 0
    data = api_post("/api/v1/themes/assign-unthemed", {"batch_size": 500}, timeout=1800)
    return data.get("assigned", 0)


# ── Phase 1.5: Reassign misplaced claims ─────────────────────────────────────

def reassign_misplaced_claims():
    """Detect and reassign misplaced claims via boundary_ratio + centroid_distance."""
    headers = get_auth_headers()
    stats = {"checked": 0, "reassigned": 0, "unthemed": 0, "kept": 0, "skipped": 0, "errors": 0}

    resp = requests.get(
        f"{API_URL}/api/v1/clusters/boundary-claims",
        params={"min_boundary_ratio": 0.90, "min_centroid_distance": 0.45, "limit": 500},
        headers=headers, timeout=30,
    )
    resp.raise_for_status()
    candidates = resp.json().get("claims", [])
    stats["checked"] = len(candidates)

    if not candidates:
        return stats

    for claim in candidates:
        claim_id = claim["claim_id"]
        try:
            eval_resp = requests.post(
                f"{API_URL}/api/v1/themes/reassign",
                json={
                    "claim_id": claim_id,
                    "execute": not DRY_RUN,
                    "improvement_threshold": 0.85,
                    "outlier_distance": 0.60,
                    "alt_distance_cap": 0.50,
                },
                headers=headers, timeout=10,
            )
            eval_resp.raise_for_status()
            result = eval_resp.json()
            action = result.get("action", "skipped")

            if action == "reassigned":
                stats["reassigned"] += 1
                print(
                    f"    {'[DRY] ' if DRY_RUN else ''}Reassign {claim_id[:8]}.. "
                    f"from '{result.get('current_theme_label', '?')}' "
                    f"to '{result.get('best_alternative_label', '?')}' "
                    f"(ratio={result.get('improvement_ratio', 0):.3f})",
                    file=sys.stderr,
                )
            elif action == "unthemed":
                stats["unthemed"] += 1
                print(
                    f"    {'[DRY] ' if DRY_RUN else ''}Untheme {claim_id[:8]}.. "
                    f"from '{result.get('current_theme_label', '?')}' "
                    f"(dist={result.get('current_distance', 0):.3f})",
                    file=sys.stderr,
                )
            elif action == "kept":
                stats["kept"] += 1
            else:
                stats["skipped"] += 1
        except Exception as e:
            stats["errors"] += 1
            print(f"    Error evaluating {claim_id[:8]}..: {e}", file=sys.stderr)

    return stats


# ── Phase 2: Detect & auto-split ─────────────────────────────────────────────

def detect_and_split(affected_theme_ids):
    """Find high-variance themes and auto-split the worst offenders.

    Returns (total_splits, split_candidates, new_theme_ids).
    """
    data = api_get("/api/v1/themes/split-candidates", {
        "variance_threshold": 0.50, "min_claims": 2000, "limit": 10,
    }, timeout=1800)
    candidates = data.get("candidates", [])

    if not candidates or DRY_RUN:
        if DRY_RUN and candidates:
            for s in candidates[:3]:
                print(f"  [DRY] Would split '{s['label']}' (avg_dist={s['avg_distance']}, n={s['claim_count']})", file=sys.stderr)
        return 0, candidates, []

    total_splits = 0
    new_theme_ids = []

    for s in candidates[:3]:
        theme_id = s["theme_id"]
        theme_label = s["label"]
        print(f"  Splitting '{theme_label}' (avg_dist={s['avg_distance']}, n={s['claim_count']})...", file=sys.stderr)

        created = auto_split_theme(theme_id, theme_label)
        total_splits += len(created)
        new_theme_ids.extend(created)
        affected_theme_ids.add(theme_id)

    return total_splits, candidates, new_theme_ids


def auto_split_theme(theme_id, theme_label, n_clusters=3, min_claims=500):
    """Split a high-variance theme using client-side k-means.

    Returns list of newly created theme IDs.
    """
    try:
        import numpy as np
        from sklearn.cluster import MiniBatchKMeans
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "scikit-learn"])
        import numpy as np
        from sklearn.cluster import MiniBatchKMeans

    # Fetch embeddings via API
    data = api_get(f"/api/v1/themes/{theme_id}/embeddings", {"limit": 5000}, timeout=600)
    claims = data.get("claims", [])

    if len(claims) < min_claims:
        return []

    ids = [c["id"] for c in claims]
    embeddings = np.array([c["embedding"] for c in claims])

    km = MiniBatchKMeans(n_clusters=n_clusters, random_state=42, batch_size=min(1000, len(claims)))
    labels = km.fit_predict(embeddings)

    created_ids = []
    for c in range(n_clusters):
        mask = labels == c
        count = int(mask.sum())
        if count < 50:
            continue

        centroid = km.cluster_centers_[c].tolist()
        cluster_ids = [ids[i] for i in np.where(mask)[0]]
        sub_label = f"{theme_label} (sub-{c + 1})"

        result = api_post("/api/v1/themes/create-with-centroid", {
            "label": sub_label,
            "description": f"Auto-split from '{theme_label}'.",
            "centroid": centroid,
            "claim_ids": cluster_ids,
        })

        created_ids.append(result["theme_id"])
        print(f"     Created '{sub_label}' ({count} claims)", file=sys.stderr)

    return created_ids


# ── Phase 3: Recompute centroids ─────────────────────────────────────────────

def recompute_centroids(theme_ids=None):
    """Recompute centroids for specified themes, or all if none specified."""
    if DRY_RUN:
        print("  [DRY] Skipping centroid recomputation", file=sys.stderr)
        return 0, []
    body = {}
    if theme_ids:
        body["theme_ids"] = list(theme_ids)
    data = api_post("/api/v1/themes/recompute-centroids", body, timeout=1800)
    themes = data.get("themes", [])
    return data.get("updated", 0), themes


# ── Phase 4: Report remaining splits ─────────────────────────────────────────

def report_remaining_splits():
    """Report themes that still have high variance (lower threshold, report only)."""
    data = api_get("/api/v1/themes/split-candidates", {
        "variance_threshold": 0.35, "min_claims": 500, "limit": 20,
    }, timeout=1800)
    return data.get("candidates", [])


# ── Phase 5: Detect new theme candidates ──────────────────────────────────────

def detect_new_theme_candidates():
    """Find themes with distant outlier clusters."""
    data = api_get("/api/v1/themes/distant-claims", {
        "distance_threshold": 0.45, "min_cluster_size": 20, "limit": 20,
    }, timeout=1800)
    return data.get("candidates", [])


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=== Theme Maintenance ===", file=sys.stderr)
    if DRY_RUN:
        print("  (dry-run mode — no mutations)", file=sys.stderr)

    affected_theme_ids = set()

    # 1. Assign unthemed claims
    print("\n[1/5] Assigning unthemed claims to nearest theme...", file=sys.stderr)
    assigned = assign_unthemed_claims()
    print(f"  -> Assigned {assigned} claims", file=sys.stderr)

    # 1.5. Detect and reassign misplaced claims
    print("\n[1.5/5] Detecting and reassigning misplaced claims...", file=sys.stderr)
    misplaced_stats = reassign_misplaced_claims()
    print(
        f"  -> Checked {misplaced_stats['checked']}, "
        f"reassigned {misplaced_stats['reassigned']}, "
        f"unthemed {misplaced_stats['unthemed']}, "
        f"kept {misplaced_stats['kept']}",
        file=sys.stderr,
    )

    # 2. Detect and auto-split high-variance themes
    print("\n[2/5] Detecting and splitting high-variance themes...", file=sys.stderr)
    total_splits, splits, new_theme_ids = detect_and_split(affected_theme_ids)
    if total_splits > 0:
        print(f"  -> {total_splits} new themes created from splits", file=sys.stderr)
        affected_theme_ids.update(new_theme_ids)
    elif splits:
        print(f"  -> {len(splits)} candidates found (dry-run, no splits)", file=sys.stderr)
    else:
        print("  -> No themes need splitting", file=sys.stderr)

    # 3. Recompute centroids (only affected themes, or all if none tracked)
    print("\n[3/5] Recomputing centroids...", file=sys.stderr)
    if affected_theme_ids:
        updated, themes = recompute_centroids(theme_ids=affected_theme_ids)
        print(f"  -> Recomputed {updated} affected theme centroids", file=sys.stderr)
    else:
        updated, themes = recompute_centroids()
        print(f"  -> Recomputed {updated} theme centroids", file=sys.stderr)

    # 4. Report remaining high-variance themes
    print("\n[4/5] Reporting remaining high-variance themes...", file=sys.stderr)
    remaining_splits = report_remaining_splits()
    if remaining_splits:
        print(f"  -> {len(remaining_splits)} themes still have high variance (report only):", file=sys.stderr)
        for s in remaining_splits[:5]:
            print(f"     {s['label']}: avg_dist={s['avg_distance']}, n={s['claim_count']}", file=sys.stderr)
    else:
        print("  -> All themes within variance threshold", file=sys.stderr)

    # 5. Detect new theme candidates
    print("\n[5/5] Checking for distant claim clusters (new theme candidates)...", file=sys.stderr)
    new_themes = detect_new_theme_candidates()
    if new_themes:
        print(f"  -> {len(new_themes)} themes have distant outlier clusters:", file=sys.stderr)
        for nt in new_themes[:5]:
            print(f"     {nt['source_theme']}: {nt['distant_claims']} distant claims (avg_dist={nt['avg_distance']})", file=sys.stderr)
    else:
        print("  -> No new theme candidates detected", file=sys.stderr)

    # Output structured results
    result = {
        "assigned": assigned,
        "phase_1_5_misplaced": misplaced_stats,
        "splits": total_splits,
        "split_candidates": splits[:10] if splits else [],
        "centroids_updated": updated,
        "total_themes": len(themes) if themes else 0,
        "new_theme_candidates": new_themes[:10] if new_themes else [],
        "top_themes": [{"id": t["id"], "label": t["label"], "count": t["claim_count"]} for t in (themes or [])[:10]],
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
