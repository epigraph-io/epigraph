#!/usr/bin/env python3
"""Reference off-box command for the Atlas nightly's hook (backlog 691d283a).

    atlas_offbox_compute.py theme-cap     EXPORT_DIR RESULT_FILE
    atlas_offbox_compute.py atlas-meaning EXPORT_DIR RESULT_FILE

`atlas_nightly --offbox-command` (and `theme_cap_split.py offbox`) run their
command with exactly these three arguments and a cleared environment (PATH,
HOME and LANG only). This one computes IN PLACE, with the same code the
operator's `compute` steps run:

  theme-cap      `theme_cap_core.compute_export_dir` (W1's UMAP + k-means
                 split of each over-cap theme)
  atlas-meaning  `atlas_meaning_core.compute_export_dir` (W4's recursive
                 split of each theme into leaves)

It needs no database and no DB driver, only numpy, scikit-learn and
umap-learn. A deployment whose box cannot run UMAP points the nightly at a
wrapper that copies EXPORT_DIR to a compute host (it holds claim ids and
embeddings only: no text, no tenancy), runs this script there and copies
RESULT_FILE back. The result is written to a NEW file, owner-only; an existing
file is never overwritten.

Exit 0 when the result is written; 2 for a usage error; 1 otherwise.
"""
import json
import os
import pathlib
import sys

KINDS = ("theme-cap", "atlas-meaning")


def compute(kind, export_dir):
    """The result document for `export_dir`."""
    if kind == "theme-cap":
        import theme_cap_core

        return theme_cap_core.compute_export_dir(export_dir)
    if kind == "atlas-meaning":
        import atlas_meaning_core

        return atlas_meaning_core.compute_export_dir(export_dir)
    raise ValueError(f"unknown kind {kind!r}; expected one of {', '.join(KINDS)}")


def write_new(path, doc):
    """Write `doc` to a NEW owner-only file and fsync it."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
        f.flush()
        os.fsync(f.fileno())


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3 or argv[0] not in KINDS:
        print(f"usage: atlas_offbox_compute.py {{{'|'.join(KINDS)}}} EXPORT_DIR RESULT_FILE",
              file=sys.stderr)
        return 2
    kind, export_dir, result = argv
    doc = compute(kind, pathlib.Path(export_dir))
    write_new(result, doc)
    print(f"{kind}: {len(doc['themes'])} themes -> {result}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    sys.exit(main())
