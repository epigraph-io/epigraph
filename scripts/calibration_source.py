"""Choose the calibration file a Python belief backfill reads (backlog af23a73d).

The engine serves the file `CALIBRATION_PATH` names, or its compiled-in copy of
the repo's calibration.toml when the variable is unset
(`CalibrationConfig::cached` in crates/epigraph-engine/src/calibration.rs). A
backfill that writes `mass_functions` must use the same weights, so:

1. an explicit `--calibration` wins (the operator named a file);
2. else a non-empty `CALIBRATION_PATH`, which must name a readable file: these
   scripts write, so an unreadable override is refused rather than silently
   replaced by the repo file. (The engine, given the same unreadable path,
   logs an error and serves its embedded copy; a backfill refuses instead, so
   the operator fixes or unsets the variable and knows which weights were
   written);
3. else the repo-root calibration.toml, which is the file the engine embeds.

The returned label says which one was used, for the script to print.
"""

from __future__ import annotations

import os
from pathlib import Path


def resolve_calibration(cli_value: Path | None, default: Path) -> tuple[Path, str]:
    """Return (path, label) for the calibration file to load."""
    if cli_value is not None:
        return cli_value, f"--calibration {cli_value}"
    env = os.environ.get("CALIBRATION_PATH", "").strip()
    if env:
        path = Path(env)
        if not path.is_file():
            raise SystemExit(
                f"CALIBRATION_PATH={env} names no readable file; refusing to guess "
                f"(not falling back to {default}); fix or unset CALIBRATION_PATH"
            )
        return path, f"CALIBRATION_PATH={path}"
    return default, f"repo calibration.toml {default} (CALIBRATION_PATH unset)"
