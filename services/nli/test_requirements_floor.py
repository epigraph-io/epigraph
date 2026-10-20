"""Security floor for the pinned ML stack in services/nli/requirements.txt.

Standard-library only, so it runs without installing the (multi-GB) stack:
    python3 -m unittest services/nli/test_requirements_floor.py
    pytest services/nli/test_requirements_floor.py

Each floor is the first release that fixes the newest advisory against that
package. The floors are hardcoded here on purpose and are NOT derived from
requirements.txt, so lowering a pin (or deleting the line) turns this red.
"""
from __future__ import annotations

import pathlib
import re
import unittest

REQUIREMENTS = pathlib.Path(__file__).with_name("requirements.txt")

# package -> (minimum version, advisory that sets the floor)
SECURITY_FLOORS = {
    # Newest of the fixed torch advisories; also clears CVE-2025-32434
    # (torch.load weights_only=True RCE, fixed in 2.6.0).
    "torch": ("2.13.0", "CVE-2025-3000"),
    # Newest of the fixed transformers advisories; also clears CVE-2026-5241,
    # CVE-2026-4372 and CVE-2024-11392/11393/11394.
    "transformers": ("5.10.0", "CVE-2026-9856"),
    "sentencepiece": ("0.2.1", "CVE-2026-1260"),
}

_PIN = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([0-9][0-9A-Za-z.\-+]*)\s*$")


_RELEASE = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


def _version_key(version: str) -> tuple[tuple[int, ...], int]:
    """Orderable key for a pinned version: (release, phase).

    The release tuple drops trailing zeros, so "2.13" and "2.13.0" are equal
    and multi-digit components compare numerically ("2.13.0" > "2.3.1").
    A local tag ("+cpu") is ignored. The phase places a pre-release or dev
    build (rc1, a1, b2, .dev0, or any other unrecognised suffix) BELOW the
    final release, because the advisory ranges are "< floor" and those builds
    predate the fix; a post-release (.post1) sorts above it.
    """
    public = version.split("+", 1)[0].strip().lower()
    m = _RELEASE.match(public)
    if not m:
        return ((), -1)
    release = [int(p) for p in m.group(1).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    suffix = m.group(2).lstrip(".-_")
    if not suffix:
        phase = 0
    elif suffix.startswith(("post", "rev")) or re.fullmatch(r"r\d*", suffix):
        phase = 1
    else:
        phase = -1
    return (tuple(release), phase)


def _parse_pins(text: str) -> tuple[dict[str, str], list[str]]:
    """Return ({normalized name: pinned version}, [non-== requirement lines])."""
    pins: dict[str, str] = {}
    unpinned: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _PIN.match(line)
        if m:
            pins[m.group(1).lower().replace("_", "-")] = m.group(2)
        else:
            unpinned.append(line)
    return pins, unpinned


def _floor_violations(text: str) -> list[str]:
    pins, unpinned = _parse_pins(text)
    problems = []
    for name, (floor, advisory) in SECURITY_FLOORS.items():
        if name not in pins:
            loose = [u for u in unpinned if u.lower().startswith(name)]
            what = f"not ==-pinned ({loose[0]!r})" if loose else "missing"
            problems.append(f"{name} {what}; floor {floor} ({advisory})")
            continue
        if _version_key(pins[name]) < _version_key(floor):
            problems.append(f"{name} {pins[name]} < {floor} ({advisory})")
    return problems


class RequirementsSecurityFloorTest(unittest.TestCase):
    def test_pins_are_at_or_above_their_security_floor(self):
        problems = _floor_violations(REQUIREMENTS.read_text())
        self.assertEqual(
            problems,
            [],
            "services/nli/requirements.txt pins a package below its security "
            "floor: " + "; ".join(problems),
        )

    def test_checker_rejects_a_low_missing_or_loose_pin(self):
        # The guard itself must not pass vacuously: a low pin, a deleted line
        # and a range specifier are each reported.
        problems = _floor_violations(
            "fastapi==0.111.0\n"
            "uvicorn[standard]==0.30.1\n"
            "torch==2.12.1  # one release short\n"
            "transformers>=5.10.0\n"
        )
        self.assertEqual(
            problems,
            [
                "torch 2.12.1 < 2.13.0 (CVE-2025-3000)",
                "transformers not ==-pinned ('transformers>=5.10.0'); floor "
                "5.10.0 (CVE-2026-9856)",
                "sentencepiece missing; floor 0.2.1 (CVE-2026-1260)",
            ],
        )

    def test_version_key_orders_multi_digit_components(self):
        # 2.13.0 must sort above 2.3.1 (a string compare gets this wrong).
        self.assertLess(_version_key("2.3.1"), _version_key("2.13.0"))
        self.assertLess(_version_key("4.41.2"), _version_key("5.10.0"))
        self.assertEqual(_version_key("2.13.0"), _version_key("2.13"))

    def test_pre_release_of_a_floor_is_below_the_floor(self):
        # A pre-release or dev build of the floor version predates the fix
        # (the advisory ranges are "< floor"), so it must be reported.
        problems = _floor_violations(
            "torch==2.13.0\n"
            "transformers==5.10.0rc1\n"
            "sentencepiece==0.2.1.dev0\n"
        )
        self.assertEqual(
            problems,
            [
                "transformers 5.10.0rc1 < 5.10.0 (CVE-2026-9856)",
                "sentencepiece 0.2.1.dev0 < 0.2.1 (CVE-2026-1260)",
            ],
        )

    def test_local_and_post_releases_of_a_floor_satisfy_it(self):
        # A local build tag (the CPU wheel index publishes torch==2.13.0+cpu)
        # and a post-release are the fixed release, not earlier than it.
        self.assertEqual(
            _floor_violations(
                "torch==2.13.0+cpu\n"
                "transformers==5.10.0.post1\n"
                "sentencepiece==0.2.1\n"
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
