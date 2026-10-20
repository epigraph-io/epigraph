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


def _version_key(version: str) -> tuple[int, ...]:
    """Numeric release tuple ("2.13.0" -> (2, 13, 0)).

    Only the leading numeric release segment is compared; the floors are all
    final releases, and a pre-release of a floor version is treated as equal to
    it (the parser stops at the first non-numeric component).
    """
    parts = []
    for piece in version.split("."):
        m = re.match(r"\d+", piece)
        if not m:
            break
        parts.append(int(m.group(0)))
        if m.end() != len(piece):
            break
    return tuple(parts)


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
        self.assertEqual(_version_key("2.13.0"), (2, 13, 0))


if __name__ == "__main__":
    unittest.main()
