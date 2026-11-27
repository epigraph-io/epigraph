"""Every convention pin holds, can fail, and names its incident.

See `convention_pins.py` for what a pin is and how to add one. Standard
library only, no database and no network.
"""

import unittest

from .convention_pins import (
    INCIDENT_ID,
    PINS,
    REPO,
    check,
    delete_needle,
    normalize,
    read,
)


class ConventionPinsHold(unittest.TestCase):
    def test_every_needle_sits_inside_its_section(self):
        for pin in PINS:
            with self.subTest(pin=pin.id):
                self.assertTrue((REPO / pin.file).is_file(), f"{pin.id}: {pin.file} is missing")
                self.assertIsNone(check(pin, read(pin)))

    def test_every_section_start_is_unique(self):
        # A start that occurs twice would let a pin bind to the wrong section.
        for pin in PINS:
            with self.subTest(pin=pin.id):
                n = normalize(read(pin)).count(normalize(pin.section_start))
                self.assertEqual(n, 1, f"{pin.id}: {pin.section_start!r} occurs {n} times")


class ConventionPinsCanFail(unittest.TestCase):
    """Mutation self-tests: a pin that cannot fail pins nothing."""

    def test_every_pin_fails_with_its_needle_deleted(self):
        for pin in PINS:
            with self.subTest(pin=pin.id):
                original = read(pin)
                mutated = delete_needle(original, pin.needle)
                # A needle that matched nothing would make the mutation a no-op
                # and this test vacuous.
                self.assertTrue(mutated != normalize(original), f"{pin.id}: deletion changed nothing")
                self.assertIsNotNone(check(pin, mutated), f"{pin.id} passed with its needle deleted")

    def test_every_pin_fails_with_its_needle_outside_its_section(self):
        for pin in PINS:
            with self.subTest(pin=pin.id):
                moved = delete_needle(read(pin), pin.needle) + " " + pin.needle
                self.assertIsNotNone(check(pin, moved), f"{pin.id} passed with its needle moved out")

    def test_every_pin_fails_without_its_section(self):
        for pin in PINS:
            with self.subTest(pin=pin.id):
                text = normalize(read(pin)).replace(normalize(pin.section_start), "")
                self.assertIsNotNone(check(pin, text), f"{pin.id} passed with no section")


class ConventionPinsCiteIncidents(unittest.TestCase):
    def test_every_pin_names_an_incident_id(self):
        for pin in PINS:
            with self.subTest(pin=pin.id):
                self.assertRegex(pin.incident, INCIDENT_ID)

    def test_pin_ids_are_unique(self):
        ids = [pin.id for pin in PINS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_registry_is_not_empty(self):
        self.assertGreaterEqual(len(PINS), 3)


if __name__ == "__main__":
    unittest.main()
