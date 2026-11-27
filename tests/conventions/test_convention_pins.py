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
    pattern,
    read,
    section_span,
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
                n = len(pattern(pin.section_start).findall(read(pin)))
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
                self.assertTrue(mutated != original, f"{pin.id}: deletion changed nothing")
                self.assertIsNotNone(check(pin, mutated), f"{pin.id} passed with its needle deleted")

    def test_every_pin_fails_with_its_needle_outside_its_section(self):
        for pin in PINS:
            with self.subTest(pin=pin.id):
                # Prepended: above the first heading, outside every section.
                moved = pin.needle + "\n\n" + delete_needle(read(pin), pin.needle)
                self.assertIsNotNone(check(pin, moved), f"{pin.id} passed with its needle moved out")

    def test_every_pin_fails_without_its_section(self):
        for pin in PINS:
            with self.subTest(pin=pin.id):
                text = pattern(pin.section_start).sub("", read(pin))
                self.assertIsNotNone(check(pin, text), f"{pin.id} passed with no section")

    def test_every_heading_pin_fails_with_a_heading_inserted_above_its_needle(self):
        # A new section inserted between the pinned heading and the needle
        # moves the needle out of the pinned section; the pin must notice.
        for pin in PINS:
            if pin.section_end is not None:
                continue
            with self.subTest(pin=pin.id):
                text = read(pin)
                i, j = section_span(text, pin.section_start, pin.section_end)
                m = pattern(pin.needle).search(text, i, j)
                self.assertIsNotNone(m, f"{pin.id}: needle not in its section")
                level = pin.section_start.split()[0]
                inserted = text[: m.start()] + f"\n\n{level} Inserted section\n\n" + text[m.start() :]
                self.assertIsNotNone(check(pin, inserted), f"{pin.id} passed with a heading above its needle")


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
