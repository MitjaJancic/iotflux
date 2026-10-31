"""Tests for the human-facing command surface (family/verb CLI)."""

import unittest
from argparse import Namespace

from iotflux.core import commands


class TestArgTypes(unittest.TestCase):
    def test_duration_units(self) -> None:
        self.assertEqual(commands.duration("30"), 30)
        self.assertEqual(commands.duration("30s"), 30)
        self.assertEqual(commands.duration("5m"), 300)
        self.assertEqual(commands.duration("2h"), 7200)

    def test_duration_rejects_junk(self) -> None:
        with self.assertRaises(ValueError):
            commands.duration("banana")

    def test_address_accepts_host_and_hostport(self) -> None:
        self.assertEqual(commands.address("10.0.0.1"), "10.0.0.1")
        self.assertEqual(commands.address("10.0.0.1:80"), "10.0.0.1:80")

    def test_address_rejects_bad_port(self) -> None:
        with self.assertRaises(ValueError):
            commands.address("10.0.0.1:http")

    def test_split_address_uses_default_port(self) -> None:
        self.assertEqual(commands.split_address("10.0.0.1", 80), ("10.0.0.1", 80))
        self.assertEqual(commands.split_address("10.0.0.1:8080", 80), ("10.0.0.1", 8080))


class TestReorder(unittest.TestCase):
    def test_address_before_verb_is_moved(self) -> None:
        self.assertEqual(
            commands.reorder(["shelly", "10.0.0.1:80", "config"]),
            ["shelly", "config", "10.0.0.1:80"],
        )

    def test_flags_are_preserved(self) -> None:
        self.assertEqual(
            commands.reorder(["shelly", "10.0.0.1", "schedule", "--in", "30s"]),
            ["shelly", "schedule", "10.0.0.1", "--in", "30s"],
        )

    def test_single_verb_family_gets_the_verb_inserted(self) -> None:
        self.assertEqual(
            commands.reorder(["spray", "10.0.0.1:80", "--digest"]),
            ["spray", "run", "10.0.0.1:80", "--digest"],
        )

    def test_already_ordered_is_untouched(self) -> None:
        argv = ["shelly", "config", "10.0.0.1"]
        self.assertEqual(commands.reorder(argv), argv)

    def test_unknown_family_is_untouched(self) -> None:
        argv = ["run", "exploit/shelly_control", "-t", "10.0.0.1"]
        self.assertEqual(commands.reorder(argv), argv)


class TestResolve(unittest.TestCase):
    def test_verb_maps_to_module_and_fixed_options(self) -> None:
        args = Namespace(family="shelly", verb="config", target="10.0.0.1:80")
        module, options, target, port = commands.resolve(args)
        self.assertEqual(module, "exploit/shelly_control")
        self.assertEqual(options["ACTION"], "config")
        self.assertEqual(target, "10.0.0.1")
        self.assertEqual(port, 80)

    def test_verb_can_override_the_module(self) -> None:
        args = Namespace(family="shelly", verb="schedule", target="10.0.0.1", DELAY=30, ON=True, CHANNEL=0, TIMESPEC="")
        module, options, _, _ = commands.resolve(args)
        self.assertEqual(module, "exploit/shelly_persist")
        self.assertEqual(options["ACTION"], "schedule")
        self.assertEqual(options["DELAY"], 30)
        self.assertTrue(options["ON"])

    def test_family_default_port_applies(self) -> None:
        args = Namespace(family="ha", verb="probe", target="10.0.0.1")
        _, _, _, port = commands.resolve(args)
        self.assertEqual(port, 8123)

    def test_empty_values_are_dropped(self) -> None:
        args = Namespace(family="shelly", verb="mqtt", target="10.0.0.1", BROKER="", TOPIC_PREFIX="shelly")
        _, options, _, _ = commands.resolve(args)
        self.assertNotIn("BROKER", options)
        self.assertEqual(options["TOPIC_PREFIX"], "shelly")


class TestSurface(unittest.TestCase):
    def test_every_verb_resolves_to_a_real_module(self) -> None:
        from iotflux.modules import MODULE_REGISTRY

        for family, spec in commands.FAMILIES.items():
            for verb, vspec in spec["verbs"].items():
                module = vspec.get("module", spec["module"])
                self.assertIn(module, MODULE_REGISTRY, f"{family} {verb} -> {module}")

    def test_every_verb_has_help(self) -> None:
        for family, spec in commands.FAMILIES.items():
            for verb, vspec in spec["verbs"].items():
                self.assertTrue(vspec.get("help"), f"{family} {verb} has no help")

    def test_family_listing_is_non_empty(self) -> None:
        self.assertIn("shelly", commands.list_families())

    def test_completion_mentions_families(self) -> None:
        self.assertIn("shelly", commands.completion_script())


if __name__ == "__main__":
    unittest.main()
