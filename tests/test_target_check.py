"""Tests for code/target_check.py and the argv built by code/scan.py.

Run from the repository root:

    python3 -m unittest discover -s tests -t .
"""

import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(HERE)
CODE_DIR = os.path.join(REPO_DIR, "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

import target_check as tc  # noqa: E402

try:
    import scan  # noqa: E402  (imports sammaParser, standard library only)
except ImportError:  # pragma: no cover
    scan = None

ACCEPTED = [
    "example.com",
    "www.example.com",
    "localhost",
    "my-host-1.example.org",
    "1.2.3.4",
    "2001:db8::1",
    "::1",
    "a" * 63 + ".example",
]

REJECTED = [
    "",
    "*.example.com",
    "https://example.com",
    "example.com/path",
    "example.com:443",
    "example.com; id",
    "example.com && curl evil",
    "example.com|id",
    "$(id)",
    "`id`",
    "exa mple.com",
    "example.com\n",
    "Example.com",
    "-bad.example.com",
    "example.com.",
    "1.2.3.256",
    "10.0.0.1-254",
    "10.0.0.0/24",
    "a" * 64 + ".example",
    "x" * 254,
    "exämple.com",
    "'example.com'",
    '"example.com"',
    "2001:db8::zz",
    "1::2::3",
    "[2001:db8::1]",
    None,
]


class ValidateTargetTests(unittest.TestCase):
    def test_accepted(self):
        for target in ACCEPTED:
            with self.subTest(target=target):
                self.assertIsNone(tc.validate_target(target))

    def test_rejected(self):
        for target in REJECTED:
            with self.subTest(target=target):
                with self.assertRaises(tc.InvalidTarget):
                    tc.validate_target(target)


class PortAndTuningTests(unittest.TestCase):
    def test_ports(self):
        for port in ("443", 443, "80,443", "8000-8010", "80,443,8000-8010"):
            with self.subTest(port=port):
                tc.validate_port(port)
        for port in ("", "443; id", "443 ", "http", "443,", "-1"):
            with self.subTest(port=port):
                with self.assertRaises(tc.InvalidTarget):
                    tc.validate_port(port)

    def test_tuning(self):
        for tuning in ("23", "x", "1234567890abcde", "9"):
            with self.subTest(tuning=tuning):
                tc.validate_tuning(tuning)
        for tuning in ("", "2 3", "23;id", "F", "$(id)"):
            with self.subTest(tuning=tuning):
                with self.assertRaises(tc.InvalidTarget):
                    tc.validate_tuning(tuning)


class RequireValidTargetTests(unittest.TestCase):
    def test_returns_the_target(self):
        self.assertEqual(tc.require_valid_target({"TARGET": "example.com"}, die_file=None), "example.com")

    def test_exits_with_status_2(self):
        for environ in ({}, {"TARGET": ""}, {"TARGET": "example.com; id"}, {"TARGET": "*.example.com"}):
            with self.subTest(environ=environ):
                with self.assertRaises(SystemExit) as ctx:
                    tc.require_valid_target(environ, die_file=None)
                self.assertEqual(ctx.exception.code, 2)


NIKTO_DEFAULT = ["nikto", "-h", "example.com", "-p", "443", "-Display", "V", "-output", "/out/niktoscan.csv"]


@unittest.skipIf(scan is None, "scan.py could not be imported")
class NiktoCommandTests(unittest.TestCase):
    def test_default_command_has_no_sudo(self):
        self.assertEqual(scan.nikto_command("example.com", 443, environ={}), NIKTO_DEFAULT)

    def test_default_reads_the_process_environment(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(scan.SUDO_ENV_VAR, None)
            self.assertEqual(scan.nikto_command("example.com", 443), NIKTO_DEFAULT)
        with mock.patch.dict(os.environ, {scan.SUDO_ENV_VAR: "1"}):
            self.assertEqual(scan.nikto_command("example.com", 443), ["sudo"] + NIKTO_DEFAULT)

    def test_tuning_is_added_before_display(self):
        self.assertEqual(
            scan.nikto_command("example.com", "8443", "23", environ={}),
            ["nikto", "-h", "example.com", "-p", "8443", "-Tuning", "23", "-Display", "V", "-output", "/out/niktoscan.csv"],
        )

    def test_sudo_escape_hatch_restores_the_old_command(self):
        for value in ("1", "true", "TRUE", "yes", "on", " 1 "):
            with self.subTest(value=value):
                self.assertEqual(
                    scan.nikto_command("example.com", 443, environ={"NIKTO_USE_SUDO": value}),
                    ["sudo"] + NIKTO_DEFAULT,
                )
        self.assertEqual(
            scan.nikto_command("example.com", "8443", "23", environ={"NIKTO_USE_SUDO": "1"}),
            ["sudo", "nikto", "-h", "example.com", "-p", "8443", "-Tuning", "23", "-Display", "V", "-output", "/out/niktoscan.csv"],
        )

    def test_escape_hatch_is_off_for_other_values(self):
        for value in ("", "0", "false", "no", "off", "sudo"):
            with self.subTest(value=value):
                self.assertEqual(scan.nikto_command("example.com", 443, environ={"NIKTO_USE_SUDO": value}), NIKTO_DEFAULT)
                self.assertFalse(scan.use_sudo({"NIKTO_USE_SUDO": value}))

    def test_values_stay_single_arguments(self):
        # Even a hostile value is one argv element; there is no shell to split it.
        for environ, length in (({}, 11), ({"NIKTO_USE_SUDO": "1"}, 12)):
            with self.subTest(environ=environ):
                command = scan.nikto_command("example.com; id", "443 && id", "2 3", environ=environ)
                self.assertIn("example.com; id", command)
                self.assertIn("443 && id", command)
                self.assertIn("2 3", command)
                self.assertEqual(len(command), length)


if __name__ == "__main__":
    unittest.main()
