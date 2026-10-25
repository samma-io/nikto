"""Tests for the CSV parsing in code/scan.py (issue #6).

Run from the repository root:

    python3 -m unittest discover -s tests -t .
"""

import csv
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.join(os.path.dirname(HERE), "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

import scan  # noqa: E402

# Lines from the report nikto 2.1.5 (Ubuntu 24.04) wrote in the CI smoke scan
# of a local nginx (TARGET=web, PORT=80). The finding line has the broken
# ip/port column.
HEADER_LINE = '"Nikto - v2.1.5/2.1.5"'
BANNER_LINE = '"web","172.18.0.2","80","","","","nginx/1.27.5"'
BROKEN_LINE = ('"web","172.18.0.2"SCALAR(0x5a381367a570)80","OSVDB-0","GET","/",'
               '"The anti-clickjacking X-Frame-Options header is not present."')
GOOD_LINE = '"web","172.18.0.2","80","OSVDB-3092","GET","/admin/","This might be interesting."'


def row(line):
    return next(csv.reader([line]))


class ParseRowTests(unittest.TestCase):
    def test_broken_column_is_what_the_old_parser_saw(self):
        self.assertEqual(row(BROKEN_LINE)[1], '172.18.0.2SCALAR(0x5a381367a570)80"')
        self.assertEqual(len(row(BROKEN_LINE)), 6)

    def test_broken_line_gets_a_clean_ip_and_port(self):
        self.assertEqual(scan.parse_row(row(BROKEN_LINE), "web", "80"), {
            "host": "web",
            "target": "web",
            "type": "Nikto",
            "ip": "172.18.0.2",
            "port": "80",
            "OSVDB": "OSVDB-0",
            "request": "GET",
            "nikto_url": "/",
            "finding": "The anti-clickjacking X-Frame-Options header is not present.",
        })

    def test_good_line_is_unchanged(self):
        record = scan.parse_row(row(GOOD_LINE), "web", "80")
        self.assertEqual((record["ip"], record["port"], record["OSVDB"], record["request"],
                          record["nikto_url"], record["finding"]),
                         ("172.18.0.2", "80", "OSVDB-3092", "GET", "/admin/", "This might be interesting."))

    def test_banner_line(self):
        record = scan.parse_row(row(BANNER_LINE), "web", "80")
        self.assertEqual((record["ip"], record["port"], record["OSVDB"], record["finding"]),
                         ("172.18.0.2", "80", "", "nginx/1.27.5"))

    def test_header_and_empty_rows_are_skipped(self):
        self.assertIsNone(scan.parse_row(row(HEADER_LINE), "web", "80"))
        self.assertIsNone(scan.parse_row([], "web", "80"))
        self.assertIsNone(scan.parse_row([""], "web", "80"))

    def test_unparseable_column_falls_back_to_target_and_port(self):
        record = scan.parse_row(["web", "garbage SCALAR(oops)", "OSVDB-1", "GET", "/", "x"], "web", "8080")
        self.assertEqual((record["ip"], record["port"], record["OSVDB"]), ("web", "8080", "OSVDB-1"))

    def test_port_list_is_never_copied_into_a_record(self):
        record = scan.parse_row(["web", "junk", "OSVDB-1", "GET", "/", "x"], "web", "80,443")
        self.assertEqual(record["port"], "")
        record = scan.parse_row(["web", "1.2.3.4", "junk", "OSVDB-1", "GET", "/", "x"], "web", "80,443")
        self.assertEqual((record["ip"], record["port"]), ("1.2.3.4", ""))

    def test_ipv6_in_broken_column(self):
        record = scan.parse_row(row('"h","2001:db8::1"SCALAR(0xabc)443","OSVDB-0","GET","/","x"'), "h", "443")
        self.assertEqual((record["ip"], record["port"]), ("2001:db8::1", "443"))


class ConvertOutputTests(unittest.TestCase):
    def test_every_record_has_clean_ip_and_port(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as handle:
            handle.write("\n".join([HEADER_LINE, BANNER_LINE, BROKEN_LINE, GOOD_LINE]) + "\n")
            path = handle.name
        self.addCleanup(os.unlink, path)
        with mock.patch.object(scan, "logger") as logger:
            scan.convert_output("web", "80", path=path)
        records = [call.args[0] for call in logger.call_args_list]
        self.assertEqual(len(records), 3)
        for record in records:
            self.assertEqual((record["ip"], record["port"], record["type"]), ("172.18.0.2", "80", "Nikto"))


if __name__ == "__main__":
    unittest.main()
