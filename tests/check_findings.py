"""Check the finding records in a scanner log (CI smoke test).

Every line of the log that is a finding record (a printed dict with
'type': 'Nikto') must have an `ip` that is a plain IP address or hostname and
a numeric `port`. Exits 1 and prints the bad records otherwise, or when the
log holds no finding at all.

    python3 tests/check_findings.py nikto.log
"""

import ast
import ipaddress
import re
import sys

_HOST_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$")
_PORT_RE = re.compile(r"^[0-9]{1,5}$")


def clean_ip(value):
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return _HOST_RE.fullmatch(value) is not None


def clean_port(value):
    return isinstance(value, str) and _PORT_RE.fullmatch(value) is not None and 0 < int(value) < 65536


def findings(lines):
    for line in lines:
        line = line.strip()
        if not line.startswith("{") or "'type': 'Nikto'" not in line:
            continue
        try:
            record = ast.literal_eval(line)
        except (ValueError, SyntaxError):
            continue
        if isinstance(record, dict) and record.get("type") == "Nikto":
            yield record


def main(path):
    with open(path, errors="replace") as handle:
        records = list(findings(handle))
    bad = [r for r in records if not (clean_ip(r.get("ip")) and clean_port(r.get("port")))]
    print("{0} finding records, {1} with a bad ip or port".format(len(records), len(bad)))
    for record in bad:
        print("bad: ip={0!r} port={1!r} finding={2!r}".format(record.get("ip"), record.get("port"), record.get("finding")))
    return 0 if records and not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
