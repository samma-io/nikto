"""Check the TARGET, PORT and TUNING environment variables before nikto runs.

The target is passed to nikto as its own argv element, so a shell never sees
it. This check is the second line of defence: it refuses anything that is not
a plain DNS hostname or an IP address, which is also what the samma operator
accepts in Scanner.spec.target. No third-party imports.
"""

import ipaddress
import os
import re
import sys

_LABEL = r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?"
_HOSTNAME = r"{label}(\.{label})*".format(label=_LABEL)
_OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_IPV4 = r"({octet}\.){{3}}{octet}".format(octet=_OCTET)
_IPV6 = r"[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}"

# Same expression as the operator's target_policy.TARGET_PATTERN.
TARGET_PATTERN = "^({0}|{1}|{2})$".format(_HOSTNAME, _IPV4, _IPV6)
MAX_TARGET_LENGTH = 253

# nikto -p takes a port, a list ("80,443") or a range ("8000-8010").
PORT_PATTERN = r"^[0-9]{1,5}([,-][0-9]{1,5})*$"
# nikto -Tuning takes a string of test type codes: 0-9, a-e and x.
TUNING_PATTERN = r"^[0-9a-ex]{1,16}$"

_TARGET_RE = re.compile(TARGET_PATTERN)
# Digits, dots and hyphens only: legal DNS syntax, but nmap-style ranges such
# as "10.0.0.1-254" look like that too, so such a string must be one address.
_NUMERIC_RE = re.compile(r"[0-9.-]+")
_PORT_RE = re.compile(PORT_PATTERN)
_TUNING_RE = re.compile(TUNING_PATTERN)


class InvalidTarget(ValueError):
    """The value must not reach the scanner. The message says why."""


def validate_target(target):
    """Raise InvalidTarget unless target is a hostname or an IP literal."""
    if not isinstance(target, str):
        raise InvalidTarget("TARGET must be a string")
    if target == "":
        raise InvalidTarget("TARGET is empty")
    if len(target) > MAX_TARGET_LENGTH:
        raise InvalidTarget("TARGET is longer than {0} characters".format(MAX_TARGET_LENGTH))
    if "*" in target:
        raise InvalidTarget("TARGET {0!r} is a wildcard".format(target))
    if _TARGET_RE.fullmatch(target) is None:
        raise InvalidTarget(
            "TARGET {0!r} is not a DNS hostname (lowercase labels, no scheme, no path) "
            "or an IPv4/IPv6 address".format(target)
        )
    if ":" in target:
        try:
            ipaddress.IPv6Address(target)
        except ValueError:
            raise InvalidTarget("TARGET {0!r} is not a valid IPv6 address".format(target))
    if _NUMERIC_RE.fullmatch(target) is not None:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise InvalidTarget(
                "TARGET {0!r} looks like an IPv4 address or range but is not one address".format(target)
            )


def validate_port(port):
    """Raise InvalidTarget unless port is a number, a list or a range of numbers."""
    if _PORT_RE.fullmatch(str(port)) is None:
        raise InvalidTarget("PORT {0!r} is not a port number, list or range".format(port))


def validate_tuning(tuning):
    """Raise InvalidTarget unless tuning is a string of nikto tuning codes."""
    if _TUNING_RE.fullmatch(str(tuning)) is None:
        raise InvalidTarget("TUNING {0!r} is not a string of nikto tuning codes".format(tuning))


def _write_die(die_file):
    """Best effort: tell a sidecar that reads /out/die that the scan is over."""
    if not die_file:
        return
    try:
        with open(die_file, "w") as handle:
            handle.write("time to die")
    except OSError:
        pass


def require_valid_target(environ=os.environ, die_file="/out/die"):
    """Return the validated TARGET or exit with status 2 and a message."""
    target = environ.get("TARGET", "")
    try:
        validate_target(target)
    except InvalidTarget as exc:
        print("Refusing to scan: {0}".format(exc), file=sys.stderr)
        _write_die(die_file)
        sys.exit(2)
    return target
