# -*- coding: utf-8 -*-
##
##
#
# Start the nikto scan and wait for it to complete.
# Then format the resonse and send the data back to the server
#
import subprocess
import os
import sys
import json
import csv
import ipaddress
import re
from sammaParser import logger, endThis
from target_check import InvalidTarget, require_valid_target, validate_port, validate_tuning

OUTPUT_FILE = '/out/niktoscan.csv'
NIKTO = 'nikto'
# Set to 1 (or true, yes, on) to run the old `sudo nikto` command. Off by
# default: nikto is a perl HTTP scanner and needs no privileges, and the
# samma operator runs scanner pods with allowPrivilegeEscalation false, where
# sudo cannot work. The published image has no sudo; see the README.
SUDO_ENV_VAR = 'NIKTO_USE_SUDO'
_TRUE_VALUES = frozenset(['1', 'true', 'yes', 'on'])


def use_sudo(environ=None):
    '''True when NIKTO_USE_SUDO is set to 1, true, yes or on.'''
    if environ is None:
        environ = os.environ
    return environ.get(SUDO_ENV_VAR, '').strip().lower() in _TRUE_VALUES


def nikto_command(target, port, tuning=None, environ=None):
    '''
    Build the nikto argv list.

    nikto runs directly as the user the container runs as (samma in the
    image). It needs no privileges, so there is no sudo in front of it and
    the pod needs no privilege escalation. NIKTO_USE_SUDO=1 puts sudo back
    for an image that has sudo and a sudoers rule for nikto; the flags, the
    output file and its parsing are the same in both cases.

    Every value is its own argument, so nothing in TARGET, PORT or TUNING is
    ever interpreted by a shell.
    '''
    command = [NIKTO, '-h', target, '-p', str(port)]
    if tuning:
        command += ['-Tuning', str(tuning)]
    command += ['-Display', 'V', '-output', OUTPUT_FILE]
    if use_sudo(environ):
        command = ['sudo'] + command
    return command


def start_scan(target):
    '''
    Start the nikto scan of the target
    '''
    tuning = os.environ.get('TUNING') or False
    port = os.environ.get('PORT') or 443

    try:
        validate_port(port)
        if tuning:
            validate_tuning(tuning)
    except InvalidTarget as exc:
        print("Refusing to scan: {0}".format(exc), file=sys.stderr)
        sys.exit(2)

    print('Using the tuning of {0} and port {1}'.format(tuning, port))

    process = subprocess.Popen(nikto_command(target, port, tuning), universal_newlines=True, stdout=subprocess.PIPE)
    for stdout_line in iter(process.stdout.readline, ""):
        print(stdout_line)
    return_code = process.wait()

    print("Scanning done")


# nikto 2.1.5 (Ubuntu's package) writes the ip and port of a finding as one
# broken CSV column, e.g. `"172.18.0.2"SCALAR(0x5a381367a570)80"`, which the
# csv module reads as `172.18.0.2SCALAR(0x5a381367a570)80"`. The row then has
# six columns instead of seven. This pulls the address and the port back out.
_BROKEN_IP_PORT_RE = re.compile(r'^"?(?P<ip>[0-9A-Za-z.:-]+?)"?SCALAR\(0x[0-9a-fA-F]+\)"?(?P<port>[0-9]{1,5})"?$')
_PORT_RE = re.compile(r'^[0-9]{1,5}$')


def _clean_ip(value, target):
    '''The ip column if it is a plain IP address, else the scan target.'''
    value = (value or '').strip().strip('"')
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return target


def _clean_port(value, port):
    '''The port column if it is a port number, else the scanned PORT when it is one port.'''
    value = (value or '').strip().strip('"')
    if _PORT_RE.fullmatch(value):
        return value
    port = str(port).strip()
    return port if _PORT_RE.fullmatch(port) else ''


def parse_row(row, target, port):
    '''
    Turn one row of nikto's CSV report into a finding record, or None for a
    row that is not a finding (empty, or the "Nikto v..." header).

    A good row is host, ip, port, OSVDB, method, uri, message. nikto 2.1.5
    merges ip and port into one broken column (six columns); ip and port are
    then recovered from that column, or else taken from the validated scan
    target and port. ip is always an IP address or the target host and port
    is always a number (or empty when PORT was a list or range and the row
    did not say which).
    '''
    if not row or not row[0].strip() or row[0].startswith("Nikto"):
        return None
    if len(row) >= 7:
        ip, row_port, rest = row[1], row[2], row[3:7]
    else:
        merged = row[1] if len(row) > 1 else ''
        match = _BROKEN_IP_PORT_RE.match(merged.strip())
        ip, row_port = (match.group('ip'), match.group('port')) if match else ('', '')
        rest = (row[2:] + [''] * 4)[:4]
    return {
        "host": row[0],
        "target": target,
        "type": "Nikto",
        "ip": _clean_ip(ip, target),
        "port": _clean_port(row_port, port),
        "OSVDB": rest[0],
        "request": rest[1],
        "nikto_url": rest[2],
        "finding": rest[3],
    }


def convert_output(target=None, port=None, path=OUTPUT_FILE):
    '''
    Converts the output to json
    '''
    if target is None:
        target = os.environ['TARGET']
    if port is None:
        port = os.environ.get('PORT') or 443
    with open(path) as csvfile:
        for row in csv.reader(csvfile, delimiter=','):
            json_data = parse_row(row, target, port)
            if json_data is not None:
                logger(json_data)


if __name__ == '__main__':
    #Refuse a bad target before anything runs, then scan and get the output
    target = require_valid_target()
    start_scan(target)
    convert_output(target)
    endThis()
