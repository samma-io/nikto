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


def convert_output():
    '''
    Converts the output to json
    '''

    with open(OUTPUT_FILE) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            if row[0].startswith("Nikto"):
                pass
            else:
                try:
                    json_data ={
                        "host":row[0],
                        "target":os.environ['TARGET'],
                        "type":"Nikto",
                        "ip":row[1],
                        "port":row[2],
                        "OSVDB":row[3],
                        "request": row[4],
                        "nikto_url": row[5],
                        "finding": row[6]
                    }
                    logger(json_data)
                except:
                        json_data ={
                        "host":row[0],
                        "target":os.environ['TARGET'],
                        "type":"Nikto",
                        "ip":row[1],
                        "port":row[1],
                        "OSVDB":row[2],
                        "request": row[3],
                        "nikto_url": row[4],
                        "finding": row[5]
                        }
                        logger(json_data)



if __name__ == '__main__':
    #Refuse a bad target before anything runs, then scan and get the output
    target = require_valid_target()
    start_scan(target)
    convert_output()
    endThis()
