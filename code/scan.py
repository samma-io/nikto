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


def nikto_command(target, port, tuning=None):
    '''
    Build the nikto argv list.

    Every value is its own argument, so nothing in TARGET, PORT or TUNING is
    ever interpreted by a shell. sudo stays because the image runs as the
    samma user with a sudoers rule for nikto.
    '''
    command = ['sudo', 'nikto', '-h', target, '-p', str(port)]
    if tuning:
        command += ['-Tuning', str(tuning)]
    command += ['-Display', 'V', '-output', OUTPUT_FILE]
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
