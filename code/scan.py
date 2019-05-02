# -*- coding: utf-8 -*-
##
##
#
# Start the nmap scan and wait for it to complete.
# Then format the resonse and send the data back to the server
#
import subprocess
import os
import xmltodict, json
import csv




def start_scan():
    '''
    Start the nmap scan of the target
    '''
    process = subprocess.Popen('nikto -h {0}  -p {1} -C all  -output /niktoscan.csv'.format(os.environ['TARGET'],"80,443") , shell=True, stdout=subprocess.PIPE)
    for stdout_line in iter(process.stdout.readline, ""):
        print(stdout_line) 
    process.stdout.close()
    return_code = process.wait()
    if return_code:
        raise subprocess.CalledProcessError(return_code, cmd) 



def convert_output():
    '''
    Converts the output to json
    '''
    with open('/niktoscan.csv') as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            print(row)
            print(row[0])
            print(row[0],row[1],row[2],)


#Start the scan and get the output
start_scan()
convert_output()