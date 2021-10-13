# -*- coding: utf-8 -*-
##
##
#
# Start the nmap scan and wait for it to complete.
# Then format the resonse and send the data back to the server
#
import subprocess
import os
import json
import csv
from sammaParser import logger, endThis




def start_scan():
    '''
    Start the nmap scan of the target
    '''
    tuning = False
    try:
        tuning = format(os.environ['TUNING'])
    except:
        pass

    port = 443
    try:
        port = format(os.environ['PORT'])
    except:
        pass    
    
    print('Using the tuning of {0} and port {1}'.format(tuning,port,))

    if tuning:
        process = subprocess.Popen('sudo nikto -h {0}  -p {1} -Tuning {2}  -Display V  -output /out/niktoscan.csv'.format(os.environ['TARGET'],port,tuning) , shell=True, universal_newlines=True,stdout=subprocess.PIPE)
        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line) 
        return_code = process.wait()
    else:
        process = subprocess.Popen('sudo nikto -h {0}  -p {1}  -Display V  -output /out/niktoscan.csv'.format(os.environ['TARGET'],port,tuning) , shell=True, universal_newlines=True,stdout=subprocess.PIPE)
        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line)
        return_code = process.wait()
    
    
    print("Scanning done")


def convert_output():
    '''
    Converts the output to json
    '''
    
    with open('/out/niktoscan.csv') as csvfile:
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



#Start the scan and get the output
start_scan()
convert_output()
endThis()