import os
import json
import asyncio
import uuid

WRITE_TO_FILE = os.getenv('WRITE_TO_FILE', 'False')
PARSER        = os.getenv('PARSER', 'nikto')
NATS_ENABLED  = os.getenv('NATS_ENABLED', 'False')
NATS_URL      = os.getenv('NATS_URL', 'nats://localhost:4222')
NATS_SUBJECT  = os.getenv('NATS_SUBJECT', 'scans')
TARGET_ID     = os.getenv('TARGET_ID', '')
SCAN_ID       = str(uuid.uuid4())



#if we want to write to file lets set it up
if WRITE_TO_FILE != "False":
    f = open("/out/{}.json".format(PARSER), "a")




def WriteToFile(json_data):
    '''
    Write content into file
    '''
    json.dump(json_data, f, ensure_ascii=False, sort_keys=True, separators=(',', ': '))
    f.write("\n")

def endThis():
    '''
    When the scan is done we want to end all of this in a nice way.

    - first we send a log to put logger so we get a mark in the files that we are done
    - then we write to the file /out/die -- this tells other services to also shut down
    '''
    logger({"event": "scanner_stop"})
    logger({"scan": "done"})
    f = open("/out/die", "w")
    f.write("time to die")
    f.close()

async def _nats_publish(payload: bytes):
    import nats
    nc = await nats.connect(NATS_URL)
    await nc.publish(NATS_SUBJECT, payload)
    await nc.drain()

def logger(json_data):
    '''
    This is where we parse our json and

    - Add json data from the deployment
    - Send data to samma.io
    - Print out the data in json format
    '''
    # Samma tags
    json_samma = {}
    json_samma['scanner']   = os.getenv('SAMMA_IO_SCANNER', 'nikto')
    json_samma['id']        = os.getenv('SAMMA_IO_ID', '1234')
    json_samma['target_id'] = TARGET_ID
    json_samma['scan_id']   = SCAN_ID
    _tags_raw = os.getenv('SAMMA_IO_TAGS', 'scanner')
    json_samma['tags'] = [t.strip() for t in _tags_raw.split(',') if t.strip()]
    json_samma['json'] = os.getenv('SAMMA_IO_JSON', '{}')

    #Adding the extra data
    json_data['samma-io'] = json_samma

    #If WRITE_TO_FILE != False
    if WRITE_TO_FILE != "False":
        WriteToFile(json_data)

    if NATS_ENABLED != "False":
        payload = json.dumps(json_data, ensure_ascii=False,
                             sort_keys=True, separators=(',', ': ')).encode()
        asyncio.run(_nats_publish(payload))

    print(json_data)

# Emit scanner_start lifecycle event when module is imported
logger({"event": "scanner_start"})
