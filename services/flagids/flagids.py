#!/bin/env python
import os
import time
from datetime import datetime

import psycopg_pool
import requests
import configurations

DELAY = 5  # DELAY from start of tick
tick_length = int(os.getenv("TICK_LENGTH", 10 * 1000)) // 1000
start_date = os.getenv("TICK_START", "2018-06-27T13:00+02:00")
team_id = os.getenv("TEAM_ID", "10.10.3.1")
team_id_is_digit = team_id.isdigit()
team_id_int = int(team_id) if team_id_is_digit else None
flagid_endpoint = os.getenv("FLAGID_ENDPOINT", "http://localhost:8000/flagids.json")
flagid_scrape_enabled = os.getenv("FLAGID_SCRAPE", "") != ""
flagid_parser = os.getenv("FLAGID_PARSER", "ccit")


# DICT FORMAT: { "tulipservicename": ["flagstore1", "flagstore2"] }
FLAGSTORES_MAPPINGS = {
    "Pwnzer0tt1Shop": ["Pwnzer0tt1Shop-Article", "Pwnzer0tt1Shop-User"],
    "insecure-credential-vault": ["insecure-credential-vault"],
}

#### Build lookup tables
SERVICE_PORTS_LUT = {}
SERVICE_PORTS_LUT_BACKWARDS = {}
# Lookup port in Tulip config
for item in configurations.services:
    SERVICE_PORTS_LUT[item['name']] = item['port']
    SERVICE_PORTS_LUT_BACKWARDS[item['port']] = item['name']

FLAGSTORES_PORTS_LUT = {}
for service_name, flagstores in FLAGSTORES_MAPPINGS.items():
    for store_name in flagstores:
        FLAGSTORES_PORTS_LUT[store_name] = SERVICE_PORTS_LUT.get(service_name, None)
####


client = None
db = None
if flagid_scrape_enabled:
    print("STARTING FLAGIDS")
    print("CONFIG:")
    print("  DELAY: ", DELAY)
    print("  TICK_LENGTH: ", tick_length)
    print("  TICK_START: ", start_date)
    print("  TIMESCALE: ", os.environ.get("TIMESCALE"))
    print("  TEAM_ID: ", team_id)
    print("  FLAGID_ENDPOINT: ", flagid_endpoint)
    db = psycopg_pool.ConnectionPool(os.environ["TIMESCALE"])
    print("CONNECTION TO DB ESTABLISHED", flush=True)
else:
    print("FLAGID SCRAPE DISABLED", flush=True)


def CCIT_flag_ids_extractor(data: dict):
    # Traverse all the flagstores
    for flagstore in data:
        port = FLAGSTORES_PORTS_LUT.get(flagstore, None)

        # Traverse ticks of flagstore
        flagIdsForServiceOfOwnTeam = data[flagstore][team_id]
        for tick in flagIdsForServiceOfOwnTeam:
            # Get all flagid values
            elem = flagIdsForServiceOfOwnTeam[tick]

            if type(elem) is dict:
                for key in elem:
                    yield str(elem[key]), flagstore, port
            elif type(elem) in (list, tuple):
                for flagid in elem:
                    yield str(flagid), flagstore, port
            else:
                yield str(elem), flagstore, port

# Dict format: { FLAGID_PARSER value: parser function }
FLAGID_PARSERS_MAP = {
    "ccit": CCIT_flag_ids_extractor,
}

def extract_team_flag_ids(data: dict):
    return FLAGID_PARSERS_MAP[flagid_parser](data)

def update_flagids():
    assert db is not None

    # Fetch data
    response = requests.get(flagid_endpoint)
    rows = list(extract_team_flag_ids(response.json()))
    # use generic labels for services with a single flagstore, and add flagstore- prefix to allow for correct
    # formatting on the frontend
    for i, (flagid, flagstore, port) in enumerate(rows):
        rows[i] = (flagid, "flagstore-" + rows[i][1], port) # ugly asf lol but its ok
        if port is None:
            continue
        service_name = SERVICE_PORTS_LUT_BACKWARDS[port]
        if len(FLAGSTORES_MAPPINGS[service_name]) == 1:
            rows[i] = (flagid, "flag-id", port)
    print("Updating flagids: ", time.time(), f"({len(rows)})", flush=True)

    # Insert into the database
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.executemany("INSERT INTO flag_id (content, flagstore, dst_port) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", rows)
            conn.commit()


def main():
    start_datetime = datetime.strptime(start_date, r"%Y-%m-%dT%H:%M:%S.%fZ")
    unixtime = start_datetime.timestamp()

    while True:
        try:
            if flagid_scrape_enabled:
                update_flagids()

            crnt_time = time.time()
            time_diff = max(0, crnt_time - unixtime)
            wait = tick_length - (time_diff % tick_length) + DELAY
            time.sleep(wait)

        except Exception as e:
            print("ERROR: ", e, flush=True)
            time.sleep(10)


if __name__ == "__main__":
    main()
