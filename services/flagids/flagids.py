#!/bin/env python
import os
import time
from datetime import datetime

import psycopg_pool
import requests

DELAY = 5  # DELAY from start of tick
tick_length = int(os.getenv("TICK_LENGTH", 10 * 1000)) // 1000
start_date = os.getenv("TICK_START", "2018-06-27T13:00+02:00")
team_id = os.getenv("TEAM_ID", "10.10.3.1")
team_id_is_digit = team_id.isdigit()
team_id_int = int(team_id) if team_id_is_digit else None
flagid_endpoint = os.getenv("FLAGID_ENDPOINT", "http://localhost:8000/flagids.json")
flagid_scrape_enabled = os.getenv("FLAGID_SCRAPE", "") != ""

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

def extract_team_flag_ids(data: dict):
    # Traverse all the flagstores
    for flagstore in data:
        # Traverse ticks of flagstore
        flagIdsForServiceOfOwnTeam = data[flagstore][team_id]
        for tick in flagIdsForServiceOfOwnTeam:
            # Get all flagid values
            elem = flagIdsForServiceOfOwnTeam[tick]

            if type(elem) is dict:
                for key in elem:
                    yield str(elem[key]), flagstore
            elif type(elem) in (list, tuple):
                for flagid in elem:
                    yield str(flagid), flagstore
            else:
                yield str(elem)


def update_flagids():
    assert db is not None

    # Fetch data
    response = requests.get(flagid_endpoint)
    rows = [(flagId, flagStore) for (flagId, flagStore) in extract_team_flag_ids(response.json())]
    print("Updating flagids: ", time.time(), f"({len(rows)})", flush=True)

    # Insert into the database
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.executemany("INSERT INTO flag_id (content, flagstore) VALUES (%s, %s) ON CONFLICT DO NOTHING", rows)
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

            print("Sleeping:", wait, flush=True)
            time.sleep(wait)

        except Exception as e:
            print("ERROR: ", e, flush=True)
            time.sleep(10)


if __name__ == "__main__":
    main()
