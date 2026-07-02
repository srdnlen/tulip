#!/bin/env python
import os
import time
from datetime import datetime

import psycopg_pool
import configurations

from protocols.ccit import CCITFlagIdProtocol

DELAY = 5  # DELAY from start of tick
tick_length = int(os.getenv("TICK_LENGTH", 10 * 1000)) // 1000
start_date = os.getenv("TICK_START", "2018-06-27T13:00+02:00")
team_id = os.getenv("TEAM_ID", "10.10.3.1")
team_id_is_digit = team_id.isdigit()
team_id_int = int(team_id) if team_id_is_digit else None
flagid_endpoint = os.getenv("FLAGID_ENDPOINT", "http://localhost:8000/flagids.json")
flagid_scrape_enabled = os.getenv("FLAGID_SCRAPE", "") != ""
flagid_parser = os.getenv("FLAGID_PARSER", "ccit")


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


FLAGID_PARSERS_MAP = {
    "ccit": CCITFlagIdProtocol,
}

proto = FLAGID_PARSERS_MAP[flagid_parser](flagid_endpoint)

#### Build port lookup tables with ports from the Tulip config
SERVICE_PORTS_LUT = {}
for item in configurations.services:
    SERVICE_PORTS_LUT[item["name"]] = item["port"]


def update_flagids():
    assert db is not None

    # Fetch data
    flagids = proto.get_flagids(team_id)
    flagstores_mappings = proto.get_service_flagstores_mappings()

    rows = [
        (
            fid.content,
            f"flagstore-{fid.flagstore}"
            if len(flagstores_mappings[fid.service]) > 1
            else "flagstore-flag-id",
            SERVICE_PORTS_LUT[fid.service],
        )
        for fid in flagids
    ]

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
        # try:
        if flagid_scrape_enabled:
            update_flagids()

        crnt_time = time.time()
        time_diff = max(0, crnt_time - unixtime)
        wait = tick_length - (time_diff % tick_length) + DELAY
        time.sleep(wait)

        # except Exception as e:
        #     print("ERROR: ", e, flush=True)
        #     time.sleep(10)


if __name__ == "__main__":
    main()
