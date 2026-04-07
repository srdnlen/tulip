#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Flower.
#
# Copyright ©2018 Nicolò Mazzucato
# Copyright ©2018 Antonio Groza
# Copyright ©2018 Brunello Simone
# Copyright ©2018 Alessio Marotta
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
# Flower is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Flower is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Flower.  If not, see <https://www.gnu.org/licenses/>.

import dataclasses
from datetime import timedelta, datetime, timezone
import os
import re
import traceback
import uuid
from ipaddress import ip_network
from pathlib import Path

import dateutil.parser
from flask import Flask, Response, request, send_file
from flask_cors import CORS
from requests import get

import database
import json_util
from configurations import (
    dump_pcaps_dir,
    flag_lifetime,
    flag_regex,
    services,
    start_date,
    tick_length,
    traffic_dir,
    visualizer_url,
)
from data2req import convert_flow_to_http_requests, convert_single_http_requests
from flow2pwn import flow2pwn

application = Flask(__name__)
CORS(application)
db = database.Pool(os.environ["TIMESCALE"])


def return_json_response(object, **kwargs):
    return Response(json_util.dumps(object), mimetype="application/json", **kwargs)


def return_text_response(object, **kwargs):
    return Response(object, mimetype="text/plain", **kwargs)


@application.route("/")
def hello_world():
    return "Hello, World!"


@application.route("/tick_info")
def getTickInfo():
    data = {
        "startDate": start_date,
        "tickLength": tick_length,
        "flagLifetime": flag_lifetime,
    }
    return return_json_response(data)


@application.route("/query", methods=["POST"])
def query():
    query = request.get_json()

    try:
        query = database.FlowQuery(
            regex_insensitive=(
                re.compile(query["regex_insensitive"])
                if "regex_insensitive" in query
                else None
            ),
            ip_src=ip_network(query["ip_src"]) if "ip_src" in query else None,
            ip_dst=ip_network(query["ip_dst"]) if "ip_dst" in query else None,
            port_src=query.get("port_src"),
            port_dst=query.get("port_dst"),
            time_from=(
                dateutil.parser.parse(query["time_from"])
                if "time_from" in query
                else None
            ),
            time_to=(
                dateutil.parser.parse(query["time_to"]) if "time_to" in query else None
            ),
            tags_include=[str(elem) for elem in query.get("tags_include", [])],
            tags_exclude=[str(elem) for elem in query.get("tags_exclude", [])],
            tag_intersection_and=query.get("tag_intersection_mode", "").lower()
            == "and",
        )
    except re.error as error:
        return return_json_response(
            {
                "error": str(error),
            },
            status=400,
        )

    with db.connection() as c:
        flows = c.flow_query(query)
    flows = list(map(dataclasses.asdict, flows))
    return return_json_response(flows)


@application.route("/stats")
def getStats():
    query = request.args

    tick_from = query.get("tick_from", type=int)
    tick_to = query.get("tick_to", type=int)
    time_from = query.get("time_from")
    time_to = query.get("time_to")

    if (tick_from or tick_to) and (time_from or time_to):
        return return_json_response(
            {
                "error": "Specify either tick_from/tick_to or time_from/time_to, not both",
            },
            status=400,
        )

    # Converting time-based queries to tick-based queries
    print(
        "Received stats query with time_from:",
        time_from,
        "time_to:",
        time_to,
        flush=True,
    )
    if time_from or time_to:
        tick_first = dateutil.parser.parse(start_date)
        tick_length_delta = timedelta(milliseconds=int(tick_length))

        if time_from:
            ms_from = int(time_from)
            parsed_time_from = datetime.fromtimestamp(ms_from / 1000.0, tz=timezone.utc)
            tick_from = ((parsed_time_from - tick_first) // tick_length_delta) + 1

        if time_to:
            ms_to = int(time_to)
            parsed_time_to = datetime.fromtimestamp(ms_to / 1000.0, tz=timezone.utc)
            tick_to = ((parsed_time_to - tick_first) // tick_length_delta) + 1

        print("From:", time_from, "parsed as", tick_from, flush=True)
        print("To:", time_to, "parsed as", tick_to, flush=True)

    query = database.StatsQuery(
        service=query.get("service"),
        tick_from=int(tick_from) if tick_from else None,
        tick_to=int(tick_to) if tick_to else None,
    )

    with db.connection() as c:
        stats = c.stats_query(query)
    stats = list(stats.values())
    return return_json_response(stats)


@application.route("/under_attack")
def getUnderAttack():
    res = get(
        f"{visualizer_url}/api/under-attack",
        params={
            "from_tick": request.args.get("from_tick"),
            "to_tick": request.args.get("to_tick"),
        },
    )
    assert res.status_code == 200

    tick_data = res.json()
    return return_json_response(tick_data)


@application.route("/tags")
def getTags():
    with db.connection() as c:
        tags = c.tag_list()
    return return_json_response(tags)


@application.route("/star", methods=["POST"])
def setStar():
    query = request.get_json()
    flow_id = uuid.UUID(query.get("id"))
    apply = bool(query.get("star"))
    with db.connection() as c:
        c.flow_tag(flow_id, "starred", apply)
    return "ok!"


@application.route("/services")
def getServices():
    return return_json_response(services)


@application.route("/flag_regex")
def getFlagRegex():
    return return_json_response(flag_regex)


@application.route("/flow/<id>")
def getFlowDetail(id):
    id = uuid.UUID(id)
    with db.connection() as c:
        flow = c.flow_detail(id)
    return return_json_response(flow)


@application.route("/to_single_python_request", methods=["POST"])
def convertToSingleRequest():
    flow_id = request.args.get("id", "")
    item_index = request.args.get("index", "")

    if flow_id == "":
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "No flow id", "No flow id param"
            )
        )
    if item_index == "":
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "No index", "No item index param"
            )
        )

    flow_id = uuid.UUID(flow_id)
    item_index = int(item_index)
    with db.connection() as c:
        flow = c.flow_detail(flow_id)
    if not flow:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "Invalid flow", "Invalid flow id"
            )
        )
    if item_index >= len(flow.items):
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "Invalid index", "Index out of range"
            )
        )

    tokenize = bool(request.args.get("tokenize", False))
    use_requests_session = bool(request.args.get("use_requests_session", False))
    try:
        converted = convert_single_http_requests(
            flow, item_index, tokenize, use_requests_session
        )
    except Exception as ex:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                type(ex).__name__, traceback.format_exc()
            )
        )
    return return_text_response(converted)


@application.route("/to_python_request/<id>")
def convertToRequests(id):
    id = uuid.UUID(id)
    with db.connection() as c:
        flow = c.flow_detail(id)
    if not flow:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "Invalid flow", "Invalid flow id"
            )
        )
    tokenize = bool(request.args.get("tokenize", True))
    use_requests_session = bool(request.args.get("use_requests_session", True))
    try:
        converted = convert_flow_to_http_requests(flow, tokenize, use_requests_session)
    except Exception as ex:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                type(ex).__name__, traceback.format_exc()
            )
        )
    return return_text_response(converted)


@application.route("/to_pwn/<id>")
def confertToPwn(id):
    id = uuid.UUID(id)
    with db.connection() as c:
        flow = c.flow_detail(id)
    if not flow:
        return return_text_response(
            "There was an error while converting the request:\n{}: {}".format(
                "Invalid flow", "Invalid flow id"
            )
        )
    return return_text_response(flow2pwn(flow))


@application.route("/download/")
def downloadFile():
    filepath = request.args.get("file")
    if filepath is None:
        return return_text_response(
            "There was an error while downloading the requested file:\n{}: {}".format(
                "Invalid 'file'", "No 'file' given"
            )
        )
    filepath = Path(filepath)

    # Check for path traversal by resolving the file first.
    filepath = filepath.resolve()
    if traffic_dir not in filepath.parents and dump_pcaps_dir not in filepath.parents:
        return return_text_response(
            "There was an error while downloading the requested file:\n{}: {}".format(
                "Invalid 'file'",
                "'file' was not in a subdirectory of traffic_dir or dump_pcaps_dir",
            )
        )

    try:
        return send_file(filepath, as_attachment=True)
    except FileNotFoundError:
        return return_text_response(
            "There was an error while downloading the requested file:\n{}: {}".format(
                "Invalid 'file'", "'file' not found"
            )
        )


def create_app():
    db.open()
    return application


if __name__ == "__main__":
    try:
        db.open()
        application.run(host="0.0.0.0", threaded=True)
    finally:
        db.close()
