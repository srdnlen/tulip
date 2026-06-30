#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Flower.
#
# Copyright ©2018 Nicolò Mazzucato
# Copyright ©2018 Antonio Groza
# Copyright ©2018 Brunello Simone
# Copyright ©2018 Alessio Marotta
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
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

import json
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from urllib.parse import parse_qs, urlsplit

from jinja2 import BaseLoader, Environment

from database import FlowDetail

DISCARD_COOKIES = ["PHPSESSID", "wordpress_logged_in_", "session"]


HEADER_TEMPLATE = """#!/usr/bin/env python3
import os
import sys

import requests

PORT = {{port}}
SCHEME = "https" if os.getenv("TARGET_HTTPS", "0") == "1" else "http"
HOST = (
    os.getenv("TARGET_IP")
    or os.getenv("TARGET_HOST")
    or (sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1")
)
BASE_URL = f"{SCHEME}://{HOST}:{PORT}"
TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "5"))
{% if use_requests_session %}
s = requests.Session()
{% endif -%}
"""

REQUEST_TEMPLATE = """
# {{request_method|upper}} {{request_path_comment}}
headers_{{request_index}} = {{headers}}
{% if data is not none %}{{payload_name}} = {{data}}
{% endif %}r{{request_index}} = {{"s" if use_requests_session else "requests"}}.{{request_method}}(
    BASE_URL + {{request_path_repr}},
    headers=headers_{{request_index}},
{% if data is not none %}    {{data_param_name}}={{payload_name}},
{% endif %}    timeout=TIMEOUT,
)
print(r{{request_index}}.text)
"""

FOOTER_TEMPLATE = ""


def render(template, **kwargs):
    return Environment(loader=BaseLoader()).from_string(template).render(kwargs)


# class to parse request informations
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, raw_http_request: bytes):
        self.rfile = BytesIO(raw_http_request)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

        self.headers: dict[str, str]
        try:
            self.headers = dict(self.headers)
        except AttributeError:
            self.headers = {}

        _, separator, body = raw_http_request.partition(b"\r\n\r\n")
        self.body = body if separator else b""

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message


def decode_http_request(raw_request: bytes, tokenize):
    request = HTTPRequest(raw_request)
    headers = {}
    blocked_headers = [
        "content-length",
        "accept-encoding",
        "connection",
        "host",
        "user-agent",
    ]
    content_type = ""
    data = None
    data_param_name = None

    for header_name in request.headers:
        normalized_header = header_name.lower()

        if normalized_header == "content-type":
            content_type = request.headers[header_name].lower()
        if normalized_header in blocked_headers:
            continue
        if normalized_header == "cookie":
            cookie = filter_cookie_header(request.headers[header_name])
            if cookie:
                headers[header_name] = cookie
            continue
        headers[header_name] = request.headers[header_name]

    # if tokenization is enabled and body is not empty, try to decode form body or JSON body
    if tokenize and request.body:
        # try to deserialize form data
        if content_type.startswith("application/x-www-form-urlencoded"):
            data_param_name = "data"
            data = {}
            body_dict = parse_qs(
                request.body.decode(),
                keep_blank_values=True,
            )
            for key, value in body_dict.items():
                if len(value) == 1:
                    data[key] = value[0]
                else:
                    data[key] = value

        # try to deserialize json
        if content_type.startswith("application/json"):
            data_param_name = "json"
            try:
                data = json.loads(request.body)
            except json.decoder.JSONDecodeError:
                pass

        # Forms with files are not yet implemented
        # # try to extract files
        # if content_type.startswith("multipart/form-data"):
        #     data_param_name = "files"
        #     data  = ...

        # Fallback to use raw text if nothing else worked out
        if data is None:
            data_param_name = "data"
            data = request.body

    elif request.body:
        data_param_name = "data"
        data = request.body

    return request, data, data_param_name, headers


def filter_cookie_header(cookie_header: str) -> str:
    cookie = SimpleCookie()

    try:
        cookie.load(cookie_header)
    except Exception:
        return cookie_header

    kept_cookies = []
    for morsel in cookie.values():
        if should_discard_cookie(morsel.key):
            continue
        kept_cookies.append(f"{morsel.key}={morsel.value}")

    return "; ".join(kept_cookies)


def should_discard_cookie(cookie_name: str) -> bool:
    return any(cookie_name.startswith(prefix) for prefix in DISCARD_COOKIES)


def normalize_request_path(path: str) -> str:
    parsed = urlsplit(path)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

    if not path.startswith("/"):
        raise Exception("request path must start with / to be a valid HTTP request")

    return path


# tokenize used for automatically fill data param of request
def convert_single_http_requests(
    flow: FlowDetail,
    item_index: int,
    tokenize: bool = True,
    use_requests_session: bool = False,
):
    if not flow.items:
        return "No data"

    request, data, data_param_name, headers = decode_http_request(
        flow.items[item_index].data, tokenize
    )
    request_path = normalize_request_path(request.path)
    request_path_repr = repr(request_path)
    request_method = validate_request_method(request.command)

    return render(
        HEADER_TEMPLATE,
        use_requests_session=use_requests_session,
        port=flow.port_dst,
    ) + render(
        REQUEST_TEMPLATE,
        request_index=1,
        headers=repr(headers),
        data=repr(data) if data is not None else None,
        payload_name=build_payload_name(data_param_name, 1),
        request_method=request_method,
        request_path_comment=repr(request_path),
        request_path_repr=request_path_repr,
        data_param_name=data_param_name,
        use_requests_session=use_requests_session,
    ) + render(FOOTER_TEMPLATE)


def convert_flow_to_http_requests(
    flow: FlowDetail, tokenize: bool = True, use_requests_session: bool = True
):
    port = flow.port_dst
    script = render(
        HEADER_TEMPLATE,
        use_requests_session=use_requests_session,
        port=port,
    )

    request_index = 1
    for item in flow.kind_items():
        if item.direction == "c":
            request, data, data_param_name, headers = decode_http_request(
                item.data, tokenize
            )
            request_method = validate_request_method(request.command)
            request_path = normalize_request_path(request.path)
            request_path_repr = repr(request_path)

            script += render(
                REQUEST_TEMPLATE,
                request_index=request_index,
                headers=repr(headers),
                data=repr(data) if data is not None else None,
                payload_name=build_payload_name(data_param_name, request_index),
                request_method=request_method,
                request_path_comment=repr(request_path),
                request_path_repr=request_path_repr,
                data_param_name=data_param_name,
                use_requests_session=use_requests_session,
            )
            request_index += 1
    return script + render(FOOTER_TEMPLATE)


def build_payload_name(data_param_name: str | None, request_index: int) -> str:
    if data_param_name == "json":
        return f"json_data_{request_index}"
    return f"data_{request_index}"


def validate_request_method(request_method: str):
    request_method = request_method.lower()
    if request_method not in [
        "delete",
        "get",
        "head",
        "options",
        "patch",
        "post",
        "put",
    ]:
        # Throw Exception for a bad method to prevent command inject via a nasty request method
        raise Exception(f"Invalid request method: {request_method}")
    return request_method
