#!/usr/bin/env python3
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

from database import FlowDetail

MARKER_SIZE = 32

HEADER_TEMPLATE = """#!/usr/bin/env python3
import os
import sys

from pwn import *

HOST = "10.60.0.1"
PORT = {port}
SSL = False
TIMEOUT = 5
context.log_level = "info"

def main():
    io = remote(HOST, PORT, ssl=SSL)
"""


FOOTER_TEMPLATE = """
    io.close()

if __name__ == "__main__":
    main()
"""


# convert a flow into pwn script
def flow2pwn(flow: FlowDetail):
    script = HEADER_TEMPLATE.format(
        port=flow.port_dst,
    )

    expected_output = b""
    for item in flow.kind_items():
        if item.direction == "c":
            script += render_send(item.data, expected_output)
            expected_output = b""

        else:
            expected_output = extract_marker(item.data)

    return script + FOOTER_TEMPLATE


def render_send(data: bytes, expected_output: bytes = b"") -> str:
    if expected_output:
        return f"    io.sendafter({expected_output!r}, {data!r})\n"

    return f"    io.send({data!r})\n"


def extract_marker(data: bytes) -> bytes:
    if not data:
        return b""

    return data[-MARKER_SIZE:]
