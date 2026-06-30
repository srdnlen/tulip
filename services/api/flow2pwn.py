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

PORT = {port}
SSL = bool(int(os.getenv("TARGET_SSL", "0")))
HOST = (
    os.getenv("TARGET_IP")
    or os.getenv("TARGET_HOST")
    or (sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1")
)
TIMEOUT = float(os.getenv("PWN_TIMEOUT", "5"))
context.log_level = os.getenv("PWN_LOG_LEVEL", "info")


def connect():
    return remote(HOST, PORT, ssl=SSL)


def main():
    io = connect()
"""


FOOTER_TEMPLATE = """
    return io


if __name__ == "__main__":
    main()
"""


# convert a flow into pwn script
def flow2pwn(flow: FlowDetail):
    script = HEADER_TEMPLATE.format(
        port=flow.port_dst,
    )

    for item in flow.kind_items():
        if item.direction == "c":
            script += render_send(item.data)

        else:
            script += render_recvuntil(item.data)

    return script + FOOTER_TEMPLATE


def render_send(data: bytes) -> str:
    return f"    io.send({data!r})\n"


def render_recvuntil(data: bytes) -> str:
    if not data:
        return ""

    marker = data[-MARKER_SIZE:]
    return f"    io.recvuntil({marker!r}, timeout=TIMEOUT)\n"
