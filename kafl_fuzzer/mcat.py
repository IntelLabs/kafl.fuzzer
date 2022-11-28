#!/usr/bin/env python3
#
# Copyright 2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2021 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Pretty-Print msgpack files produced by kAFL
"""

from dynaconf import LazySettings

import msgpack
from pprint import pprint

def read_binary_file(filename):
    with open(filename, 'rb') as f:
        return f.read()


def start(settings: LazySettings):
    for file in settings.pack_file:
        pprint(msgpack.unpackb(read_binary_file(file), strict_map_key=False))
