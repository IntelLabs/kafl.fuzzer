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

import logging
import msgpack
from pprint import pprint

logger = logging.getLogger(__name__)

def read_binary_file(filename):
    with open(filename, 'rb') as f:
        return f.read()


def start(settings: LazySettings):
    for file in settings.pack_file:
        try:
            pprint(msgpack.unpackb(read_binary_file(file), strict_map_key=False))
        except OSError as e:
            logger.error(e)
        except ValueError as e:
            logger.error(f"Could not parse '{file}': {e}")
