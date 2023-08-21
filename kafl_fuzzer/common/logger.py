# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from dynaconf import LazySettings
import yaml
import logging
from logging import LoggerAdapter
from pathlib import Path
from logging.config import dictConfig

import kafl_fuzzer

LOGGING_CONFIG = None
LOGGING_CONFIG_FILE = Path(kafl_fuzzer.__file__).parent / "logging.yaml"
DEBUG_FILENAME = 'kafl_fuzzer.log'

def load_logging_config():
    global LOGGING_CONFIG
    with open(LOGGING_CONFIG_FILE) as f:
        LOGGING_CONFIG = yaml.safe_load(f)

class WorkerLogAdapter(LoggerAdapter):
    def process(self, msg, kwargs):
        return f'Worker-{self.extra["pid"]:02d} {msg}', kwargs

def setup_basic_logging(config: LazySettings):
    global LOGGING_CONFIG
    assert(LOGGING_CONFIG is not None)
    # Default is INFO level to console, and no file logging.
    # Useful modifiers:
    #  -v / -q to increase/decrease console logging
    #  -l / --log to enable file logging at standard level
    #  --debug to enable extra debug checks, qemu tracing, etc (slow!)
    #
    # We allow some sensible combinations, e.g. --quiet --log [--debug]
    console_level = None
    if config.quiet:
        console_level = logging.WARNING
    elif config.verbose or config.debug:
        console_level = logging.DEBUG

    # update logger yaml config based on command line params
    if console_level:
        LOGGING_CONFIG['root']['level'] = console_level
    # configure logging
    dictConfig(LOGGING_CONFIG)


def add_logging_file(config: LazySettings):
    global LOGGING_CONFIG
    assert(LOGGING_CONFIG is not None)
    if config.log:
        # define file handler filepath
        log_filepath = Path(config.workdir) / DEBUG_FILENAME
        # define file handler in log_config
        LOGGING_CONFIG['handlers']['file'] = {
            'class': 'logging.FileHandler',
            'formatter': 'default',
            'level': 'NOTSET',
            'filename': log_filepath,
            'mode': 'w+'
        }
        # add file handler as output for root logger
        LOGGING_CONFIG['root']['handlers'].append('file')
        # configure logging
        dictConfig(LOGGING_CONFIG)

load_logging_config()
