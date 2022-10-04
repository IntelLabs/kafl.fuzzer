# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import yaml
import logging
from pathlib import Path
from logging.config import dictConfig
from argparse import Namespace
from pprint import pformat

import kafl_fuzzer

LOGGING_CONFIG_FILE = Path(kafl_fuzzer.__file__).parent / "logging.yaml"
DEBUG_FILENAME = 'kafl_fuzzer.log'

def setup_logging(config: Namespace):
    # read config file
    with open(LOGGING_CONFIG_FILE) as f:
        log_config = yaml.safe_load(f)

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
        log_config['root']['level'] = console_level
    if config.log:
        # define file handler filepath
        log_filepath = Path(config.work_dir) / DEBUG_FILENAME
        # define file handler in log_config
        log_config['handlers']['file'] = {
            'class': 'logging.FileHandler',
            'formatter': 'default',
            'level': 'NOTSET',
            'filename': log_filepath,
            'mode': 'w+'
        }
        # add file handler as output for root logger
        log_config['root']['handlers'].append('file')

    # configure logging
    dictConfig(log_config)
    # dump final logger config
    logging.debug('Logger configuration:')
    logging.debug(pformat(log_config))
