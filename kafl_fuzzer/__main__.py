# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
from pprint import pformat

from kafl_fuzzer.common.config import settings, update_from_namespace, validate, ConfigParserBuilder
from kafl_fuzzer.common.logger import setup_basic_logging

def main():
    parser_builder = ConfigParserBuilder()
    parser = parser_builder()
    # parse cmdline args
    args = parser.parse_args()
    # override Dynaconf settings with command line settings
    update_from_namespace(args)
    # before validation, setup logging on stdout
    # and dump currently loaded config
    setup_basic_logging(settings)
    logger = logging.getLogger(__name__)
    logger.debug("Loaded configuration files:")
    logger.debug(pformat(settings._loaded_files))
    logger.debug("Command line configuration:")
    logger.debug(pformat(vars(args)))
    logger.debug("Loaded configuration values:")
    logger.debug(pformat(settings._loaded_by_loaders))
    # validate settings
    validate()
    logger.debug("Final configuration:")
    logger.debug(pformat(settings.to_dict()))
    # call subcommand assigned default start func
    args.func(settings)
