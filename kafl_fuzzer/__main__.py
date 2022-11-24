# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from kafl_fuzzer.common.config import settings, update_from_namespace, validate, ConfigParserBuilder

def main():
    parser_builder = ConfigParserBuilder()
    parser = parser_builder()
    # parse cmdline args
    args = parser.parse_args()
    # override Dynaconf settings with command line settings
    update_from_namespace(args)
    # validate settings
    validate()
    # call subcommand assigned default start func
    args.func(settings)

