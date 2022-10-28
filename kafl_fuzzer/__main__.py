# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from kafl_fuzzer.common.config import ConfigParserBuilder, update_settings_from_cmdline

def main():
    parser_builder = ConfigParserBuilder()
    parser = parser_builder()
    breakpoint()
    # parse cmdline args
    args = parser.parse_args()
    # update global config settings object
    settings = update_settings_from_cmdline(args)
    # call subcommand assigned default start func
    args.func(settings)

