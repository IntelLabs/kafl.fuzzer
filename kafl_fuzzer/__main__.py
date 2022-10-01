# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from kafl_fuzzer.common.config import ConfigParserBuilder

def main():
    parser_builder = ConfigParserBuilder()
    parser = parser_builder()
    args = parser.parse_args()
    args.func(args)

