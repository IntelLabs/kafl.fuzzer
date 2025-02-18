# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# This module defines the command line interface for kafl, with its subcommands and parameters
# An important point to mention is that the add_argument() calls shouldn't define
# - default values
# - validation functions
# as this has been delegated to Dynaconf in settings.py
#
# the flow can be define as the following:
# the command line will be parsed as a Namespace object via parser.parse_args()
# this Namespace object will be send to settings.py:update_from_namespace() to update the dynaconf settings
# finally a validation step now occurs to ensure the settings are coherent and casted into the expected values
# through settings.py:validate()

import argparse
import logging
from enum import Enum, auto
from argparse import _SubParsersAction, ArgumentParser
from typing import Any

from .settings import settings
from kafl_fuzzer.manager.core import start as fuzz_start
from kafl_fuzzer.debug.core import start as debug_start
from kafl_fuzzer.coverage import start as cov_start
from kafl_fuzzer.gui import start as gui_start
from kafl_fuzzer.plot import start as plot_start
from kafl_fuzzer.mcat import start as mcat_start

DEBUG_MODES_HELP = '<benchmark>\tperform performance benchmark\n' \
                    '<gdb>\t\trun payload with Qemu gdbserver (must compile without redqueen!)\n' \
                    '<trace>\t\tperform trace run\n' \
                    '<trace-qemu>\tperform trace run and print QEMU stdout\n' \
                    '<noise>\t\tperform run and messure nondeterminism\n' \
                    '<printk>\t\tredirect printk calls to kAFL\n' \
                    '<redqueen>\trun redqueen debugger\n' \
                    '<redqueen-qemu>\trun redqueen debugger and print QEMU stdout\n' \
                    '<verify>\t\trun verifcation steps\n'

class KaflSubcommands(Enum):
    FUZZ = auto()
    DEBUG = auto()
    COV = auto()
    GUI = auto()
    PLOT = auto()
    MCAT = auto()

logger = logging.getLogger(__name__)



def hidden(msg, unmask=False):
    if unmask or settings.debug:
        return msg
    return argparse.SUPPRESS

def add_workdir_argument(parser):
    """add the workdir argument to the given parser"""
    parser.add_argument('-w', '--workdir', '--work-dir', dest='workdir', metavar='<dir>', required=False,
                        help='path to the output/working directory.')

# General startup options used by fuzzer, qemu, and/or utilities
def add_args_general(parser):
    add_workdir_argument(parser)
    parser.add_argument('--purge', required=False, help='purge the working directory at startup.',
                        action='store_true', default=False)
    parser.add_argument('-r', '--resume', required=False, help='use VM snapshot from existing workdir (for cov/gdb)',
                        action='store_true', default=False)
    parser.add_argument('-p', '--processes', required=False, metavar='<n>',
                        help='number of parallel processes')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', default=False,
                        help='enable verbose output')
    parser.add_argument('-q', '--quiet', help='only print warnings and errors to console',
                        required=False, action='store_true', default=False)
    parser.add_argument('-l', '--log', help='enable logging to $workdir/debug.log',
                        action='store_true', default=False)
    parser.add_argument('--debug', help='enable extra debug checks and max logging verbosity',
                        action='store_true', default=False)

# kAFL/Fuzzer-specific options
def add_args_fuzzer(parser):
    parser.add_argument('--seed-dir', metavar='<dir>', help='path to the seed directory.')
    parser.add_argument('--dict', required=False, metavar='<file>',
                        help='import dictionary file for use in havoc stage.', default=None)
    parser.add_argument('--funky', required=False, help='perform extra validation and store funky inputs.',
                        action='store_true', default=False)
    parser.add_argument('-D', '--afl-dumb-mode', required=False, help='skip deterministic stage (dumb mode)',
                        action='store_true', default=False)
    parser.add_argument('--afl-no-effector', required=False, help=hidden('disable effector maps during deterministic stage'),
                        action='store_true', default=False)
    parser.add_argument('--afl-skip-zero', required=False, help=hidden('skip zero bytes during deterministic stage'),
                        action='store_true', default=False)
    # parser.add_argument('--afl-skip-range', required=False, type=parse_ignore_range, metavar="<start-end>", action='append',
    #                     help=hidden('skip byte range during deterministic stage'))
    parser.add_argument('--afl-arith-max', metavar='<n>', help=hidden("max arithmetic range for afl_arith_n mutation"), required=False)
    parser.add_argument('--radamsa', required=False, action='store_true', help='enable Radamsa as additional havoc stage')
    parser.add_argument('--grimoire', required=False, action='store_true', help='enable Grimoire analysis & mutation stages', default=False)
    parser.add_argument('--redqueen', required=False, action='store_true', help='enable Redqueen trace & insertion stages', default=False)
    parser.add_argument('--redqueen-hashes', required=False, action='store_true', help=hidden('enable Redqueen checksum fixer (broken)'), default=False)
    parser.add_argument('--redqueen-hammer', required=False, action='store_true', help=hidden('enable Redqueen jump table hammering'), default=False)
    parser.add_argument('--redqueen-simple', required=False, action='store_true', help=hidden('do not ignore simple matches in Redqueen'), default=False)
    parser.add_argument('--cpu-offset', metavar='<n>', help="start CPU pinning at offset <n>", required=False)
    parser.add_argument('--abort-time', metavar='<n>', help="exit after <n> hours", default=None)
    parser.add_argument('--abort-exec', metavar='<n>', help="exit after max <n> executions", default=None)
    parser.add_argument('-ts', '--t-soft', dest='timeout_soft', required=False, metavar='<n>', help="soft execution timeout (in seconds)")
    parser.add_argument('-tc', '--t-check', dest='timeout_check', required=False, action='store_true', help="validate timeouts against hard limit (slower)", default=False)
    parser.add_argument('--kickstart', metavar='<n>', help="kickstart fuzzing with <n> byte random strings (default 256, 0 to disable)", required=False)
    parser.add_argument('--radamsa-path', metavar='<file>', help=hidden('path to radamsa executable'), required=False)


# Qemu/Worker-specific launch options
def add_args_qemu(parser):
    # BIOS/Image/Kernel load modes are partly exclusive, but we need at least one of them
    parser.add_argument('--image', dest='qemu_image', metavar='<qcow2>', help='path to Qemu disk image.')
    parser.add_argument('--snapshot', dest='qemu_snapshot', metavar='<dir>', required=False, help='path to VM pre-snapshot directory.')
    parser.add_argument('--bios', dest='qemu_bios', metavar='<file>', required=False, help='path to the BIOS image.')
    parser.add_argument('--kernel', dest='qemu_kernel', metavar='<file>', required=False, help='path to the Kernel image.')
    parser.add_argument('--initrd', dest='qemu_initrd', metavar='<file>', required=False, help='path to the initrd/initramfs file.')
    parser.add_argument('--append', dest='qemu_append', metavar='<str>', required=False, help='Qemu -append option')
    parser.add_argument('-m', '--memory', dest='qemu_memory', metavar='<n>', help='size of VM RAM in MB (default: 256).')

    parser.add_argument('--qemu-base', metavar='<str>', required=False, help='base Qemu config (check defaults!)')
    parser.add_argument('--qemu-serial', metavar='<str>', required=False, help='Qemu serial emulation (redirected to file, see defaults)')
    parser.add_argument('--qemu-extra', metavar='<str>', required=False, help='extra Qemu config (check defaults!)')
    parser.add_argument('--qemu-path', metavar='<file>', help=hidden('path to Qemu-Nyx executable'))

    parser.add_argument('-ip0', required=False, metavar='<n-m>', help='set IP trace filter range 0 (should be page-aligned)')
    parser.add_argument('-ip1', required=False, metavar='<n-m>', help='Set IP trace filter range 1 (should be page-aligned)')
    parser.add_argument('-ip2', required=False, metavar='<n-m>', help=hidden('Set IP trace filter range 2 (should be page-aligned)'))
    parser.add_argument('-ip3', required=False, metavar='<n-m>', help=hidden('Set IP trace filter range 3 (should be page-aligned)'))

    parser.add_argument('--sharedir', metavar='<dir>', required=False, help='path to the page buffer share directory.')
    parser.add_argument('-R', '--reload', metavar='<n>', required=False, help='snapshot-reload every N execs (default: 1)')
    parser.add_argument('--gdbserver', required=False, action='store_true', help=hidden('enable Qemu gdbserver (use via kafl_debug.py!'))
    parser.add_argument('--log-hprintf', required=False, action='store_true', help="redirect hprintf logging to workdir/hprintf_NN.log")
    parser.add_argument('--log-crashes', required=False, action='store_true', help="store hprintf logs only for crashes/timeouts")
    parser.add_argument('-t', '--t-hard', dest='timeout_hard', required=False, metavar='<n>', help="hard execution timeout (seconds)")
    parser.add_argument('--payload-size', metavar='<n>', required=False, help=hidden("maximum payload size in bytes (minus headers)"))
    parser.add_argument('--bitmap-size', metavar='<n>', help="size of feedback bitmap (must be power of 2)")
    parser.add_argument('--trace', required=False, action='store_true', help='store binary PT traces of new inputs (fast).')
    parser.add_argument("--trace-cb", required=False, action='store_true', help='store decoded PT traces of new inputs (slow).')


# kafl_debug launch options
def add_args_debug(parser):
    parser.add_argument('--input', metavar='<file/dir>', help='path to input file or workdir.')
    parser.add_argument('-n', '--iterations', metavar='<n>', help='execute <n> times (for some actions)')
    parser.add_argument('--ptdump-path', required=False, metavar='<file>', help=hidden('path to ptdump executable'))


class ConfigParserBuilder():

    def __call__(self, *args: Any, **kwds: Any) -> ArgumentParser:
        parser = self._base_parser()
        # enable subcommands
        subcommands = parser.add_subparsers(dest="command", required=True)
        # add subcommands
        self._add_fuzz_subcommand(subcommands)
        self._add_debug_subcommand(subcommands)
        self._add_cov_subcommand(subcommands)
        self._add_gui_subcommand(subcommands)
        self._add_plot_subcommand(subcommands)
        self._add_mcat_subcommand(subcommands)
        return parser

    def _base_parser(self) -> ArgumentParser:
        return argparse.ArgumentParser(fromfile_prefix_chars='@')

    def _add_fuzz_subcommand(self, parser: _SubParsersAction):
        fuzz_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.FUZZ.name.lower(), help="kAFL Fuzzer")

        general_grp = fuzz_subcommand.add_argument_group('General options')
        add_args_general(general_grp)

        fuzzer_grp = fuzz_subcommand.add_argument_group('Fuzzer options')
        add_args_fuzzer(fuzzer_grp)

        qemu_grp = fuzz_subcommand.add_argument_group('Qemu/Nyx options')
        add_args_qemu(qemu_grp)

        fuzz_subcommand.set_defaults(func=fuzz_start)

    def _add_debug_subcommand(self, parser: _SubParsersAction):
        debug_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.DEBUG.name.lower(), help="kAFL Debugger")

        general_grp = debug_subcommand.add_argument_group('General options')
        add_args_general(general_grp)

        debug_grp = debug_subcommand.add_argument_group("Debug options")
        add_args_debug(debug_grp)
        # add "action" argument, only for "debug" subcommand
        debug_grp.add_argument('--action', required=True, metavar='<cmd>', help=DEBUG_MODES_HELP)

        qemu_grp = debug_subcommand.add_argument_group('Qemu/Nyx options')
        add_args_qemu(qemu_grp)

        debug_subcommand.set_defaults(func=debug_start)

    def _add_cov_subcommand(self, parser: _SubParsersAction):
        cov_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.COV.name.lower(), help="kAFL Coverage Analyzer")

        general_grp = cov_subcommand.add_argument_group('General options')
        add_args_general(general_grp)

        debug_grp = cov_subcommand.add_argument_group("Debug options")
        add_args_debug(debug_grp)

        qemu_grp = cov_subcommand.add_argument_group('Qemu/Nyx options')
        add_args_qemu(qemu_grp)

        cov_subcommand.set_defaults(func=cov_start)

    def _add_gui_subcommand(self, parser: _SubParsersAction):
        gui_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.GUI.name.lower(), help="kAFL GUI")

        add_workdir_argument(gui_subcommand)

        gui_subcommand.set_defaults(func=gui_start)

    def _add_plot_subcommand(self, parser: _SubParsersAction):
        plot_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.PLOT.name.lower(), help="kAFL Plotter")

        add_workdir_argument(plot_subcommand)
        plot_subcommand.add_argument("--dot-file", metavar="<dotfile>", help="Write DOT graph to file (requires pygraphviz)")

        plot_subcommand.set_defaults(func=plot_start)

    def _add_mcat_subcommand(self, parser: _SubParsersAction):
        mcat_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.MCAT.name.lower(), help="kAFL msgpack Pretty-Printer")

        mcat_subcommand.add_argument("pack_file", nargs="+", metavar="<msgpack file>", help="MessagePack file to decode")

        mcat_subcommand.set_defaults(func=mcat_start)
