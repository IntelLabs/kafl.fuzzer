# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import shutil
import sys
import tempfile
import string
import logging
from shutil import copyfile
from typing import Tuple, Any, Dict

import psutil

import kafl_fuzzer.common.color as color

logger = logging.getLogger(__name__)

class Singleton(type):
    _instances: Dict[type, Any] = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


# print any qemu-like processes owned by this user
def qemu_sweep(msg):
    pids = [
        p.info['pid'] for p in psutil.process_iter(['pid', 'name', 'uids'])
        if p.info['name'] == 'qemu-system-x86_64' and p.info['uids'].real == os.getuid()
    ]

    if (len(pids) > 0):
        logger.warn(msg + " " + repr(pids))

# filter available CPUs by those with existing qemu instances
def filter_available_cpus():
    def get_qemu_processes():
        for proc in psutil.process_iter(['pid', 'name']):
            if 'qemu-system-x86_64' in proc.info['name']:
                yield (proc.info['pid'])

    avail = os.sched_getaffinity(0)
    used = set()
    for pid in get_qemu_processes():
        used |= os.sched_getaffinity(pid)
    return avail, used

# pretty-printed hexdump
def hexdump(src, length=16):
    hexdump_filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c + length]
        hex_value = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and hexdump_filter[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex_value, printable))
    return ''.join(lines)

# return safely printable portion of binary input data
# use verbatim=True to maintain whitespace/formatting
def strdump(data, verbatim=False):
    dump = data.decode("utf-8", errors='backslashreplace')

    if verbatim:
        dump = ''.join([x if x in string.printable or x in "\b\x1b" else "." for x in dump])
    else:
        dump = ''.join([x if x in string.printable and x not in "\a\b\t\n\r\x0b\x0c" else "." for x in dump])
    return dump

def atomic_write(filename, data):
    # rename() is atomic only on same filesystem so the tempfile must be in same directory
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(filename), delete=False) as f:
        f.write(data)
    os.chmod(f.name, 0o644)
    os.rename(f.name, filename)

def read_binary_file(filename) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()

def find_diffs(data_a: bytes, data_b: bytes) -> Tuple[int, int]:
    first_diff = 0
    last_diff = 0
    for i in range(min(len(data_a), len(data_b))):
        if data_a[i] != data_b[i]:
            if first_diff == 0:
                first_diff = i
            last_diff = i
    return first_diff, last_diff

def prepare_working_dir(config):

    workdir   = config.workdir
    purge      = config.purge
    resume     = config.resume

    folders = ["/corpus/regular", "/corpus/crash",
               "/corpus/kasan", "/corpus/timeout",
               "/metadata", "/bitmaps", "/imports",
               "/snapshot", "/funky", "/traces", "/logs"]

    if resume and purge:
        logger.error("Cannot set both --purge and --resume at the same time. Abort.")
        return False

    if purge:
        shutil.rmtree(workdir, ignore_errors=True)

    try:
        for folder in folders:
            os.makedirs(workdir + folder, exist_ok=resume)
    except FileExistsError:
        logger.error("Refuse to operate on existing workdir, supply either --purge or --resume.")
        return False
    except PermissionError as e:
        logger.error(str(e))
        return False

    return True

def copy_seed_files(working_directory, seed_directory):
    if len(os.listdir(seed_directory)) == 0:
        return False

    if len(os.listdir(working_directory)) == 0:
        return False

    i = 0
    for (directory, _, files) in os.walk(seed_directory):
        for f in files:
            path = os.path.join(directory, f)
            if os.path.exists(path):
                try:
                    copyfile(path, working_directory + "/imports/" + "seed_%05d" % i)
                    i += 1
                except PermissionError:
                    logger.error("Skipping seed file %s (permission denied)." % path)
    return True

def print_hprintf(msg):
    sys.stdout.write(color.FLUSH_LINE + color.HPRINTF + msg + color.ENDC)
    sys.stdout.flush()

fancy_banner = r"""
    __                        __  ___    ________
   / /_____  _________  ___  / / /   |  / ____/ /
  / //_/ _ \/ ___/ __ \/ _ \/ / / /| | / /_  / /
 / ,< /  __/ /  / / / /  __/ / / ___ |/ __/ / /___
/_/|_|\___/_/  /_/ /_/\___/_/ /_/  |_/_/   /_____/
===================================================
"""

def print_banner(msg, quiet=False):
    if not quiet:
        print(fancy_banner)
    print("<< " + color.BOLD + color.OKGREEN + msg + color.ENDC + " >>\n")

def is_float(value):
    try:
        float(value)
        return True
    except ValueError:
        return False

def is_int(value):
    try:
        int(value)
        return True
    except ValueError:
        return False

def json_dumper(obj):
    return obj.__dict__
