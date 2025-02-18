#!/usr/bin/env python3
#
# Copyright (C) 2019-2020 Intel Corporation
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
This file offers an alternative/standalone entry point to tests/, e.g.
to launch some benchmarks contained there.

To execute all regular tests, run pytest inside kAFL-Fuzzer/ directory.
"""

from tests.test_random import rand_main
from tests.test_deterministic import deter_main
from tests.test_havoc_handler import havoc_main

if __name__ == '__main__':

    print("\nRunning benchmarks... (use pytest -v to run actual tests!)\n")

    rand_main()
    deter_main()
    havoc_main()

    print("\nDone!")
