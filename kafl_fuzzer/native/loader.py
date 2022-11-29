# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later


"""
Helper for loading C extension
"""

import glob
import inspect
import os
import logging

import kafl_fuzzer.native as native_pkg

logger = logging.getLogger(__name__)

def bitmap_path():
    native_path = os.path.dirname(inspect.getfile(native_pkg))
    bitmap_paths = glob.glob(native_path + "/bitmap*so")
    assert len(bitmap_paths) > 0, "Failed to resolve native bitmap.so library."
    return bitmap_paths[0]
