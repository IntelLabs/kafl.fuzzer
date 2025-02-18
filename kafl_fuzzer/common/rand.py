# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Wrapper for your favorite RNG solution
"""

import random

import fastrand

class rand:

    @staticmethod
    def reseed():
        # seed from system and flush initial output
        fastrand.pcg32_seed(random.getrandbits(63))
        fastrand.pcg32()
        fastrand.pcg32()

    @staticmethod
    def bytes(num):
        return bytes([rand.int(256) for _ in range(num)])

    # return integer N := 0 <= n < limit
    # Intended semantics:
    #   if rand.int(100) < 50 # execute with p(0.5)
    #   if rand.int(2)        # execute with p(0.5)
    # a[rand.int(len(a)) = 5  # never out of bounds
    @staticmethod
    def int(limit):
        if limit == 0:
            return 0
        return fastrand.pcg32bounded(limit)

    @staticmethod
    def select(arg):
        return arg[rand.int(len(arg))]

    @staticmethod
    def shuffle(arg):
        return random.shuffle(arg)

