# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
kAFL Worker Implementation.

Request fuzz input from Manager and process it through various fuzzing stages/mutations.
Each Worker is associated with a single Qemu instance for executing fuzz inputs.
"""

import os
import time
import signal
import sys
import shutil
import tempfile
import logging
import lz4.frame as lz4

#from kafl_fuzzer.common.config import FuzzerConfiguration
from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.common.util import atomic_write
from kafl_fuzzer.manager.bitmap import BitmapStorage, GlobalBitmap
from kafl_fuzzer.manager.communicator import ClientConnection, MSG_IMPORT, MSG_RUN_NODE, MSG_BUSY
from kafl_fuzzer.manager.node import QueueNode
from kafl_fuzzer.manager.statistics import WorkerStatistics
from kafl_fuzzer.worker.state_logic import FuzzingStateLogic
from kafl_fuzzer.worker.qemu import QemuIOException
from kafl_fuzzer.worker.qemu import qemu as Qemu
from kafl_fuzzer.common.logger import WorkerLogAdapter

def worker_loader(pid, config):
    worker = WorkerTask(pid, config)
    worker.start()

class WorkerTask:

    def __init__(self, pid, config):
        self.config = config
        self.pid = pid
        self.logger_no_prefix = logging.getLogger(__name__)
        self.logger = WorkerLogAdapter(self.logger_no_prefix, {'pid': self.pid})

        self.q = Qemu(self.pid, self.config)
        self.conn = ClientConnection(pid, config)
        self.statistics = WorkerStatistics(self.pid, config)
        self.logic = FuzzingStateLogic(self, config)
        self.bitmap_storage = BitmapStorage(self.config, "main")

        self.payload_size = self.q.get_payload_size()
        self.t_hard = config.timeout_hard
        self.t_soft = config.timeout_soft
        self.t_check = config.timeout_check
        self.num_funky = 0

    def handle_import(self, msg):
        meta_data = {"state": {"name": "import"}, "id": 0}
        payload = msg["task"]["payload"]
        self.q.set_timeout(self.t_hard)
        try:
            self.logic.process_import(payload, meta_data)
        except QemuIOException:
            self.logger.warn("Execution failure on import.")
            self.conn.send_node_abort(None, None)
            raise
        self.conn.send_ready()

    def handle_busy(self):
        busy_timeout = 4
        kickstart = self.config.kickstart

        if kickstart:
            self.logger.debug("No inputs in queue, attempting kickstart(%d)..", kickstart)
            self.q.set_timeout(self.t_hard)
            self.logic.process_kickstart(kickstart)
        else:
            self.logger.info("No inputs in queue, sleeping %ds..", busy_timeout)
            time.sleep(busy_timeout)
        self.conn.send_ready()

    def handle_node(self, msg):
        meta_data: bytes = QueueNode.get_metadata(self.config.workdir, msg["task"]["nid"])
        payload: bytes = QueueNode.get_payload(self.config.workdir, meta_data)

        # fixme: determine globally based on all seen regulars
        t_dyn = self.t_soft + 1.2 * meta_data["info"]["performance"]
        self.q.set_timeout(min(self.t_hard, t_dyn))

        try:
            results, new_payload = self.logic.process_node(payload, meta_data)
        except QemuIOException:
            # mark node as crashing and free it before escalating
            self.logger.info("Qemu execution failed for node %d." % meta_data["id"])
            results = self.logic.create_update(meta_data["state"], {"crashing": True})
            self.conn.send_node_abort(meta_data["id"], results)
            raise

        if new_payload:
            default_info = {"method": "validate_bits", "parent": meta_data["id"]}
            if self.validate_bits(new_payload, meta_data, default_info):
                self.logger.debug("Stage %s found alternative payload for node %d", meta_data["state"]["name"], meta_data["id"])
            else:
                self.logger.warn("Provided alternative payload found invalid - bug in stage %s?", meta_data["state"]["name"])
        self.conn.send_node_done(meta_data["id"], results, new_payload)

    def start(self):

        def sigterm_handler(signal, frame):
            if self.q:
                self.q.async_exit()
            sys.exit(0)

        signal.signal(signal.SIGTERM, sigterm_handler)
        os.setpgrp()
        rand.reseed()

        # pin worker N to the Nth available CPU of this task group
        try:
            cpu_offset = self.config.cpu_offset + self.pid
            cpu = sorted(os.sched_getaffinity(0))[cpu_offset]
            os.sched_setaffinity(0, [cpu])
        except Exception:
            self.logger.error("failed to set CPU affinity to %d out of %d. Aborting..", cpu_offset, len(os.sched_getaffinity(0)))
            return

        # start Qemu and commence main worker loop
        try:
            if self.q.start():
                self.loop()
            else:
                self.logger.error("Failed to launch Qemu.")
                self.conn.send_node_abort(None, None)
        except QemuIOException:
            # Qemu has likely died on us - try to restart?
            pass
        finally:
            if self.q:
                self.q.async_exit()
            self.logger.info("Exit.")

    def loop(self):
        self.logger.info("Entering fuzz loop..")
        self.conn.send_ready()

        while True:
            try:
                msg = self.conn.recv()
            except ConnectionResetError:
                self.logger.error("Lost connection to Manager. Shutting down.")
                return

            if msg["type"] == MSG_RUN_NODE:
                self.handle_node(msg)
            elif msg["type"] == MSG_IMPORT:
                self.handle_import(msg)
            elif msg["type"] == MSG_BUSY:
                self.handle_busy()
            else:
                raise ValueError("Unknown message type {}".format(msg))

    def quick_validate(self, data, old_res, trace=False):
        # Validate in persistent mode. Faster but problematic for very funky targets
        old_array = old_res.copy_to_array()

        if trace:
            self.q.set_trace_mode(True)
            # give a little extra time in case payload is close to limit
            dyn_timeout = self.q.get_timeout()
            self.q.set_timeout(self.t_hard*2)

        new_res = self.__execute(data).apply_lut()
        new_array = new_res.copy_to_array()

        if trace:
            self.q.set_trace_mode(False)
            self.q.set_timeout(dyn_timeout)

        if new_array == old_array:
            return True, new_res.performance

        return False, new_res.performance

    def funky_validate(self, data, old_res, trace=False):
        # Validate in persistent mode with stochastic prop of funky results

        validations = 8
        confirmations = 0
        runtime_avg = 0
        num = 0
        trace_round=False

        for num in range(validations):
            stable, runtime = self.quick_validate(data, old_res, trace=trace_round)
            if stable:
                confirmations += 1
                runtime_avg += runtime

            if confirmations >= 0.5*validations:
                trace_round=trace

            if confirmations >= 0.75*validations:
                return True, runtime_avg/num

        self.logger.debug("Funky input received %d/%d confirmations. Rejecting..", confirmations, validations)
        if self.config.debug:
            self.store_funky(data)
        return False, runtime_avg/num

    def store_funky(self, data):
        # store funky input for further analysis 
        filename = f"%s/funky/payload_%04x%02x" % (self.config.workdir, self.num_funky, self.pid)
        atomic_write(filename, data)
        self.num_funky += 1



    def validate_bits(self, data, old_node, default_info):
        new_bitmap, _ = self.execute(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        old_bits.update(old_node["new_bits"])
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def validate_bytes(self, data, old_node, default_info):
        new_bitmap, _ = self.execute(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def execute_redqueen(self, data):
        # execute in trace mode, then restore settings
        # setting a timeout seems to interfere with tracing
        self.statistics.event_exec_redqueen()
        self.q.qemu_aux_buffer.set_redqueen_mode(True)
        exec_res = self.execute_naked(data, timeout=0)
        self.q.qemu_aux_buffer.set_redqueen_mode(False)
        return exec_res

    def __send_to_manager(self, data, exec_res, info):
        info["time"] = time.time()
        info["exit_reason"] = exec_res.exit_reason
        info["performance"] = exec_res.performance
        info["hash"]        = exec_res.hash()
        info["starved"]     = exec_res.starved
        info["trashed"]     = exec_res.trashed
        if self.conn is not None:
            self.conn.send_new_input(data, exec_res.copy_to_array(), info)

    def trace_payload(self, data, info):
        # Legacy implementation of -trace (now -trace_cb) using libxdc_edge_callback hook.
        # This is generally slower and produces different bitmaps so we execute it in
        # a different phase as part of calibration stage.
        # Optionally pickup pt_trace_dump* files as well in case both methods are enabled.
        trace_edge_in = self.config.workdir + "/redqueen_workdir_%d/pt_trace_results.txt" % self.pid
        trace_dump_in = self.config.workdir + "/pt_trace_dump_%d" % self.pid
        trace_edge_out = self.config.workdir + "/traces/fuzz_cb_%05d.lst" % info['id']
        trace_dump_out = self.config.workdir + "/traces/fuzz_cb_%05d.bin" % info['id']

        self.logger.info("Tracing payload_%05d..", info['id'])

        if len(data) > self.payload_size:
            data = data[:self.payload_size]

        try:
            self.q.set_payload(data)
            old_timeout = self.q.get_timeout()
            self.q.set_timeout(0)
            self.q.set_trace_mode(True)
            exec_res = self.q.send_payload()

            self.q.set_trace_mode(False)
            self.q.set_timeout(old_timeout)

            if os.path.exists(trace_edge_in):
                with open(trace_edge_in, 'rb') as f_in:
                    with lz4.LZ4FrameFile(trace_edge_out + ".lz4", 'wb',
                            compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                        shutil.copyfileobj(f_in, f_out)

            if os.path.exists(trace_dump_in):
                with open(trace_dump_in, 'rb') as f_in:
                    with lz4.LZ4FrameFile(trace_dump_out + ".lz4", 'wb',
                            compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                        shutil.copyfileobj(f_in, f_out)

            if not exec_res.is_regular():
                self.statistics.event_reload(exec_res.exit_reason)
                self.q.reload()
        except Exception as e:
            self.logger.info("Failed to produce trace %s: %s (skipping..)", trace_edge_out, e)
            return None

        return exec_res

    def execute_naked(self, data, timeout=None):

        if len(data) > self.payload_size:
            data = data[:self.payload_size]

        if timeout:
            old_timeout = self.q.get_timeout()
            self.q.set_timeout(timeout)

        exec_res = self.__execute(data)

        if timeout:
            self.q.set_timeout(old_timeout)

        # restart Qemu on crash
        if exec_res.is_crash():
            self.statistics.event_reload(exec_res.exit_reason)
            self.q.reload()

        return exec_res


    def __execute(self, data, retry=0):

        try:
            self.q.set_payload(data)
            res = self.q.send_payload()
            self.statistics.event_exec(bb_cov=self.q.bb_seen, trashed=res.trashed)
            return res
        except (ValueError, BrokenPipeError, ConnectionResetError) as e:
            if retry > 2:
                # TODO if it reliably kills qemu, perhaps log to Manager for harvesting..
                self.logger.error("Aborting due to repeated SHM/socket error.")
                raise QemuIOException("Qemu SHM/socket failure.") from e

            self.logger.warn("Qemu SHM/socket error (retry %d)", retry)
            self.statistics.event_reload("shm/socket error")
            if not self.q.restart():
                raise QemuIOException("Qemu restart failure.") from e
        return self.__execute(data, retry=retry+1)


    def execute(self, data, info, hard_timeout=False):

        if len(data) > self.payload_size:
            data = data[:self.payload_size]

        exec_res = self.__execute(data)

        is_new_input = self.bitmap_storage.should_send_to_manager(exec_res, exec_res.exit_reason)
        crash = exec_res.is_crash()
        stable = False

        # -trace_cb causes slower execution and different bitmap computation
        # if both -trace and -trace_cb is provided, we must delay tracing to calibration stage
        trace_pt = self.config.trace and not self.config.trace_cb

        # store crashes and any validated new behavior
        # do not validate timeouts and crashes at this point as they tend to be nondeterministic
        if is_new_input:
            if not crash:
                assert exec_res.is_lut_applied()

                if self.config.funky:
                    stable, runtime = self.funky_validate(data, exec_res, trace=trace_pt)
                    exec_res.performance = runtime
                else:
                    stable, runtime = self.quick_validate(data, exec_res, trace=trace_pt)
                    exec_res.performance = (exec_res.performance + runtime)/2

                if trace_pt and stable:
                    trace_in = "%s/pt_trace_dump_%d" % (self.config.workdir, self.pid)
                    if os.path.exists(trace_in):
                        with tempfile.NamedTemporaryFile(delete=False,dir=self.config.workdir + "/traces") as f:
                            shutil.move(trace_in, f.name)
                            info['pt_dump'] = f.name
                if not stable:
                    # TODO: auto-throttle persistent runs based on funky rate?
                    self.logger.debug("Input validation failed! Target funky?..")
                    self.statistics.event_funky()
            if exec_res.exit_reason == "timeout" and not hard_timeout:
                # re-run payload with max timeout
                # can be quite slow, so we only do this if prior run has some new edges or t_check=True.
                # t_dyn should grow over time and eventually include slower inputs up to max timeout
                maybe_new_regular = self.bitmap_storage.should_send_to_manager(exec_res, "regular")
                if self.t_check or maybe_new_regular:
                    dyn_timeout = self.q.get_timeout()
                    self.q.set_timeout(self.t_hard)
                    # if still new, register the payload as regular or (true) timeout
                    exec_res, is_new = self.execute(data, info, hard_timeout=True)
                    self.q.set_timeout(dyn_timeout)
                    if is_new and exec_res.exit_reason != "timeout":
                        self.logger.debug("Timeout checker found non-timeout with runtime %f >= %f!" % (exec_res.performance, dyn_timeout))
                    else:
                        # uselessly spend time validating a soft-timeout
                        # log it so user may adjust soft-timeout handling
                        self.statistics.event_reload("slow")
                    # sub-call to execute() has submitted the payload if relevant, so we can just return its result here
                    return exec_res, is_new

            if crash and self.config.log_crashes:
                self.q.store_crashlogs(exec_res.exit_reason, exec_res.hash())

            if crash or stable:
                self.__send_to_manager(data, exec_res, info)

        # restart Qemu on crash
        if crash:
            self.statistics.event_reload(exec_res.exit_reason)
            self.q.reload()

        return exec_res, is_new_input
