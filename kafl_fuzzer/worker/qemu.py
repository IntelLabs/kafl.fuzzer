# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Launch Qemu VMs and execute test inputs produced by kAFL-Fuzzer.
"""

import ctypes
import mmap
import os
import socket
import struct
import subprocess
import sys
import time
import shutil
import logging

from kafl_fuzzer.common.util import strdump, print_hprintf
from kafl_fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from kafl_fuzzer.worker.execution_result import ExecutionResult
from kafl_fuzzer.worker.qemu_aux_buffer import QemuAuxBuffer
from kafl_fuzzer.worker.qemu_aux_buffer import QemuAuxRC as RC
from kafl_fuzzer.common.logger import WorkerLogAdapter
from kafl_fuzzer.common.config.settings import INTEL_PT_MAX_RANGES

class QemuIOException(Exception):
        """Exception raised when Qemu interaction fails"""
        pass

class qemu:
    payload_header_size = 4 # must correspond to set_payload() and nyx_api.h
    page_size = 4096


    def __init__(self, pid, config, debug_mode=False, notifiers=True, resume=False):

        self.debug_mode = debug_mode
        self.ijonmap_size = 0x1000 # quick fix - bitmaps are not processed!
        self.bitmap_size = config.bitmap_size
        self.payload_size = config.payload_size
        self.payload_size_aligned = ((config.payload_size + qemu.payload_header_size + qemu.page_size - 1) // qemu.page_size) * qemu.page_size
        self.config = config
        self.pid = pid
        self.alt_bitmap = bytearray(self.bitmap_size)
        self.alt_edges = 0
        self.bb_seen = 0
        self.logger_no_prefix = logging.getLogger(__name__)
        self.logger = WorkerLogAdapter(self.logger_no_prefix, {'pid': self.pid})

        self.process = None
        self.control = None
        self.exiting = False
        self.persistent_runs = 0

        workdir = self.config.workdir

        self.qemu_aux_buffer_filename = workdir + "/aux_buffer_%d" % self.pid

        self.bitmap_filename = workdir + "/bitmap_%d" % self.pid
        self.ijonmap_filename = workdir + "/ijon_%d" % self.pid
        self.payload_filename = workdir + "/payload_%d" % self.pid
        self.control_filename = workdir + "/interface_%d" % self.pid
        self.qemu_trace_log = workdir + "/qemu_trace_%02d.log" % self.pid
        self.serial_logfile = workdir + "/serial_%02d.log" % self.pid
        self.hprintf_log = self.config.log_hprintf or self.config.log_crashes
        self.hprintf_logfile = workdir + "/hprintf_%02d.log" % self.pid

        self.redqueen_workdir = RedqueenWorkdir(self.pid, config)
        self.redqueen_workdir.init_dir()

        if not resume:
            for page_cache_ext in ["lock", "dump", "addr"]:
                with open(self.config.workdir + "/page_cache." + page_cache_ext, 'w') as f:
                    f.truncate(0)

        # TODO: list append should work better than string concatenation, especially for str.replace() and later popen()
        self.cmd = self.config.qemu_base
        self.cmd += " -chardev socket,server,id=nyx_socket,path=" + self.control_filename + \
                    " -device nyx,chardev=nyx_socket" + \
                    ",workdir=" + workdir + \
                    ",worker_id=%d" % self.pid + \
                    ",bitmap_size=" + str(self.bitmap_size) + \
                    ",input_buffer_size=" + str(self.payload_size_aligned)

        if self.config.trace:
            self.cmd += ",dump_pt_trace"

        if self.config.trace_cb:
            self.cmd += ",edge_cb_trace"

        if self.config.sharedir:
            self.cmd += ",sharedir=" + self.config.sharedir

        for i in range(INTEL_PT_MAX_RANGES):
            if self.config[f"ip{i}"]:
                range_a = hex(self.config[f"ip{i}"][0]).replace("L", "")
                range_b = hex(self.config[f"ip{i}"][1]).replace("L", "")
                self.cmd += ",ip" + str(i) + "_a=" + range_a + ",ip" + str(i) + "_b=" + range_b

        self.cmd = [_f for _f in self.cmd.split(" ") if _f]

        if self.config.qemu_serial:
            # config.qemu_serial should just contain the device(s) to emulate, with id=kafl_serial
            self.cmd.extend(self.config.qemu_serial.split(" "))
            self.cmd.extend(["-chardev", "file,id=kafl_serial,mux=on,path=" + self.serial_logfile])

        self.cmd.extend(["-m", str(config.qemu_memory)])

        if self.config.log:
            self.cmd.extend(["-D", self.qemu_trace_log])
            if self.config.debug:
                self.cmd.extend(["-d", "nyx"])
                #self.cmd.extend(["-d", "kafl,trace:kvm*"])

        if self.config.gdbserver:
            self.cmd.extend(["-s", "-S"])

        # Lauch either as VM snapshot, direct kernel/initrd boot, or -bios boot
        if self.config.qemu_image:
            self.cmd.extend(["-drive", "file=" + self.config.qemu_image])
        if self.config.qemu_kernel:
            self.cmd.extend(["-kernel", self.config.qemu_kernel])
            if self.config.qemu_initrd:
                self.cmd.extend(["-initrd", self.config.qemu_initrd])
        if self.config.qemu_bios:
            self.cmd.extend(["-bios", self.config.qemu_bios])

        # Qemu -append option
        if self.config.qemu_append:
            self.cmd.extend(["-append", self.config.qemu_append])

        # Qemu extra options
        if self.config.qemu_extra:
            self.cmd.extend(self.config.qemu_extra.split(" "))

        # Fast VM snapshot configuration
        self.cmd.append("-fast_vm_reload")
        snapshot_path = workdir + "/snapshot/"

        if pid == 0 or pid == 1337 and not resume:
            # boot and create snapshot
            if self.config.qemu_snapshot:
                self.cmd.append("path=%s,load=off,pre_path=%s" % (snapshot_path, self.config.qemu_snapshot))
            else:
                self.cmd.append("path=%s,load=off" % snapshot_path)
        else:
            # boot and wait for snapshot creation (or load from existing file)
            self.cmd.append("path=%s,load=on" % (snapshot_path))

    # Asynchronous exit by Worker. Note this may be called multiple times
    # while we were in the middle of shutdown(), start(), send_payload(), ..
    def async_exit(self):
        if self.exiting:
            sys.exit(0)

        self.exiting = True
        self.shutdown()


    def shutdown(self):
        self.logger.info("Shutting down Qemu after %d execs..", self.persistent_runs)

        if not self.process:
            # start() has never been called, all files/shm are closed.
            return 0

        # If Qemu exists, try to graciously read its I/O and SIGTERM it.
        # If still alive, attempt SIGKILL or loop-wait on kill -9.
        output = ""
        try:
            self.process.terminate()
            output = strdump(self.process.communicate(timeout=1)[0], verbatim=True)
        except:
            pass

        if self.process.returncode is None:
            try:
                self.process.kill()
            except:
                pass

        self.logger.debug(f"Qemu exit code: {self.process.returncode}")

        if len(output) > 0:
            header = "\n=================<%s Console Output>==================\n" %self
            footer = "====================</Console Output>======================\n"
            self.logger.info(header + output + footer)

        try:
            self.kafl_shm.close()
        except (BufferError, AttributeError):
            pass

        try:
            self.fs_shm.close()
        except:
            pass

        try:
            os.close(self.kafl_shm_f)
        except:
            pass

        try:
            os.close(self.fs_shm_f)
        except:
            pass

        for tmp_file in [
                self.qemu_aux_buffer_filename,
                self.payload_filename,
                self.control_filename,
                self.ijonmap_filename,
                self.bitmap_filename]:
            try:
                os.remove(tmp_file)
            except:
                pass

        self.redqueen_workdir.rmtree()
        return self.process.returncode

    def start(self):

        if self.exiting:
            return False

        self.persistent_runs = 0

        # SHM files must exist on Qemu launch
        self.ijon_shm_f     = os.open(self.ijonmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.kafl_shm_f     = os.open(self.bitmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.fs_shm_f       = os.open(self.payload_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)

        os.ftruncate(self.ijon_shm_f, self.ijonmap_size)
        os.ftruncate(self.kafl_shm_f, self.bitmap_size)
        os.ftruncate(self.fs_shm_f, self.payload_size_aligned)

        if self.pid not in [0, 1337]:
            final_cmdline = ""
        else:
            final_cmdline = "\n" + self.config.qemu_path
            for arg in self.cmd:
                if arg[0] == '-':
                    final_cmdline += '\n\t' + arg
                else:
                    final_cmdline += ' ' + arg

        # delayed Qemu startup - some nasty race condition when launching too many at once
        if self.pid not in [0, 1337]:
            time.sleep(4 + 0.1*self.pid)

        self.logger.info("Launching virtual machine...%s", final_cmdline)


        # Launch Qemu. stderr to stdout, stdout is logged on VM exit
        # os.setpgrp() prevents signals from being propagated to Qemu, instead allowing an
        # organized shutdown via async_exit()
        self.process = subprocess.Popen([self.config.qemu_path] + self.cmd,
                preexec_fn=os.setpgrp,
                stdin=subprocess.DEVNULL)
                #stdin=subprocess.PIPE,
                #stdout=subprocess.PIPE,
                #stderr=subprocess.STDOUT)

        try:
            self.__qemu_connect()
            self.__qemu_handshake()
        except (OSError, BrokenPipeError, QemuIOException) as e:
            if not self.exiting:
                self.logger.error("Failed to connect to Qemu: %s", str(e))
                self.async_exit()
            return False

        self.logger.debug("Handshake done.")

        # for -R = {0,1}, set reload_mode here just once
        if self.config['reload'] == 1:
            self.qemu_aux_buffer.set_reload_mode(True)
        else:
            self.qemu_aux_buffer.set_reload_mode(False)
        self.qemu_aux_buffer.set_timeout(self.config.timeout_hard)

        return True

    # release Qemu and wait for it to return
    def run_qemu(self):
        self.control.send(b'x')
        self.control.recv(1)

    def wait_qemu(self):
        self.control.recv(1)

    def __qemu_handshake(self):

        self.wait_qemu()

        self.qemu_aux_buffer = QemuAuxBuffer(self.qemu_aux_buffer_filename)
        if not self.qemu_aux_buffer.validate_header():
            self.logger.error("Invalid header in qemu_aux_buffer.py. Abort.")
            self.async_exit()

        while self.qemu_aux_buffer.get_state() != 3:
            self.logger.debug("Waiting for target to enter fuzz mode..")
            result = self.qemu_aux_buffer.get_result()
            if result.exec_code == RC.ABORT:
                self.handle_habort()
            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()
            self.run_qemu()

        # Qemu tends to truncate / resize the files. Not sure why..
        assert(self.payload_size_aligned == os.path.getsize(self.payload_filename))
        assert(self.bitmap_size == os.path.getsize(self.bitmap_filename))
        assert(self.ijonmap_size == os.path.getsize(self.ijonmap_filename))
        self.kafl_shm = mmap.mmap(self.kafl_shm_f, 0)
        self.c_bitmap = (ctypes.c_uint8 * self.bitmap_size).from_buffer(self.kafl_shm)
        self.fs_shm = mmap.mmap(self.fs_shm_f, 0)

    def __qemu_connect(self):
        # Note: setblocking() disables the timeout! settimeout() will automatically set blocking!
        self.control = socket.socket(socket.AF_UNIX)
        self.control.settimeout(None)
        self.control.setblocking(1)

        # Wait for the socket to appear. Fail early if Qemu is done and we get no socket.
        retry_timeout = 6
        retry_interval = 0.1
        for _ in range(int(retry_timeout/retry_interval)):
            try:
                self.control.connect(self.control_filename)
                return True
            except socket.error as e:
                if self.process.poll() is not None:
                    self.logger.error("Aborting due to unexpected Qemu exit.")
                    raise e
            self.logger.debug("Waiting for Qemu connect..")
            time.sleep(retry_interval)

    def store_crashlogs(self, label, stamp):
        # Collect current/accumulated logs
        # We don't have a payload ID yet and in fact manager may refuse to store
        if self.hprintf_log and os.path.exists(self.hprintf_logfile):
            if os.path.getsize(self.hprintf_logfile) > 0:
                shutil.copy(self.hprintf_logfile, "%s/logs/%s_%s.log" % (
                    self.config.workdir, label[:5], stamp[:6]))
                os.truncate(self.hprintf_logfile, 0)

    def flush_crashlogs(self):
        if self.hprintf_log and os.path.exists(self.hprintf_logfile):
            os.truncate(self.hprintf_logfile, 0)

    def handle_hprintf(self):
        msg = self.qemu_aux_buffer.get_misc_buf()
        msg = msg.decode('latin-1', errors='backslashreplace')

        if self.hprintf_log:
            with open(self.hprintf_logfile, "a") as f:
                f.write(msg)
        elif not self.config.quiet:
            print_hprintf(msg)

    def handle_habort(self):
        msg = self.qemu_aux_buffer.get_misc_buf()
        msg = msg.decode('latin-1', errors='backslashreplace')
        msg = "Guest ABORT: %s" % msg

        self.logger.error(msg)
        if self.hprintf_log:
            with open(self.hprintf_logfile, "a") as f:
                f.write(msg)

        raise QemuIOException(msg)

    # Fully stop/start Qemu instance to store logs + possibly recover
    def restart(self):
        # Nyx backend does not tend to die anymore so this is a NOP
        # To enable recovery again, new Qemu instances must respect the snapshot
        # settings and avoid overwriting a possibly existing snapshot
        return True

    # Reset Qemu after crash/timeout - not required anymore
    def reload(self):
        return True

    # Wait forever on Qemu to execute the payload - useful for interactive debug
    def debug_payload(self):

        self.set_timeout(0)
        #self.send_payload()
        while True:
            self.run_qemu()
            result = self.qemu_aux_buffer.get_result()
            if result.page_fault:
                self.logger.warn("Unhandled page fault in debug mode!")
            if result.pt_overflow:
                self.logger.warn("PT overflow!")
            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()
                continue
            if result.exec_code == RC.ABORT:
                self.handle_habort()
            if result.exec_done:
                break

        self.logger.info("Result: %s\n", self.exit_reason(result))
        #self.audit(result)
        return result

    def send_payload(self):

        if self.exiting:
            sys.exit(0)

        # for -R > 1, count and toggle reload_mode at runtime
        # note the special syntax for config['reload'] due to dynaconfig internals
        if self.config['reload'] > 1:
            self.persistent_runs += 1
            if self.persistent_runs == 1:
                self.qemu_aux_buffer.set_reload_mode(False)
            if self.persistent_runs >= self.config['reload']:
                self.qemu_aux_buffer.set_reload_mode(True)
                self.persistent_runs = 0

        if self.config.log_crashes and self.persistent_runs == 0:
            # flush crashlogs after VM state reset (persistent_runs=0)
            self.flush_crashlogs()

        result = None
        old_address = 0
        start_time = time.time()

        while True:
            self.run_qemu()

            result = self.qemu_aux_buffer.get_result()

            if result.pt_overflow:
                self.logger.debug("PT overflow!")

            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()
                continue

            if result.exec_code == RC.ABORT:
                self.handle_habort()

            if result.exec_done:
                break

            if result.page_fault:
                self.logger.debug("Page fault encountered!")
                if result.page_fault_addr == old_address:
                    self.logger.error("Failed to resolve page after second execution! Qemu status:\n%s", str(result._asdict()))
                    break
                old_address = result.page_fault_addr
                self.qemu_aux_buffer.dump_page(result.page_fault_addr)

        # record highest seen BBs
        self.bb_seen = max(self.bb_seen, result.bb_cov)

        #runtime = result.runtime_sec + result.runtime_usec/1000/1000
        res = ExecutionResult(
                self.c_bitmap,
                self.bitmap_size,
                self.exit_reason(result),
                time.time() - start_time,
                starved = result.exec_code == RC.STARVED,
                trashed = result.pt_overflow)

        #self.audit(res.copy_to_array())
        #self.audit(bytearray(self.c_bitmap))
        return res

    def audit(self, bitmap):

        if len(bitmap) != self.bitmap_size:
            self.logger.info("bitmap size: %d" % len(bitmap))

        new_bytes = 0
        new_bits = 0
        for idx in range(self.bitmap_size):
            if bitmap[idx] != 0x00:
                if self.alt_bitmap[idx] == 0x00:
                    self.alt_bitmap[idx] = bitmap[idx]
                    new_bytes += 1
                else:
                    new_bits += 1
        if new_bytes > 0:
            self.alt_edges += new_bytes;
            self.logger.info("New bytes: %03d, bits: %03d, total edges seen: %03d", new_bytes, new_bits, self.alt_edges)


    def exit_reason(self, result):
        if result.exec_code == RC.CRASH:
            return "crash"
        if result.exec_code == RC.TIMEOUT:
            return "timeout"
        elif result.exec_code == RC.SANITIZER:
            return "kasan"
        elif result.exec_code == RC.SUCCESS:
            return "regular"
        elif result.exec_code == RC.STARVED:
            return "regular"
        else:
            raise QemuIOException("Unknown QemuAuxRC code")

    def set_timeout(self, timeout):
        assert(self.qemu_aux_buffer)
        self.qemu_aux_buffer.set_timeout(timeout)

    def get_timeout(self):
        return self.qemu_aux_buffer.get_timeout()

    def set_trace_mode(self, enable):
        assert(self.qemu_aux_buffer)
        self.qemu_aux_buffer.set_trace_mode(enable)

    def get_payload_size(self):
        return self.payload_size

    def set_payload(self, payload):
        # Ensure the payload fits into SHM. Caller has to cut off since they also report findings.
        # actual payload is limited to payload_size
        assert(len(payload) <= self.payload_size), "Payload size %d > SHM limit %d. Check size/shm config" % (len(payload),self.payload_size)

        #if len(payload) > self.payload_size:
        #    payload = payload[:self.payload_size]
        try:
            struct.pack_into("=I", self.fs_shm, 0, len(payload))
            self.fs_shm.seek(4)
            self.fs_shm.write(payload)
            #self.fs_shm.flush()
        except ValueError:
            if self.exiting:
                sys.exit(0)
            # Qemu crashed. Could be due to prior payload but more likely harness/config is broken..
            self.logger.error("Failed to set new payload - Qemu crash?")
            raise
