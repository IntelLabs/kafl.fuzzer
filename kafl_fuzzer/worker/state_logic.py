# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Main logic used by Worker to push nodes through various fuzzing stages/mutators.
"""

import time

from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.technique.grimoire_inference import GrimoireInference
from kafl_fuzzer.technique.redqueen.colorize import ColorizerStrategy
from kafl_fuzzer.technique.redqueen.mod import RedqueenInfoGatherer
from kafl_fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from kafl_fuzzer.technique import trim, bitflip, arithmetic, interesting_values, havoc, radamsa
from kafl_fuzzer.technique import grimoire_mutations as grimoire
#from kafl_fuzzer.technique.trim import perform_trim, perform_center_trim, perform_extend
#import kafl_fuzzer.technique.bitflip as bitflip
#import kafl_fuzzer.technique.havoc as havoc
#import kafl_fuzzer.technique.radamsa as radamsa
#import kafl_fuzzer.technique.interesting_values as interesting_values

class FuzzingStateLogic:
    HAVOC_MULTIPLIER = 4
    RADAMSA_DIV = 10
    COLORIZATION_COUNT = 1
    COLORIZATION_STEPS = 1500
    COLORIZATION_TIMEOUT = 5

    def __init__(self, worker, config):
        self.worker = worker
        self.logger = self.worker.logger
        self.config = config
        self.grimoire = GrimoireInference(config, self.validate_bytes)
        havoc.init_havoc(config)
        radamsa.init_radamsa(config, self.worker.pid)

        self.stage_info = {}
        self.stage_info_start_time = None
        self.stage_info_execs = None
        self.stage_info_findings = 0
        self.attention_secs_start = None
        self.attention_execs_start = None

    def __str__(self):
        return str(self.worker)

    def create_limiter_map(self, payload):
        limiter_map = bytearray([1 for _ in range(len(payload))])
        if self.config.afl_skip_range:
            for ignores in self.config.afl_skip_range:
                self.logger.debug("AFL ignore-range 0: " + str(ignores[0]) + " " + str(min(ignores[0], len(payload))))
                self.logger.debug("AFL ignore-range 1: " + str(ignores[1]) + " " + str(min(ignores[1], len(payload))))
                for i in range(min(ignores[0], len(payload)), min(ignores[1], len(payload))):
                    limiter_map[i] = 0

        return limiter_map

    def stage_timeout_reached(self, limit=20):
        if time.time() - self.stage_info_start_time > limit:
            return True
        else:
            return False

    def create_update(self, new_state, additional_data):
        ret = {}
        ret["state"] = new_state
        ret["attention_execs"] = self.stage_info_execs
        ret["attention_secs"] = time.time() - self.stage_info_start_time
        ret["state_time_initial"] = self.initial_time
        ret["state_time_havoc"] = self.havoc_time
        ret["state_time_splice"] = self.splice_time
        ret["state_time_radamsa"] = self.radamsa_time
        ret["state_time_grimoire"] = self.grimoire_time
        ret["state_time_grimoire_inference"] = self.grimoire_inference_time
        ret["state_time_redqueen"] = self.redqueen_time
        ret["performance"] = self.performance

        if additional_data:
            ret.update(additional_data)

        return ret

    def process_import(self, payload, metadata):
        self.init_stage_info(metadata)
        self.handle_import(payload, metadata)

    def process_kickstart(self, kick_len):
        metadata = {"state": {"name": "kickstart"}, "id": 0}
        self.init_stage_info(metadata)
        self.handle_kickstart(kick_len, metadata)

    def process_node(self, payload: bytes, metadata):
        self.init_stage_info(metadata)

        if metadata["state"]["name"] == "initial":
            new_payload = self.handle_initial(payload, metadata)
            return self.create_update({"name": "redq/grim"}, None), new_payload
        elif metadata["state"]["name"] == "redq/grim":
            grimoire_info = self.handle_grimoire_inference(payload, metadata)
            self.handle_redqueen(payload, metadata)
            return self.create_update({"name": "deterministic"}, {"grimoire": grimoire_info}), None
        elif metadata["state"]["name"] == "deterministic":
            resume, afl_det_info = self.handle_deterministic(payload, metadata)
            if resume:
                return self.create_update({"name": "deterministic"}, {"afl_det_info": afl_det_info}), None
            return self.create_update({"name": "havoc"}, {"afl_det_info": afl_det_info}), None
        elif metadata["state"]["name"] == "havoc":
            self.handle_havoc(payload, metadata)
            return self.create_update({"name": "final"}, None), None
        elif metadata["state"]["name"] == "final":
            self.handle_havoc(payload, metadata)
            return self.create_update({"name": "final"}, None), None
        else:
            raise ValueError("Unknown task stage %s" % metadata["state"]["name"])

    def init_stage_info(self, metadata, verbose=False):
        stage = metadata["state"]["name"]
        nid = metadata["id"]

        self.stage_info["stage"] = stage
        self.stage_info["parent"] = nid
        self.stage_info["method"] = "fixme"

        self.stage_info_start_time = time.time()
        self.stage_info_execs = 0
        self.attention_secs_start = metadata.get("attention_secs", 0)
        self.attention_execs_start = metadata.get("attention_execs", 0)
        self.performance = metadata.get("performance", 0)

        self.initial_time = 0
        self.havoc_time = 0
        self.splice_time = 0
        self.radamsa_time = 0
        self.grimoire_time = 0
        self.grimoire_inference_time = 0
        self.redqueen_time = 0

        self.worker.statistics.event_stage(stage, nid)

    def stage_update_label(self, method):
        self.stage_info["method"] = method
        self.worker.statistics.event_method(method)

    def get_parent_info(self, extra_info=None):
        info = self.stage_info.copy()
        info["parent_execs"] = self.attention_execs_start + self.stage_info_execs
        info["parent_secs"]  = self.attention_secs_start  + time.time() - self.stage_info_start_time

        if extra_info:
            info.update(extra_info)
        return info

    def handle_import(self, payload, metadata):
        # for funky targets, retry seed a couple times to avoid false negatives
        retries = 1
        if self.config.funky:
            retries = 8

        for _ in range(retries):
            _, is_new = self.execute(payload, label="import")
            if is_new: break

        # Inform user if seed yields no new coverage. This may happen if -ip0 is
        # wrong or the harness is buggy.
        if not is_new:
            self.logger.debug("Imported payload produced no new coverage, skipping..")

    def handle_kickstart(self, kick_len, metadata):
        # random injection loop to kickstart corpus with no seeds, or to scan/test a target
        busy_timeout = 5
        start_time = time.time()
        while (time.time() - start_time) < busy_timeout:
            payload = rand.bytes(kick_len)
            self.execute(payload, label="kickstart")

    def handle_initial(self, payload, metadata):
        time_initial_start = time.time()

        if self.config.trace_cb:
            self.stage_update_label("trace")
            self.worker.trace_payload(payload, metadata)

        self.stage_update_label("calibrate")
        # Update input performance using multiple randomized executions
        # Scheduler will de-prioritize execution of very slow nodes..
        num_execs = 10
        timer_start = time.time()
        havoc.mutate_seq_havoc_array(payload, self.execute, num_execs)
        timer_end = time.time()
        self.performance = (timer_end-timer_start) / num_execs

        # Trimming only for stable + non-crashing inputs
        if metadata["info"]["exit_reason"] != "regular": #  or metadata["info"]["stable"]:
            self.logger.debug("Validate: Skip trimming..")
            return None

        if metadata['info']['starved']:
            return trim.perform_extend(payload, metadata, self.execute, self.worker.payload_size)

        new_payload = trim.perform_trim(payload, metadata, self.execute)

        center_trim = True
        if center_trim:
            new_payload = trim.perform_center_trim(new_payload, metadata, self.execute)

        self.initial_time += time.time() - time_initial_start
        if new_payload == payload:
            return None
        #self.logger.debug("before trim:\t\t{}".format(repr(payload)), self)
        #self.logger.debug("after trim:\t\t{}".format(repr(new_payload)), self)
        return new_payload

    def handle_grimoire_inference(self, payload, metadata):
        grimoire_info = {}

        if not self.config.grimoire:
            return grimoire_info
        if len(metadata["new_bytes"]) <= 0 or len(payload) >= 16384:
            return grimoire_info

        self.stage_update_label("grim_infer")
        start_time = time.time()

        generalized_input = self.grimoire.generalize_input(payload, metadata)

        if generalized_input is None:
            return grimoire_info

        grimoire_info["generalized_input"] = generalized_input

        self.grimoire_inference_time = time.time() - start_time
        self.logger.debug("Grimoire generalization took %d seconds", self.grimoire_inference_time)
        self.logger.debug("Number of unique generalized inputs: %d", len(list(self.grimoire.generalized_inputs.keys())))
        return grimoire_info

    def __perform_grimoire(self, payload, metadata):
        perf = 1 / metadata["performance"]
        grimoire_input = None

        if "grimoire" in metadata:
            if "generalized_input" in metadata["grimoire"]:
                grimoire_input = metadata["grimoire"]["generalized_input"]

        self.stage_update_label("grim_havoc")
        if grimoire_input:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER * 2.0)
            if len(self.grimoire.generalized_inputs) < havoc_amount / 4:
                havoc_amount = len(self.grimoire.generalized_inputs) * 2
            grimoire.havoc(tuple(grimoire_input), self.execute, self.grimoire, havoc_amount, generalized=True)
        else:
            havoc_amount = havoc.havoc_range(perf * self.HAVOC_MULTIPLIER)
            if len(self.grimoire.generalized_inputs) < havoc_amount / 4:
                havoc_amount = len(self.grimoire.generalized_inputs)
            generalized_input = tuple([b''] + [bytes([c]) for c in payload] + [b''])
            grimoire.havoc(generalized_input, self.execute, self.grimoire, havoc_amount, generalized=False)

    def handle_redqueen(self, payload, metadata):
        redqueen_start_time = time.time()
        if self.config.redqueen:
            self.__perform_redqueen(payload, metadata)
        self.redqueen_time += time.time() - redqueen_start_time

    def handle_havoc(self, payload: bytes, metadata):
        havoc_afl = True
        havoc_splice = True
        havoc_radamsa = self.config.radamsa
        havoc_grimoire = self.config.grimoire
        havoc_redqueen = self.config.redqueen

        for i in range(1):
            # Dict based on RQ learned tokens
            # TODO: AFL only has deterministic dict stage for manual dictionary.
            # However RQ dict and auto-dict actually grow over time. Perhaps
            # create multiple dicts over time and store progress in metadata?
            if havoc_redqueen:
                self.__perform_rq_dict(payload, metadata)

            if havoc_grimoire:
                grimoire_start_time = time.time()
                self.__perform_grimoire(payload, metadata)
                self.grimoire_time += time.time() - grimoire_start_time

            if havoc_radamsa:
                radamsa_start_time = time.time()
                self.__perform_radamsa(payload, metadata)
                self.radamsa_time += time.time() - radamsa_start_time

            if havoc_afl:
                havoc_start_time = time.time()
                self.__perform_havoc(payload, metadata, use_splicing=False)
                self.havoc_time += time.time() - havoc_start_time

            if havoc_splice:
                splice_start_time = time.time()
                self.__perform_havoc(payload, metadata, use_splicing=True)
                self.splice_time += time.time() - splice_start_time

        self.logger.debug("HAVOC times: afl: %.1f, splice: %.1f, grim: %.1f, rdmsa: %.1f", self.havoc_time, self.splice_time, self.grimoire_time, self.radamsa_time)


    def validate_bytes(self, payload, metadata, extra_info=None):
        self.stage_info_execs += 1
        # FIXME: can we lift this function from worker to this class and avoid this wrapper?
        parent_info = self.get_parent_info(extra_info)
        return self.worker.validate_bytes(payload, metadata, parent_info)


    def execute(self, payload, label=None, extra_info=None):

        self.stage_info_execs += 1
        if label and label != self.stage_info["method"]:
            self.stage_update_label(label)

        parent_info = self.get_parent_info(extra_info)
        bitmap, is_new = self.worker.execute(payload, parent_info)
        if is_new:
            self.stage_info_findings += 1
        return bitmap, is_new


    def execute_redqueen(self, payload):
        # one regular execution to ensure all pages cached
        # also colored payload may yield new findings(?)
        self.execute(payload)
        return self.worker.execute_redqueen(payload)


    def __get_bitmap_hash(self, payload):
        bitmap, _ = self.execute(payload)
        if bitmap is None:
            return None
        return bitmap.hash()


    def __get_bitmap_hash_robust(self, payload):
        hashes = {self.__get_bitmap_hash(payload) for _ in range(3)}
        if len(hashes) == 1:
            return hashes.pop()
        # self.logger.warn("Hash doesn't seem stable")
        return None


    def __perform_redqueen(self, payload, metadata):
        self.stage_update_label("redq_color")

        orig_hash = self.__get_bitmap_hash_robust(payload)
        extension = bytes([207, 117, 130, 107, 183, 200, 143, 154])
        appended_hash = self.__get_bitmap_hash_robust(payload + extension)

        if orig_hash and orig_hash == appended_hash:
            self.logger.debug("Redqueen: Input can be extended")
            payload_array = bytearray(payload + extension)
        else:
            payload_array = bytearray(payload)

        colored_alternatives = self.__perform_coloring(payload_array)
        if colored_alternatives:
            payload_array = colored_alternatives[0]
            assert isinstance(colored_alternatives[0], bytearray), print(
                    "!! ColoredAlternatives:", repr(colored_alternatives[0]), type(colored_alternatives[0]))
        else:
            self.logger.debug("Redqueen: Input is not stable, skipping..")
            return

        self.stage_update_label("redq_trace")
        rq_info = RedqueenInfoGatherer()
        rq_info.make_paths(RedqueenWorkdir(self.worker.pid, self.config))
        rq_info.verbose = False
        for pld in colored_alternatives:
            if self.execute_redqueen(pld):
                rq_info.get_info(pld)

        rq_info.get_proposals()
        self.stage_update_label("redq_mutate")
        rq_info.run_mutate_redqueen(payload_array, self.execute)

        #if self.mode_fix_checksum:
        #    for addr in rq_info.get_hash_candidates():
        #        self.redqueen_state.add_candidate_hash_addr(addr)

        # for addr in rq_info.get_boring_cmps():
        #    self.redqueen_state.blacklist_cmp_addr(addr)
        # self.redqueen_state.update_redqueen_blacklist(RedqueenWorkdir(0))


    def dilate_effector_map(self, effector_map, limiter_map):
        ignore_limit = 2
        effector_map[0] = 1
        effector_map[-1] = 1
        for i in range(len(effector_map) // ignore_limit):
            base = i * ignore_limit
            effector_slice = effector_map[base:base + ignore_limit]
            limiter_slice = limiter_map[base:base + ignore_limit]
            if any(effector_slice) and any(limiter_slice):
                for j in range(len(effector_slice)):
                    effector_map[i + j] = 1

    def handle_deterministic(self, payload, metadata):
        if self.config.afl_dumb_mode:
            return False, {}

        skip_zero = self.config.afl_skip_zero
        arith_max = self.config.afl_arith_max
        use_effector_map = not self.config.afl_no_effector and len(payload) > 128
        limiter_map = self.create_limiter_map(payload)
        effector_map = None

        # Mutable payload allows faster bitwise manipulations
        payload_array = bytearray(payload)
        
        default_info = {"stage": "flip_1"}
        det_info = metadata.get("afl_det_info", default_info)

        # Walking bitflips
        if det_info["stage"] == "flip_1":
            bitflip.mutate_seq_walking_bits(payload_array,      self.execute, skip_null=skip_zero, effector_map=limiter_map)
            bitflip.mutate_seq_two_walking_bits(payload_array,  self.execute, skip_null=skip_zero, effector_map=limiter_map)
            bitflip.mutate_seq_four_walking_bits(payload_array, self.execute, skip_null=skip_zero, effector_map=limiter_map)

            det_info["stage"] = "flip_8"
            if self.stage_timeout_reached():
                return True, det_info

        # Walking byte sets..
        if det_info["stage"] == "flip_8":
            # Generate AFL-style effector map based on walking_bytes()
            if use_effector_map:
                self.logger.debug("Preparing effector map..")
                effector_map = bytearray(limiter_map)

            bitflip.mutate_seq_walking_byte(payload_array, self.execute, skip_null=skip_zero, limiter_map=limiter_map, effector_map=effector_map)

            if use_effector_map:
                self.dilate_effector_map(effector_map, limiter_map)
            else:
                effector_map = limiter_map

            bitflip.mutate_seq_two_walking_bytes(payload_array,  self.execute, effector_map=effector_map)
            bitflip.mutate_seq_four_walking_bytes(payload_array, self.execute, effector_map=effector_map)

            det_info["stage"] = "arith"
            if effector_map:
                det_info["eff_map"] = bytearray(effector_map)
            if self.stage_timeout_reached():
                return True, det_info

        # Arithmetic mutations..
        if det_info["stage"] == "arith":
            effector_map = det_info.get("eff_map", None)
            arithmetic.mutate_seq_8_bit_arithmetic(payload_array,  self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
            arithmetic.mutate_seq_16_bit_arithmetic(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
            arithmetic.mutate_seq_32_bit_arithmetic(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)

            det_info["stage"] = "intr"
            if self.stage_timeout_reached():
                return True, det_info

        # Interesting value mutations..
        if det_info["stage"] == "intr":
            effector_map = det_info.get("eff_map", None)
            interesting_values.mutate_seq_8_bit_interesting(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map)
            interesting_values.mutate_seq_16_bit_interesting(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
            interesting_values.mutate_seq_32_bit_interesting(payload_array, self.execute, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)

            det_info["stage"] = "done"

        return False, det_info


    def __perform_rq_dict(self, payload_array, metadata):
        rq_dict = havoc.get_redqueen_dict()
        counter = 0
        seen_addr_to_value = havoc.get_redqueen_seen_addr_to_value()
        if len(payload_array) < 256:
            for addr in rq_dict:
                for repl in rq_dict[addr]:
                    if addr in seen_addr_to_value and (
                            len(seen_addr_to_value[addr]) > 32 or repl in seen_addr_to_value[addr]):
                        continue
                    if not addr in seen_addr_to_value:
                        seen_addr_to_value[addr] = set()
                    seen_addr_to_value[addr].add(repl)
                    self.logger.debug("RQ-Dict: attempting %s ", repr(repl))
                    for apply_dict in [havoc.dict_insert_sequence, havoc.dict_replace_sequence]:
                        for i in range(len(payload_array)-len(repl)):
                            counter += 1
                            mutated = apply_dict(payload_array, repl, i)
                            self.execute(mutated, label="redq_dict")
        self.logger.debug("RedQ-Dict: Have performed %d iters", counter)


    def __perform_radamsa(self, payload_array, metadata):
        perf = metadata["performance"]
        radamsa_amount = havoc.havoc_range(self.HAVOC_MULTIPLIER/perf) // self.RADAMSA_DIV

        self.stage_update_label("radamsa")
        radamsa.mutate_seq_radamsa_array(payload_array, self.execute, radamsa_amount)

    def __perform_havoc(self, payload_array: bytes, metadata, use_splicing):
        perf = metadata["performance"]
        havoc_amount = havoc.havoc_range(self.HAVOC_MULTIPLIER / perf)

        if use_splicing:
            self.stage_update_label("afl_splice")
            havoc.mutate_seq_splice_array(payload_array, self.execute, havoc_amount)
        else:
            self.stage_update_label("afl_havoc")
            havoc.mutate_seq_havoc_array(payload_array, self.execute, havoc_amount)


    def __check_colorization(self, orig_hash, payload_array, min, max):
        backup = payload_array[min:max]
        for i in range(min, max):
            payload_array[i] = rand.int(255)
        new_hash = self.__get_bitmap_hash(payload_array)
        if new_hash is not None and new_hash == orig_hash:
            return True
        else:
            payload_array[min:max] = backup
            return False

    def __colorize_payload(self, orig_hash, payload_array):
        def checker(min_i, max_i):
            self.__check_colorization(orig_hash, payload_array, min_i, max_i)

        c = ColorizerStrategy(len(payload_array), checker)
        t = time.time()
        i = 0
        while True:
            if i >= FuzzingStateLogic.COLORIZATION_STEPS and time.time() - t > FuzzingStateLogic.COLORIZATION_TIMEOUT:  # TODO add to config
                break
            if len(c.unknown_ranges) == 0:
                break
            c.colorize_step()
            i += 1


    def __perform_coloring(self, payload_array):
        self.logger.debug("Redqueen: Initial colorize...")
        orig_hash = self.__get_bitmap_hash_robust(payload_array)
        if orig_hash is None:
            return None

        colored_arrays = []
        for i in range(FuzzingStateLogic.COLORIZATION_COUNT):
            if len(colored_arrays) >= FuzzingStateLogic.COLORIZATION_COUNT:
                assert False  # TODO remove me
            tmpdata = bytearray(payload_array)
            self.__colorize_payload(orig_hash, tmpdata)
            new_hash = self.__get_bitmap_hash(tmpdata)
            if new_hash is not None and new_hash == orig_hash:
                colored_arrays.append(tmpdata)
            else:
                return None

        colored_arrays.append(payload_array)
        return colored_arrays
