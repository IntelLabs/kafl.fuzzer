import os
import re
from contextlib import suppress
from pathlib import Path
from argparse import Namespace

from appdirs import AppDirs
from dynaconf import Dynaconf, Validator

from typing import List

CUR_DIR = Path(__file__).parent
APPNAME = 'kAFL'
SETTINGS_FILENAME = "settings.yaml"

# default values for Validators
DEFAULT_PROCESSES = 1
DEFAULT_CPU_OFFSET = 0
DEFAULT_TIMEOUT_SOFT = 1/1000
DEFAULT_KICKSTART = 256
DEFAULT_AFL_ARTIH_MAX = 34
DEFAULT_QEMU_MEMORY = 256
DEFAULT_QEMU_CONFIG_BASE = '-enable-kvm -machine kAFL64-v1 -cpu kAFL64-Hypervisor-v1,+vmx -no-reboot -net none -display none'
DEFAULT_RELOAD = 1
DEFAULT_TIMEOUT_HARD = 4
DEFAULT_PAYLOAD_SIZE = 131072
DEFAULT_BITMAP_SIZE = 65536
DEFAULT_ITERATIONS = 5

VALID_DEBUG_ACTIONS = ["benchmark", "gdb", "trace", "single", "trace-qemu", "noise", "printk", "redqueen",
                   "redqueen-qemu", "verify"]

def app_settings_files() -> List[str]:
    settings_files = [
        # default config
        str(CUR_DIR / f"default_{SETTINGS_FILENAME}"),
        # /etc/xdg/kAFL/
        str(Path(appdirs.site_config_dir) / SETTINGS_FILENAME),
        # $HOME/.config/kAFL
        str(Path(appdirs.user_config_dir) / SETTINGS_FILENAME),
        # local
        "kafl.yaml",
    ]
    # env var KAFL_CONFIG_FILE if present
    try:
        settings_files.append(os.environ['KAFL_CONFIG_FILE'])
    except KeyError:
        pass
    return settings_files

appdirs = AppDirs(APPNAME)
settings = Dynaconf(
    envvar_prefix=APPNAME.upper(),
    settings_files=app_settings_files()
)

# validator condition funcs
def is_dir(value) -> bool:
    return Path(value).is_dir()

def is_file(value) -> bool:
    return Path(value).is_file()

# TODO: should be used to validate --afl-skip-range
# def parse_ignore_range(string: str) -> bool:
#     m = re.match(r"(\d+)(?:-(\d+))?$", string)
#     if not m:
#         raise argparse.ArgumentTypeError("'" + string + "' is not a range of number.")
#     start = min(int(m.group(1)), int(m.group(2)))
#     end = max(int(m.group(1)), int(m.group(2))) or start
#     if end > (128 << 10):
#         raise argparse.ArgumentTypeError("Value out of range (max 128KB).")

#     if start == 0 and end == (128 << 10):
#         raise argparse.ArgumentTypeError("Invalid range specified.")
#     return list([start, end])

def cast_ip_range_to_list(parameter: str) -> List[int]:
    """Checks that a given IP range string is valid and returns a List of that range"""
    m = re.match(r"([(0-9abcdef]{1,16})(?:-([0-9abcdef]{1,16}))?$", parameter.replace("0x", "").lower())
    if not m:
        raise ValueError(f"{parameter}: invalid range specified: not a number")
    # check that start < end
    start = min(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16))
    end = max(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16)) or start
    if start > end:
        raise ValueError(f"{parameter}: invalid range specified: start > end")
    return [start, end]

# register validators
settings.validators.register(
    # general
    Validator("work_dir", must_exist=True, cast=Path),
    Validator("purge", default=False, cast=bool),
    Validator("resume", default=False, cast=bool),
    Validator("processes", default=DEFAULT_PROCESSES, cast=int),
    Validator("verbose", default=False, cast=bool),
    Validator("quiet", default=False, cast=bool),
    Validator("log", default=False, cast=bool),
    Validator("debug", default=False, cast=bool),
    # fuzz
    Validator("seed_dir", default=None, condition=is_dir),
    Validator("dict", default=None, condition=is_file),
    Validator("funky", default=False, cast=bool),
    Validator("afl_dump_mode", default=False, cast=bool),
    Validator("afl_skip_zero", default=False, cast=bool),
    # Validator("afl-skip-range", default=None),
    Validator("afl_arith_max", default=DEFAULT_AFL_ARTIH_MAX, cast=int),
    Validator("radamsa", default=False, cast=bool),
    Validator("redqueen", default=False, cast=bool),
    Validator("redqueen_hashes", default=False, cast=bool),
    Validator("redqueen_hammer", default=False, cast=bool),
    Validator("redqueen_simple", default=False, cast=bool),
    Validator("cpu_offset", default=DEFAULT_CPU_OFFSET, cast=int),
    Validator("abort_time", default=None),
    Validator("abort_exec", default=None),
    Validator("timeout_soft", default=DEFAULT_TIMEOUT_SOFT, cast=float),
    Validator("timeout_check", default=False, cast=bool),
    Validator("kickstart", default=DEFAULT_KICKSTART, cast=int),
    Validator("radamsa_path", default=None, condition=is_file),
    # qemu
    Validator("qemu_image", default=None, condition=is_file),
    Validator("qemu_snapshot", default=None, condition=is_dir),
    Validator("qemu_bios", default=None, condition=is_file),
    Validator("qemu_kernel", default=None, condition=is_file),
    Validator("qemu_initrd", default=None, condition=is_file),
    Validator("qemu_append", default=None),
    Validator("qemu_memory", default=DEFAULT_QEMU_MEMORY, cast=int),
    Validator("qemu_base", default=DEFAULT_QEMU_CONFIG_BASE),
    Validator("qemu_serial", default=None),
    Validator("qemu_extra", default=None),
    Validator("qemu_path", condition=is_file),
    Validator("ip0", default=None, cast=cast_ip_range_to_list),
    Validator("ip1", default=None, cast=cast_ip_range_to_list),
    Validator("ip2", default=None, cast=cast_ip_range_to_list),
    Validator("ip3", default=None, cast=cast_ip_range_to_list),
    Validator("sharedir", default=None, condition=is_dir),
    Validator("reload", default=DEFAULT_RELOAD, cast=int),
    Validator("gdbserver", default=False, cast=bool),
    Validator("log_hprintf", default=False, cast=bool),
    Validator("log_crashes", default=False, cast=bool),
    Validator("timeout_hard", default=DEFAULT_TIMEOUT_HARD, cast=float),
    Validator("payload_size", default=DEFAULT_PAYLOAD_SIZE, cast=int),
    Validator("bitmap_size", default=DEFAULT_PAYLOAD_SIZE, cast=int),
    Validator("trace", default=False, cast=bool),
    Validator("trace_cb", default=False, cast=bool),
    # debug
    Validator("input", condition=lambda x: Path(x).exists()),
    Validator("iterations", default=DEFAULT_ITERATIONS, cast=int),
    Validator("action", is_in=VALID_DEBUG_ACTIONS),
    Validator("ptdump_path", condition=is_file)
)

def update_from_namespace(namespace: Namespace):
    """Update dynaconf settings from an argparse Namespace"""
    global settings
    # get dict from namespace
    dict_namespace = vars(namespace)
    # exclude entries with None values
    dict_namespace = {k:v for k,v in dict_namespace.items() if v is not None}
    # remove extra attributes which are not cmdline arguments
    with suppress(KeyError):
        del dict_namespace['func']
    # update dynaconf settings
    settings.update(dict_namespace)


def validate():
    """Validate Dynaconf configuration.
    
    the settings.validators.validate() function cannot be relied upon because of a bug in Dynaconf."""
    global settings
    settings.validators.validate()
    # workaround Dynaconf bug
    # https://github.com/dynaconf/dynaconf/issues/834
    for validator in settings.validators:
        cast_func = validator.cast
        try:
            settings[validator.names[0]] = cast_func(settings[validator.names[0]])
        except KeyError:
            pass
