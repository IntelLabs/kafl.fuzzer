import os
import re
from contextlib import suppress
from pathlib import Path
from argparse import Namespace

from appdirs import AppDirs
from dynaconf import Dynaconf, Validator, ValidationError, loaders, LazySettings
from dynaconf.utils.boxing import DynaBox

from typing import List, Optional, Any

CUR_DIR = Path(__file__).parent
APPNAME = 'kAFL'
SETTINGS_FILENAME = "settings.yaml"

VALID_DEBUG_ACTIONS = ["benchmark", "gdb", "trace", "single", "trace-qemu", "noise", "printk", "redqueen",
                   "redqueen-qemu", "verify"]

# default internal to kAFL
DEFAULT_CONFIG_FILENAME = "config.yaml"

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
    env_config_file = os.environ.get('KAFL_CONFIG_FILE', None)
    if env_config_file is not None:
        # check if file exists and raise an error if not to warn user
        if not Path(env_config_file).is_file():
            raise ValidationError(f"KAFL_CONFIG_FILE: {env_config_file} not found")
        settings_files.append(env_config_file)
    return settings_files

appdirs = AppDirs(APPNAME)
settings = Dynaconf(
    envvar_prefix=APPNAME.upper(),
    settings_files=app_settings_files()
)

# validator condition funcs
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

def cast_ip_range_to_list(parameter: Any) -> Optional[List[int]]:
    """Checks that a given IP range string is valid and returns a List of that range"""
    if parameter is None:
        return None
    m = re.match(r"([(0-9abcdef]{1,16})(?:-([0-9abcdef]{1,16}))?$", parameter.replace("0x", "").lower())
    if not m:
        raise ValueError(f"{parameter}: invalid range specified: not a number")
    # check that start < end
    start = min(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16))
    end = max(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16)) or start
    if start > end:
        raise ValueError(f"{parameter}: invalid range specified: start > end")
    return [start, end]

def cast_expand_path(parameter: Any) -> Optional[str]:
    if parameter is None:
        return None
    exp_str = os.path.expandvars(parameter)
    # ensure exists
    p = Path(exp_str)
    if not p.exists():
        raise FileNotFoundError(f"Path {p} doesn't exist")
    # return string and not PosixPath, since this object is not serializable
    return str(p)

# register validators
settings.validators.register(
    # general
    Validator("work_dir", must_exist=True),
    Validator("purge", default=False, cast=bool),
    Validator("resume", default=False, cast=bool),
    Validator("processes", cast=int),
    Validator("verbose", default=False, cast=bool),
    Validator("quiet", default=False, cast=bool),
    Validator("log", default=False, cast=bool),
    Validator("debug", default=False, cast=bool),
    # fuzz
    Validator("seed_dir", default=None, cast=cast_expand_path),
    Validator("dict", default=None, cast=cast_expand_path),
    Validator("funky", default=False, cast=bool),
    Validator("afl_dump_mode", default=False, cast=bool),
    Validator("afl_skip_zero", default=False, cast=bool),
    # Validator("afl-skip-range", default=None),
    Validator("afl_arith_max", cast=int),
    Validator("radamsa", default=False, cast=bool),
    Validator("redqueen", default=False, cast=bool),
    Validator("redqueen_hashes", default=False, cast=bool),
    Validator("redqueen_hammer", default=False, cast=bool),
    Validator("redqueen_simple", default=False, cast=bool),
    Validator("cpu_offset", cast=int),
    Validator("abort_time", default=None),
    Validator("abort_exec", default=None),
    Validator("timeout_soft", cast=float),
    Validator("timeout_check", default=False, cast=bool),
    Validator("kickstart", cast=int),
    Validator("radamsa_path", default=None, cast=cast_expand_path),
    # qemu
    Validator("qemu_image", default=None, cast=cast_expand_path),
    Validator("qemu_snapshot", default=None, cast=cast_expand_path),
    Validator("qemu_bios", default=None, cast=cast_expand_path),
    Validator("qemu_kernel", default=None, cast=cast_expand_path),
    Validator("qemu_initrd", default=None, cast=cast_expand_path),
    Validator("qemu_append", default=None),
    Validator("qemu_memory", cast=int),
    Validator("qemu_base"),
    Validator("qemu_serial", default=None),
    Validator("qemu_extra", default=None),
    Validator("qemu_path", cast=cast_expand_path),
    Validator("ip0", default=None, cast=cast_ip_range_to_list),
    Validator("ip1", default=None, cast=cast_ip_range_to_list),
    Validator("ip2", default=None, cast=cast_ip_range_to_list),
    Validator("ip3", default=None, cast=cast_ip_range_to_list),
    Validator("sharedir", default=None, cast=cast_expand_path),
    Validator("reload", cast=int),
    Validator("gdbserver", default=False, cast=bool),
    Validator("log_hprintf", default=False, cast=bool),
    Validator("log_crashes", default=False, cast=bool),
    Validator("timeout_hard", cast=float),
    Validator("payload_size", cast=int),
    Validator("bitmap_size", cast=int),
    Validator("trace", default=False, cast=bool),
    Validator("trace_cb", default=False, cast=bool),
    # debug
    Validator("input", default=None, cast=cast_expand_path),
    Validator("iterations", cast=int),
    Validator("action", is_in=VALID_DEBUG_ACTIONS),
    Validator("ptdump_path", default=None, cast=cast_expand_path),
    # plot
    Validator("outfile", default=None),
    # mcat
    Validator("pack_file"),
    # internal for kAFL
    Validator("workdir_config", default=lambda config, _validator: str(Path(config.work_dir) / DEFAULT_CONFIG_FILENAME))
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

def dump_config():
    """Dump current configuration in workdir config file"""
    global settings
    # generate a dict with all the keys for the current environment
    config = settings.to_dict()
    # dump to a file, format is infered by file extension
    loaders.write(settings.workdir_config, DynaBox(config).to_dict())

def load_config() -> LazySettings:
    """Load an additional configuration file with Dynaconf and returns the settings object"""
    global settings
    settings.load_file(settings.workdir_config)
    return settings
