import os
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
    # qemu
    Validator("qemu_image", default=None, condition=is_file)
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
