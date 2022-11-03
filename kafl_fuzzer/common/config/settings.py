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
    Validator("work_dir", must_exist=True),
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
