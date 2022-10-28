import os
from pathlib import Path

from appdirs import AppDirs
from dynaconf import Dynaconf
from dynaconf.base import LazySettings

from argparse import Namespace
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
        # local where the program is started
        SETTINGS_FILENAME
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

# register validators
# settings.validators.register()



def update_settings_from_cmdline(args: Namespace) -> LazySettings:
    global settings
    # update settings

    # validate config
    # settings.validators.validate()
    return settings
