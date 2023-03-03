# 🌟 Features

# ✨ Improvements

- refactor kafl command-line with subcommands (#22)
    - move kafl scripts into a single kafl entrypoint:
        - `kafl_fuzz.py`    -> `kafl fuzz`
        - `kafl_debug.py`   -> `kafl debug`
        - `kafl_cov.py`     -> `kafl cov`
        - `kafl_plot.py`    -> `kalf plot`
        - `kafl_gui.py`     -> `kafl gui`
        - `scripts/mcat.py` -> `kafl mcat`
    - option `--afl-skip-ranges` has been removed (never used anyway)
    - removed config override via `$PWD/kafl.yaml` (not explicit, users don't expect that behavior)
    - rename and reformat `$WORKDIR/config` (MessagePack) -> `$WORKDIR/config.yaml` (YAML)
- add early logging of fuzzer loaded configuration before validation (#38)
    - deprecate `KAFL_CONFIG_DEBUG`
- remove `pygraphviz` dependency (#43)
- `input` config key will default to the `workdir` value (#58)
    - no need to specify `kafl cov --input $KAFL_WORKDIR` anymore

# 🔧 Fixes

- avoid Qemu hang when handling ABORT in pre-init phase (#34)
- fix including `default_settings.yaml` in the final package (#35)
- remove dynaconf validation workaround (#60)
- fix appdirs import (#61)

# 📖 Documentation

- add `docs/fuzzer_configuration.md` to document new configuration management based on Dynaconf (#22)

# 🧰 Behind the scenes

