# 🌟 Features

- Official Github releases (https://github.com/IntelLabs/kafl.fuzzer/pull/31)

# ✨ Improvements

- turn hardcoded serial and append params into default config values (https://github.com/IntelLabs/kafl.fuzzer/pull/7)
- Smarter CPU affinity selection (https://github.com/IntelLabs/kafl.fuzzer/pull/10)
- config.py: do variable expansion for qemu_base and qemu_extra options (https://github.com/IntelLabs/kafl.fuzzer/pull/19)
- qemu.py: redirect qemu outputs on --log (https://github.com/IntelLabs/kafl.fuzzer/pull/29)

# 🔧 Fixes

- abort if both --resume and --purge are given (https://github.com/IntelLabs/kafl.fuzzer/pull/2)
- fix infinite loop in kafl_debug / gdb action (https://github.com/IntelLabs/kafl.fuzzer/pull/3)
- worker.py: fix custom timeout setting in execute_naked() (https://github.com/IntelLabs/kafl.fuzzer/pull/4)
- robustness fixes to qemu startup (https://github.com/IntelLabs/kafl.fuzzer/pull/5)
- Fix config loading defaults and error handling (https://github.com/IntelLabs/kafl.fuzzer/pull/9)
- ghidra_run.sh: fail to stderr (https://github.com/IntelLabs/kafl.fuzzer/pull/11)
- config.py: apply expand_vars only to existing config options (https://github.com/IntelLabs/kafl.fuzzer/pull/20)
- kafl_cov.py: fix handling of timeout exception (https://github.com/IntelLabs/kafl.fuzzer/pull/21)
- fix kafl_debug.py for new pt dump trace mode (https://github.com/IntelLabs/kafl.fuzzer/pull/26)
- cpu affinity: consider --cpu-offset as override to auto-detection (https://github.com/IntelLabs/kafl.fuzzer/pull/27)

# 📖 Documentation

# 🧰 Behind the scenes

- Basic CI/CD (https://github.com/IntelLabs/kafl.fuzzer/pull/16)
- Use ghidra role (https://github.com/IntelLabs/kafl.fuzzer/pull/8)
- remove install.sh (https://github.com/IntelLabs/kafl.fuzzer/pull/15)
- Replace custom logger with stdlib logging (https://github.com/IntelLabs/kafl.fuzzer/pull/17)
- tests: initialize mutation helper non-class for pytest (https://github.com/IntelLabs/kafl.fuzzer/pull/18)
- do not die on existing stackdump logs, just warn (https://github.com/IntelLabs/kafl.fuzzer/pull/24)
- cpu affinity: try to continue even if cpus seem busy (https://github.com/IntelLabs/kafl.fuzzer/pull/23)
- improve startup/failure reporting of Worker instances (https://github.com/IntelLabs/kafl.fuzzer/pull/25)
- also detect qemu.start() failure and avoid double-shutdown (https://github.com/IntelLabs/kafl.fuzzer/pull/30)
