<h1 align="center">
  <br>kAFL-Fuzzer</br>
</h1>

<h3 align="center">
HW-assisted Feedback Fuzzer for x86 VMs
</h3>

<p align="center">
  <a href="https://github.com/IntelLabs/kafl.fuzzer/actions/workflows/ci.yml">
    <img src="https://github.com/IntelLabs/kafl.fuzzer/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://github.com/IntelLabs/kafl.fuzzer/releases">
    <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/IntelLabs/kafl.fuzzer">
  </a>
</p>


`Note: All components are provided for research and validation purposes only. Use at your own risk.`

kAFL-Fuzzer is a AFL-like fuzzer written in Python. Originally published as just "kAFL"
(and partly updated/rereleased as part of "Redqueen" and "Grimoire" projects) this project
maintains the fuzzer frontend as a separate component for use with the newer
libxdc/Qemu/KVM stack (aka. [Nyx backend](https://nyx-fuzz.com).

For installation, usage and reporting issues, please refer to [kAFL](https://github.com/IntelLabs/kAFL).
