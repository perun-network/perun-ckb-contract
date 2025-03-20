# Notes
## Goal
Migrate Capsule project into a project consistent with [CKP-script-templates](https://github.com/cryptape/ckb-script-templates).

## Steps
* Generated ckb-script workspace
* Copied script code from capsule project to workspace contracts folder
* Update dependencies
* Add tests

## Problems

### 1: Missing string.h When Building for riscv64imac-unknown-none-elf
When compiling the project for RISC-V, the blake2b-rs dependency requires string.h, which is missing in the cross-compilation environment. This leads to build errors.
To solve this we need to set and unset the environment variables:
```
export RUSTFLAGS="-C linker=rust-lld"
export CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER=rust-lld
export TARGET_CC=riscv64-unknown-elf-gcc
export TARGET_AR=riscv64-unknown-elf-ar
export C_INCLUDE_PATH=/usr/riscv64-linux-gnu/include
export CFLAGS="-I/usr/riscv64-linux-gnu/include"
export TARGET_CFLAGS="-I/usr/riscv64-linux-gnu/include"
```
### 2: ckb-testtool script building
When running tests we get the error at perun-channel-typescript `verify_valid_lock_script(...)`:
```[contract debug] hash: Byte32(0x82b899a99feaee6e1e48305c4c7c52fc2fa37a60e55ad667e115ad7e3e81eccf)
[contract debug] invalid type Byte(0x01), Byte(0x02)


opening channel: Error { details: "Script(TransactionScriptError { source: Outputs[1].Type, cause: ValidationFailure: see error code -1 on page https://nervosnetwork.github.io/ckb-script-error-codes/by-type-hash/a1af60c2193ddac558f440939e446f40acf9a3fd83c16c52f78c5d02a89eedfb.html#-1 })" }
thread 'tests::channel_test_bench' panicked at tests/src/tests.rs:110:14:
```
this is most likely a result of the dependency updates.
