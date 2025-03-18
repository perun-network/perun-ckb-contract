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
```export RUSTFLAGS="-C linker=rust-lld"
export CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER=rust-lld
export TARGET_CC=riscv64-unknown-elf-gcc
export TARGET_AR=riscv64-unknown-elf-ar
export C_INCLUDE_PATH=/usr/riscv64-linux-gnu/include
export CFLAGS="-I/usr/riscv64-linux-gnu/include"
export TARGET_CFLAGS="-I/usr/riscv64-linux-gnu/include"```