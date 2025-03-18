# Notes
## Goal
Migrate Capsule project into a project consistent with [CKP-script-templates](https://github.com/cryptape/ckb-script-templates).

## Steps
* Generated ckb-script workspace
* Copied script code from capsule project to workspace contracts folder
* Update dependencies
* Add tests

## Problems
### 1: build and test target
To correctly generate the build files: we first need to set environment variables given in setup.env
Then to run `make test` we need to unset these variables again.
When running the automatically generated tests on x86_64-unknown-linux-gnu, we get errors like this:
```error[E0282]: type annotations needed
--> contracts/perun-channel-typescript/src/lib.rs:905:10
|
905 |         .unpack()[..]
|          ^^^^^^
|
help: try using a fully qualified path to specify the expected types
|
901 ~     if <Byte32 as ckb_std::ckb_gen_types::prelude::Unpack<T>>::unpack(&channel_constants
902 |         .params()
903 |         .party_a()
904 ~         .payment_script_hash())[..]
|
```
This means the x86_64-unknown-linux-gnu which is used for testing needs type annotations, but these will in return break the build process.

### 2: Missing string.h When Building for riscv64imac-unknown-none-elf
When compiling the project for RISC-V, the blake2b-rs dependency requires string.h, which is missing in the cross-compilation environment. This leads to build errors.
To solve this we need to set and unset the environment variables:
```export RUSTFLAGS="-C linker=rust-lld"
export CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER=rust-lld
export TARGET_CC=riscv64-unknown-elf-gcc
export TARGET_AR=riscv64-unknown-elf-ar
export C_INCLUDE_PATH=/usr/riscv64-linux-gnu/include
export CFLAGS="-I/usr/riscv64-linux-gnu/include"
export TARGET_CFLAGS="-I/usr/riscv64-linux-gnu/include"```