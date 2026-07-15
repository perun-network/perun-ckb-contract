#!/bin/sh

# Helper script to set the correct environment for build and test

if [ "$1" = "build" ]; then
    echo "🔧 Setting environment for BUILD (RISC-V)..."
    unset RUSTFLAGS
    export CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER=rust-lld
    export CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_RUSTFLAGS="-C linker=rust-lld"
    export TARGET_CC=riscv64-unknown-elf-gcc
    export TARGET_AR=riscv64-unknown-elf-ar
    # Use target-scoped C toolchain flags so host (x86_64) builds are not polluted.
    export CC_riscv64imac_unknown_none_elf=clang-18
    export CFLAGS_riscv64imac_unknown_none_elf="-I/usr/riscv64-linux-gnu/include"
    unset CC
    unset CFLAGS
    unset C_INCLUDE_PATH
    unset TARGET_CFLAGS

elif [ "$1" = "test" ]; then
    echo "🧪 Setting environment for TEST (x86_64)..."
    export RUSTFLAGS=""
    unset CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER
    unset CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_RUSTFLAGS
    unset TARGET_CC
    unset TARGET_AR
    unset CC_riscv64imac_unknown_none_elf
    unset CFLAGS_riscv64imac_unknown_none_elf
    unset C_INCLUDE_PATH
    unset CFLAGS
    unset TARGET_CFLAGS
    unset CC
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="gcc"

fi