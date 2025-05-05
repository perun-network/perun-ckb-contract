#!/bin/sh

# Helper script to set the correct environment for build and test

if [ "$1" = "build" ]; then
    echo "🔧 Setting environment for BUILD (RISC-V)..."
    export RUSTFLAGS="-C linker=rust-lld"
    export CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER=rust-lld
    export TARGET_CC=riscv64-unknown-elf-gcc
    export TARGET_AR=riscv64-unknown-elf-ar
    export C_INCLUDE_PATH=/usr/riscv64-linux-gnu/include
    export CFLAGS="-I/usr/riscv64-linux-gnu/include"
    export TARGET_CFLAGS="-I/usr/riscv64-linux-gnu/include"
    export CC=clang-18

elif [ "$1" = "test" ]; then
    echo "🧪 Setting environment for TEST (x86_64)..."
    export RUSTFLAGS=""
    unset CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER
    unset TARGET_CC
    unset TARGET_AR
    unset C_INCLUDE_PATH
    unset CFLAGS
    unset TARGET_CFLAGS
    unset CC
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="gcc"

fi
