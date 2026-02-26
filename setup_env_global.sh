#!/bin/sh

# Helper script to set the correct environment for build and test

if [ "$1" = "build" ]; then
    echo "🔧 Setting environment for BUILD (RISC-V)..."
    export RUSTFLAGS="-C linker=rust-lld"
    export CARGO_TARGET_RISCV64IMAC_UNKNOWN_NONE_ELF_LINKER=rust-lld
    export SYSROOT=/usr/riscv64-linux-gnu
    export TARGET_CC=riscv64-unknown-elf-gcc
    export TARGET_AR=riscv64-unknown-elf-ar
    export CC=riscv64-unknown-elf-gcc
    export C_INCLUDE_PATH="$SYSROOT/include"
    export CFLAGS="--sysroot=$SYSROOT -I/usr/lib/gcc/riscv64-unknown-elf/10.2.0/include -I/usr/lib/gcc/riscv64-unknown-elf/10.2.0/include-fixed"
    export TARGET_CFLAGS="--sysroot=$SYSROOT -I/usr/lib/gcc/riscv64-unknown-elf/10.2.0/include -I/usr/lib/gcc/riscv64-unknown-elf/10.2.0/include-fixed"

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
