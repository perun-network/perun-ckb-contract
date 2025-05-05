<h1 align="center"><br>
    <a href="https://perun.network/"><img src=".assets/go-perun.png" alt="Perun" width="196"></a>
<br></h1>

<h2 align="center">Perun CKB Contracts </h2>

<p align="center">
  <a href="https://www.apache.org/licenses/LICENSE-2.0.txt"><img src="https://img.shields.io/badge/license-Apache%202-blue" alt="License: Apache 2.0"></a>
  <a href="https://github.com/perun-network/perun-ckb-contract/actions/workflows/rust.yml"><img src="https://github.com/perun-network/perun-ckb-contract/actions/workflows/rust.yml/badge.svg?branch=dev" alt="CI status"></a>
</p>

# [Perun](https://perun.network/) CKB contracts

This repository contains the scripts used to realize Perun channels on CKB.
There are three scripts available:

## perun-channel-lockscript
This script is used to handle access-rights to the live Perun channel cell.
It ensures that only participants of the Perun channel in question are able to
consume the live channel cell.

## perun-channel-typescript
This script is used to handle a Perun channel's state progression on-chain.
Basically a NFT script with extra functionality.

## perun-funds-lockscript
This script handle access rights to all funds belonging to a Perun channel.
It ensures that only channel participants are able to consume said funds.

## Prerequisites
Update the rustc version to 1.85.0 and install the following:
```
sudo apt install gcc-riscv64-unknown-elf binutils-riscv64-unknown-elf \
libc6-dev-riscv64-cross libc6-riscv64-cross linux-libc-dev-riscv64-cross
```
```
wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 18 && rm llvm.sh
```
```
cargo install cargo-generate
```
Add the target:
```
rustup target add riscv64imac-unknown-none-elf
```

## Build and Test
Build contracts:

``` sh
chmod +x ./setup_env.sh
```

``` sh
make prepare
```

``` sh
source ./setup_env.sh build && make build
```

Run tests:

``` sh
source ./setup_env.sh test && make test
```
or run them using the IDE

## perun-common
Additionally, to the available contracts we extracted common functionality into
its own `perun-common` crate which gives some additional helpers and
convenience functions when interacting with types used in Perun contracts.

## Problems
### 1. Missing file gnu/stubs-lp64.h
A common issue when compiling for RISC-V is the missing file: `gnu/stubs-lp64.h`

If the necessary packages are already installed, the file `/usr/riscv64-linux-gnu/include/gnu/stubs-lp64d.h`
should exist instead. This is due to the toolchain using the lp64d ABI (which includes double-precision floating point support) rather than plain lp64.

To resolve this, simply create a symbolic link:
```
sudo ln -s /usr/riscv64-linux-gnu/include/gnu/stubs-lp64d.h /usr/riscv64-linux-gnu/include/gnu/stubs-lp64.h
```

Then try compiling again.
