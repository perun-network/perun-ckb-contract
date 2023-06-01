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

Build contracts:

``` sh
capsule build
```

Run tests:

``` sh
capsule test
```

## perun-common
Additionally to the available contracts we extracted common functionality into
its own `perun-common` crate which gives some additional helpers and
convenience functions when interacting with types used in Perun contracts.
