# perun-ckb-contracts

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
