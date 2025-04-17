// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use perun_common::error::Error;

// The perun-channel-lockscript (pcls) is used to lock access to interacting with a channel and is attached as lock script
// to the channel-cell (the cell which uses the perun-channel-type-script (pcts) as its type script).
// A channel defines two participants, each of which has their own unlock_script_hash (also defined in the ChannelConstants.params.{party_a,party_b}).
// The pcls allows a transaction to interact with the channel, if at least one input cell is present with:
// - cell's lock script hash == unlock_script_hash of party_a or
// - cell's lock script hash == unlock_script_hash of party_b
// We recommend using the secp256k1_blake160_sighash_all script as unlock script and corresponding payment args for the participants.
//
// Note: This means, that each participant needs to use a secp256k1_blake160_sighash_all as input to interact with the channel.
// This should not be a substantial restriction, since a payment input will likely be used anyway (e.g. for funding or fees).

pub fn main() -> Result<(), Error> {
    Ok(())
}
