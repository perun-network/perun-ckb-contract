// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{load_cell_lock_hash, load_cell_type, load_script},
    syscalls::SysError,
};
use perun_common::{error::Error, perun_types::ChannelConstants};

// The perun-channel-lockscript (pcls) is used to lock access to interacting with a channel and is attached as lock script
// to the cell containing the perun-channel-type-script (pcts).
//
// > ian: Cell which data is the code of pcts, or cell which uses pcts as its type script?
//
// A channel defines two participants, each of which has their own unlock_script_hash (also defined in the ChannelConstants.params.{party_a,party_b}).
// The pcls allows a transaction to interact with the channel, if at least one input cell is present with:
// - cell's lock script hash == unlock_script_hash of party_a or
// - cell's lock script hash == unlock_script_hash of party_b
// We recommend using the secp256k1_blake160_sighash_all script as unlock script and corresponding payment args for the participants.
//
// Note: This means, that each participant needs to use a secp256k1_blake160_sighash_all as input to interact with the channel.
// This should not be a substantial restriction, since a payment input will likely be used anyway (e.g. for funding or fees).

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    // return an error if args is invalid
    if !args.is_empty() {
        return Err(Error::PCLSWithArgs);
    }

    // locate the ChannelConstants in the type script of the input cell.
    let type_script = load_cell_type(0, Source::GroupInput)?.expect("type script not found");
    let type_script_args: Bytes = type_script.args().unpack();

    let constants = ChannelConstants::from_slice(&type_script_args)
        .expect("unable to parse args as channel parameters");

    let is_participant = verify_is_participant(
        &constants.params().party_a().unlock_script_hash().unpack(),
        &constants.params().party_a().unlock_script_hash().unpack(),
    )?;

    if !is_participant {
        return Err(Error::NotParticipant);
    }

    return Ok(());
}

/// check_is_participant checks if the current transaction is executed by a channel participant.
/// It does so by looking for an input cell with the same lock script hash as the unlock_script_hash
pub fn verify_is_participant(
    unlock_script_hash_a: &[u8; 32],
    unlock_script_hash_b: &[u8; 32],
) -> Result<bool, Error> {
    for i in 0.. {
        // Loop over all input cells.
        let cell_lock_script_hash = match load_cell_lock_hash(i, Source::Input) {
            Ok(lock_hash) => lock_hash,
            Err(SysError::IndexOutOfBound) => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        if cell_lock_script_hash[..] == unlock_script_hash_a[..]
            || cell_lock_script_hash[..] == unlock_script_hash_b[..]
        {
            return Ok(true);
        }
    }
    Ok(false)
}
