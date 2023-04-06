// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{
        bytes::Bytes,
        packed::{Byte32, Script},
        prelude::*,
    },
    high_level::{load_cell_lock, load_cell_lock_hash, load_cell_type, load_script},
    syscalls::SysError,
};
use perun_common::{error::Error, perun_types::ChannelConstants};

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    // return an error if args is invalid
    if !args.is_empty() {
        return Err(Error::PCLSWithArgs);
    }

    let idx = get_own_input_index(&script)?;
    let type_script = load_cell_type(idx, Source::Input)?.expect("type script not found");
    let type_script_args: Bytes = type_script.args().unpack();

    let constants = ChannelConstants::from_slice(&type_script_args)
        .expect("unable to parse args as channel parameters");

    let is_participant = verify_is_participant(
        &constants.pcls_unlock_script_hash(),
        &constants.params().party_a().unlock_args().unpack(),
        &constants.params().party_b().unlock_args().unpack(),
    )?;

    if !is_participant {
        return Err(Error::NotParticipant);
    }

    return Ok(());
}

// check_is_participant checks if the current transaction is executed by a channel participant.
// It does so by checking if a pay2pubkeyhash cell to a channel participant is present in the inputs.
pub fn verify_is_participant(
    unlock_script_hash: &Byte32,
    unlock_args_a: &Bytes,
    unlock_args_b: &Bytes,
) -> Result<bool, Error> {
    // look for a pay2pubkeyhash script in the inputs
    let unlock_script_hash_array = unlock_script_hash.unpack();
    for i in 0.. {
        // Loop over all input cells.
        let lock_hash = match load_cell_lock_hash(i, Source::Input) {
            Ok(lock_hash) => lock_hash,
            Err(SysError::IndexOutOfBound) => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        if lock_hash[..] == unlock_script_hash_array[..] {
            let unlock_script = load_cell_lock(i, Source::Input).unwrap();
            let unlock_script_args: Bytes = unlock_script.args().unpack();
            if unlock_script_args[..] == unlock_args_a[..]
                || unlock_script_args[..] == unlock_args_b[..]
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn get_own_input_index(own_script: &Script) -> Result<usize, Error> {
    for i in 0.. {
        let cell_lock_hash = load_cell_lock_hash(i, Source::Input)?;
        if cell_lock_hash[..] == own_script.code_hash().unpack()[..] {
            return Ok(i);
        }
    }
    Err(Error::OwnIndexNotFound)
}
