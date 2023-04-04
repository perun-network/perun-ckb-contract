// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::{Source},
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    high_level::{load_cell_lock_hash, load_script, load_cell_lock},
    syscalls::{SysError},
};
use perun_common::perun_types::ChannelParameters;

use crate::error::Error;

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    debug!("script args is {:?}", args);

    // return an error if args is invalid
    if args.is_empty() {
        return Err(Error::NoArgs);
    }

    let params = ChannelParameters::from_slice(&args).expect("unable to parse args as channel parameters");

    let is_participant = check_is_participant(&params)?;

    if !is_participant {
        return Err(Error::NotParticipant);
    }

    return Ok(());
}

// check_is_participant checks if the current transaction is executed by a channel participant.
// It does so by checking if a pay2pubkeyhash cell to a channel participant is present in the inputs.
pub fn check_is_participant(params: &ChannelParameters) -> Result<bool, Error> {
    // look for a pay2pubkeyhash script in the inputs
    let p2pkh_code_hash : Bytes = [0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9, 0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8].to_vec().into();
    for i in 0.. {
        // Loop over all input cells.
        let lock_hash = match load_cell_lock_hash(i, Source::Input) {
            Ok(lock_hash) => lock_hash,
            Err(SysError::IndexOutOfBound) => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        if lock_hash[..] == p2pkh_code_hash[..] {
            let payment_script = load_cell_lock(i, Source::Input).unwrap();
            let payment_args: Bytes = payment_script.args().unpack();
            if payment_args[..] == params.participants().nth0().payment_args().as_slice()[..] ||
                payment_args[..] == params.participants().nth1().payment_args().as_slice()[..] {
                return Ok(true);
            }
        }
    }
    Ok(false)
}