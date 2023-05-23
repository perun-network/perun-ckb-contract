// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{load_cell_lock_hash, load_script, load_cell_data},
    syscalls::SysError,
};
use perun_common::error::Error;


pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    // return success if owner mode is true
    if check_owner_mode(&args)? {
        return Ok(());
    }

    let inputs_amount = collect_inputs_amount()?;
    let outputs_amount = collect_outputs_amount()?;

    if inputs_amount < outputs_amount {
        return Err(Error::DecreasingAmount);
    }

    Ok(())
}

pub fn check_owner_mode(args: &Bytes) -> Result<bool, Error> {
    // With owner lock script extracted, we will look through each input in the
    // current transaction to see if any unlocked cell uses owner lock.
    for i in 0.. {
        // check input's lock_hash with script args
        let lock_hash = match load_cell_lock_hash(
            i,
            Source::Input,
        ) {
            Ok(lock_hash) => lock_hash,
            Err(SysError::IndexOutOfBound) => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        // invalid length of loaded data
        if args[..] == lock_hash[..] {
           return Ok(true);
        }
    }
    Ok(false)
}

const UDT_LEN: usize = 16;

pub fn collect_inputs_amount() -> Result<u128, Error> {
    // let's loop through all input cells containing current UDTs,
    // and gather the sum of all input tokens.
    let mut inputs_amount: u128 = 0;
    let mut buf = [0u8; UDT_LEN];

    // u128 is 16 bytes
    for i in 0.. {
        let data = match load_cell_data(i, Source::GroupInput) {
            Ok(data) => data,
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };

        if data.len() != UDT_LEN {
            return Err(Error::Encoding);
        }
        buf.copy_from_slice(&data);
        inputs_amount += u128::from_le_bytes(buf);
    }
    Ok(inputs_amount)
}

fn collect_outputs_amount() -> Result<u128, Error> {
    // With the sum of all input UDT tokens gathered, let's now iterate through
    // output cells to grab the sum of all output UDT tokens.
    let mut outputs_amount: u128 = 0;

    // u128 is 16 bytes
    let mut buf = [0u8; UDT_LEN];
    for i in 0.. {
        let data = match load_cell_data(i, Source::GroupOutput) {
            Ok(data) => data,
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };

        if data.len() != UDT_LEN {
            return Err(Error::Encoding);
        }
        buf.copy_from_slice(&data);
        outputs_amount += u128::from_le_bytes(buf);
    }
    Ok(outputs_amount)
}