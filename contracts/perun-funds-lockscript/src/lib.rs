#![cfg_attr(not(feature = "library"), no_std)]
#![allow(special_module_name)]
#![allow(unused_attributes)]

use ckb_std::default_alloc;

ckb_std::entry!(program_entry);
default_alloc!();

use perun_common::error::Error;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, packed::Byte32, prelude::*},
    high_level::{load_cell_type_hash, load_script, load_transaction},
};

/// **Main entry point for contract**
pub fn program_entry() -> i8 {
    match main() {
        Ok(_) => 0,   // Success
        Err(_) => -1, // Failure
    }
}

// The Perun Funds Lock Script can be unlocked by including an input cell with the pcts script hash
// that is specified in the args of the pfls.
pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    if args.is_empty() {
        return Err(Error::NoArgs);
    }

    let pcts_script_hash = Byte32::from_slice(&args)?;

    return verify_pcts_in_inputs(&pcts_script_hash.unpack());
}

pub fn verify_pcts_in_inputs(pcts_script_hash: &[u8; 32]) -> Result<(), Error> {
    let num_inputs = load_transaction()?.raw().inputs().len();
    for i in 0..num_inputs {
        match load_cell_type_hash(i, Source::Input)? {
            Some(cell_type_script_hash) => {
                if cell_type_script_hash[..] == pcts_script_hash[..] {
                    return Ok(());
                } else {
                    continue;
                }
            }
            None => continue,
        };
    }
    Err(Error::PCTSNotFound)
}
