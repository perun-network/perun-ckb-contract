// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html

use perun_common::error::Error;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, packed::Byte32, prelude::*},
    high_level::{load_cell_type_hash, load_script, load_transaction},
};

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
//#note: basically checks that the channel cell is present in the inputs of the transaction and if it is, then it allows the Tx to occur
//this means that it delegates the actual logic of whether the transaction is valid to the pcts script
pub fn verify_pcts_in_inputs(pcts_script_hash: &[u8; 32]) -> Result<(), Error> {
    let num_inputs = load_transaction()?.raw().inputs().len();
    for i in 0..num_inputs {
        match load_cell_type_hash(i, Source::Input)? {  //#note load the hash of the type-script of the i-th input cell and match
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
