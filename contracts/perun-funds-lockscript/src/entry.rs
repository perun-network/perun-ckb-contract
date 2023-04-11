// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc;

use perun_common::{
    error::Error,
    perun_types::{ChannelConstants, PFLSArgs},
};

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    high_level::{load_cell_type, load_cell_type_hash, load_script, load_transaction},
};

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    debug!("script args is {:?}", args);

    if args.is_empty() {
        return Err(Error::NoArgs);
    }

    let pfls_args = PFLSArgs::from_slice(&args)?;

    return verify_pcts_in_inputs(&pfls_args);
}

pub fn verify_pcts_in_inputs(pfls_args: &PFLSArgs) -> Result<(), Error> {
    let num_inputs = load_transaction()?.raw().inputs().len();
    let pcts_hash = pfls_args.pcts_hash().unpack();
    for i in 0..num_inputs {
        match load_cell_type_hash(i, Source::Input)? {
            Some(cell_type_hash) => {
                if cell_type_hash[..] != pcts_hash[..] {
                    continue;
                }
            }
            None => continue,
        };
        let cell_type_script = load_cell_type(i, Source::Input)?.unwrap();
        let cell_type_args: Bytes = cell_type_script.args().unpack();
        let channel_constants = ChannelConstants::from_slice(&cell_type_args)?;
        if channel_constants.thread_token().as_slice()[..]
            == pfls_args.thread_token().as_slice()[..]
        {
            return Ok(());
        }
    }
    Err(Error::PCTSNotFound)
}
