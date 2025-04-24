#![cfg_attr(not(feature = "library"), no_std)]
#![allow(special_module_name)]
#![allow(unused_attributes)]

use ckb_std::default_alloc;

ckb_std::entry!(program_entry);
default_alloc!();

use perun_common::error::Error;

pub fn program_entry() -> i8 {
    match main() {
        Ok(_) => 0,   // Success
        Err(_) => -1, // Failure
    }
}

pub fn main() -> Result<(), Error> {
    Ok(())
}
