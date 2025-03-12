#![no_std]
#![no_main]

mod lib;

use ckb_std::default_alloc;

// Set up memory allocator
default_alloc!();

// Define the script's entry point by linking it to `lib::main`
ckb_std::entry!(lib::program_entry);
