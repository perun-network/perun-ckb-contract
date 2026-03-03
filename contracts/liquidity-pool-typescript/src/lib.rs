//! liquidity-pool-typescript – library wrapper
//!
//! For on-chain binary builds: `src/main.rs` is the crate root.
//! For library / test builds (feature = "library"): this file is the root
//! and exposes `program_entry` by pulling in `main.rs` as a sub-module.
#![cfg_attr(not(feature = "library"), no_std)]
#![allow(special_module_name)]
#![allow(unused_attributes)]

#[cfg(feature = "library")]
extern crate alloc;

#[cfg(feature = "library")]
mod main;
#[cfg(feature = "library")]
pub use main::program_entry;
