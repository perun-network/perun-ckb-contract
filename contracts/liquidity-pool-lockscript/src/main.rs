/*!
 * liquidity-pool-lockscript  –  main entry / implementation
 *
 * The lock script placed on every **pool-state cell**.  It requires that the
 * corresponding pool typescript is running in the same transaction, delegating
 * all state-transition logic there.
 *
 * # Args (32 bytes)
 * Full script hash of the pool typescript for this pool instance.
 *
 * # Security invariant
 * A pool-state cell can never be consumed without the typescript's validation
 * because the lockscript will reject any transaction that does not include a
 * cell with the expected type-script hash.
 */
#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
use ckb_std::default_alloc;
#[cfg(not(any(feature = "library", test)))]
default_alloc!();

use perun_common::error::Error;

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{load_cell_type_hash, load_script, load_transaction},
    syscalls::SysError,
};

pub fn program_entry() -> i8 {
    match main() {
        Ok(_) => 0,
        Err(e) => e.into(),
    }
}

fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    // Args must be exactly 32 bytes: the pool typescript's full script hash.
    if args.len() != 32 {
        return Err(Error::PoolLSNoArgs);
    }

    let pool_ts_hash: [u8; 32] = args.as_ref().try_into().map_err(|_| Error::PoolLSNoArgs)?;

    verify_pool_typescript_in_inputs(&pool_ts_hash)
}

/// Scan all input cells; succeed if any has a type-script hash matching
/// `pool_ts_hash`.  This guarantees the pool typescript script is running
/// and will validate the operation.
fn verify_pool_typescript_in_inputs(pool_ts_hash: &[u8; 32]) -> Result<(), Error> {
    let num_inputs = load_transaction()?.raw().inputs().len();
    for i in 0..num_inputs {
        match load_cell_type_hash(i, Source::Input) {
            Ok(Some(ts_hash)) => {
                if &ts_hash == pool_ts_hash {
                    return Ok(());
                }
            }
            Ok(None) => continue,
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::PoolTypescriptNotFound)
}
