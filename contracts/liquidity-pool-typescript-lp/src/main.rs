#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

extern crate alloc as _alloc;
use _alloc::vec::Vec;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
use ckb_std::default_alloc;
#[cfg(not(any(feature = "library", test)))]
default_alloc!();

use perun_common::{
    error::Error,
    pool_lp::{LPCell, PoolWitness},
};

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{load_cell_data, load_cell_lock_hash, load_script, load_witness_args},
    syscalls::SysError,
};

pub fn program_entry() -> i8 {
    match main() {
        Ok(_) => 0,
        Err(e) => e.into(),
    }
}

struct GroupContext {
    lp_inputs: Vec<LPCell>,
    lp_outputs: Vec<LPCell>,
}

fn main() -> Result<(), Error> {
    let pool_id = load_pool_id()?;
    let ctx = collect_group()?;
    verify_pool_ids(&ctx, &pool_id)?;
    let witness = load_pool_witness()?;

    match witness {
        PoolWitness::LPDeposit => check_lp_deposit(&ctx),
        PoolWitness::LPWithdraw { ckb_out } => check_lp_withdraw(&ctx, ckb_out),
        PoolWitness::FundChannelExtract {
            channel_id: _,
            contribution_id: _,
            extract_ckb,
        } => check_fund_channel_extract(&ctx, extract_ckb),
        PoolWitness::SettleChannelInsert {
            channel_id: _,
            contribution_id: _,
            principal_returned,
            fee_ckb,
            price_x64: _,
        } => check_settle_channel_insert(&ctx, principal_returned, fee_ckb),
        PoolWitness::CancelReservation {
            channel_id: _,
            contribution_id: _,
        } => check_cancel_reservation(&ctx),
        PoolWitness::RotateOperator {
            new_operator_lock_hash,
        } => check_rotate_operator(&ctx, &new_operator_lock_hash),
    }
}

fn load_pool_id() -> Result<[u8; 32], Error> {
    let args: Bytes = load_script()?.args().unpack();
    if args.len() < 32 {
        return Err(Error::PoolLSNoArgs);
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&args[..32]);
    Ok(id)
}

fn load_pool_witness() -> Result<PoolWitness, Error> {
    let wa = load_witness_args(0, Source::GroupInput)?;
    let raw = wa
        .input_type()
        .to_opt()
        .ok_or(Error::PoolWitnessMissing)?
        .raw_data();
    PoolWitness::decode(raw.as_ref())
}

fn collect_group() -> Result<GroupContext, Error> {
    let mut ctx = GroupContext {
        lp_inputs: Vec::new(),
        lp_outputs: Vec::new(),
    };

    for idx in 0usize.. {
        match load_cell_data(idx, Source::GroupInput) {
            Ok(d) => {
                if LPCell::is_lp_cell(d.as_ref()) {
                    ctx.lp_inputs.push(LPCell::decode(d.as_ref())?);
                }
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }

    for idx in 0usize.. {
        match load_cell_data(idx, Source::GroupOutput) {
            Ok(d) => {
                if LPCell::is_lp_cell(d.as_ref()) {
                    ctx.lp_outputs.push(LPCell::decode(d.as_ref())?);
                }
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }

    if ctx.lp_inputs.is_empty() && ctx.lp_outputs.is_empty() {
        return Err(Error::PoolInvalidCellMagic);
    }

    Ok(ctx)
}

fn verify_pool_ids(ctx: &GroupContext, expected: &[u8; 32]) -> Result<(), Error> {
    for lp in ctx.lp_inputs.iter().chain(&ctx.lp_outputs) {
        if &lp.pool_id != expected {
            return Err(Error::PoolIdMismatch);
        }
    }
    Ok(())
}

fn verify_operator_signing(operator_lock_hash: &[u8; 32]) -> Result<(), Error> {
    for i in 0usize.. {
        match load_cell_lock_hash(i, Source::Input) {
            Ok(h) if h.as_slice() == operator_lock_hash => return Ok(()),
            Ok(_) => continue,
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::OperatorNotSigning)
}

fn one_lp_in_out(ctx: &GroupContext) -> Result<(&LPCell, &LPCell), Error> {
    if ctx.lp_inputs.len() != 1 || ctx.lp_outputs.len() != 1 {
        return Err(Error::MultipleLPCells);
    }
    Ok((&ctx.lp_inputs[0], &ctx.lp_outputs[0]))
}

fn check_lp_deposit(ctx: &GroupContext) -> Result<(), Error> {
    if ctx.lp_outputs.is_empty() {
        return Err(Error::LPCellOutputMissing);
    }
    Ok(())
}

fn check_lp_withdraw(ctx: &GroupContext, ckb_out: u64) -> Result<(), Error> {
    if ckb_out == 0 {
        return Err(Error::PoolCKBAmountZero);
    }
    if ctx.lp_inputs.is_empty() {
        return Err(Error::LPCellInputMissing);
    }
    Ok(())
}

fn check_fund_channel_extract(ctx: &GroupContext, extract_ckb: u64) -> Result<(), Error> {
    if extract_ckb == 0 {
        return Err(Error::PoolCKBAmountZero);
    }
    let (inp, _) = one_lp_in_out(ctx)?;
    verify_operator_signing(&inp.operator_lock_hash)?;
    Ok(())
}

fn check_settle_channel_insert(
    ctx: &GroupContext,
    principal_returned: u64,
    fee_ckb: u64,
) -> Result<(), Error> {
    if principal_returned == 0 && fee_ckb == 0 {
        return Err(Error::InvalidSettlement);
    }
    let (inp, _) = one_lp_in_out(ctx)?;
    verify_operator_signing(&inp.operator_lock_hash)?;
    Ok(())
}

fn check_cancel_reservation(ctx: &GroupContext) -> Result<(), Error> {
    let (inp, _) = one_lp_in_out(ctx)?;
    verify_operator_signing(&inp.operator_lock_hash)?;
    Ok(())
}

fn check_rotate_operator(ctx: &GroupContext, new_operator_lock_hash: &[u8; 32]) -> Result<(), Error> {
    let (inp, out) = one_lp_in_out(ctx)?;
    verify_operator_signing(&inp.operator_lock_hash)?;
    if &out.operator_lock_hash != new_operator_lock_hash {
        return Err(Error::LPBadOperatorRotation);
    }
    Ok(())
}
