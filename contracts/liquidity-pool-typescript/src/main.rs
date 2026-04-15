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
    perun_types::ChannelStatus,
    pool::{LPCell, PoolWitness},
};

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{
        load_cell_capacity, load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_script,
        load_witness_args,
    },
    syscalls::SysError,
};

const POLICY_FLAG_ENFORCE_MAX_FEE: u32 = 1 << 0;
const POLICY_FLAG_ENFORCE_MIN_FEE: u32 = 1 << 1;
const POLICY_FLAG_REQUIRE_PRICE: u32 = 1 << 2;
const POLICY_FLAG_ALLOWED_MASK: u32 =
    POLICY_FLAG_ENFORCE_MAX_FEE | POLICY_FLAG_ENFORCE_MIN_FEE | POLICY_FLAG_REQUIRE_PRICE;

pub fn program_entry() -> i8 {
    match main() {
        Ok(_) => 0,
        Err(e) => e.into(),
    }
}

struct GroupContext {
    lp_inputs: Vec<(LPCell, u64)>,
    lp_outputs: Vec<(LPCell, u64)>,
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
            channel_id,
            contribution_id,
            extract_ckb,
        } => check_fund_channel_extract(&ctx, &channel_id, &contribution_id, extract_ckb),
        PoolWitness::SettleChannelInsert {
            channel_id,
            contribution_id,
            principal_returned,
            fee_ckb,
            price_x64,
        } => check_settle_channel_insert(
            &ctx,
            &channel_id,
            &contribution_id,
            principal_returned,
            fee_ckb,
            price_x64,
        ),
        PoolWitness::CancelReservation {
            channel_id,
            contribution_id,
        } => check_cancel_reservation(&ctx, &channel_id, &contribution_id),
        PoolWitness::RotateOperator {
            new_operator_lock_hash,
        } => check_rotate_operator(&ctx, &new_operator_lock_hash),
        PoolWitness::LPChallengeClose { .. } => Err(Error::PoolWitnessInvalid),
        PoolWitness::LPRecoverAfterChallenge { .. } => Err(Error::PoolWitnessInvalid),
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
                if !LPCell::is_lp_cell(d.as_ref()) {
                    return Err(Error::PoolInvalidCellMagic);
                }
                let lp = LPCell::decode(d.as_ref())?;
                let cap = load_cell_capacity(idx, Source::GroupInput)?;
                ctx.lp_inputs.push((lp, cap));
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }

    for idx in 0usize.. {
        match load_cell_data(idx, Source::GroupOutput) {
            Ok(d) => {
                if !LPCell::is_lp_cell(d.as_ref()) {
                    return Err(Error::PoolInvalidCellMagic);
                }
                let lp = LPCell::decode(d.as_ref())?;
                let cap = load_cell_capacity(idx, Source::GroupOutput)?;
                ctx.lp_outputs.push((lp, cap));
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
    for (lp, _) in ctx.lp_inputs.iter().chain(&ctx.lp_outputs) {
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

fn verify_owner_signing(owner_lock_hash: &[u8; 32]) -> Result<(), Error> {
    for i in 0usize.. {
        match load_cell_lock_hash(i, Source::Input) {
            Ok(h) if h.as_slice() == owner_lock_hash => return Ok(()),
            Ok(_) => continue,
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::InvalidSignature)
}

fn one_lp_in_out(ctx: &GroupContext) -> Result<(&LPCell, u64, &LPCell, u64), Error> {
    if ctx.lp_inputs.len() != 1 || ctx.lp_outputs.len() != 1 {
        return Err(Error::MultipleLPCells);
    }
    let (inp, inp_cap) = &ctx.lp_inputs[0];
    let (out, out_cap) = &ctx.lp_outputs[0];
    Ok((inp, *inp_cap, out, *out_cap))
}

fn checked_add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::LPArithmetic)
}

fn checked_sub(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_sub(b).ok_or(Error::LPArithmetic)
}

fn channel_capacity_by_id(channel_id: &[u8; 32], source: Source) -> Result<u64, Error> {
    let mut total = 0u64;
    for idx in 0usize.. {
        match load_cell_data(idx, source) {
            Ok(d) => {
                if let Ok(status) = ChannelStatus::from_slice(d.as_ref()) {
                    let cid: [u8; 32] = status.state().channel_id().unpack();
                    if &cid == channel_id {
                        let cap = load_cell_capacity(idx, source)?;
                        total = checked_add(total, cap)?;
                    }
                }
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(total)
}

fn channel_exists_by_id(channel_id: &[u8; 32], source: Source) -> Result<bool, Error> {
    for idx in 0usize.. {
        match load_cell_data(idx, source) {
            Ok(d) => {
                if let Ok(status) = ChannelStatus::from_slice(d.as_ref()) {
                    let cid: [u8; 32] = status.state().channel_id().unpack();
                    if &cid == channel_id {
                        return Ok(true);
                    }
                }
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}

#[derive(Clone, Copy)]
struct ChannelBinding {
    lock_hash: [u8; 32],
    type_hash: Option<[u8; 32]>,
}

fn channel_bindings_by_id(
    channel_id: &[u8; 32],
    source: Source,
) -> Result<Vec<ChannelBinding>, Error> {
    let mut bindings = Vec::new();
    for idx in 0usize.. {
        match load_cell_data(idx, source) {
            Ok(d) => {
                if let Ok(status) = ChannelStatus::from_slice(d.as_ref()) {
                    let cid: [u8; 32] = status.state().channel_id().unpack();
                    if &cid == channel_id {
                        let lock_hash_raw = load_cell_lock_hash(idx, source)?;
                        let mut lock_hash = [0u8; 32];
                        lock_hash.copy_from_slice(lock_hash_raw.as_slice());
                        let type_hash = load_cell_type_hash(idx, source)?;
                        bindings.push(ChannelBinding {
                            lock_hash,
                            type_hash,
                        });
                    }
                }
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(bindings)
}

fn require_uniform_channel_bindings(bindings: &[ChannelBinding]) -> Result<(), Error> {
    if let Some(first) = bindings.first() {
        for b in bindings.iter().skip(1) {
            if b.lock_hash != first.lock_hash || b.type_hash != first.type_hash {
                return Err(Error::LPWitnessMismatch);
            }
        }
    }
    Ok(())
}

fn require_nonzero_id(id: &[u8; 32]) -> Result<(), Error> {
    if *id == [0u8; 32] {
        return Err(Error::LPWitnessMismatch);
    }
    Ok(())
}

fn validate_policy_fields(policy: &perun_common::pool::LPPolicy) -> Result<(), Error> {
    if policy.fee_rate_bps == 0 {
        return Err(Error::LPPolicyViolation);
    }
    if policy.policy_version == 0 {
        return Err(Error::LPPolicyViolation);
    }
    if (policy.policy_flags & !POLICY_FLAG_ALLOWED_MASK) != 0 {
        return Err(Error::LPPolicyViolation);
    }
    Ok(())
}

fn owner_non_lp_capacity(owner_lock_hash: &[u8; 32], source: Source) -> Result<u64, Error> {
    let mut total = 0u64;
    for idx in 0usize.. {
        match load_cell_lock_hash(idx, source) {
            Ok(h) => {
                if h.as_slice() != owner_lock_hash {
                    continue;
                }
                let d = load_cell_data(idx, source)?;
                if LPCell::is_lp_cell(d.as_ref()) {
                    continue;
                }
                total = checked_add(total, load_cell_capacity(idx, source)?)?;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(total)
}

fn same_policy(a: &LPCell, b: &LPCell) -> bool {
    a.policy.max_trading_volume == b.policy.max_trading_volume
        && a.policy.fee_rate_bps == b.policy.fee_rate_bps
        && a.policy.policy_flags == b.policy.policy_flags
        && a.policy.policy_version == b.policy.policy_version
}

fn require_immutable_except_operator(inp: &LPCell, out: &LPCell) -> Result<(), Error> {
    if inp.pool_id != out.pool_id
        || inp.owner_lock_hash != out.owner_lock_hash
        || !same_policy(inp, out)
        || inp.active != out.active
    {
        return Err(Error::LPWitnessMismatch);
    }
    Ok(())
}

fn require_operator_unchanged(inp: &LPCell, out: &LPCell) -> Result<(), Error> {
    if inp.operator_lock_hash != out.operator_lock_hash {
        return Err(Error::LPWitnessMismatch);
    }
    Ok(())
}

fn require_nonce_inc(inp: &LPCell, out: &LPCell) -> Result<(), Error> {
    let expected = checked_add(inp.nonce, 1)?;
    if out.nonce != expected {
        return Err(Error::VersionNumberNotIncreasing);
    }
    Ok(())
}

fn check_lp_deposit(ctx: &GroupContext) -> Result<(), Error> {
    if ctx.lp_outputs.is_empty() {
        return Err(Error::LPCellOutputMissing);
    }

    if ctx.lp_inputs.is_empty() {
        if ctx.lp_outputs.len() != 1 {
            return Err(Error::MultipleLPCells);
        }
        let (out, out_cap) = &ctx.lp_outputs[0];
        if !out.active {
            return Err(Error::LPWitnessMismatch);
        }
        if out.available_ckb != *out_cap
            || out.reserved_ckb != 0
            || out.cumulative_fees_earned_ckb != 0
            || out.nonce != 0
        {
            return Err(Error::PoolReserveMismatch);
        }
        validate_policy_fields(&out.policy)?;
        return Ok(());
    }

    let (inp, inp_cap, out, out_cap) = one_lp_in_out(ctx)?;
    verify_owner_signing(&inp.owner_lock_hash)?;
    require_immutable_except_operator(inp, out)?;
    require_operator_unchanged(inp, out)?;
    require_nonce_inc(inp, out)?;

    if out_cap <= inp_cap {
        return Err(Error::PoolReserveMismatch);
    }
    let delta = checked_sub(out_cap, inp_cap)?;
    if out.available_ckb != checked_add(inp.available_ckb, delta)?
        || out.reserved_ckb != inp.reserved_ckb
        || out.cumulative_fees_earned_ckb != inp.cumulative_fees_earned_ckb
    {
        return Err(Error::PoolReserveMismatch);
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

    let (inp, inp_cap, out, out_cap) = one_lp_in_out(ctx)?;
    verify_owner_signing(&inp.owner_lock_hash)?;
    require_immutable_except_operator(inp, out)?;
    require_operator_unchanged(inp, out)?;
    require_nonce_inc(inp, out)?;

    if ckb_out > inp.available_ckb {
        return Err(Error::InsufficientCKBLiquidity);
    }
    if out_cap != checked_sub(inp_cap, ckb_out)?
        || out.available_ckb != checked_sub(inp.available_ckb, ckb_out)?
        || out.reserved_ckb != inp.reserved_ckb
        || out.cumulative_fees_earned_ckb != inp.cumulative_fees_earned_ckb
    {
        return Err(Error::PoolReserveMismatch);
    }

    let in_owner_non_lp = owner_non_lp_capacity(&inp.owner_lock_hash, Source::Input)?;
    let out_owner_non_lp = owner_non_lp_capacity(&inp.owner_lock_hash, Source::Output)?;
    let owner_delta = out_owner_non_lp.saturating_sub(in_owner_non_lp);
    if owner_delta < ckb_out {
        return Err(Error::LPWitnessMismatch);
    }

    Ok(())
}

fn check_fund_channel_extract(
    ctx: &GroupContext,
    channel_id: &[u8; 32],
    contribution_id: &[u8; 32],
    extract_ckb: u64,
) -> Result<(), Error> {
    if extract_ckb == 0 {
        return Err(Error::PoolCKBAmountZero);
    }
    let (inp, inp_cap, out, out_cap) = one_lp_in_out(ctx)?;
    verify_operator_signing(&inp.operator_lock_hash)?;
    require_nonzero_id(contribution_id)?;

    require_immutable_except_operator(inp, out)?;
    require_operator_unchanged(inp, out)?;
    require_nonce_inc(inp, out)?;

    if extract_ckb > inp.available_ckb {
        return Err(Error::InsufficientCKBLiquidity);
    }
    if inp.policy.max_trading_volume != 0 && extract_ckb > inp.policy.max_trading_volume {
        return Err(Error::LPPolicyViolation);
    }

    // Funding path must feed a concrete channel output with the witness channel_id.
    if !channel_exists_by_id(channel_id, Source::Output)? {
        return Err(Error::LPWitnessMismatch);
    }

    // Channel capacity increase for this channel must match extracted CKB.
    let ch_in_cap = channel_capacity_by_id(channel_id, Source::Input)?;
    let ch_out_cap = channel_capacity_by_id(channel_id, Source::Output)?;
    if checked_sub(ch_out_cap, ch_in_cap)? != extract_ckb {
        return Err(Error::PoolReserveMismatch);
    }

    let output_bindings = channel_bindings_by_id(channel_id, Source::Output)?;
    if output_bindings.is_empty() {
        return Err(Error::LPWitnessMismatch);
    }
    require_uniform_channel_bindings(&output_bindings)?;

    let input_bindings = channel_bindings_by_id(channel_id, Source::Input)?;
    require_uniform_channel_bindings(&input_bindings)?;
    if let (Some(first_in), Some(first_out)) = (input_bindings.first(), output_bindings.first()) {
        if first_in.lock_hash != first_out.lock_hash || first_in.type_hash != first_out.type_hash {
            return Err(Error::LPWitnessMismatch);
        }
    }

    if out_cap != checked_sub(inp_cap, extract_ckb)?
        || out.available_ckb != checked_sub(inp.available_ckb, extract_ckb)?
        || out.reserved_ckb != checked_add(inp.reserved_ckb, extract_ckb)?
        || out.cumulative_fees_earned_ckb != inp.cumulative_fees_earned_ckb
    {
        return Err(Error::PoolReserveMismatch);
    }

    Ok(())
}

fn check_settle_channel_insert(
    ctx: &GroupContext,
    channel_id: &[u8; 32],
    contribution_id: &[u8; 32],
    principal_returned: u64,
    fee_ckb: u64,
    price_x64: u128,
) -> Result<(), Error> {
    if principal_returned == 0 && fee_ckb == 0 {
        return Err(Error::InvalidSettlement);
    }
    let (inp, inp_cap, out, out_cap) = one_lp_in_out(ctx)?;
    verify_operator_signing(&inp.operator_lock_hash)?;
    require_nonzero_id(contribution_id)?;

    if price_x64 == 0
        || (inp.policy.policy_flags & POLICY_FLAG_REQUIRE_PRICE) != 0 && price_x64 == 0
    {
        return Err(Error::LPPolicyViolation);
    }

    require_immutable_except_operator(inp, out)?;
    require_operator_unchanged(inp, out)?;
    require_nonce_inc(inp, out)?;

    if principal_returned > inp.reserved_ckb {
        return Err(Error::InvalidSettlement);
    }

    if inp.policy.fee_rate_bps != 0
        && (inp.policy.policy_flags & (POLICY_FLAG_ENFORCE_MAX_FEE | POLICY_FLAG_ENFORCE_MIN_FEE))
            != 0
    {
        let policy_fee_u128 = (principal_returned as u128)
            .checked_mul(inp.policy.fee_rate_bps as u128)
            .ok_or(Error::LPArithmetic)?
            / 10_000u128;
        let policy_fee = u64::try_from(policy_fee_u128).map_err(|_| Error::LPArithmetic)?;
        if (inp.policy.policy_flags & POLICY_FLAG_ENFORCE_MAX_FEE) != 0 && fee_ckb > policy_fee {
            return Err(Error::LPPolicyViolation);
        }
        if (inp.policy.policy_flags & POLICY_FLAG_ENFORCE_MIN_FEE) != 0 && fee_ckb < policy_fee {
            return Err(Error::LPPolicyViolation);
        }
    }

    // Settlement path must consume the channel cell and return value to LP cell.
    if !channel_exists_by_id(channel_id, Source::Input)? {
        return Err(Error::InvalidSettlement);
    }
    if channel_exists_by_id(channel_id, Source::Output)? {
        return Err(Error::InvalidSettlement);
    }

    let total_return = checked_add(principal_returned, fee_ckb)?;

    // The consumed channel must hold enough capacity to back the LP return.
    let ch_in_cap = channel_capacity_by_id(channel_id, Source::Input)?;
    if ch_in_cap < total_return {
        return Err(Error::InvalidSettlement);
    }

    let input_bindings = channel_bindings_by_id(channel_id, Source::Input)?;
    if input_bindings.is_empty() {
        return Err(Error::InvalidSettlement);
    }
    require_uniform_channel_bindings(&input_bindings)?;

    if out_cap != checked_add(inp_cap, total_return)?
        || out.available_ckb != checked_add(inp.available_ckb, total_return)?
        || out.reserved_ckb != checked_sub(inp.reserved_ckb, principal_returned)?
        || out.cumulative_fees_earned_ckb != checked_add(inp.cumulative_fees_earned_ckb, fee_ckb)?
    {
        return Err(Error::PoolReserveMismatch);
    }

    Ok(())
}

fn check_cancel_reservation(
    ctx: &GroupContext,
    channel_id: &[u8; 32],
    contribution_id: &[u8; 32],
) -> Result<(), Error> {
    let (inp, inp_cap, out, out_cap) = one_lp_in_out(ctx)?;
    verify_operator_signing(&inp.operator_lock_hash)?;
    require_nonzero_id(contribution_id)?;

    require_immutable_except_operator(inp, out)?;
    require_operator_unchanged(inp, out)?;
    require_nonce_inc(inp, out)?;

    // CancelReservation is only valid when referenced channel is not currently present.
    if channel_exists_by_id(channel_id, Source::Input)?
        || channel_exists_by_id(channel_id, Source::Output)?
    {
        return Err(Error::InvalidReservationState);
    }

    if out_cap != inp_cap || out.reserved_ckb > inp.reserved_ckb {
        return Err(Error::PoolReserveMismatch);
    }

    let released = checked_sub(inp.reserved_ckb, out.reserved_ckb)?;
    if released == 0 {
        return Err(Error::InvalidReservationState);
    }

    if out.available_ckb != checked_add(inp.available_ckb, released)?
        || out.cumulative_fees_earned_ckb != inp.cumulative_fees_earned_ckb
    {
        return Err(Error::PoolReserveMismatch);
    }

    Ok(())
}

fn check_rotate_operator(
    ctx: &GroupContext,
    new_operator_lock_hash: &[u8; 32],
) -> Result<(), Error> {
    let (inp, inp_cap, out, out_cap) = one_lp_in_out(ctx)?;
    verify_operator_signing(&inp.operator_lock_hash)?;

    require_immutable_except_operator(inp, out)?;
    require_nonce_inc(inp, out)?;

    if *new_operator_lock_hash == [0u8; 32] {
        return Err(Error::LPBadOperatorRotation);
    }

    if &out.operator_lock_hash != new_operator_lock_hash {
        return Err(Error::LPBadOperatorRotation);
    }

    if out.operator_lock_hash == inp.operator_lock_hash {
        return Err(Error::LPBadOperatorRotation);
    }

    if out_cap != inp_cap
        || out.available_ckb != inp.available_ckb
        || out.reserved_ckb != inp.reserved_ckb
        || out.cumulative_fees_earned_ckb != inp.cumulative_fees_earned_ckb
    {
        return Err(Error::LPBadOperatorRotation);
    }

    Ok(())
}
