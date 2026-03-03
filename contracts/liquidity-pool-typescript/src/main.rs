/*!
 * liquidity-pool-typescript — main entry / implementation
 *
 * Validates all state transitions for the dual-asset CKB-ETH liquidity pool.
 * Mirrors every invariant enforced by LiquidityPool.sol on the CKB side.
 *
 * # Script args (32 bytes)
 * `pool_id` – uniquely identifies this pool instance.
 *
 * # Cell roles  (all carry this type script with the same pool_id)
 * `b"PLST"` – pool-state cell  (exactly 1 per pool)
 * `b"LPPS"` – LP-position cell (one per LP provider)
 * `b"CHRV"` – channel-reservation cell (one per active Perun channel)
 *
 * # Operations (WitnessArgs.input_type of the first group input)
 * | op   | Name                   | Actor    |
 * |------|------------------------|----------|
 * | 0x01 | InitPool               | Operator |
 * | 0x02 | AddLiquidity           | LP       |
 * | 0x03 | RemoveLiquidity        | LP       |
 * | 0x04 | OperatorUpdate         | Operator |
 * | 0x05 | OperatorCKBOut         | Operator |
 * | 0x06 | OperatorCKBIn          | Operator |
 * | 0x07 | ReserveForChannel      | Operator |
 * | 0x08 | ExtractToHub           | Operator |
 * | 0x09 | CancelReservation      | Operator |
 * | 0x0A | RedistributeSettlement | Operator |
 * | 0x0B | RecordSwap             | Operator |
 * | 0x0C | ClaimFees              | LP       |
 * | 0x0D | EmergencyWithdraw      | Operator |
 */
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
    pool::{
        self, apply_fee, ckb_for_lp_burn, claimable_fees, eth_for_lp_burn, lp_tokens_for_deposit,
        ChannelReservation, LPPosition, PoolState, PoolWitness, CHANNEL_RES_SIZE, LP_POSITION_SIZE,
        MAX_RESERVATION_BLOCKS, POOL_STATE_SIZE,
    },
};

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{
        load_cell_capacity, load_cell_data, load_cell_lock_hash, load_script, load_witness_args,
    },
    syscalls::SysError,
};

// ── Entry ─────────────────────────────────────────────────────────────────────

pub fn program_entry() -> i8 {
    match main() {
        Ok(_) => 0,
        Err(e) => e.into(),
    }
}

// ── Core ──────────────────────────────────────────────────────────────────────

fn main() -> Result<(), Error> {
    let pool_id = load_pool_id()?;
    let ctx = collect_group()?;
    verify_pool_ids(&ctx, &pool_id)?;
    let witness = load_pool_witness()?;

    match witness {
        PoolWitness::InitPool {
            initial_eth_reserve,
            swap_fee_bps,
        } => check_init_pool(&ctx, &pool_id, initial_eth_reserve, swap_fee_bps),
        PoolWitness::AddLiquidity { eth_in, min_lp_out } => {
            check_add_liquidity(&ctx, eth_in, min_lp_out)
        }
        PoolWitness::RemoveLiquidity {
            min_ckb_out,
            min_eth_out,
        } => check_remove_liquidity(&ctx, min_ckb_out, min_eth_out),
        PoolWitness::OperatorUpdate {
            new_eth_reserve,
            new_fee_bps,
        } => check_operator_update(&ctx, new_eth_reserve, new_fee_bps),
        PoolWitness::OperatorCKBOut {
            ckb_out,
            new_eth_reserve,
        } => check_operator_ckb_out(&ctx, ckb_out, new_eth_reserve),
        PoolWitness::OperatorCKBIn {
            ckb_in,
            new_eth_reserve,
        } => check_operator_ckb_in(&ctx, ckb_in, new_eth_reserve),
        PoolWitness::ReserveForChannel {
            channel_id,
            ckb_delta,
            eth_delta,
        } => check_reserve_for_channel(&ctx, &channel_id, ckb_delta, eth_delta),
        PoolWitness::ExtractToHub { channel_id } => check_extract_to_hub(&ctx, &channel_id),
        PoolWitness::CancelReservation { channel_id } => {
            check_cancel_reservation(&ctx, &channel_id)
        }
        PoolWitness::RedistributeSettlement {
            channel_id,
            ckb_returned,
            eth_returned,
            fee_ckb,
            fee_eth,
        } => check_redistribute_settlement(
            &ctx,
            &channel_id,
            ckb_returned,
            eth_returned,
            fee_ckb,
            fee_eth,
        ),
        PoolWitness::RecordSwap { channel_id } => check_record_swap(&ctx, &channel_id),
        PoolWitness::ClaimFees => check_claim_fees(&ctx),
        PoolWitness::EmergencyWithdraw => check_emergency_withdraw(&ctx),
    }
}

// ── GroupContext ──────────────────────────────────────────────────────────────

struct GroupContext {
    pool_state_inputs: Vec<(PoolState, u64)>, // (decoded, capacity shannons)
    pool_state_outputs: Vec<(PoolState, u64)>,
    lp_pos_inputs: Vec<LPPosition>,
    lp_pos_outputs: Vec<LPPosition>,
    channel_res_inputs: Vec<ChannelReservation>,
    channel_res_outputs: Vec<ChannelReservation>,
}

fn collect_group() -> Result<GroupContext, Error> {
    let mut ctx = GroupContext {
        pool_state_inputs: Vec::new(),
        pool_state_outputs: Vec::new(),
        lp_pos_inputs: Vec::new(),
        lp_pos_outputs: Vec::new(),
        channel_res_inputs: Vec::new(),
        channel_res_outputs: Vec::new(),
    };
    for idx in 0usize.. {
        match load_cell_data(idx, Source::GroupInput) {
            Ok(d) => classify_cell(
                d.as_ref(),
                load_cell_capacity(idx, Source::GroupInput)?,
                &mut ctx.pool_state_inputs,
                &mut ctx.lp_pos_inputs,
                &mut ctx.channel_res_inputs,
            )?,
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    for idx in 0usize.. {
        match load_cell_data(idx, Source::GroupOutput) {
            Ok(d) => classify_cell(
                d.as_ref(),
                load_cell_capacity(idx, Source::GroupOutput)?,
                &mut ctx.pool_state_outputs,
                &mut ctx.lp_pos_outputs,
                &mut ctx.channel_res_outputs,
            )?,
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(ctx)
}

fn classify_cell(
    data: &[u8],
    capacity: u64,
    pool_states: &mut Vec<(PoolState, u64)>,
    lp_pos: &mut Vec<LPPosition>,
    chan_res: &mut Vec<ChannelReservation>,
) -> Result<(), Error> {
    if PoolState::is_pool_state(data) {
        pool_states.push((PoolState::decode(data)?, capacity));
    } else if LPPosition::is_lp_position(data) {
        lp_pos.push(LPPosition::decode(data)?);
    } else if ChannelReservation::is_channel_reservation(data) {
        chan_res.push(ChannelReservation::decode(data)?);
    } else {
        return Err(Error::PoolInvalidCellMagic);
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_pool_id() -> Result<[u8; 32], Error> {
    let args: Bytes = load_script()?.args().unpack();
    if args.len() < 32 {
        return Err(Error::PoolLSNoArgs);
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&args[..32]);
    Ok(id)
}

fn verify_pool_ids(ctx: &GroupContext, expected: &[u8; 32]) -> Result<(), Error> {
    for (ps, _) in ctx.pool_state_inputs.iter().chain(&ctx.pool_state_outputs) {
        if &ps.pool_id != expected {
            return Err(Error::PoolIdMismatch);
        }
    }
    for lp in ctx.lp_pos_inputs.iter().chain(&ctx.lp_pos_outputs) {
        if &lp.pool_id != expected {
            return Err(Error::LPPositionPoolIdMismatch);
        }
    }
    for cr in ctx
        .channel_res_inputs
        .iter()
        .chain(&ctx.channel_res_outputs)
    {
        if &cr.pool_id != expected {
            return Err(Error::PoolIdMismatch);
        }
    }
    Ok(())
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

fn verify_operator_signing(operator_lock_hash: &[u8; 32]) -> Result<(), Error> {
    for i in 0usize.. {
        match load_cell_lock_hash(i, Source::Input) {
            Ok(h) if &h == operator_lock_hash => return Ok(()),
            Ok(_) => continue,
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::OperatorNotSigning)
}

fn one_pool_state_in_out(
    ctx: &GroupContext,
) -> Result<(&(PoolState, u64), &(PoolState, u64)), Error> {
    if ctx.pool_state_inputs.len() != 1 {
        return Err(Error::PoolStateInputMissing);
    }
    if ctx.pool_state_outputs.len() != 1 {
        return Err(Error::PoolStateOutputMissing);
    }
    Ok((&ctx.pool_state_inputs[0], &ctx.pool_state_outputs[0]))
}

fn find_res_input<'a>(
    ctx: &'a GroupContext,
    channel_id: &[u8; 32],
) -> Result<&'a ChannelReservation, Error> {
    ctx.channel_res_inputs
        .iter()
        .find(|r| &r.channel_id == channel_id && r.active)
        .ok_or(Error::ChannelNotReserved)
}

fn find_res_output<'a>(
    ctx: &'a GroupContext,
    channel_id: &[u8; 32],
) -> Option<&'a ChannelReservation> {
    ctx.channel_res_outputs
        .iter()
        .find(|r| &r.channel_id == channel_id)
}

// Derive the CKB deposited into the pool state cell from capacity delta.
fn ckb_deposited_into_pool(in_cap: u64, out_cap: u64) -> Result<u64, Error> {
    out_cap.checked_sub(in_cap).ok_or(Error::PoolCKBAmountZero)
}

// ── 0x01  InitPool ────────────────────────────────────────────────────────────
fn check_init_pool(
    ctx: &GroupContext,
    pool_id: &[u8; 32],
    initial_eth_reserve: u128,
    swap_fee_bps: u32,
) -> Result<(), Error> {
    if !ctx.pool_state_inputs.is_empty() || !ctx.lp_pos_inputs.is_empty() {
        return Err(Error::PoolAlreadyInitialised);
    }
    if ctx.pool_state_outputs.len() != 1 {
        return Err(Error::PoolStateOutputMissing);
    }
    let (out, _) = &ctx.pool_state_outputs[0];
    if &out.pool_id != pool_id {
        return Err(Error::PoolIdInitMismatch);
    }
    verify_operator_signing(&out.operator_lock_hash)?;
    if out.ckb_reserve != 0 {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out.lp_token_supply != 0 {
        return Err(Error::LPArithmetic);
    }
    if out.ckb_reserved != 0 {
        return Err(Error::InvalidReservationState);
    }
    if out.eth_reserved != 0 {
        return Err(Error::InvalidReservationState);
    }
    if out.accumulated_fee_ckb != 0 {
        return Err(Error::InvalidFeeAccounting);
    }
    if out.accumulated_fee_eth != 0 {
        return Err(Error::InvalidFeeAccounting);
    }
    if out.swap_count != 0 {
        return Err(Error::InvalidSwapOutput);
    }
    if out.swap_fee_bps != swap_fee_bps {
        return Err(Error::PoolReserveMismatch);
    }
    if out.eth_reserve != initial_eth_reserve {
        return Err(Error::PoolReserveMismatch);
    }
    Ok(())
}

// ── 0x02  AddLiquidity ────────────────────────────────────────────────────────
// Mirrors addLiquidity() in LiquidityPool.sol.
// CKB delta is inferred from pool-cell capacity change.
// ETH delta is operator-reported in the witness.
fn check_add_liquidity(ctx: &GroupContext, eth_in: u128, min_lp_out: u128) -> Result<(), Error> {
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;

    // Exactly 1 new LP position in outputs.
    if ctx.lp_pos_outputs.len() != 1 {
        return Err(Error::PoolStateOutputMissing);
    }
    let new_lp = &ctx.lp_pos_outputs[0];
    if !new_lp.active {
        return Err(Error::NoActivePosition);
    }

    let ckb_in = ckb_deposited_into_pool(*in_cap, *out_cap)?;
    if ckb_in == 0 {
        return Err(Error::PoolCKBAmountZero);
    }

    let lp_minted = lp_tokens_for_deposit(
        ckb_in,
        eth_in,
        in_ps.ckb_reserve,
        in_ps.eth_reserve,
        in_ps.lp_token_supply,
    )
    .ok_or(Error::LPArithmetic)?;

    if lp_minted < min_lp_out {
        return Err(Error::SlippageExceeded);
    }
    if lp_minted == 0 {
        return Err(Error::LPAmountZero);
    }
    if new_lp.lp_amount != lp_minted {
        return Err(Error::LPArithmetic);
    }
    if new_lp.ckb_amount != ckb_in {
        return Err(Error::LPArithmetic);
    }
    if new_lp.eth_amount != eth_in {
        return Err(Error::LPArithmetic);
    }

    // Reserve accounting
    if out_ps.ckb_reserve
        != in_ps
            .ckb_reserve
            .checked_add(ckb_in)
            .ok_or(Error::LPArithmetic)?
    {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.eth_reserve
        != in_ps
            .eth_reserve
            .checked_add(eth_in)
            .ok_or(Error::LPArithmetic)?
    {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.lp_token_supply
        != in_ps
            .lp_token_supply
            .checked_add(lp_minted)
            .ok_or(Error::LPArithmetic)?
    {
        return Err(Error::LPArithmetic);
    }
    // Reserved counters, fees, swap_count must be unchanged
    if out_ps.ckb_reserved != in_ps.ckb_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.eth_reserved != in_ps.eth_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.accumulated_fee_ckb != in_ps.accumulated_fee_ckb {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.accumulated_fee_eth != in_ps.accumulated_fee_eth {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.swap_fee_bps != in_ps.swap_fee_bps {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.operator_lock_hash != in_ps.operator_lock_hash {
        return Err(Error::OperatorNotSigning);
    }
    Ok(())
}

// ── 0x03  RemoveLiquidity ─────────────────────────────────────────────────────
// Uses *available* (total − reserved) reserves so locked funds stay safe.
fn check_remove_liquidity(
    ctx: &GroupContext,
    min_ckb_out: u64,
    min_eth_out: u128,
) -> Result<(), Error> {
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;

    if ctx.lp_pos_inputs.len() != 1 {
        return Err(Error::LPPositionInputMissing);
    }
    // LP position consumed (not in outputs)
    if !ctx.lp_pos_outputs.is_empty() {
        return Err(Error::MultiplePoolStateCells);
    }
    let burned = &ctx.lp_pos_inputs[0];

    if burned.lp_amount == 0 {
        return Err(Error::LPAmountZero);
    }
    if in_ps.lp_token_supply == 0 {
        return Err(Error::LPSupplyZero);
    }

    let avail_ckb = in_ps.available_ckb();
    let avail_eth = in_ps.available_eth();

    let ckb_out = ckb_for_lp_burn(burned.lp_amount, avail_ckb, in_ps.lp_token_supply)
        .ok_or(Error::LPArithmetic)?;
    let eth_out = eth_for_lp_burn(burned.lp_amount, avail_eth, in_ps.lp_token_supply)
        .ok_or(Error::LPArithmetic)?;

    if ckb_out < min_ckb_out {
        return Err(Error::SlippageExceeded);
    }
    if eth_out < min_eth_out {
        return Err(Error::SlippageExceeded);
    }
    if ckb_out == 0 {
        return Err(Error::PoolCKBAmountZero);
    }

    let exp_ckb = in_ps
        .ckb_reserve
        .checked_sub(ckb_out)
        .ok_or(Error::LPArithmetic)?;
    let exp_eth = in_ps
        .eth_reserve
        .checked_sub(eth_out)
        .ok_or(Error::LPArithmetic)?;
    let exp_lp = in_ps
        .lp_token_supply
        .checked_sub(burned.lp_amount)
        .ok_or(Error::LPArithmetic)?;
    let exp_cap = in_cap.checked_sub(ckb_out).ok_or(Error::LPArithmetic)?;

    if out_ps.ckb_reserve != exp_ckb {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.eth_reserve != exp_eth {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.lp_token_supply != exp_lp {
        return Err(Error::LPArithmetic);
    }
    if *out_cap != exp_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }

    if out_ps.ckb_reserved != in_ps.ckb_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.eth_reserved != in_ps.eth_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.accumulated_fee_ckb != in_ps.accumulated_fee_ckb {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.accumulated_fee_eth != in_ps.accumulated_fee_eth {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.swap_fee_bps != in_ps.swap_fee_bps {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.operator_lock_hash != in_ps.operator_lock_hash {
        return Err(Error::OperatorNotSigning);
    }
    Ok(())
}

// ── 0x04  OperatorUpdate ─────────────────────────────────────────────────────
fn check_operator_update(
    ctx: &GroupContext,
    new_eth_reserve: u128,
    new_fee_bps: u32,
) -> Result<(), Error> {
    if !ctx.lp_pos_inputs.is_empty() || !ctx.lp_pos_outputs.is_empty() {
        return Err(Error::MultiplePoolStateCells);
    }
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;
    verify_operator_signing(&in_ps.operator_lock_hash)?;
    if new_fee_bps > 1_000 {
        return Err(Error::PoolReserveMismatch);
    } // max 10 %
    if out_ps.eth_reserve != new_eth_reserve {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.swap_fee_bps != new_fee_bps {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.ckb_reserve != in_ps.ckb_reserve {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.lp_token_supply != in_ps.lp_token_supply {
        return Err(Error::LPArithmetic);
    }
    if out_ps.ckb_reserved != in_ps.ckb_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.eth_reserved != in_ps.eth_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.accumulated_fee_ckb != in_ps.accumulated_fee_ckb {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.accumulated_fee_eth != in_ps.accumulated_fee_eth {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.operator_lock_hash != in_ps.operator_lock_hash {
        return Err(Error::OperatorNotSigning);
    }
    if out_cap != in_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    Ok(())
}

// ── 0x05  OperatorCKBOut ─────────────────────────────────────────────────────
fn check_operator_ckb_out(
    ctx: &GroupContext,
    ckb_out: u64,
    new_eth_reserve: u128,
) -> Result<(), Error> {
    if !ctx.lp_pos_inputs.is_empty() || !ctx.lp_pos_outputs.is_empty() {
        return Err(Error::MultiplePoolStateCells);
    }
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;
    verify_operator_signing(&in_ps.operator_lock_hash)?;

    if ckb_out == 0 {
        return Err(Error::PoolCKBAmountZero);
    }
    if ckb_out > in_ps.available_ckb() {
        return Err(Error::InsufficientCKBLiquidity);
    }

    // Fee stays in pool; only net amount leaves capacity
    let net = apply_fee(ckb_out, in_ps.swap_fee_bps).ok_or(Error::LPArithmetic)?;
    let fee = ckb_out - net;

    let exp_cap = in_cap.checked_sub(net).ok_or(Error::LPArithmetic)?;
    let exp_ckb = in_ps
        .ckb_reserve
        .checked_sub(net)
        .ok_or(Error::LPArithmetic)?;

    if *out_cap != exp_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.ckb_reserve != exp_ckb {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.eth_reserve != new_eth_reserve {
        return Err(Error::PoolReserveMismatch);
    }

    // Fee portion stays in pool — accumulated_fee_ckb increases
    if out_ps.accumulated_fee_ckb
        != in_ps
            .accumulated_fee_ckb
            .checked_add(fee)
            .ok_or(Error::InvalidFeeAccounting)?
    {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.lp_token_supply != in_ps.lp_token_supply {
        return Err(Error::LPArithmetic);
    }
    if out_ps.swap_fee_bps != in_ps.swap_fee_bps {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.ckb_reserved != in_ps.ckb_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.accumulated_fee_eth != in_ps.accumulated_fee_eth {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.operator_lock_hash != in_ps.operator_lock_hash {
        return Err(Error::OperatorNotSigning);
    }
    Ok(())
}

// ── 0x06  OperatorCKBIn ──────────────────────────────────────────────────────
fn check_operator_ckb_in(
    ctx: &GroupContext,
    ckb_in: u64,
    new_eth_reserve: u128,
) -> Result<(), Error> {
    if !ctx.lp_pos_inputs.is_empty() || !ctx.lp_pos_outputs.is_empty() {
        return Err(Error::MultiplePoolStateCells);
    }
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;
    verify_operator_signing(&in_ps.operator_lock_hash)?;

    if ckb_in == 0 {
        return Err(Error::PoolCKBAmountZero);
    }

    let exp_cap = in_cap.checked_add(ckb_in).ok_or(Error::LPArithmetic)?;
    let exp_ckb = in_ps
        .ckb_reserve
        .checked_add(ckb_in)
        .ok_or(Error::LPArithmetic)?;

    if *out_cap != exp_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.ckb_reserve != exp_ckb {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.eth_reserve != new_eth_reserve {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.lp_token_supply != in_ps.lp_token_supply {
        return Err(Error::LPArithmetic);
    }
    if out_ps.swap_fee_bps != in_ps.swap_fee_bps {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.ckb_reserved != in_ps.ckb_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.accumulated_fee_ckb != in_ps.accumulated_fee_ckb {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.accumulated_fee_eth != in_ps.accumulated_fee_eth {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.operator_lock_hash != in_ps.operator_lock_hash {
        return Err(Error::OperatorNotSigning);
    }
    Ok(())
}

// ── 0x07  ReserveForChannel ───────────────────────────────────────────────────
// Locks liquidity for a Perun channel.  Funds stay in pool cell (reserved).
// Creates a new ChannelReservation cell in outputs.
fn check_reserve_for_channel(
    ctx: &GroupContext,
    channel_id: &[u8; 32],
    ckb_delta: u64,
    eth_delta: u128,
) -> Result<(), Error> {
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;
    verify_operator_signing(&in_ps.operator_lock_hash)?;

    // Must not already exist
    if ctx
        .channel_res_inputs
        .iter()
        .any(|r| &r.channel_id == channel_id && r.active)
    {
        return Err(Error::ChannelAlreadyReserved);
    }
    if ckb_delta > in_ps.available_ckb() {
        return Err(Error::InsufficientCKBLiquidity);
    }
    if eth_delta > in_ps.available_eth() {
        return Err(Error::InsufficientETHLiquidity);
    }

    // Pool reserved counters increase; actual reserves unchanged (funds still in cell)
    if out_ps.ckb_reserved
        != in_ps
            .ckb_reserved
            .checked_add(ckb_delta)
            .ok_or(Error::LPArithmetic)?
    {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.eth_reserved
        != in_ps
            .eth_reserved
            .checked_add(eth_delta)
            .ok_or(Error::LPArithmetic)?
    {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.ckb_reserve != in_ps.ckb_reserve {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.eth_reserve != in_ps.eth_reserve {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.lp_token_supply != in_ps.lp_token_supply {
        return Err(Error::LPArithmetic);
    }
    if out_cap != in_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }

    // New reservation output cell
    let res_out = find_res_output(ctx, channel_id).ok_or(Error::ChannelNotReserved)?;
    if res_out.ckb_reserved != ckb_delta {
        return Err(Error::InvalidReservationState);
    }
    if res_out.eth_reserved != eth_delta {
        return Err(Error::InvalidReservationState);
    }
    if !res_out.active {
        return Err(Error::InvalidReservationState);
    }
    Ok(())
}

// ── 0x08  ExtractToHub ────────────────────────────────────────────────────────
// CKB physically leaves the pool cell → hub.
// Reserved counters are released (funds are now outside the pool).
// Reservation cell updated but stays active (needed for redistribution).
fn check_extract_to_hub(ctx: &GroupContext, channel_id: &[u8; 32]) -> Result<(), Error> {
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;
    verify_operator_signing(&in_ps.operator_lock_hash)?;

    let res = find_res_input(ctx, channel_id)?;

    // Pool CKB decreases by reservation amount
    let exp_cap = in_cap
        .checked_sub(res.ckb_reserved)
        .ok_or(Error::LPArithmetic)?;
    let exp_ckb = in_ps
        .ckb_reserve
        .checked_sub(res.ckb_reserved)
        .ok_or(Error::LPArithmetic)?;
    // Reserved counter also released (funds have left)
    let exp_ckb_res = in_ps
        .ckb_reserved
        .checked_sub(res.ckb_reserved)
        .ok_or(Error::LPArithmetic)?;
    let exp_eth_res = in_ps
        .eth_reserved
        .checked_sub(res.eth_reserved)
        .ok_or(Error::LPArithmetic)?;

    if *out_cap != exp_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.ckb_reserve != exp_ckb {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.ckb_reserved != exp_ckb_res {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.eth_reserved != exp_eth_res {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.lp_token_supply != in_ps.lp_token_supply {
        return Err(Error::LPArithmetic);
    }

    // Reservation cell must remain in outputs (still active — awaits settlement)
    let res_out = find_res_output(ctx, channel_id).ok_or(Error::ChannelNotReserved)?;
    if !res_out.active {
        return Err(Error::InvalidReservationState);
    }
    Ok(())
}

// ── 0x09  CancelReservation ───────────────────────────────────────────────────
// Operator cancels a reservation before extraction.
// Reserved counters released; reservation cell consumed.
fn check_cancel_reservation(ctx: &GroupContext, channel_id: &[u8; 32]) -> Result<(), Error> {
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;
    verify_operator_signing(&in_ps.operator_lock_hash)?;

    let res = find_res_input(ctx, channel_id)?;

    let exp_ckb_res = in_ps
        .ckb_reserved
        .checked_sub(res.ckb_reserved)
        .ok_or(Error::LPArithmetic)?;
    let exp_eth_res = in_ps
        .eth_reserved
        .checked_sub(res.eth_reserved)
        .ok_or(Error::LPArithmetic)?;

    if out_ps.ckb_reserved != exp_ckb_res {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.eth_reserved != exp_eth_res {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.ckb_reserve != in_ps.ckb_reserve {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.eth_reserve != in_ps.eth_reserve {
        return Err(Error::PoolReserveMismatch);
    }
    if out_cap != in_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }

    // Reservation must NOT appear in outputs (consumed)
    if find_res_output(ctx, channel_id).is_some() {
        return Err(Error::InvalidReservationState);
    }
    Ok(())
}

// ── 0x0A  RedistributeSettlement ─────────────────────────────────────────────
// Hub returns CKB + fees after Perun channel closes.
// Mirrors redistributeFromSettlement() in LiquidityPool.sol.
fn check_redistribute_settlement(
    ctx: &GroupContext,
    channel_id: &[u8; 32],
    ckb_returned: u64,
    eth_returned: u128,
    fee_ckb: u64,
    fee_eth: u128,
) -> Result<(), Error> {
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;
    verify_operator_signing(&in_ps.operator_lock_hash)?;

    let res = find_res_input(ctx, channel_id)?;

    // Net pool change: old_reserve − extracted + returned
    // For a CancelledExtraction (CKB never actually left), this would look
    // different; for the standard flow after ExtractToHub the pool's
    // ckb_reserve was already decremented, so here it just goes up by ckb_returned.
    let exp_ckb = in_ps
        .ckb_reserve
        .checked_add(ckb_returned)
        .ok_or(Error::LPArithmetic)?;
    let exp_eth = in_ps
        .eth_reserve
        .checked_add(eth_returned)
        .ok_or(Error::LPArithmetic)?;
    let exp_cap = in_cap
        .checked_add(ckb_returned)
        .ok_or(Error::LPArithmetic)?;

    if *out_cap != exp_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.ckb_reserve != exp_ckb {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.eth_reserve != exp_eth {
        return Err(Error::PoolReserveMismatch);
    }

    // Fee accumulators increase
    if out_ps.accumulated_fee_ckb
        != in_ps
            .accumulated_fee_ckb
            .checked_add(fee_ckb)
            .ok_or(Error::InvalidFeeAccounting)?
    {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.accumulated_fee_eth
        != in_ps
            .accumulated_fee_eth
            .checked_add(fee_eth)
            .ok_or(Error::InvalidFeeAccounting)?
    {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.lp_token_supply != in_ps.lp_token_supply {
        return Err(Error::LPArithmetic);
    }

    // Reservation consumed (channel closed)
    if find_res_output(ctx, channel_id).is_some() {
        return Err(Error::InvalidReservationState);
    }
    Ok(())
}

// ── 0x0B  RecordSwap ─────────────────────────────────────────────────────────
// Operator records a swap completed inside a channel.
// Increments swap_count; no reserve changes.
fn check_record_swap(ctx: &GroupContext, channel_id: &[u8; 32]) -> Result<(), Error> {
    let _ = find_res_input(ctx, channel_id)?; // reservation must exist
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;
    verify_operator_signing(&in_ps.operator_lock_hash)?;

    if out_ps.swap_count
        != in_ps
            .swap_count
            .checked_add(1)
            .ok_or(Error::InvalidSwapOutput)?
    {
        return Err(Error::InvalidSwapOutput);
    }
    if out_ps.ckb_reserve != in_ps.ckb_reserve {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.eth_reserve != in_ps.eth_reserve {
        return Err(Error::PoolReserveMismatch);
    }
    if out_ps.lp_token_supply != in_ps.lp_token_supply {
        return Err(Error::LPArithmetic);
    }
    if out_ps.ckb_reserved != in_ps.ckb_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.accumulated_fee_ckb != in_ps.accumulated_fee_ckb {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.accumulated_fee_eth != in_ps.accumulated_fee_eth {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_cap != in_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }

    // Reservation cell must remain
    let res_out = find_res_output(ctx, channel_id).ok_or(Error::ChannelNotReserved)?;
    if !res_out.active {
        return Err(Error::InvalidReservationState);
    }
    Ok(())
}

// ── 0x0C  ClaimFees ──────────────────────────────────────────────────────────
// LP claims their proportional share of accumulated fees.
// Mirrors claimFees() in LiquidityPool.sol.
fn check_claim_fees(ctx: &GroupContext) -> Result<(), Error> {
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;

    if ctx.lp_pos_inputs.len() != 1 {
        return Err(Error::NoActivePosition);
    }
    if ctx.lp_pos_outputs.len() != 1 {
        return Err(Error::NoActivePosition);
    }
    let lp_in = &ctx.lp_pos_inputs[0];
    let lp_out = &ctx.lp_pos_outputs[0];

    if !lp_in.active {
        return Err(Error::NoActivePosition);
    }
    if lp_in.lp_amount == 0 {
        return Err(Error::LPAmountZero);
    }

    let (fee_ckb, fee_eth) = claimable_fees(
        in_ps.accumulated_fee_ckb,
        in_ps.accumulated_fee_eth,
        lp_in.lp_amount,
        in_ps.lp_token_supply,
    )
    .ok_or(Error::NoFeesToClaim)?;

    if fee_ckb == 0 && fee_eth == 0 {
        return Err(Error::NoFeesToClaim);
    }

    // Pool fees decrease
    if out_ps.accumulated_fee_ckb
        != in_ps
            .accumulated_fee_ckb
            .checked_sub(fee_ckb)
            .ok_or(Error::InvalidFeeAccounting)?
    {
        return Err(Error::InvalidFeeAccounting);
    }
    if out_ps.accumulated_fee_eth
        != in_ps
            .accumulated_fee_eth
            .checked_sub(fee_eth)
            .ok_or(Error::InvalidFeeAccounting)?
    {
        return Err(Error::InvalidFeeAccounting);
    }
    // CKB leaves pool cell for the LP
    let exp_cap = in_cap.checked_sub(fee_ckb).ok_or(Error::LPArithmetic)?;
    if *out_cap != exp_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    let exp_ckb = in_ps
        .ckb_reserve
        .checked_sub(fee_ckb)
        .ok_or(Error::LPArithmetic)?;
    if out_ps.ckb_reserve != exp_ckb {
        return Err(Error::PoolCKBReserveInconsistent);
    }

    // LP position records lifetime claimed fees
    if lp_out.accumulated_fees_ckb
        != lp_in
            .accumulated_fees_ckb
            .checked_add(fee_ckb)
            .ok_or(Error::InvalidFeeAccounting)?
    {
        return Err(Error::InvalidFeeAccounting);
    }
    if lp_out.accumulated_fees_eth
        != lp_in
            .accumulated_fees_eth
            .checked_add(fee_eth)
            .ok_or(Error::InvalidFeeAccounting)?
    {
        return Err(Error::InvalidFeeAccounting);
    }
    // LP shares unchanged
    if lp_out.lp_amount != lp_in.lp_amount {
        return Err(Error::LPArithmetic);
    }
    if out_ps.lp_token_supply != in_ps.lp_token_supply {
        return Err(Error::LPArithmetic);
    }
    if out_ps.ckb_reserved != in_ps.ckb_reserved {
        return Err(Error::InvalidReservationState);
    }
    Ok(())
}

// ── 0x0D  EmergencyWithdraw ───────────────────────────────────────────────────
// Operator withdraws all *available* (unreserved) CKB.
// Mirrors emergencyWithdraw() in LiquidityPool.sol.
fn check_emergency_withdraw(ctx: &GroupContext) -> Result<(), Error> {
    if !ctx.lp_pos_inputs.is_empty() || !ctx.lp_pos_outputs.is_empty() {
        return Err(Error::MultiplePoolStateCells);
    }
    let (inp, out) = one_pool_state_in_out(ctx)?;
    let (in_ps, in_cap) = inp;
    let (out_ps, out_cap) = out;
    verify_operator_signing(&in_ps.operator_lock_hash)?;

    let available = in_ps.available_ckb();
    if available == 0 {
        return Err(Error::PoolCKBAmountZero);
    }

    let exp_cap = in_cap.checked_sub(available).ok_or(Error::LPArithmetic)?;
    let exp_ckb = in_ps
        .ckb_reserve
        .checked_sub(available)
        .ok_or(Error::LPArithmetic)?;

    if *out_cap != exp_cap {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    if out_ps.ckb_reserve != exp_ckb {
        return Err(Error::PoolCKBReserveInconsistent);
    }
    // Reserved amounts stay (channels still live)
    if out_ps.ckb_reserved != in_ps.ckb_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.eth_reserved != in_ps.eth_reserved {
        return Err(Error::InvalidReservationState);
    }
    if out_ps.lp_token_supply != in_ps.lp_token_supply {
        return Err(Error::LPArithmetic);
    }
    Ok(())
}

// Keep unused constant alive (suppresses dead-code lint for re-exported consts)
const _: usize = POOL_STATE_SIZE;
const _: usize = LP_POSITION_SIZE;
const _: usize = CHANNEL_RES_SIZE;
const _: u64 = MAX_RESERVATION_BLOCKS;
