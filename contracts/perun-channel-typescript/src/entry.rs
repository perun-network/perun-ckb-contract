// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;
// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{
        bytes::Bytes,
        packed::{Byte32, Script},
        prelude::*,
    },
    debug,
    high_level::{
        load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash,
        load_cell_type_hash, load_header, load_script, load_transaction, load_witness_args,
    },
};
use perun_common::{
    error::Error,
    helpers::{blake2b256, is_matching_output},
    perun_types::{
        Balances, ChannelConstants, ChannelParameters, ChannelState, ChannelStatus, ChannelToken,
        ChannelWitness, ChannelWitnessUnion, PubKey, Signature,
    },
};

pub const MAX_TIMESTAMP_DRIFT: u64 = 1000 * 15; // 20 seconds

pub enum ChannelAction {
    Progress {
        old_status: ChannelStatus,
        new_status: ChannelStatus,
    }, // one PCTS input, one PCTS output
    Start {
        new_status: ChannelStatus,
    }, // no PCTS input, one PCTS output
    Close {
        old_status: ChannelStatus,
    }, // one PCTS input , no PCTS output
}

pub fn main() -> Result<(), Error> {
    // remove below examples and write your code here

    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    debug!("script args is {:?}", args);

    // return an error if args is invalid
    if args.is_empty() {
        return Err(Error::NoArgs);
    }

    let channel_constants =
        ChannelConstants::from_slice(&args).expect("unable to parse args as ChannelParameters");
    verify_channel_params_compatibility(&channel_constants.params())?;

    // Todo: figure out which kind of ChannelAction we are actually dealing with!
    //load_cell_data(0, Source::GroupInput)?;
    //load_cell_data(0, Source::GroupOutput)?;
    let channel_action = get_channel_action()?;

    match channel_action {
        ChannelAction::Start { new_status } => {
            check_valid_start(&new_status, &channel_constants, &script)
        }
        ChannelAction::Progress {
            old_status,
            new_status,
        } => {
            let channel_witness = load_witness()?;
            check_valid_progress(
                &old_status,
                &new_status,
                &channel_witness,
                &channel_constants,
                &script,
            )
        }
        ChannelAction::Close { old_status } => {
            let channel_witness = load_witness()?;
            check_valid_close(&old_status, &channel_witness, &channel_constants)
        }
    }
}

pub fn check_valid_start(
    new_status: &ChannelStatus,
    channel_constants: &ChannelConstants,
    own_script: &Script,
) -> Result<(), Error> {
    verify_thread_token_integrity(&channel_constants.thread_token())?;
    verify_channel_id_integrity(
        &new_status.state().channel_id(),
        &channel_constants.params(),
    )?;
    verify_valid_lock_script(own_script, channel_constants)?;

    verify_no_funds_in_inputs(&channel_constants.pfls_hash())?;
    verify_state_valid_as_start(&new_status.state())?;

    verify_funding_in_status(0, &new_status.funding(), &new_status.state())?;
    verify_funding_is_zero_at_index(1, &new_status.funding())?;
    verify_funding_in_outputs(0, &new_status.state().balances(), channel_constants)?;
    verify_funded_status(new_status)?;
    verify_status_not_disputed(new_status)?;
    Ok(())
}

pub fn check_valid_progress(
    old_status: &ChannelStatus,
    new_status: &ChannelStatus,
    witness: &ChannelWitness,
    channel_constants: &ChannelConstants,
    own_script: &Script,
) -> Result<(), Error> {
    verify_equal_channel_id(&old_status.state(), &new_status.state())?;
    verify_no_funds_in_inputs(&channel_constants.pfls_hash())?;
    verify_channel_continues(own_script)?;
    match witness.to_enum() {
        ChannelWitnessUnion::Fund(f) => {
            verify_equal_channel_state(&old_status.state(), &new_status.state())?;
            verify_status_not_funded(&old_status)?;
            verify_funding_unchanged(
                f.index().idx_of_peer(),
                &old_status.funding(),
                &new_status.funding(),
            )?;
            verify_funding_in_status(
                f.index().to_idx(),
                &new_status.funding(),
                &new_status.state(),
            )?;
            verify_funding_in_outputs(
                f.index().to_idx(),
                &old_status.state().balances(),
                channel_constants,
            )?;
            verify_status_not_disputed(new_status)?;
            verify_funded_status(&new_status)?;
            Ok(())
        }
        ChannelWitnessUnion::Dispute(d) => {
            verify_channel_state_progression(&old_status.state(), &new_status.state())?;
            verify_status_funded(old_status)?;
            verify_status_disputed(new_status)?;
            verify_correct_time_stamp(new_status.timestamp().unpack())?;
            verify_valid_state_sig(
                &d.sig_a(),
                &new_status.state(),
                &channel_constants.params().party_a().pub_key(),
            )?;
            verify_valid_state_sig(
                &d.sig_b(),
                &new_status.state(),
                &channel_constants.params().party_b().pub_key(),
            )?;
            Ok(())
        }
        ChannelWitnessUnion::Close(_) => Err(Error::ChannelCloseWithChannelOutput),
        ChannelWitnessUnion::ForceClose(_) => Err(Error::ChannelForceCloseWithChannelOutput),
        ChannelWitnessUnion::Abort(_) => Err(Error::ChannelAbortWithChannelOutput),
    }
}

pub fn check_valid_close(
    old_status: &ChannelStatus,
    channel_witness: &ChannelWitness,
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    let channel_capacity = load_cell_capacity(0, Source::GroupInput)?;
    match channel_witness.to_enum() {
        ChannelWitnessUnion::Abort(_) => {
            verify_status_not_funded(old_status)?;
            verify_all_payed(&old_status.funding(), channel_capacity, channel_constants)?;
            Ok(())
        }
        ChannelWitnessUnion::ForceClose(_) => {
            verify_status_funded(old_status)?;
            verify_time_lock_expired(
                channel_constants.params().challenge_duration().unpack(),
                old_status.timestamp().unpack(),
            )?;
            verify_status_disputed(old_status)?;
            verify_all_payed(&old_status.funding(), channel_capacity, channel_constants)?;
            Ok(())
        }
        ChannelWitnessUnion::Close(c) => {
            verify_equal_channel_id(&old_status.state(), &c.state())?;
            verify_status_funded(old_status)?;
            verify_state_finalized(&c.state())?;
            verify_valid_state_sig(
                &c.sig_a(),
                &c.state(),
                &channel_constants.params().party_a().pub_key(),
            )?;
            verify_valid_state_sig(
                &c.sig_b(),
                &c.state(),
                &channel_constants.params().party_b().pub_key(),
            )?;
            verify_all_payed(&c.state().balances(), channel_capacity, channel_constants)?;
            Ok(())
        }
        ChannelWitnessUnion::Fund(_) => Err(Error::ChannelFundWithoutChannelOutput),
        ChannelWitnessUnion::Dispute(_) => Err(Error::ChannelDisputeWithoutChannelOutput),
    }
}

pub fn load_witness() -> Result<ChannelWitness, Error> {
    // What if there is only an output?
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let witness_bytes: Bytes = witness_args
        .input_type()
        .to_opt()
        .ok_or(Error::NoWitness)?
        .unpack();
    let channel_witness = ChannelWitness::from_slice(&witness_bytes)?;
    Ok(channel_witness)
}

pub fn verify_increasing_version_number(
    old_state: &ChannelState,
    new_state: &ChannelState,
) -> Result<(), Error> {
    if old_state.version().unpack() < new_state.version().unpack() {
        return Ok(());
    }
    Err(Error::VersionNumberNotIncreasing)
}

pub fn verify_valid_state_sig(
    sig: &Signature,
    state: &ChannelState,
    pub_key: &PubKey,
) -> Result<(), Error> {
    Err(todo!())
}

pub fn verify_state_not_finalized(state: &ChannelState) -> Result<(), Error> {
    if state.is_final().to_bool() {
        return Err(Error::StateIsFinal);
    }
    Ok(())
}

pub fn verify_status_funded(status: &ChannelStatus) -> Result<(), Error> {
    if !status.funded().to_bool() {
        return Err(Error::ChannelNotFunded);
    }
    Ok(())
}

pub fn verify_equal_balances(
    old_balances: &Balances,
    new_balances: &Balances,
) -> Result<(), Error> {
    if old_balances.equal(new_balances) {
        return Ok(());
    }
    Err(Error::BalancesNotEqual)
}

pub fn verify_channel_continues(own_script: &Script) -> Result<(), Error> {
    let idx = get_own_input_index(own_script)?;
    let corresponding_lock_script = load_cell_lock(idx, Source::Input)?;
    let outputs = load_transaction()?.raw().outputs();

    let mut found_match = false;
    for output in outputs.into_iter() {
        if is_matching_output(&output, &corresponding_lock_script, own_script) && !found_match {
            found_match = true;
        } else if is_matching_output(&output, &corresponding_lock_script, own_script) && found_match
        {
            return Err(Error::MultipleMatchingOutputs);
        }
    }

    if found_match {
        return Ok(());
    }
    return Err(Error::ChannelDoesNotContinue);
}

pub fn get_own_input_index(own_script: &Script) -> Result<usize, Error> {
    for i in 0.. {
        let cell_type_hash = load_cell_type_hash(i, Source::Input)?;
        if cell_type_hash.is_some()
            && cell_type_hash.unwrap()[..] == own_script.code_hash().unpack()[..]
        {
            return Ok(i);
        }
    }
    Err(Error::OwnIndexNotFound)
}

pub fn verify_no_funds_in_inputs(pfls_hash: &Byte32) -> Result<(), Error> {
    let num_inputs = load_transaction()?.raw().inputs().len();
    for i in 0..num_inputs {
        let cell_lock_hash = load_cell_lock_hash(i, Source::Input)?;
        if cell_lock_hash[..] == pfls_hash.unpack() {
            return Err(Error::FundsInInputs);
        }
    }
    Ok(())
}

pub fn verify_equal_channel_state(
    old_state: &ChannelState,
    new_state: &ChannelState,
) -> Result<(), Error> {
    if old_state.as_slice()[..] == new_state.as_slice()[..] {
        return Ok(());
    }
    Err(Error::ChannelStateNotEqual)
}

// Note: idx is the acting party!
pub fn verify_funding_unchanged(
    idx: usize,
    old_funding: &Balances,
    new_funding: &Balances,
) -> Result<(), Error> {
    if old_funding.get(idx)? != new_funding.get(idx)? {
        return Err(Error::FundingChanged);
    }
    Ok(())
}

pub fn verify_funding_in_status(
    idx: usize,
    new_funding: &Balances,
    initial_state: &ChannelState,
) -> Result<(), Error> {
    if new_funding.get(idx)? != initial_state.balances().get(idx)? {
        return Err(Error::FundingNotInStatus);
    }
    Ok(())
}

// Note: To support UDT Assets, this function needs to be extended to check the presence of an amount of the asset instead of the capacity.
pub fn verify_funding_in_outputs(
    idx: usize,
    initial_balance: &Balances,
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    let to_fund = initial_balance.get(idx)?;
    if to_fund == 0 {
        return Ok(());
    }
    let outputs = load_transaction()?.raw().outputs();
    let pfls_hash = channel_constants.pfls_hash().unpack();
    let pfls_args: Bytes = channel_constants.pfls_args().unpack();
    let mut capacity_sum: u128 = 0;
    for output in outputs.into_iter() {
        if output.lock().code_hash().unpack()[..] == pfls_hash[..] {
            let lock_args: Bytes = output.lock().args().unpack();
            if lock_args[..] == pfls_args[..] {
                capacity_sum += u128::from(output.capacity().unpack());
            }
        }
    }
    if capacity_sum != to_fund {
        return Err(Error::OwnFundingNotInOutputs);
    }
    Ok(())
}

pub fn verify_funded_status(status: &ChannelStatus) -> Result<(), Error> {
    if status.funded().to_bool() == status.state().balances().equal(&status.funding()) {
        return Ok(());
    }
    Err(Error::FundedBitStatusNotCorrect)
}

pub fn verify_status_not_funded(status: &ChannelStatus) -> Result<(), Error> {
    if status.funded().to_bool() {
        return Err(Error::StateIsFunded);
    }
    Ok(())
}

pub fn verify_channel_params_compatibility(params: &ChannelParameters) -> Result<(), Error> {
    if params.app().to_opt().is_some() {
        return Err(Error::AppChannelsNotSupported);
    }
    if !params.is_ledger_channel().to_bool() {
        return Err(Error::NonLedgerChannelsNotSupported);
    }
    if params.is_virtual_channel().to_bool() {
        return Err(Error::VirtualChannelsNotSupported);
    }
    Ok(())
}

pub fn verify_equal_channel_id(
    old_state: &ChannelState,
    new_state: &ChannelState,
) -> Result<(), Error> {
    if old_state.channel_id().unpack()[..] != new_state.channel_id().unpack()[..] {
        return Err(Error::ChannelIdMismatch);
    }
    Ok(())
}

pub fn verify_channel_state_progression(
    old_state: &ChannelState,
    new_state: &ChannelState,
) -> Result<(), Error> {
    verify_equal_channel_id(old_state, new_state)?;
    verify_increasing_version_number(old_state, new_state)?;
    verify_equal_balances(&old_state.balances(), &new_state.balances())?;
    verify_state_not_finalized(old_state)?;
    Ok(())
}

pub fn verify_thread_token_integrity(thread_token: &ChannelToken) -> Result<(), Error> {
    let inputs = load_transaction()?.raw().inputs();
    for input in inputs.into_iter() {
        if input.previous_output().as_slice()[..] == thread_token.out_point().as_slice()[..] {
            return Ok(());
        }
    }
    Err(Error::InvalidThreadToken)
}

pub fn verify_channel_id_integrity(
    channel_id: &Byte32,
    params: &ChannelParameters,
) -> Result<(), Error> {
    let digest = blake2b256(params.as_slice());
    if digest[..] != channel_id.unpack()[..] {
        return Err(Error::InvalidChannelId);
    }
    Ok(())
}

pub fn verify_state_valid_as_start(state: &ChannelState) -> Result<(), Error> {
    if state.version().unpack() != 0 {
        return Err(Error::StartWithNonZeroVersion);
    }
    if state.is_final().to_bool() {
        return Err(Error::StartWithFinalizedState);
    }
    // TODO: Check that each individual balance is large enough to be funded.
    Ok(())
}

pub fn verify_valid_lock_script(
    own_type_script: &Script,
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    let idx = get_own_input_index(own_type_script)?;
    let lock_script = load_cell_lock(idx, Source::Input)?;
    let lock_script_args: Bytes = lock_script.args().unpack();
    if lock_script.code_hash().unpack()[..] != channel_constants.pcls_hash().unpack()[..] {
        return Err(Error::InvalidPCLSHash);
    }
    if !lock_script_args.is_empty() {
        return Err(Error::PCLSWithArgs);
    }
    Ok(())
}

pub fn verify_status_not_disputed(status: &ChannelStatus) -> Result<(), Error> {
    if status.disputed().to_bool() {
        return Err(Error::StatusDisputed);
    }
    Ok(())
}

pub fn verify_status_disputed(status: &ChannelStatus) -> Result<(), Error> {
    if !status.disputed().to_bool() {
        return Err(Error::StatusNotDisputed);
    }
    Ok(())
}

pub fn verify_funding_is_zero_at_index(idx: usize, funding: &Balances) -> Result<(), Error> {
    if funding.get(idx)? != 0 {
        return Err(Error::FundingNotZero);
    }
    Ok(())
}

pub fn verify_all_payed(
    final_balance: &Balances,
    channel_capacity: u64,
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    let balance_fst: u128 = final_balance.get(0)? + u128::from(channel_capacity);
    let payment_args_fst: Bytes = channel_constants.params().party_a().payment_args().unpack();

    let balance_snd: u128 = final_balance.get(1)?;
    let payment_args_snd: Bytes = channel_constants.params().party_b().payment_args().unpack();

    let payment_lock_hash = channel_constants.payment_lock_hash().unpack();

    let mut outputs_fst = 0;
    let mut outputs_snd = 0;

    let outputs = load_transaction()?.raw().outputs();

    // TODO: Maybe we want to check that there is only one paying output per party?
    for output in outputs.into_iter() {
        if output.type_().to_opt().is_some() {
            continue;
        }
        let lock_hash = output.lock().code_hash().unpack();
        if lock_hash[..] != payment_lock_hash[..] {
            continue;
        }
        let lock_args: Bytes = output.lock().args().unpack();
        if lock_args[..] == payment_args_fst[..] {
            outputs_fst += u128::from(output.capacity().unpack());
        }
        if lock_args[..] == payment_args_snd[..] {
            outputs_snd += u128::from(output.capacity().unpack());
        }
    }
    if balance_fst != outputs_fst || balance_snd != outputs_snd {
        return Err(Error::NotAllPayed);
    }
    Ok(())
}

pub fn verify_correct_time_stamp(timestamp: u64) -> Result<(), Error> {
    let current_time = find_closest_current_time();
    if timestamp >= current_time && timestamp <= current_time + MAX_TIMESTAMP_DRIFT {
        return Ok(());
    }
    Err(Error::InvalidTimestamp)
}

pub fn verify_time_lock_expired(time_lock: u64, old_timestamp: u64) -> Result<(), Error> {
    let current_time = find_closest_current_time();
    if old_timestamp + time_lock > current_time {
        return Err(Error::TimeLockNotExpired);
    }
    Ok(())
}

pub fn find_closest_current_time() -> u64 {
    let mut latest_time = 0;
    for i in 0.. {
        match load_header(i, Source::HeaderDep) {
            Ok(header) => {
                let timestamp = header.raw().timestamp().unpack();
                if timestamp > latest_time {
                    latest_time = timestamp;
                }
            }
            Err(_) => break,
        }
    }
    latest_time
}

pub fn verify_state_finalized(state: &ChannelState) -> Result<(), Error> {
    if !state.is_final().to_bool() {
        return Err(Error::StateNotFinal);
    }
    Ok(())
}

// TODO: Verify that there are never PCTS in inputs or outputs.
pub fn get_channel_action() -> Result<ChannelAction, Error> {
    let mut input_status_opt: Option<ChannelStatus> = None;
    let mut output_status_opt: Option<ChannelStatus> = None;

    // Hack: If load_cell_type_hash succeeds, we know that this type script exists at least in an input of the transaction.
    // If it does not succeed, we know that it does not exist in any input of the transaction.
    // We do not actually care about the hash.
    match load_cell_type_hash(0, Source::GroupInput) {
        Ok(_) => {
            input_status_opt = Some(ChannelStatus::from_slice(
                load_cell_data(0, Source::GroupInput)?.as_slice(),
            )?);
        }
        Err(_) => {}
    }

    // Hack: If load_cell_type_hash succeeds, we know that this type script exists at least in an output of the transaction.
    // If it does not succeed, we know that it does not exist in any output of the transaction.
    // We do not actually care about the hash.
    match load_cell_type_hash(0, Source::GroupOutput) {
        Ok(_) => {
            output_status_opt = Some(ChannelStatus::from_slice(
                load_cell_data(0, Source::GroupOutput)?.as_slice(),
            )?);
        }
        Err(_) => {}
    }
    match (input_status_opt, output_status_opt) {
        (Some(old_status), Some(new_status)) => Ok(ChannelAction::Progress {
            old_status,
            new_status,
        }),
        (Some(old_status), None) => Ok(ChannelAction::Close { old_status }),
        (None, Some(new_status)) => Ok(ChannelAction::Start { new_status }),
        (None, None) => Err(Error::UnableToLoadAnyChannelStatus),
    }
}
