// Import from `core` instead of from `std` since we are in no-std mode
use core::{result::Result};
// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{self, vec};

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
        load_header, load_script, load_script_hash, load_transaction, load_witness_args,
    }, syscalls::{SysError, self},
};
use perun_common::{
    error::Error,
    helpers::blake2b256,
    perun_types::{
        Balances, ChannelConstants, ChannelParameters, ChannelState, ChannelStatus, ChannelToken,
        ChannelWitness, ChannelWitnessUnion, SEC1EncodedPubKey,
    },
    sig::verify_signature,
};

const SUDT_MIN_LEN: usize = 16;

/// ChannelAction describes what kind of interaction with the channel is currently happening.
///
/// If there is an old ChannelStatus, it is the status of the channel before the interaction.
/// The old ChannelStatus lives in the cell data of the pcts input cell.
/// It is stored in the parallel outputs_data array of the transaction that produced the consumed
/// channel output cell.
///
/// If there is a new ChannelStatus, it is the status of the channel after the interaction.
/// The new ChannelStatus lives in the cell data of the pcts output cell. It is stored in the
/// parallel outputs_data array of the consuming transaction
pub enum ChannelAction {
    /// Progress indicates that a channel is being progressed. This means that a channel cell is consumed
    /// in the inputs and the same channel with updated state is progressed in the outputs.
    /// The possible redeemers associated with the Progress action are Fund and Dispute.
    Progress {
        old_status: ChannelStatus,
        new_status: ChannelStatus,
    }, // one PCTS input, one PCTS output
    /// Start indicates that a channel is being started. This means that a **new channel** lives in the
    /// output cells of this transaction. No channel cell is consumes as an input.
    /// As Start does not consume a channel cell, there is no Witness associated with the Start action.
    Start { new_status: ChannelStatus }, // no PCTS input, one PCTS output
    /// Close indicates that a channel is being closed. This means that a channel's cell is consumed without being
    /// recreated in the outputs with updated state. The possible redeemers associated with the Close action are
    /// Close, Abort and ForceClose.
    /// The channel type script assures that all funds are payed out to the correct parties upon closing.
    Close { old_status: ChannelStatus }, // one PCTS input , no PCTS output
}

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    // return an error if args is empty
    if args.is_empty() {
        return Err(Error::NoArgs);
    }

    // We verify that there is at most one channel in the GroupInputs and GroupOutputs respectively.
    verify_max_one_channel()?;
    debug!("verify_max_one_channel passed");

    // The channel constants do not change during the lifetime of a channel. They are located in the
    // args field of the pcts.
    let channel_constants =
        ChannelConstants::from_slice(&args).expect("unable to parse args as ChannelConstants");
    debug!("parsing channel constants passed");

    // Verify that the channel parameters are compatible with the currently supported
    // features of perun channels.
    verify_channel_params_compatibility(&channel_constants.params())?;
    debug!("verify_channel_params_compatibility passed");

    // Next, we determine whether the transaction starts, progresses or closes the channel and fetch
    // the respective old and/or new channel status.
    let channel_action = get_channel_action()?;
    debug!("get_channel_action passed");

    match channel_action {
        ChannelAction::Start { new_status } => check_valid_start(&new_status, &channel_constants),
        ChannelAction::Progress {
            old_status,
            new_status,
        } => {
            let channel_witness = load_witness()?;
            debug!("load_witness passed");
            check_valid_progress(
                &old_status,
                &new_status,
                &channel_witness,
                &channel_constants,
            )
        }
        ChannelAction::Close { old_status } => {
            let channel_witness = load_witness()?;
            debug!("load_witness passed");
            check_valid_close(&old_status, &channel_witness, &channel_constants)
        }
    }
}

pub fn check_valid_start(
    new_status: &ChannelStatus,
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    const FUNDER_INDEX: usize = 0;

    debug!("check_valid_start");

    // Upon start of a channel, the channel constants are stored in the args field of the pcts output.
    // We uniquely identify a channel through the combination of the channel id (hash of ChannelParameters,
    // which is part of the ChannelConstants) and the "thread token".
    // The thread token contains an OutPoint and the channel type script verifies, that that outpoint is
    // consumed in the inputs of the transaction that starts the channel.
    // This means: Once a (pcts-hash, channel-id, thread-token) tuple appears once on chain and is recognized
    // as the on-chain representation of this channel by all peers, no other "copy" or "fake" of that channel
    // can be created on chain, as an OutPoint can only be consumed once.

    // here, we verify that the OutPoint in the thread token is actually consumed.
    verify_thread_token_integrity(&channel_constants.thread_token())?;
    debug!("verify_thread_token_integrity passed");

    // We verify that the channel id is the hash of the channel parameters.
    verify_channel_id_integrity(
        &new_status.state().channel_id(),
        &channel_constants.params(),
    )?;
    debug!("verify_channel_id_integrity passed");

    // We verify that the pcts is guarded by the pcls script specified in the channel constants
    verify_valid_lock_script(channel_constants)?;
    debug!("verify_valid_lock_script passed");

    // We verify that the channel participants have different payment addresses
    // For this purpose we consider a payment address to be the script hash of the lock script used for payments to that party
    verify_different_payment_addresses(channel_constants)?;
    debug!("verify_different_payment_addresses passed");

    // We verify that there are no funds locked by the pfls hash of this channel in the inputs of the transaction.
    // This check is not strictly necessary for the current implementation of the pfls, but it is good practice to
    // verify this anyway, as there is no reason to include funds locked for any channel in the input of a transaction
    // that creates a new channel besides trying some kind of attack.
    verify_no_funds_in_inputs(channel_constants)?;
    debug!("verify_no_funds_in_inputs passed");

    // We verify that the state the channel starts with is valid according to the utxo-adaption of the perun protocol.
    // For example, the channel must not be final and the version number must be 0.
    verify_state_valid_as_start(
        &new_status.state(),
        channel_constants.pfls_min_capacity().unpack(),
    )?;
    debug!("verify_state_valid_as_start passed");

    // Here we verify that the first party completes its funding and that itsfunds are actually locked to the pfls with correct args.
    verify_funding_in_outputs(FUNDER_INDEX, &new_status.state().balances(), channel_constants)?;
    debug!("verify_funding_in_outputs passed");

    // We check that the funded bit in the channel status is set to true, exactly if the funding is complete.
    verify_funded_status(new_status, true)?;
    debug!("verify_funded_status passed");

    // We verify that the channel status is not disputed upon start.
    verify_status_not_disputed(new_status)?;
    debug!("verify_status_not_disputed passed");
    Ok(())
}

pub fn check_valid_progress(
    old_status: &ChannelStatus,
    new_status: &ChannelStatus,
    witness: &ChannelWitness,
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    debug!("check_valid_progress");

    // At this point we know that the transaction progresses the channel. There are two different
    // kinds of channel progression: Funding and Dispute. Which kind of progression is performed
    // depends on the witness.

    // Some checks are common to both kinds of progression and are performed here.
    // We check that both the old and the new state have the same channel id.
    verify_equal_channel_id(&old_status.state(), &new_status.state())?;
    debug!("verify_equal_channel_id passed");

    // No kind of channel progression should pay out any funds locked by the pfls, so we just check
    // that there are no funds locked by the pfls in the inputs of the transaction.
    verify_no_funds_in_inputs(channel_constants)?;
    debug!("verify_no_funds_in_inputs passed");
    // Here we verify that the cell with the PCTS in the outputs is locked by the same lock script
    // as the input channel cell.
    verify_channel_continues_locked()?;
    debug!("verify_channel_continues_locked passed");

    match witness.to_enum() {
        ChannelWitnessUnion::Fund(_) => {
            const FUNDER_INDEX: usize = 1;
            debug!("ChannelWitnessUnion::Fund");

            // The funding array in a channel status reflects how much each party has funded up to that point.
            // Funding must not alter the channel's state.
            verify_equal_channel_state(&old_status.state(), &new_status.state())?;
            debug!("verify_equal_channel_state passed");

            // Funding an already funded status is invalid.
            verify_status_not_funded(&old_status)?;
            debug!("verify_status_not_funded passed");

            verify_funding_in_outputs(
                FUNDER_INDEX,
                &old_status.state().balances(),
                channel_constants,
            )?;
            debug!("verify_funding_in_outputs passed");

            // Funding a disputed status is invalid. This should not be able to happen anyway, but we check
            // it nontheless.
            verify_status_not_disputed(new_status)?;
            debug!("verify_status_not_disputed passed");

            // We check that the funded bit in the channel status is set to true, iff the funding is complete.
            verify_funded_status(&new_status, false)?;
            debug!("verify_funded_status passed");
            Ok(())
        }
        ChannelWitnessUnion::Dispute(d) => {
            debug!("ChannelWitnessUnion::Dispute");

            // An honest party will dispute a channel, e.g. if its peer does not respond and it wants to close
            // the channel. For this, the honest party needs to provide the latest state (in the "new" channel status)
            // as well as a valid signature by each party on that state (in the witness). After the expiration of the
            // relative time lock (challenge duration), the honest party can forcibly close the channel.
            // If a malicious party disputes with an old channel state, an honest party can dispute again with
            // the latest state (with higher version number) and the corresponding signatures within the challenge
            // duration.

            // First, we verify the integrity of the channel state. For this, the following must hold:
            // - channel id is equal
            // - version number is increasing (see verify_increasing_version_number)
            // - sum of balances is equal
            // - old state is not final
            verify_channel_state_progression(old_status, &new_status.state())?;
            debug!("verify_channel_state_progression passed");

            // One cannot dispute if funding is not complete.
            verify_status_funded(old_status)?;
            debug!("verify_status_funded passed");

            // The disputed flag in the new status must be set. This indicates that the channel can be closed
            // forcibly after the expiration of the challenge duration in a later transaction.
            verify_status_disputed(new_status)?;
            debug!("verify_status_disputed passed");

            // We verify that the signatures of both parties are valid on the new channel state.
            verify_valid_state_sigs(
                &d.sig_a().unpack(),
                &d.sig_b().unpack(),
                &new_status.state(),
                &channel_constants.params().party_a().pub_key(),
                &channel_constants.params().party_b().pub_key(),
            )?;
            debug!("verify_valid_state_sigs passed");
            Ok(())
        }
        // Close, ForceClose and Abort may not happen as channel progression (if there is a continuing channel output).
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
    debug!("check_valid_close");

    // At this point we know that this transaction closes the channel. There are three different kinds of
    // closing: Abort, ForceClose and Close. Which kind of closing is performed depends on the witness.
    // Every channel closing transaction must pay out all funds the the channel participants. The amount
    // to be payed to each party
    let channel_capacity = load_cell_capacity(0, Source::GroupInput)?;
    match channel_witness.to_enum() {
        ChannelWitnessUnion::Abort(_) => {
            const PARTY_B_INDEX: usize = 1;

            debug!("ChannelWitnessUnion::Abort");

            // An abort can be performed at any time by a channel participant on a channel for which funding
            // is not yet complete. It allows the initial party to reclaim its funds if e.g. the other party
            // refuses to fund the channel.
            verify_status_not_funded(old_status)?;
            debug!("verify_status_not_funded passed");

            // We verify that every party is payed the amount of funds that it has locked to the channel so far.
            // If abourt is called, Party A must have fully funded the channel and Party B can not have funded
            // the channel because of our funding protocol.
            verify_all_payed(&old_status.state().balances().clear_index(PARTY_B_INDEX)?, channel_capacity, channel_constants, true)?;
            debug!("verify_all_payed passed");
            Ok(())
        }
        ChannelWitnessUnion::ForceClose(_) => {
            debug!("ChannelWitnessUnion::ForceClose");
            // A force close can be performed after the channel was disputed and the challenge duration has
            // expired. Upon force close, each party is payed according to the balance distribution in the
            // latest state.
            verify_status_funded(old_status)?;
            debug!("verify_status_funded passed");
            verify_time_lock_expired(channel_constants.params().challenge_duration().unpack())?;
            debug!("verify_time_lock_expired passed");
            verify_status_disputed(old_status)?;
            debug!("verify_status_disputed passed");
            verify_all_payed(&old_status.state().balances(), channel_capacity, channel_constants, false)?;
            debug!("verify_all_payed passed");
            Ok(())
        }
        ChannelWitnessUnion::Close(c) => {
            debug!("check_valid_close: Close");

            // A channel can be closed by either party at any time after funding is complete.
            // For this the party needs to provide a final state (final bit set) and signatures
            // by all peers on that state.
            verify_equal_channel_id(&old_status.state(), &c.state())?;
            debug!("check_valid_close: Channel id verified");
            verify_status_funded(old_status)?;
            debug!("check_valid_close: Status funded verified");
            verify_state_finalized(&c.state())?;
            debug!("check_valid_close: State finalized verified");
            verify_valid_state_sigs(
                &c.sig_a().unpack(),
                &c.sig_b().unpack(),
                &c.state(),
                &channel_constants.params().party_a().pub_key(),
                &channel_constants.params().party_b().pub_key(),
            )?;
            // We verify that each party is payed according to the balance distribution in the final state.
            verify_all_payed(&c.state().balances(), channel_capacity, channel_constants, false)?;
            debug!("verify_all_payed passed");
            Ok(())
        }
        ChannelWitnessUnion::Fund(_) => Err(Error::ChannelFundWithoutChannelOutput),
        ChannelWitnessUnion::Dispute(_) => Err(Error::ChannelDisputeWithoutChannelOutput),
    }
}

pub fn load_witness() -> Result<ChannelWitness, Error> {
    debug!("load_witness");

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
    old_status: &ChannelStatus,
    new_state: &ChannelState,
) -> Result<(), Error> {
    debug!("verify_increasing_version_number old_state disputed:  {}", old_status.disputed().to_bool());
    debug!("verify_increasing_version_number old: {},  new: {}", old_status.state().version().unpack(), new_state.version().unpack());
    // Allow registering initial state
    if !old_status.disputed().to_bool() && old_status.state().version().unpack() == 0 && new_state.version().unpack() == 0 {
        return Ok(());
    }
    if old_status.state().version().unpack() < new_state.version().unpack() {
        return Ok(());
    }
    Err(Error::VersionNumberNotIncreasing)
}

pub fn verify_valid_state_sigs(
    sig_a: &Bytes,
    sig_b: &Bytes,
    state: &ChannelState,
    pub_key_a: &SEC1EncodedPubKey,
    pub_key_b: &SEC1EncodedPubKey,
) -> Result<(), Error> {
    let msg_hash = blake2b256(state.as_slice());
    verify_signature(&msg_hash, sig_a, pub_key_a.as_slice())?;
    debug!("verify_valid_state_sigs: Signature A verified");
    verify_signature(&msg_hash, sig_b, pub_key_b.as_slice())?;
    debug!("verify_valid_state_sigs: Signature B verified");
    Ok(())
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

pub fn verify_equal_sum_of_balances(
    old_balances: &Balances,
    new_balances: &Balances,
) -> Result<(), Error> {
    if !old_balances.equal_in_sum(new_balances)? {
        return Err(Error::SumOfBalancesNotEqual);
    }
    Ok(())
}

pub fn verify_channel_continues_locked() -> Result<(), Error> {
    let input_lock_script = load_cell_lock(0, Source::GroupInput)?;
    let output_lock_script = load_cell_lock(0, Source::GroupOutput)?;
    if input_lock_script.as_slice()[..] != output_lock_script.as_slice()[..] {
        return Err(Error::ChannelDoesNotContinue);
    }
    Ok(())
}

pub fn verify_no_funds_in_inputs(channel_constants: &ChannelConstants) -> Result<(), Error> {
    let num_inputs = load_transaction()?.raw().inputs().len();
    for i in 0..num_inputs {
        let cell_lock_hash = load_cell_lock(i, Source::Input)?;
        if cell_lock_hash.code_hash().unpack()[..]
            == channel_constants.pfls_code_hash().unpack()[..]
        {
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

pub fn verify_funding_in_outputs(
    idx: usize,
    initial_balance: &Balances,
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    let ckbytes_locked_for_sudts = initial_balance.sudts().get_locked_ckbytes();
    let to_fund = initial_balance.ckbytes().get(idx)? + ckbytes_locked_for_sudts;
    if to_fund == 0 {
        return Ok(());
    }
    
    let mut udt_sum = vec![0u128, initial_balance.sudts().len().try_into().unwrap()].into_boxed_slice();

    let expected_pcts_script_hash = load_script_hash()?;
    let outputs = load_transaction()?.raw().outputs();
    let expected_pfls_code_hash = channel_constants.pfls_code_hash().unpack();
    let expected_pfls_hash_type = channel_constants.pfls_hash_type();
    let mut capacity_sum: u64 = 0;
    for (i, output) in outputs.into_iter().enumerate() {
        if output.lock().code_hash().unpack()[..] == expected_pfls_code_hash[..]
            && output.lock().hash_type().eq(&expected_pfls_hash_type)
        {
            let output_lock_args: Bytes = output.lock().args().unpack();
            let script_hash_in_pfls_args = Byte32::from_slice(&output_lock_args)?.unpack();
            if script_hash_in_pfls_args[..] == expected_pcts_script_hash[..] {
                capacity_sum += output.capacity().unpack();
            } else {
                return Err(Error::InvalidPFLSInOutputs);
            }
            if output.type_().is_some() {
                let (sudt_idx, amount) = get_sudt_amout(initial_balance, i, &output.type_().to_opt().expect("checked above"))?;
                udt_sum[sudt_idx] += amount;
            }
        }
    }
    if capacity_sum != to_fund {
        debug!("verify_funding_in_outputs: capacity_sum: {}, to_fund: {}", capacity_sum, to_fund);
        return Err(Error::OwnFundingNotInOutputs);
    }
    if !initial_balance.sudts().fully_represented(idx, &udt_sum)? {
        return Err(Error::OwnFundingNotInOutputs);
    }

    Ok(())
}

pub fn verify_funded_status(status: &ChannelStatus, is_start: bool) -> Result<(), Error> {
    if !is_start {
        if !status.funded().to_bool() {
            return Err(Error::FundedBitStatusNotCorrect);
        }
        return Ok(());
    }
    if status.state().balances().ckbytes().get(1)? != 0 {
        if status.funded().to_bool() {
            return Err(Error::FundedBitStatusNotCorrect);
        }
        return Ok(());
    }
    if status.state().balances().sudts().len() != 0 {
        if status.funded().to_bool() {
            return Err(Error::FundedBitStatusNotCorrect);
        }
        return Ok(());
    }
    if !status.funded().to_bool() {
        return Err(Error::FundedBitStatusNotCorrect);
    }
    Ok(())
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
    old_status: &ChannelStatus,
    new_state: &ChannelState,
) -> Result<(), Error> {
    verify_equal_channel_id(&old_status.state(), new_state)?;
    verify_increasing_version_number(old_status, new_state)?;
    verify_equal_sum_of_balances(&old_status.state().balances(), &new_state.balances())?;
    verify_state_not_finalized(&old_status.state())?;
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

pub fn verify_state_valid_as_start(
    state: &ChannelState,
    pfls_min_capacity: u64,
) -> Result<(), Error> {
    if state.version().unpack() != 0 {
        return Err(Error::StartWithNonZeroVersion);
    }
    if state.is_final().to_bool() {
        return Err(Error::StartWithFinalizedState);
    }

    // We verify that each participant's initial balance is at least the minimum capacity of a PFLS (or zero),
    // to ensure that funding is possible for the initial balance distribution.
    let balance_a = state.balances().ckbytes().get(0)?;
    let balance_b = state.balances().ckbytes().get(1)?;
    if balance_a < pfls_min_capacity && balance_a != 0 {
        return Err(Error::BalanceBelowPFLSMinCapacity);
    }
    if balance_b < pfls_min_capacity && balance_b != 0 {
        return Err(Error::BalanceBelowPFLSMinCapacity);
    }
    Ok(())
}

pub fn verify_valid_lock_script(channel_constants: &ChannelConstants) -> Result<(), Error> {
    let lock_script = load_cell_lock(0, Source::GroupOutput)?;
    if lock_script.code_hash().unpack()[..] != channel_constants.pcls_code_hash().unpack()[..] {
        return Err(Error::InvalidPCLSCodeHash);
    }
    if !lock_script
        .hash_type()
        .eq(&channel_constants.pcls_hash_type())
    {
        return Err(Error::InvalidPCLSHashType);
    }

    if !lock_script.args().is_empty() {
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

pub fn verify_all_payed(
    final_balance: &Balances,
    channel_capacity: u64,
    channel_constants: &ChannelConstants,
    is_abort: bool,
) -> Result<(), Error> {
    debug!("verify_all_payed");
    debug!("is_abort: {}", is_abort);
    let minimum_payment_a = channel_constants
        .params()
        .party_a()
        .payment_min_capacity()
        .unpack();
    let minimum_payment_b: u64 = channel_constants
        .params()
        .party_b()
        .payment_min_capacity()
        .unpack();

    let reimburse_a = final_balance.sudts().get_locked_ckbytes();
    let mut reimburse_b = 0u64;
    if !is_abort {
        reimburse_b = reimburse_a;
    }


    let ckbytes_balance_a = final_balance.ckbytes().get(0)? + channel_capacity + reimburse_a;
    let payment_script_hash_a = channel_constants
        .params()
        .party_a()
        .payment_script_hash()
        .unpack();

    let ckbytes_balance_b = final_balance.ckbytes().get(1)? + reimburse_b;
    let payment_script_hash_b = channel_constants
        .params()
        .party_b()
        .payment_script_hash()
        .unpack();

    debug!("ckbytes_balance_a: {}", ckbytes_balance_a);
    debug!("ckbytes_balance_b: {}", ckbytes_balance_b);

    let mut ckbytes_outputs_a = 0;
    let mut ckbytes_outputs_b = 0;

    let mut udt_outputs_a = vec![0u128; final_balance.sudts().len().try_into().unwrap()].into_boxed_slice();
    let mut udt_outputs_b = vec![0u128; final_balance.sudts().len().try_into().unwrap()].into_boxed_slice();

    let outputs = load_transaction()?.raw().outputs();

    // Note: Currently it is allowed to pay out a party's CKBytes in the capacity field of an
    // output, that is used as SUDT payment.
    for (i, output) in outputs.into_iter().enumerate() {
        let output_lock_script_hash = load_cell_lock_hash(i, Source::Output)?;

        if output_lock_script_hash[..] == payment_script_hash_a[..] {
            if output.type_().is_some() {
                let (sudt_idx, amount) = get_sudt_amout(final_balance, i, &output.type_().to_opt().expect("checked above"))?; 
                udt_outputs_a[sudt_idx] += amount;
            }
            ckbytes_outputs_a += output.capacity().unpack();
        }
        if output_lock_script_hash[..] == payment_script_hash_b[..] {
            if output.type_().is_some() {
                let (sudt_idx, amount) = get_sudt_amout(final_balance, i, &output.type_().to_opt().expect("checked above"))?; 
                udt_outputs_b[sudt_idx] += amount;
            }
            ckbytes_outputs_b += output.capacity().unpack();
        }
    }
    debug!("ckbytes_outputs_a: {}", ckbytes_outputs_a);
    debug!("ckbytes_outputs_b: {}", ckbytes_outputs_b);

    // Parties with balances below the minimum capacity of the payment script
    // are not required to be payed.
    if (ckbytes_balance_a > ckbytes_outputs_a && ckbytes_balance_a >= minimum_payment_a)
        || (ckbytes_balance_b > ckbytes_outputs_b && ckbytes_balance_b >= minimum_payment_b)
    {
        return Err(Error::NotAllPayed);
    }

    debug!("udt_outputs_a: {:?}", udt_outputs_a);
    debug!("udt_outputs_b: {:?}", udt_outputs_b);

    if !final_balance.sudts().fully_represented(0, &udt_outputs_a)? {
        return Err(Error::NotAllPayed);
    }
    if !final_balance.sudts().fully_represented(1, &udt_outputs_b)? {
        return Err(Error::NotAllPayed);
    }
    Ok(())
}


// TODO: We might want to verify that the capacity of the sudt output is at least the max_capacity of the SUDT asset.
//      Not doing so may result in the ability to steal funds up to the 
//      (max_capacity of the SUDT asset - actual occupied capacity of the SUDT type script), if the SUDT asset's max_capacity
//      is smaller than the payment_min_capacity of the participant. We do not do this for now, because it is an extreme edge case
//      and the max_capacity of an SUDT should never be set that low.
pub fn get_sudt_amout(balances: &Balances, output_idx: usize, type_script: &Script) -> Result<(usize, u128), Error> {
    let mut buf  = [0u8; SUDT_MIN_LEN];

    let (sudt_idx, _) = balances.sudts().get_distribution(type_script)?;
    let sudt_data = load_cell_data(output_idx, Source::Output)?;
    if sudt_data.len() < SUDT_MIN_LEN {
        return Err(Error::InvalidSUDTDataLength);
    }
    buf.copy_from_slice(&sudt_data[..SUDT_MIN_LEN]);
    return Ok((sudt_idx, u128::from_le_bytes(buf)));
}

pub fn verify_time_lock_expired(time_lock: u64) -> Result<(), Error> {
    let old_header = load_header(0, Source::GroupInput)?;
    let old_timestamp = old_header.raw().timestamp().unpack();
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

pub fn get_channel_action() -> Result<ChannelAction, Error> {
    let input_status_opt = load_cell_data(0, Source::GroupInput)
        .ok()
        .map(|data| ChannelStatus::from_slice(data.as_slice()))
        .map_or(Ok(None), |v| v.map(Some))?;

    let output_status_opt = load_cell_data(0, Source::GroupOutput)
        .ok()
        .map(|data| ChannelStatus::from_slice(data.as_slice()))
        .map_or(Ok(None), |v| v.map(Some))?;

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

/// verify_max_one_channel verifies that there is at most one channel in the group input and group output respectively.
pub fn verify_max_one_channel() -> Result<(), Error> {
    if count_cells(Source::GroupInput)? > 1 || count_cells(Source::GroupOutput)? > 1 {
        return Err(Error::MoreThanOneChannel);
    } else {
        return Ok(());
    }
}

pub fn count_cells(source: Source) -> Result<usize, Error> {
    let mut null_buf: [u8; 0] = [];
    for i in 0.. {
        match syscalls::load_cell(&mut null_buf, 0, i, source) {
            Ok(_) => continue,
            Err(SysError::LengthNotEnough(_)) => continue,
            Err(SysError::IndexOutOfBound) => return Ok(i),
            Err(err) => return Err(err.into()),
        }
    }
    Ok(0)
}

pub fn verify_different_payment_addresses(
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    if channel_constants
        .params()
        .party_a()
        .payment_script_hash()
        .unpack()[..]
        == channel_constants
            .params()
            .party_b()
            .payment_script_hash()
            .unpack()[..]
    {
        return Err(Error::SamePaymentAddress);
    }
    Ok(())
}
