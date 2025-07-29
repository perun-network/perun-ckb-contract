#![cfg_attr(not(feature = "library"), no_std)]
#![allow(special_module_name)]
#![allow(unused_attributes)]

use ckb_std::default_alloc;

ckb_std::entry!(program_entry);
default_alloc!();
// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;
// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::vec;
use core::iter::IntoIterator;
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
        load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash, load_cell_type,
        load_cell_type_hash, load_script, load_script_hash, load_transaction, load_witness_args,
    },
};
use perun_common::{
    channels::{
        find_cell_by_type_hash, get_channel_action, unpack_byte32, unpack_u64,
        verify_channel_id_integrity, verify_max_one_channel, verify_thread_token_integrity,
        verify_time_lock_expired, PChannelAction,
    },
    error::Error,
    perun_types::{
        Balances, ChannelConstants, ChannelParameters, ChannelState, ChannelStatus, ChannelWitness,
        ChannelWitnessUnion, Dispute, IndexMap, ParentsVec, SEC1EncodedPubKey, VCChannelConstants,
        VirtualChannelStatus,
    },
    sig::{
        verify_signature,
        ethereum_message_hash,
    },
};

const SUDT_MIN_LEN: usize = 16;

pub fn program_entry() -> i8 {
    match main() {
        Ok(_) => 0,   // Success
        Err(_) => -1, // Failure
    }
}

pub fn main() -> Result<(), Error> {
    debug!("PCTS");
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
        PChannelAction::Start { new_status } => check_valid_start(&new_status, &channel_constants),
        PChannelAction::Progress {
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
        PChannelAction::Close { old_status } => {
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
    verify_funding_in_outputs(
        FUNDER_INDEX,
        &new_status.state().balances(),
        channel_constants,
    )?;
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
            check_normal_dispute(old_status, new_status, channel_constants, &d)
        }

        ChannelWitnessUnion::VCDispute(vcd) => {
            debug!("ChannelWitnessUnion::VCDispute");
            check_normal_dispute(
                old_status,
                new_status,
                channel_constants,
                &vcd.parent_state_sigs(),
            )?;
            check_vc_dispute(old_status, new_status)
        }
        // Close, ForceClose and Abort may not happen as channel progression (if there is a continuing channel output).
        ChannelWitnessUnion::Close(_) => Err(Error::ChannelCloseWithChannelOutput),
        ChannelWitnessUnion::ForceClose(_) => Err(Error::ChannelForceCloseWithChannelOutput),
        ChannelWitnessUnion::Abort(_) => Err(Error::ChannelAbortWithChannelOutput),
    }
}

pub fn check_vc_dispute(
    old_status: &ChannelStatus,
    new_status: &ChannelStatus,
) -> Result<(), Error> {
    debug!("check_vc_dispute");

    //A vc cell can only be created once by this channel cell
    if !(!old_status.disputed().to_bool() && new_status.disputed().to_bool()) {
        return Err(Error::InvalidVCTxStart);
    }
    debug!("Verified that vc cell can only be created once by this lc cell");

    //A vc cell having the same vcts hash should exist in the outputs
    let vcts_hash = new_status.vcts_hash().unpack();
    let output_vc_idx = match find_cell_by_type_hash(&vcts_hash, Source::Output) {
        Ok(Some(idx)) => idx,
        Ok(None) => return Err(Error::VCOutputCellMissingIngStartTx),
        Err(err) => return Err(err.into()),
    };
    debug!("Verified that vc cell having the same vcts hash exists in the outputs");
    let vc_status = match load_cell_data(output_vc_idx, Source::Output) {
        Ok(data) => VirtualChannelStatus::from_slice(data.as_slice())?,
        Err(err) => return Err(err.into()),
    };
    verify_vc_parent(&vc_status)?;
    debug!("verify_vc_parent passed");

    //Funds in lc are blocked for vc
    verify_locked_funds(new_status, &vc_status)?;
    debug!("verify_locked_funds passed");
    debug!("check_vc_dispute passed");
    Ok(())
}

pub fn check_normal_dispute(
    old_status: &ChannelStatus,
    new_status: &ChannelStatus,
    channel_constants: &ChannelConstants,
    d: &Dispute,
) -> Result<(), Error> {
    // An honest party will dispute a channel, e.g. if its peer does not respond and it wants to close
    // the channel. For this, the honest party needs to provide the latest state (in the "new" channel status)
    // as well as a valid signature by each party on that state (in the witness). After the expiration of the
    // relative time lock (challenge duration), the honest party can forcibly close the channel.
    // If a malicious party disputes with an old channel state, an honest party can dispute again with
    // the latest state (with higher version number) and the corresponding signatures within the challenge
    // duration.

    // In normal cases (no vc dispute), we verify the integrity of the channel state. For this, the following must hold:
    // - channel id is equal
    // - version number is increasing (see verify_increasing_version_number)
    // - sum of balances is equal
    // - old state is not final
    // In case of vc disputes, we allow version number to be non-decreasing
    debug!("check_normal_dispute");
    if !old_status.vc_disputed().to_bool() {
        debug!("verify_channel_state_progression");
        verify_channel_state_progression(old_status, &new_status.state())?;
    } else {
        debug!("verify_vc_parent_state_progression");
        verify_vc_parent_state_progression(old_status, &new_status.state())?;
    }
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
    debug!("check_normal_dispute passed");
    Ok(())
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
    // to be paid to each party
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

            // We verify that every party is paid the amount of funds that it has locked to the channel so far.
            // If abourt is called, Party A must have fully funded the channel and Party B can not have funded
            // the channel because of our funding protocol.
            verify_all_paid(
                &old_status.state().balances().clear_index(PARTY_B_INDEX)?,
                channel_capacity,
                channel_constants,
                true,
            )?;
            debug!("verify_all_paid passed");
            Ok(())
        }
        ChannelWitnessUnion::ForceClose(_) => {
            debug!("ChannelWitnessUnion::ForceClose");
            if old_status.vc_disputed().to_bool() {
                debug!("Force Close (VC)");
                let vc_pcts_hash = old_status.vcts_hash().unpack();
                let input_vc_idx = match find_cell_by_type_hash(&vc_pcts_hash, Source::Input) {
                    Ok(Some(idx)) => idx,
                    Ok(None) => return Err(Error::VCInputCellMissingInClose1Tx),
                    Err(err) => return Err(err.into()),
                };
                let vc_status = match load_cell_data(input_vc_idx, Source::Input) {
                    Ok(data) => VirtualChannelStatus::from_slice(data.as_slice())?,
                    Err(err) => return Err(err.into()),
                };
                let vcts = match load_cell_type(input_vc_idx, Source::Input) {
                    Ok(Some(script)) => script,
                    Ok(None) => return Err(Error::VCInputCellMissingInClose1Tx),
                    Err(err) => return Err(err.into()),
                };
                let vcts_args: Bytes = vcts.args().unpack();
                let vchannel_constants = match VCChannelConstants::from_slice(&vcts_args) {
                    Ok(args) => args,
                    Err(err) => {
                        debug!("Error encountered while reading VCChannelConstants");
                        return Err(err.into());
                    }
                };
                check_vc_force_close(
                    old_status,
                    channel_constants,
                    &vc_status,
                    &vchannel_constants,
                )
            } else {
                debug!("Force Close (Normal)");
                check_normal_force_close(old_status, channel_constants, channel_capacity)
            }
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
            // We verify that each party is paid according to the balance distribution in the final state.
            verify_all_paid(
                &c.state().balances(),
                channel_capacity,
                channel_constants,
                false,
            )?;
            debug!("verify_all_paid passed");
            Ok(())
        }
        ChannelWitnessUnion::Fund(_) => Err(Error::ChannelFundWithoutChannelOutput),
        ChannelWitnessUnion::Dispute(_) => Err(Error::ChannelDisputeWithoutChannelOutput),
        ChannelWitnessUnion::VCDispute(_) => Err(Error::VCDisputeWithoutChannelOutput),
    }
}

pub fn check_vc_force_close(
    old_status: &ChannelStatus,
    channel_constants: &ChannelConstants,
    vc_status: &VirtualChannelStatus,
    vcts_args: &VCChannelConstants,
) -> Result<(), Error> {
    debug!("check_vc_force_close");
    let channel_capacity = load_cell_capacity(0, Source::GroupInput)?;

    //perform closing checks for ledger channel
    verify_status_funded(old_status)?;
    debug!("verify_status_funded(lc) passed");
    verify_time_lock_expired(channel_constants.params().challenge_duration().unpack())?;
    debug!("verify_time_lock_expired(lc) passed");
    verify_status_disputed(old_status)?;
    debug!("verify_status_disputed(lc) passed");

    //perform checks for child vc
    verify_time_lock_expired(vcts_args.params().challenge_duration().unpack())?;
    debug!("verify_time_lock_expired(vc) passed");

    //check that the funds are payed out correctly
    verify_all_paid_vc(
        &old_status.state().balances(),
        channel_capacity,
        channel_constants,
        &vc_status,
    )?;
    debug!("verify_all_paid_vc passed");
    Ok(())
}

pub fn check_normal_force_close(
    old_status: &ChannelStatus,
    channel_constants: &ChannelConstants,
    channel_capacity: u64,
) -> Result<(), Error> {
    debug!("ChannelWitnessUnion::ForceClose (Normal)");
    // A force close can be performed after the channel was disputed and the challenge duration has
    // expired. Upon force close, each party is paid according to the balance distribution in the
    // latest state.

    verify_status_funded(old_status)?;
    debug!("verify_status_funded passed");
    verify_time_lock_expired(channel_constants.params().challenge_duration().unpack())?;
    debug!("verify_time_lock_expired passed");
    verify_status_disputed(old_status)?;
    debug!("verify_status_disputed passed");

    // Check if this is a case where vc cell is being closed
    verify_all_paid(
        &old_status.state().balances(),
        channel_capacity,
        channel_constants,
        false,
    )?;
    debug!("verify_all_paid passed");
    Ok(())
}

pub fn verify_locked_funds(
    new_lc_status: &ChannelStatus,
    new_vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    let vc_balances = new_vc_status.vcstate().balances();
    let locked_funds_in_lc = new_lc_status.state().balances().locked();
    let vc_id = new_vc_status.vcstate().channel_id();

    for sub_alloc in locked_funds_in_lc.into_iter() {
        if sub_alloc.id().as_slice() == vc_id.as_slice() {
            if sub_alloc.balances().equal_in_sum(&vc_balances)? {
                return Ok(());
            } else {
                return Err(Error::UnequalBalanceInLockedFundsAndVirtualChannelBalance);
            }
        }
    }
    Err(Error::FundsForVCNotLocked)
}
pub fn verify_vc_parent(vc_status: &VirtualChannelStatus) -> Result<(), Error> {
    let parents = vc_status.parents();
    let pcts_hash = load_script_hash()?;
    let mut found = false;
    for i in 0..parents.len() {
        let parent = match parents.get(i) {
            Some(parent) => parent,
            None => return Err(Error::InvalidVCParentData),
        };
        let parent_hash: [u8; 32] = parent.pcts_hash().unpack();
        if parent_hash == pcts_hash {
            found = true;
            break;
        }
    }
    if !found {
        return Err(Error::InvalidVCParentData);
    }
    Ok(())
}

pub fn verify_all_paid_vc(
    lc_final_balances: &Balances,
    lc_channel_capacity: u64,
    lc_channel_constants: &ChannelConstants,
    vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    debug!("verify_all_paid_vc");
    let vc_sudts = vc_status.vcstate().balances().sudts();
    let minimum_payment_a = lc_channel_constants
        .params()
        .party_a()
        .payment_min_capacity()
        .unpack();

    let minimum_payment_b = lc_channel_constants
        .params()
        .party_b()
        .payment_min_capacity()
        .unpack();

    let reimburse_a = lc_final_balances.sudts().get_locked_ckbytes();

    let reimburse_b = reimburse_a;
    let idx_map = match get_idx_map(&vc_status.parents()) {
        Ok(map) => map,
        Err(err) => return Err(err.into()),
    };

    let party_a_vc_participant_idx = get_vc_participant_idx(0, &idx_map)?;
    let party_b_vc_participant_idx = get_vc_participant_idx(1, &idx_map)?;

    let ckbytes_balance_a = lc_final_balances.ckbytes().get(0)? + lc_channel_capacity + reimburse_a;
    let ckbytes_balance_vc_a = vc_status
        .vcstate()
        .balances()
        .ckbytes()
        .get(party_a_vc_participant_idx)?;
    let total_ckbytes_balance_a = ckbytes_balance_vc_a + ckbytes_balance_a;
    let payment_script_hash_a: [u8; 32] = lc_channel_constants
        .params()
        .party_a()
        .payment_script_hash()
        .unpack();

    let ckbytes_balance_b = lc_final_balances.ckbytes().get(1)? + reimburse_b;
    let ckbytes_balance_vc_b = vc_status
        .vcstate()
        .balances()
        .ckbytes()
        .get(party_b_vc_participant_idx)?;
    let total_ckbytes_balance_b = ckbytes_balance_vc_b + ckbytes_balance_b;

    let payment_script_hash_b: [u8; 32] = lc_channel_constants
        .params()
        .party_b()
        .payment_script_hash()
        .unpack();

    let mut ckbytes_outputs_a = 0;
    let mut ckbytes_outputs_b = 0;

    let mut udt_outputs_a =
        vec![0u128; lc_final_balances.sudts().len().try_into().unwrap()].into_boxed_slice();
    let mut udt_outputs_b =
        vec![0u128; lc_final_balances.sudts().len().try_into().unwrap()].into_boxed_slice();

    let outputs = load_transaction()?.raw().outputs();

    // Note: Currently it is allowed to pay out a party's CKBytes in the capacity field of an
    // output, that is used as SUDT payment.
    for (i, output) in outputs.into_iter().enumerate() {
        let output_lock_script_hash = load_cell_lock_hash(i, Source::Output)?;

        if output_lock_script_hash[..] == payment_script_hash_a[..] {
            if output.type_().is_some() {
                let (sudt_idx, amount) = get_sudt_amount(
                    lc_final_balances,
                    i,
                    &output.type_().to_opt().expect("checked above"),
                )?;
                udt_outputs_a[sudt_idx] += amount;
            }
            let output_cap: u64 = output.capacity().unpack();
            ckbytes_outputs_a += output_cap;
        }
        if output_lock_script_hash[..] == payment_script_hash_b[..] {
            if output.type_().is_some() {
                let (sudt_idx, amount) = get_sudt_amount(
                    lc_final_balances,
                    i,
                    &output.type_().to_opt().expect("checked above"),
                )?;
                udt_outputs_b[sudt_idx] += amount;
            }
            let output_cap: u64 = output.capacity().unpack();
            ckbytes_outputs_b += output_cap;
        }
    }

    // Parties with balances below the minimum capacity of the payment script
    // are not required to be payed.
    if (total_ckbytes_balance_a > ckbytes_outputs_a && total_ckbytes_balance_a >= minimum_payment_a)
        || (total_ckbytes_balance_b > ckbytes_outputs_b
            && total_ckbytes_balance_b >= minimum_payment_b)
    {
        return Err(Error::NotAllPaid);
    }

    if !lc_final_balances.sudts().fully_represented_vc(
        0,
        party_a_vc_participant_idx,
        &vc_sudts,
        &udt_outputs_a,
    )? {
        return Err(Error::NotAllPaid);
    }
    if !lc_final_balances.sudts().fully_represented_vc(
        1,
        party_b_vc_participant_idx,
        &vc_sudts,
        &udt_outputs_b,
    )? {
        return Err(Error::NotAllPaid);
    }
    Ok(())
}

/// get the participant index in vc, for a given participant index in lc
pub fn get_vc_participant_idx(lc_participant_idx: u8, idx_map: &IndexMap) -> Result<usize, Error> {
    //CONTEXT:
    //For any perun channel, the participant index of proposer is defined to be 0 and that of proposee is 1
    // Consider the situation where:
    //  Alice and Ingrid have a ledger channel (C_AI),
    //  Ingrid and Bob have lc C_IB,
    //  Alice and Bob have virtual channel VC_AB
    //
    // Let Bob be the proposer of the VC_AB then,
    //      participant index of Bob in VC_AB is 0
    //      participant index of Alice in VC_AB is 1
    // In C_IB, let Ingrid be the proposer then,
    //      participant index of Ingrid in C_IB is 0
    //      participant index of Bob in C_IB is 1
    //
    // An index map exists for every parent of a VC. Thus VC_AB will have an index map for C_AI and one for C_IB
    // The index map for C_IB will be [1,0]. Why?
    // index_map[0] = 1 ==> This means the funds for Proposer of VC (aka Bob) is covered by the proposee of C_IB (aka Bob) ===> True according to given situation
    // index_map[1] = 0 ==> This means the funds for Proposee of VC (aka Alice) is covered by the proposer of C_IB (aka Ingrid) ===> True according to given situation
    //
    // Which idx does this function return?
    // Let this PCTS belong to C_IB, then
    //      calling this function for Bob i.e, get_vc_participant_idx(1, &index_map) should return 0
    //      calling this function for Ingrid i.e, get_vc_participant_idx(0, &index_map) should return 1
    if idx_map.nth0().as_slice()[0] == lc_participant_idx {
        return Ok(0);
    }
    if idx_map.nth1().as_slice()[0] == lc_participant_idx {
        return Ok(1);
    }
    Err(Error::VCParticipantIdxNotFound)
}

/// get the index map for the channel cell running this pcts
pub fn get_idx_map(parents: &ParentsVec) -> Result<IndexMap, Error> {
    let pcts_hash = match load_cell_type_hash(0, Source::GroupInput)? {
        Some(hash) => hash,
        None => panic!("type script not found"),
    };
    for i in 0..parents.len() {
        let parent = match parents.get(i) {
            Some(parent) => parent,
            None => return Err(Error::InvalidVCParentData),
        };
        let parent_hash: [u8; 32] = parent.pcts_hash().unpack();
        if parent_hash == pcts_hash {
            return Ok(parent.idx_map());
        }
    }
    Err(Error::InvalidVCParentData)
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
    let old_status_disputed: bool = old_status.disputed().to_bool();
    let old_state_version: u64 = old_status.state().version().unpack();
    let new_state_version: u64 = new_state.version().unpack();

    // Allow registering initial state
    if !old_status_disputed && old_state_version == 0 && new_state_version == 0 {
        debug!("Allow registering initial state");
        return Ok(());
    }
    if old_state_version < new_state_version {
        return Ok(());
    }
    Err(Error::VersionNumberNotIncreasing)
}

pub fn verify_non_decreasing_version_number(
    old_status: &ChannelStatus,
    new_state: &ChannelState,
) -> Result<(), Error> {
    let old_state_version: u64 = old_status.state().version().unpack();
    let new_state_version: u64 = new_state.version().unpack();

    if old_state_version > new_state_version {
        return Err(Error::InvalidVersionNumberVCProgressTx);
    }
    Ok(())
}

pub fn verify_valid_state_sigs(
    sig_a: &Bytes,
    sig_b: &Bytes,
    state: &ChannelState,
    pub_key_a: &SEC1EncodedPubKey,
    pub_key_b: &SEC1EncodedPubKey,
) -> Result<(), Error> {
    let msg_hash = ethereum_message_hash(state.as_slice());
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
    debug!("old balances {:?}", old_balances);
    debug!("new balances {:?}", new_balances);
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
        let cell_lockscript = load_cell_lock(i, Source::Input)?;
        let lockscript_codehash: [u8; 32] = cell_lockscript.code_hash().unpack();
        let pfls_code_hash: [u8; 32] = channel_constants.pfls_code_hash().unpack();
        if lockscript_codehash[..] == pfls_code_hash[..] {
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

    let mut udt_sum =
        vec![0u128, initial_balance.sudts().len().try_into().unwrap()].into_boxed_slice();

    let expected_pcts_script_hash = load_script_hash()?;
    let outputs = load_transaction()?.raw().outputs();
    let expected_pfls_code_hash: [u8; 32] = channel_constants.pfls_code_hash().unpack();
    let expected_pfls_hash_type = channel_constants.pfls_hash_type();
    let mut capacity_sum: u64 = 0;
    for (i, output) in outputs.into_iter().enumerate() {
        let output_lockscript_codehash: [u8; 32] = output.lock().code_hash().unpack();
        if output_lockscript_codehash[..] == expected_pfls_code_hash[..]
            && output.lock().hash_type().eq(&expected_pfls_hash_type)
        {
            let output_lock_args: Bytes = output.lock().args().unpack();
            let script_hash_in_pfls_args: [u8; 32] =
                Byte32::from_slice(&output_lock_args)?.unpack();
            if script_hash_in_pfls_args[..] == expected_pcts_script_hash[..] {
                capacity_sum += unpack_u64(&output.capacity());
            } else {
                return Err(Error::InvalidPFLSInOutputs);
            }
            if output.type_().is_some() {
                let (sudt_idx, amount) = get_sudt_amount(
                    initial_balance,
                    i,
                    &output.type_().to_opt().expect("checked above"),
                )?;
                udt_sum[sudt_idx] += amount;
            }
        }
    }
    if capacity_sum != to_fund {
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
        return Err(Error::WrongChannelType);
    }
    if params.is_virtual_channel().to_bool() {
        return Err(Error::WrongChannelType);
    }
    Ok(())
}

pub fn verify_equal_channel_id(
    old_state: &ChannelState,
    new_state: &ChannelState,
) -> Result<(), Error> {
    if unpack_byte32(&old_state.channel_id())[..] != unpack_byte32(&new_state.channel_id())[..] {
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

pub fn verify_vc_parent_state_progression(
    old_status: &ChannelStatus,
    new_state: &ChannelState,
) -> Result<(), Error> {
    verify_equal_channel_id(&old_status.state(), new_state)?;
    verify_non_decreasing_version_number(old_status, new_state)?;
    verify_equal_sum_of_balances(&old_status.state().balances(), &new_state.balances())?;
    verify_state_not_finalized(&old_status.state())?;
    Ok(())
}

pub fn verify_state_valid_as_start(
    state: &ChannelState,
    pfls_min_capacity: u64,
) -> Result<(), Error> {
    if unpack_u64(&state.version()) != 0 {
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
    if unpack_byte32(&lock_script.code_hash())[..]
        != unpack_byte32(&channel_constants.pcls_code_hash())[..]
    {
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

pub fn verify_all_paid(
    final_balance: &Balances,
    channel_capacity: u64,
    channel_constants: &ChannelConstants,
    is_abort: bool,
) -> Result<(), Error> {
    debug!("verify_all_paid");
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
    let payment_script_hash_a =
        unpack_byte32(&channel_constants.params().party_a().payment_script_hash());

    let ckbytes_balance_b = final_balance.ckbytes().get(1)? + reimburse_b;
    let payment_script_hash_b =
        unpack_byte32(&channel_constants.params().party_b().payment_script_hash());

    debug!("ckbytes_balance_a: {}", ckbytes_balance_a);
    debug!("ckbytes_balance_b: {}", ckbytes_balance_b);

    let mut ckbytes_outputs_a = 0;
    let mut ckbytes_outputs_b = 0;

    let mut udt_outputs_a =
        vec![0u128; final_balance.sudts().len().try_into().unwrap()].into_boxed_slice();
    let mut udt_outputs_b =
        vec![0u128; final_balance.sudts().len().try_into().unwrap()].into_boxed_slice();

    let outputs = load_transaction()?.raw().outputs();

    // Note: Currently it is allowed to pay out a party's CKBytes in the capacity field of an
    // output, that is used as SUDT payment.
    for (i, output) in outputs.into_iter().enumerate() {
        let output_lock_script_hash = load_cell_lock_hash(i, Source::Output)?;

        if output_lock_script_hash[..] == payment_script_hash_a[..] {
            if output.type_().is_some() {
                let (sudt_idx, amount) = get_sudt_amount(
                    final_balance,
                    i,
                    &output.type_().to_opt().expect("checked above"),
                )?;
                udt_outputs_a[sudt_idx] += amount;
            }
            ckbytes_outputs_a += unpack_u64(&output.capacity());
        }
        if output_lock_script_hash[..] == payment_script_hash_b[..] {
            if output.type_().is_some() {
                let (sudt_idx, amount) = get_sudt_amount(
                    final_balance,
                    i,
                    &output.type_().to_opt().expect("checked above"),
                )?;
                udt_outputs_b[sudt_idx] += amount;
            }
            ckbytes_outputs_b += unpack_u64(&output.capacity());
        }
    }
    debug!("ckbytes_outputs_a: {}", ckbytes_outputs_a);
    debug!("ckbytes_outputs_b: {}", ckbytes_outputs_b);

    // Parties with balances below the minimum capacity of the payment script
    // are not required to be paid.
    if (ckbytes_balance_a > ckbytes_outputs_a && ckbytes_balance_a >= minimum_payment_a)
        || (ckbytes_balance_b > ckbytes_outputs_b && ckbytes_balance_b >= minimum_payment_b)
    {
        return Err(Error::NotAllPaid);
    }

    debug!("udt_outputs_a: {:?}", udt_outputs_a);
    debug!("udt_outputs_b: {:?}", udt_outputs_b);

    if !final_balance.sudts().fully_represented(0, &udt_outputs_a)? {
        return Err(Error::NotAllPaid);
    }
    if !final_balance.sudts().fully_represented(1, &udt_outputs_b)? {
        return Err(Error::NotAllPaid);
    }
    Ok(())
}

pub fn verify_state_finalized(state: &ChannelState) -> Result<(), Error> {
    if !state.is_final().to_bool() {
        return Err(Error::StateNotFinal);
    }
    Ok(())
}

pub fn verify_different_payment_addresses(
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    let payment_script_hash_a: [u8; 32] = channel_constants
        .params()
        .party_a()
        .payment_script_hash()
        .unpack();
    let payment_script_hash_b: [u8; 32] = channel_constants
        .params()
        .party_b()
        .payment_script_hash()
        .unpack();
    if payment_script_hash_a[..] == payment_script_hash_b[..] {
        return Err(Error::SamePaymentAddress);
    }
    Ok(())
}

// TODO: We might want to verify that the capacity of the sudt output is at least the max_capacity of the SUDT asset.
//      Not doing so may result in the ability to steal funds up to the
//      (max_capacity of the SUDT asset - actual occupied capacity of the SUDT type script), if the SUDT asset's max_capacity
//      is smaller than the payment_min_capacity of the participant. We do not do this for now, because it is an extreme edge case
//      and the max_capacity of an SUDT should never be set that low.
pub fn get_sudt_amount(
    balances: &Balances,
    output_idx: usize,
    type_script: &Script,
) -> Result<(usize, u128), Error> {
    let mut buf = [0u8; SUDT_MIN_LEN];

    let (sudt_idx, _) = balances.sudts().get_distribution(type_script)?;
    let sudt_data = load_cell_data(output_idx, Source::Output)?;
    if sudt_data.len() < SUDT_MIN_LEN {
        return Err(Error::InvalidSUDTDataLength);
    }
    buf.copy_from_slice(&sudt_data[..SUDT_MIN_LEN]);
    return Ok((sudt_idx, u128::from_le_bytes(buf)));
}
