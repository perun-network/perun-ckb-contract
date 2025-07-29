#![cfg_attr(not(feature = "library"), no_std)]
#![allow(special_module_name)]
#![allow(unused_attributes)]

use ckb_std::default_alloc;

ckb_std::entry!(program_entry);
default_alloc!();
use alloc::vec;
use core::iter::IntoIterator;
use core::{result::Result, usize};

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, packed::Byte32, prelude::*},
    debug,
    high_level::{
        load_cell_capacity, load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_header,
        load_script, load_script_hash, load_witness_args, QueryIter,
    },
    syscalls::SysError,
};

use perun_common::{
    channels::{find_cell_by_type_hash, unpack_byte32, VChannelAction},
    error::Error,
    helpers::blake2b256,
    perun_types::{
        Balances, ChannelParameters, ChannelState, ChannelStatus, ChannelWitness,
        ChannelWitnessUnion, Participant, SEC1EncodedPubKey, VCChannelConstants,
        VirtualChannelStatus,
    },
    sig::verify_signature,
};
use perun_common::sig::ethereum_message_hash;

pub fn program_entry() -> i8 {
    match main() {
        Ok(_) => 0,   // Success
        Err(_) => -1, // Failure
    }
}

pub fn main() -> Result<(), Error> {
    debug!("VCTS");
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    if args.is_empty() {
        return Err(Error::NoArgs);
    }
    let channel_constants =
        VCChannelConstants::from_slice(&args).expect("unable to parse args as ChannelParams");
    debug!("parsing channel parameters passed");

    // Verify that the channel parameters are compatible with the currently supported
    // features of perun channels.
    verify_vchannel_params_compatibility(&channel_constants.params())?;
    debug!("verify_channel_params_compatibility passed");

    // Next, we determine whether the transaction starts, progresses or closes the channel and fetch
    // the respective old and/or new channel status.
    let channel_action = get_vchannel_action()?;
    debug!("get_channel_action passed");

    match channel_action {
        VChannelAction::Start {
            new_vc_status,
            old_lc_status,
            new_lc_status,
        } => {
            debug!("Start action detected");
            check_valid_vc_start(
                &old_lc_status,
                &new_lc_status,
                &new_vc_status,
                &channel_constants,
            )
        }
        VChannelAction::Progress {
            old_status,
            new_status,
        } => check_valid_vc_progress(&old_status, &new_status, &channel_constants),
        VChannelAction::Merge {
            input_vc_status1,
            input_vc_status2,
            merged_vc_status,
        } => {
            debug!("Merge Tx detected");
            check_valid_vc_merge(&input_vc_status1, &input_vc_status2, &merged_vc_status)
        }

        VChannelAction::Close1 {
            input_vc_status,
            output_vc_status,
        } => {
            debug!("Close1 Tx detected");
            check_valid_close1(&input_vc_status, &output_vc_status, &channel_constants)
        }

        VChannelAction::Close2 {
            input_lc_status,
            input_vc_status,
        } => {
            debug!("Close2 Tx detected");
            check_valid_close2(&input_lc_status, &input_vc_status, &channel_constants)
        }
    }
}

pub fn check_valid_vc_start(
    _: &ChannelStatus,
    _: &ChannelStatus,
    new_vc_status: &VirtualChannelStatus,
    vc_channel_constants: &VCChannelConstants,
) -> Result<(), Error> {
    debug!("check_valid_vc_start");

    //channel_id is the hash of channel parameters
    let vc_chanid = new_vc_status.vcstate().channel_id();
    verify_vchannel_id_integrity(&vc_chanid, &vc_channel_constants.params())?;
    debug!("verify_channel_id_integrity passed");

    //validate newly created vc state
    verify_vc_sigs_start(&new_vc_status, &vc_channel_constants.params())?;
    debug!("verify_vc_sigs passed");

    //verify that FirstForceCloseFlag is not set
    verify_first_forced_closed_flag_not_set(&new_vc_status)?;

    //verify that the lock script is always success lock-script
    verify_always_success_lock_script(vc_channel_constants)?;
    debug!("verify_always_success_lock_script passed");

    //verify that the owner lock hash is correctly set
    verify_owner_lock(&new_vc_status.owner())?;
    // verify that there is only one and the same parent lc cell in inputs and outputs
    verify_max_one_parent(&new_vc_status)?;
    debug!("verify_max_one_parent passed");

    Ok(())
}

pub fn verify_owner_lock(owner: &Participant) -> Result<(), Error> {
    let owner_lock_hash: [u8; 32] = owner.payment_script_hash().unpack();
    let matches: vec::Vec<usize> = QueryIter::new(load_cell_lock_hash, Source::Input)
        .enumerate()
        .filter_map(|(idx, hash)| {
            if hash == owner_lock_hash {
                Some(idx)
            } else {
                None
            }
        })
        .collect();

    match matches.len() {
        0 => return Err(Error::InvalidVCTxStart), //Input should contain at least cell belonging to owner
        _ => (),
    };
    Ok(())
}

pub fn check_valid_vc_progress(
    old_vc_status: &VirtualChannelStatus,
    new_vc_status: &VirtualChannelStatus,
    vc_constants: &VCChannelConstants,
) -> Result<(), Error> {
    debug!("check_valid_vc_progress");
    verify_equal_channel_id_vc(old_vc_status, new_vc_status)?;
    debug!("verify_equal_channel_id_vc passed");

    verify_first_forced_closed_flag_not_set(new_vc_status)?;
    debug!("verify_first_forced_closed_flag_not_set passed");

    verify_non_decreasing_version_number_vc(old_vc_status, new_vc_status)?;
    debug!("verify_non_decreasing_version_number_vc passed");

    let old_vc_state_version: u64 = old_vc_status.vcstate().version().unpack();
    let new_vc_state_version: u64 = new_vc_status.vcstate().version().unpack();
    if old_vc_state_version < new_vc_state_version {
        debug!("vc state version number is increasing");
        verify_vc_sigs_progress(new_vc_status, &vc_constants.params())?;
        debug!("verify_vc_sigs_progress passed");
        verify_equal_sum_of_balances(
            &old_vc_status.vcstate().balances(),
            &new_vc_status.vcstate().balances(),
        )?;
        debug!("verify_equal_sum_of_balances passed");
    }
    if old_vc_state_version == new_vc_state_version {
        verify_equal_vc_status(old_vc_status, new_vc_status)?;
        debug!("verify_equal_channel_state passed");
    }

    debug!("verify_valid_vc_progress passed");
    Ok(())
}

pub fn check_valid_vc_merge(
    input_vc_stats1: &VirtualChannelStatus,
    input_vc_stats2: &VirtualChannelStatus,
    merged_vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    debug!("check_valid_vc_merge");
    // 1. We take the vc cell that was created first i.e., lower block number
    let vc_cell1_block_num: u64 = load_header(0, Source::GroupInput)?.raw().number().unpack();
    debug!("vc_cell1_block_num: {:?}", vc_cell1_block_num);
    let vc_cell2_block_num: u64 = load_header(1, Source::GroupInput)?.raw().number().unpack();
    debug!("vc_cell2_block_num: {:?}", vc_cell2_block_num);

    let selected_vc_cell;
    let discarded_vc_cell;
    if vc_cell1_block_num < vc_cell2_block_num {
        selected_vc_cell = Some(input_vc_stats1);
        discarded_vc_cell = Some(input_vc_stats2);
    } else if vc_cell1_block_num > vc_cell2_block_num {
        selected_vc_cell = Some(input_vc_stats2);
        discarded_vc_cell = Some(input_vc_stats1);
    } else if vc_cell1_block_num == vc_cell2_block_num {
        selected_vc_cell = Some(input_vc_stats1);
        discarded_vc_cell = Some(input_vc_stats2);
    } else {
        return Err(Error::InvalidVCMergeTx);
    }
    debug!("selected the block with lower block number");

    verify_equal_vc_status(selected_vc_cell.unwrap(), merged_vc_status)?;
    debug!("verify_equal_vc_status passed");

    // funds put up for the vc cell being removed from chain should be returned to owner
    verify_vc_rent_payout_merge(&discarded_vc_cell.unwrap().owner())?;
    debug!("verify_vc_rent_payout_merge passed");

    debug!("check_valid_vc_merge passed");
    Ok(())
}

pub fn check_valid_close1(
    input_vc_status: &VirtualChannelStatus,
    output_vc_status: &VirtualChannelStatus,
    _: &VCChannelConstants,
) -> Result<(), Error> {
    debug!("check_valid_close1");
    // a parent pcts must appear as input
    let parent_input_idx = match get_parent_of_vc(input_vc_status, Source::Input) {
        Ok(idx) => idx,
        Err(e) => return Err(e),
    };
    // parent lc cell is in forceClose Operation
    verify_parent_in_force_close(parent_input_idx)?;
    debug!("verify_parent_in_force_close passed");

    //first force close flag is set in output vc cell
    verify_first_forced_closed_flag_set(output_vc_status)?;
    debug!("verify first force close flag set passed");

    // all othe fields except first force close flag are equal
    if input_vc_status.parents().as_slice() != output_vc_status.parents().as_slice()
        && input_vc_status.vcstate().as_slice() != output_vc_status.vcstate().as_slice()
    {
        return Err(Error::InvalidVCClose1Tx);
    }
    Ok(())
}

pub fn check_valid_close2(
    _input_lc_status: &ChannelStatus,
    input_vc_status: &VirtualChannelStatus,
    _vc_constants: &VCChannelConstants,
) -> Result<(), Error> {
    let parent_input_idx = match get_parent_of_vc(input_vc_status, Source::Input) {
        Ok(idx) => idx,
        Err(e) => return Err(e),
    };
    // parent lc cell is in forceClose Operation
    verify_parent_in_force_close(parent_input_idx)?;
    debug!("verify_parent_in_force_close passed");

    //first force close flag is set in input vc cell
    verify_first_forced_closed_flag_set(input_vc_status)?;
    debug!("verify first force close flag set passed");

    // verify that the output contains a payout cell for the participant, which created vc cell
    verify_vc_rent_payout_close2(&input_vc_status.owner())?;
    debug!("verify_vc_rent_payout_cell passed");
    Ok(())
}

pub fn verify_vc_rent_payout_close2(owner: &Participant) -> Result<(), Error> {
    let owner_lock_hash: [u8; 32] = owner.payment_script_hash().unpack();
    let vc_cell_capacity = load_cell_capacity(0, Source::GroupInput)?;

    let matches: vec::Vec<usize> = QueryIter::new(load_cell_lock_hash, Source::Output)
        .enumerate()
        .filter_map(|(idx, hash)| {
            if hash == owner_lock_hash {
                Some(idx)
            } else {
                None
            }
        })
        .collect();

    if matches.len() == 0 {
        return Err(Error::NoVCRentPayoutCell);
    }

    let mut total_capacity = 0;
    for idx in matches.iter() {
        let output_capacity = load_cell_capacity(*idx, Source::Output)?;
        total_capacity += output_capacity;
    }

    debug!("vc cell capacity: {:?}", vc_cell_capacity);
    debug!("total output capacity: {:?}", total_capacity);

    if vc_cell_capacity > total_capacity {
        return Err(Error::InvalidVCRentPayoutCell);
    }
    Ok(())
}

pub fn verify_vc_rent_payout_merge(owner: &Participant) -> Result<(), Error> {
    let owner_lock_hash: [u8; 32] = owner.payment_script_hash().unpack();
    let vc_cell_capacity = load_cell_capacity(0, Source::GroupInput)?;

    let matches: vec::Vec<usize> = QueryIter::new(load_cell_lock_hash, Source::Output)
        .enumerate()
        .filter_map(|(idx, hash)| {
            if hash == owner_lock_hash {
                Some(idx)
            } else {
                None
            }
        })
        .collect();

    let output_idx = match matches.len() {
        1 => matches.get(0).unwrap(),
        _ => return Err(Error::NoVCRentPayoutCell), //output shoud contain exactly one payout cell
    };

    let output_capacity = load_cell_capacity(output_idx.clone(), Source::Output)?;
    debug!("vc cell capacity: {:?}", vc_cell_capacity);
    debug!("output_capacity: {:?}", output_capacity);

    if vc_cell_capacity != output_capacity {
        return Err(Error::InvalidVCRentPayoutCell);
    }
    Ok(())
}

// two vc statuses are considered equal if all their fields except owner is identical
pub fn verify_equal_vc_status(
    input_vc_status: &VirtualChannelStatus,
    merged_vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    if input_vc_status.vcstate().as_slice() != merged_vc_status.vcstate().as_slice() {
        return Err(Error::InvalidVCMergeTx);
    }

    if input_vc_status.parents().as_slice() != merged_vc_status.parents().as_slice() {
        return Err(Error::InvalidVCMergeTx);
    }

    if input_vc_status.first_force_close().as_slice()
        != merged_vc_status.first_force_close().as_slice()
    {
        return Err(Error::InvalidVCMergeTx);
    }
    Ok(())
}

pub fn verify_always_success_lock_script(vc_constants: &VCChannelConstants) -> Result<(), Error> {
    let lock_script_hash = load_cell_lock_hash(0, Source::GroupOutput)?;
    if lock_script_hash != vc_constants.vcls_code_hash().as_slice() {
        return Err(Error::InvalidVCLockScript);
    }
    Ok(())
}

pub fn verify_first_forced_closed_flag_not_set(
    vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    if vc_status.first_force_close().to_bool() {
        return Err(Error::FirstForceCloseFlagSet);
    }
    Ok(())
}

pub fn verify_first_forced_closed_flag_set(vc_status: &VirtualChannelStatus) -> Result<(), Error> {
    if !vc_status.first_force_close().to_bool() {
        debug!("FirstForceCloseFlagNotSet");
        return Err(Error::FirstForceCloseFlagNotSet);
    }
    Ok(())
}

pub fn verify_non_decreasing_version_number_vc(
    old_vc_status: &VirtualChannelStatus,
    new_vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    let old_vc_state_version: u64 = old_vc_status.vcstate().version().unpack();
    let new_vc_state_version: u64 = new_vc_status.vcstate().version().unpack();
    if old_vc_state_version > new_vc_state_version {
        return Err(Error::InvalidVersionNumberVCProgressTx);
    }
    Ok(())
}

pub fn verify_equal_channel_id_vc(
    old_vc_status: &VirtualChannelStatus,
    new_vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    let old_vc_state_channel_id: [u8; 32] = old_vc_status.vcstate().channel_id().unpack();
    let new_vc_state_channel_id: [u8; 32] = new_vc_status.vcstate().channel_id().unpack();
    if old_vc_state_channel_id[..] != new_vc_state_channel_id[..] {
        return Err(Error::ChannelIdMismatch);
    }
    Ok(())
}

pub fn verify_vc_sigs_start(
    new_vc_status: &VirtualChannelStatus,
    vc_params: &ChannelParameters,
) -> Result<(), Error> {
    let parent_input_idx = match get_parent_of_vc(new_vc_status, Source::Input) {
        Ok(idx) => idx,
        Err(e) => return Err(e),
    };
    let witnes_args = load_witness_args(parent_input_idx, Source::Input)?;
    debug!("witness_args loaded");
    let witness_bytes: Bytes = witnes_args
        .input_type()
        .to_opt()
        .ok_or(Error::NoWitness)?
        .unpack();
    let witness = ChannelWitness::from_slice(&witness_bytes)?;
    let vc_witness = match witness.to_enum() {
        ChannelWitnessUnion::VCDispute(vcd) => vcd,
        _ => return Err(Error::InvalidVCTxStart),
    };
    debug!("VCDispute loaded");
    verify_valid_state_sigs(
        &vc_witness.sig_a().unpack(),
        &vc_witness.sig_b().unpack(),
        &new_vc_status.vcstate(),
        &vc_params.party_a().pub_key(),
        &vc_params.party_b().pub_key(),
    )?;
    Ok(())
}

pub fn verify_vc_sigs_progress(
    new_vc_status: &VirtualChannelStatus,
    vc_params: &ChannelParameters,
) -> Result<(), Error> {
    let witnes_args = load_witness_args(0, Source::GroupInput)?;
    let witness_bytes: Bytes = witnes_args
        .input_type()
        .to_opt()
        .ok_or(Error::NoWitness)?
        .unpack();

    let vc_witness = ChannelWitness::from_slice(&witness_bytes)?;
    let vc_sigs = match vc_witness.to_enum() {
        ChannelWitnessUnion::Dispute(d) => d,
        _ => return Err(Error::InvalidVCTx),
    };
    verify_valid_state_sigs(
        &vc_sigs.sig_a().unpack(),
        &vc_sigs.sig_b().unpack(),
        &new_vc_status.vcstate(),
        &vc_params.party_a().pub_key(),
        &vc_params.party_b().pub_key(),
    )?;
    Ok(())
}

pub fn verify_parent_in_force_close(parent_input_idx: usize) -> Result<(), Error> {
    let witnes_args = load_witness_args(parent_input_idx, Source::Input)?;
    let witness_bytes: Bytes = witnes_args
        .input_type()
        .to_opt()
        .ok_or(Error::NoWitness)?
        .unpack();
    let parent_witness = ChannelWitness::from_slice(&witness_bytes)?;

    match parent_witness.to_enum() {
        ChannelWitnessUnion::ForceClose(_) => Ok(()),
        _ => Err(Error::ParentNotInForceClose),
    }
}

//checks that only one (and the same) parent ledger channel cell exists in inputs and outputs
pub fn verify_max_one_parent(vc_status: &VirtualChannelStatus) -> Result<(), Error> {
    let parent1_hash = match vc_status.parents().get(0) {
        Some(parent) => parent.pcts_hash().unpack(),
        None => return Err(Error::ParentPCTSHashNotFound),
    };

    let parent2_hash = match vc_status.parents().get(1) {
        Some(parent) => parent.pcts_hash().unpack(),
        None => return Err(Error::ParentPCTSHashNotFound),
    };

    let hashes = &[(&parent1_hash, "parent1"), (&parent2_hash, "parent2")];
    let mut found_parent = None;

    for (hash, parent) in hashes.iter() {
        if let Some(_) = find_cell_by_type_hash(&hash, Source::Input)? {
            found_parent = Some(*parent);
            break;
        }
    }

    if let Some(parent) = found_parent {
        let parent_hash = if parent == "parent1" {
            &parent1_hash
        } else {
            &parent2_hash
        };
        if find_cell_by_type_hash(parent_hash, Source::Output)?.is_none() {
            return Err(Error::ParentNotFoundInOutputs);
        }
        Ok(())
    } else {
        Err(Error::InvalidVCTxStart)
    }
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

pub fn verify_equal_sum_of_balances(
    old_balances: &Balances,
    new_balances: &Balances,
) -> Result<(), Error> {
    if !old_balances.equal_in_sum(new_balances)? {
        return Err(Error::SumOfBalancesNotEqual);
    }
    Ok(())
}

pub fn verify_vchannel_params_compatibility(params: &ChannelParameters) -> Result<(), Error> {
    if params.app().to_opt().is_some() {
        return Err(Error::AppChannelsNotSupported);
    }
    if params.is_ledger_channel().to_bool() {
        return Err(Error::WrongChannelType);
    }
    if !params.is_virtual_channel().to_bool() {
        return Err(Error::WrongChannelType);
    }
    Ok(())
}

pub fn verify_vchannel_id_integrity(
    channel_id: &Byte32,
    params: &ChannelParameters,
) -> Result<(), Error> {
    let digest = blake2b256(params.as_slice());
    if digest[..] != unpack_byte32(channel_id)[..] {
        return Err(Error::InvalidChannelId);
    }
    Ok(())
}

pub fn get_vchannel_action() -> Result<VChannelAction, Error> {
    let mut input_cell_counter = 0;
    let mut output_cell_counter = 0;
    let max_input_vc_channels = 2;
    let vcts_hash = load_script_hash().unwrap();
    for i in 0.. {
        let input_cell_hash = match load_cell_type_hash(i, Source::GroupInput) {
            Ok(Some(hash)) => hash,
            Ok(None) => continue,
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(Error::TypeHashNotFound),
        };
        if vcts_hash == input_cell_hash {
            input_cell_counter += 1;
        }
    }
    for i in 0.. {
        let output_cell_hash = match load_cell_type_hash(i, Source::GroupOutput) {
            Ok(Some(hash)) => hash,
            Ok(None) => continue,
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(Error::TypeHashNotFound),
        };

        if vcts_hash == output_cell_hash {
            output_cell_counter += 1;
        }
    }
    //MODE: VC Start Tx
    if input_cell_counter == 0 && output_cell_counter == 1 {
        let vc_status = match load_cell_data(0, Source::GroupOutput) {
            Ok(data) => VirtualChannelStatus::from_slice(data.as_slice())?,
            // Ok(None) => panic!("Cannot load cell data of vc cell in outputs"),
            Err(_) => return Err(Error::UnableToLoadVirtualChannelStatus),
        };

        let parent_input_idx = get_parent_of_vc(&vc_status, Source::Input).unwrap();
        let parent_input_data = match load_cell_data(parent_input_idx, Source::Input) {
            Ok(data) => ChannelStatus::from_slice(data.as_slice())?,
            Err(_) => return Err(Error::UnableToLoadAnyChannelStatus),
        };
        let parent_output_idx = get_parent_of_vc(&vc_status, Source::Output).unwrap();
        let parent_output_data = match load_cell_data(parent_output_idx, Source::Output) {
            Ok(data) => ChannelStatus::from_slice(data.as_slice())?,
            Err(_) => return Err(Error::UnableToLoadAnyChannelStatus),
        };

        return Ok(VChannelAction::Start {
            new_vc_status: vc_status,
            old_lc_status: parent_input_data,
            new_lc_status: parent_output_data,
        });

    //MODE: VC Merge Tx
    } else if input_cell_counter == 2 && output_cell_counter == 1 {
        let mut input_vc_statuses: [Option<VirtualChannelStatus>; 2] = [None, None];
        for i in 0..2 {
            let vc_status = match load_cell_data(i, Source::GroupInput) {
                Ok(data) => {
                    debug!("VC Status loaded");
                    VirtualChannelStatus::from_slice(data.as_slice())?
                }
                Err(err) => {
                    debug!("Error loading VC Status");
                    return Err(err.into());
                }
            };

            if i < max_input_vc_channels {
                input_vc_statuses[i] = Some(vc_status);
            }
        }

        if input_vc_statuses.iter().all(|status| !status.is_some()) {
            return Err(Error::VCInputCellMissingInMergeTx);
        }

        let output_vc_status = match load_cell_data(0, Source::GroupOutput) {
            Ok(data) => VirtualChannelStatus::from_slice(data.as_slice())?,
            Err(err) => return Err(err.into()),
        };

        return Ok(VChannelAction::Merge {
            input_vc_status1: input_vc_statuses[0].clone().unwrap(),
            input_vc_status2: input_vc_statuses[1].clone().unwrap(),
            merged_vc_status: output_vc_status,
        });

    //MODE: Either VC Dispute Progress or VC Close 1
    } else if input_cell_counter == 1 && output_cell_counter == 1 {
        let input_vc_status = match load_cell_data(0, Source::GroupInput) {
            Ok(data) => VirtualChannelStatus::from_slice(data.as_slice())?,
            Err(err) => return Err(err.into()),
        };
        let output_vc_status = match load_cell_data(0, Source::GroupOutput) {
            Ok(data) => VirtualChannelStatus::from_slice(data.as_slice())?,
            Err(err) => return Err(err.into()),
        };

        let parent_input_idx = get_parent_of_vc(&input_vc_status, Source::Input).unwrap();
        let witness_args = load_witness_args(parent_input_idx, Source::Input)?;
        let witness_bytes: Bytes = witness_args
            .input_type()
            .to_opt()
            .ok_or(Error::NoWitness)?
            .unpack();
        let channel_witness = ChannelWitness::from_slice(&witness_bytes)?;
        match channel_witness.to_enum() {
            //MODE: VC Progress
            ChannelWitnessUnion::Dispute(_) => {
                return Ok(VChannelAction::Progress {
                    old_status: input_vc_status,
                    new_status: output_vc_status,
                });
            }
            //MODE: VC Close 1
            ChannelWitnessUnion::ForceClose(_) => {
                return Ok(VChannelAction::Close1 {
                    input_vc_status: input_vc_status,
                    output_vc_status: output_vc_status,
                });
            }
            _ => return Err(Error::InvalidVCTx),
        }
    } else if input_cell_counter == 1 && output_cell_counter == 0 {
        //MODE: VC Close 2
        // 1 input parent lc + 1 input vc
        // 0 output lc + 0 output vc
        let input_vc_status = match load_cell_data(0, Source::GroupInput) {
            Ok(data) => VirtualChannelStatus::from_slice(data.as_slice())?,
            Err(err) => return Err(err.into()),
        };

        let parent_input_idx = get_parent_of_vc(&input_vc_status, Source::Input).unwrap();
        let parent_data = match load_cell_data(parent_input_idx, Source::Input) {
            Ok(data) => ChannelStatus::from_slice(data.as_slice())?,
            Err(err) => return Err(err.into()),
        };

        return Ok(VChannelAction::Close2 {
            input_lc_status: parent_data,
            input_vc_status: input_vc_status,
        });
    } else {
        return Err(Error::InvalidVCTx);
    }
}

/// finds either one of the two parents of the virtual channel for the given source
pub fn get_parent_of_vc(vc_status: &VirtualChannelStatus, source: Source) -> Result<usize, Error> {
    if vc_status.parents().len() != 2 {
        return Err(Error::InvalidParentsCountForVC);
    }
    let parent1_hash = match vc_status.parents().get(0) {
        Some(parent) => parent.pcts_hash().unpack(),
        None => return Err(Error::ParentPCTSHashNotFound),
    };

    let parent2_hash = match vc_status.parents().get(1) {
        Some(parent) => parent.pcts_hash().unpack(),
        None => return Err(Error::ParentPCTSHashNotFound),
    };

    let parent_idx = match find_cell_by_type_hash(&parent1_hash, source) {
        Ok(Some(i)) => i,
        Ok(None) => match find_cell_by_type_hash(&parent2_hash, source) {
            Ok(Some(i)) => i,
            Ok(None) => return Err(Error::ParentsOfVCNotFound),
            Err(err) => return Err(err.into()),
        },
        Err(err) => return Err(err.into()),
    };
    Ok(parent_idx)
}
