// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;
// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{self, vec, vec::Vec};

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
        load_cell_type_hash, load_header, load_script, load_script_hash, load_transaction,
        load_witness_args,
    },
    syscalls::{self, SysError},
};
use perun_common::{
    channels::{
        count_cells, find_cell_by_lock_hash, find_cell_by_type_hash, find_closest_current_time,
        verify_max_one_channel, verify_thread_token_integrity, verify_time_lock_expired,
        VChannelAction,
    },
    error::Error,
    helpers::blake2b256,
    perun_types::{
        Balances, Bool, ChannelConstants, ChannelParameters, ChannelState, ChannelStatus,
        ChannelToken, ChannelWitness, ChannelWitnessUnion, Dispute, LockedBalances, ParentsVec,
        SEC1EncodedPubKey, SubAlloc, VCChannelConstants, VCDispute, VirtualChannelStatus,
    },
    sig::verify_signature,
};

const SUDT_MIN_LEN: usize = 16;

pub enum DisputeMode {
    Normal,
    VCDisputeStart {
        old_lc_status: ChannelStatus,
        new_lc_status: ChannelStatus,
        new_vc_status: VirtualChannelStatus,
    },
    VCDisputeProgress {
        old_lc_status: ChannelStatus,
        old_vc_status: VirtualChannelStatus,
        new_lc_status: ChannelStatus,
        new_vc_status: VirtualChannelStatus,
    },
}

pub enum CloseMode {
    NormalMode,
    VCMode,
}

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    // return an error if args is empty
    if args.is_empty() {
        return Err(Error::NoArgs);
    }

    //VC channels neither require funding nor they have lock scirpts, hence information for this is not needed
    // therefore, we only need channelParams in the args for vcts script
    let channel_constants =
        VCChannelConstants::from_slice(&args).expect("unable to parse args as ChannelParams");
    debug!("parsing channel parameters passed");

    debug!("channel_params: {:?}", channel_constants);

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
        } => {
            // let channel_witness = load_witness()?;
            debug!("load_witness passed");
            check_valid_vc_progress(&old_status, &new_status, &channel_constants)
        }
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
            check_valid_close2(&input_lc_status, &input_vc_status)
        } // VChannelAction::Close { old_status } => {
          //     debug!("Close action detected");
          //     let channel_witness = load_witness()?;
          //     debug!("load_witness passed");
          //     check_valid_vc_close(&old_status, &channel_witness, &channel_constants)
          // }
    }
}

pub fn check_valid_vc_start(
    old_lc_status: &ChannelStatus,
    new_lc_status: &ChannelStatus,
    new_vc_status: &VirtualChannelStatus,
    vc_channel_constants: &VCChannelConstants,
) -> Result<(), Error> {
    debug!("check_valid_vc_start");

    //channel_id is the hash of channel parameters
    let vc_chanid = new_vc_status.vcstate().channel_id();
    verify_vchannel_id_integrity(&vc_chanid, &vc_channel_constants.params())?;
    debug!("verify_channel_id_integrity passed");

    //validate newly created vc state
    verify_vc_sigs(&new_vc_status, &vc_channel_constants.params())?;
    debug!("verify_vc_sigs passed");

    //verify that FirstForceCloseFlag is not set
    verify_first_forced_closed_flag_not_set(&new_vc_status)?;

    //verify that the lock script is always success lock-script
    verify_always_success_lock_script(vc_channel_constants)?;
    debug!("verify_always_success_lock_script passed");

    // verify that there is only one and the same parent lc cell in inputs and outputs
    verify_max_one_parent(&new_vc_status)?;
    debug!("verify_max_one_parent passed");

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

    if old_vc_status.vcstate().version().unpack() < new_vc_status.vcstate().version().unpack() {
        verify_vc_sigs(new_vc_status, &vc_constants.params())?;
    }

    verify_equal_sum_of_balances(
        &old_vc_status.vcstate().balances(),
        &new_vc_status.vcstate().balances(),
    )?;
    debug!("verify_equal_sum_of_balances passed");

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
    let vc_cell1_block_num = load_header(0, Source::GroupInput)?.raw().number().unpack();
    let vc_cell2_block_num = load_header(1, Source::GroupInput)?.raw().number().unpack();

    let mut selected_vc_cell = None;

    if vc_cell1_block_num < vc_cell2_block_num {
        selected_vc_cell = Some(input_vc_stats1);
    } else if vc_cell1_block_num > vc_cell2_block_num {
        selected_vc_cell = Some(input_vc_stats2);
    } else {
        return Err(Error::InvalidVCMergeTx);
    }
    debug!("selected_vc_cell: {:?}", selected_vc_cell);
    debug!("selected the block with lower block number");
    // 2. Output vc cell should be contain a copy of the data of the selected input cell
    if let Some(vc_cell) = selected_vc_cell {
        if vc_cell.as_slice() != merged_vc_status.as_slice() {
            return Err(Error::InvalidVCMergeTx);
        }
    }
    Ok(())
}

pub fn check_valid_close1(
    input_vc_status: &VirtualChannelStatus,
    output_vc_status: &VirtualChannelStatus,
    vc_constants: &VCChannelConstants,
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
    input_lc_status: &ChannelStatus,
    input_vc_status: &VirtualChannelStatus,
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
        return Err(Error::FirstForceCloseFlagNotSet);
    }
    Ok(())
}

// pub fn verify_equal_version_number(
//     old_vc_status: &VirtualChannelStatus,
//     new_vc_status: &VirtualChannelStatus,
// ) -> Result<(), Error> {
//     if old_vc_status.vcstate().version().unpack() != new_vc_status.vcstate().version().unpack() {
//         return Err(Error::InvalidVCMergeTx);
//     }
//     Ok(())
// }

pub fn verify_non_decreasing_version_number_vc(
    old_vc_status: &VirtualChannelStatus,
    new_vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    debug!(
        "verify_non-decreasing_version_number old: {},  new: {}",
        old_vc_status.vcstate().version().unpack(),
        new_vc_status.vcstate().version().unpack()
    );

    if old_vc_status.vcstate().version().unpack() > new_vc_status.vcstate().version().unpack() {
        return Err(Error::InvalidVersionNumberVCProgressTx);
    }
    Ok(())
}

pub fn verify_equal_channel_id_vc(
    old_vc_status: &VirtualChannelStatus,
    new_vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    if old_vc_status.vcstate().channel_id().unpack()[..]
        != new_vc_status.vcstate().channel_id().unpack()[..]
    {
        return Err(Error::ChannelIdMismatch);
    }
    Ok(())
}

pub fn verify_vc_sigs(
    new_vc_status: &VirtualChannelStatus,
    vc_params: &ChannelParameters,
) -> Result<(), Error> {
    let witnes_args = load_witness_args(0, Source::GroupInput)?;
    let witness_bytes: Bytes = witnes_args
        .input_type()
        .to_opt()
        .ok_or(Error::NoWitness)?
        .unpack();
    let vc_witness = VCDispute::from_slice(&witness_bytes)?;

    verify_valid_state_sigs(
        &vc_witness.sig_a().unpack(),
        &vc_witness.sig_b().unpack(),
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

//checks that only one (and the sam) parent ledger channel cell exists in inputs and outputs
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
    let msg_hash = blake2b256(state.as_slice());
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

pub fn verify_equal_channel_state(
    old_state: &ChannelState,
    new_state: &ChannelState,
) -> Result<(), Error> {
    if old_state.as_slice()[..] == new_state.as_slice()[..] {
        return Ok(());
    }
    Err(Error::ChannelStateNotEqual)
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
    if digest[..] != channel_id.unpack()[..] {
        return Err(Error::InvalidChannelId);
    }
    Ok(())
}

pub fn get_vchannel_action() -> Result<VChannelAction, Error> {
    //vcts start
    //load this vcts script hash
    // iterate through all input cells and count the number of cells have the same type hash as this one
    // pass if and only if there are none.
    // iterate through all output cells.
    //pass iff there is exactly one cell with the same type hash as this
    let mut input_cell_counter = 0;
    let mut output_cell_counter = 0;
    let max_input_vc_channels = 2;
    let vcts_hash = load_script_hash().unwrap();
    for i in 0.. {
        let input_cell_hash = match load_cell_type_hash(i, Source::GroupInput) {
            Ok(Some(hash)) => hash,
            Ok(None) => continue,
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
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
            Err(err) => return Err(err.into()),
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
            Err(err) => return Err(err.into()),
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
        for i in 0.. {
            let vc_status = match load_cell_data(i, Source::GroupInput) {
                Ok(data) => VirtualChannelStatus::from_slice(data.as_slice())?,
                Err(err) => return Err(err.into()),
            };

            if i < max_input_vc_channels {
                input_vc_statuses[i] = Some(vc_status);
            }
        }

        if input_vc_statuses.iter().all(|status| !status.is_some()) {
            return Err(Error::VCInputCellMissingInMergeTx);
        }

        let output_vc_status = match load_cell_data(0, Source::GroupInput) {
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
        //TODO: What about a dispute, where the vc state is not being progressed but only the parent lc cell is
        let input_vc_status = match load_cell_data(0, Source::GroupInput) {
            Ok(data) => VirtualChannelStatus::from_slice(data.as_slice())?,
            // Ok(None) => panic!("Cannot load cell data of vc cell in outputs"),
            Err(err) => return Err(err.into()),
        };
        let output_vc_status = match load_cell_data(0, Source::GroupInput) {
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
                // find the input parent lc status
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
            // Ok(None) => panic!("Cannot load cell data of vc cell in outputs"),
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


pub fn verify_increasing_version_number_for_vc(
    old_vc_state: &ChannelState,
    new_vc_state: &ChannelState,
) -> Result<(), Error> {
    debug!(
        "verify_increasing_version_number for vc old: {},  new: {}",
        old_vc_state.version().unpack(),
        new_vc_state.version().unpack()
    );

    if old_vc_state.version().unpack() < new_vc_state.version().unpack() {
        return Ok(());
    }
    Err(Error::VersionNumberNotIncreasing)
}

// TODO: We might want to verify that the capacity of the sudt output is at least the max_capacity of the SUDT asset.
//      Not doing so may result in the ability to steal funds up to the
//      (max_capacity of the SUDT asset - actual occupied capacity of the SUDT type script), if the SUDT asset's max_capacity
//      is smaller than the payment_min_capacity of the participant. We do not do this for now, because it is an extreme edge case
//      and the max_capacity of an SUDT should never be set that low.
pub fn get_vc_sudt_amount(
    balances: &LockedBalances,
    output_idx: usize,
    type_script: &Script,
) -> Result<(usize, u128), Error> {
    let mut buf = [0u8; SUDT_MIN_LEN];

    let (sudt_idx, _) = balances
        .get_unchecked(output_idx)
        .balances()
        .sudts()
        .get_distribution(type_script)?; //sudts().get_distribution(type_script)?;
    let sudt_data = load_cell_data(output_idx, Source::Output)?;
    if sudt_data.len() < SUDT_MIN_LEN {
        return Err(Error::InvalidSUDTDataLength);
    }
    buf.copy_from_slice(&sudt_data[..SUDT_MIN_LEN]);
    return Ok((sudt_idx, u128::from_le_bytes(buf)));
}