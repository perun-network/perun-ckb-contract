use crate::error::Error;
use crate::helpers::blake2b256;
use crate::perun_types::{ChannelParameters, ChannelStatus, ChannelToken, VirtualChannelStatus};

extern crate alloc;

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed::Byte32, prelude::*},
    debug,
    high_level::{
        load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_header, load_transaction,
    },
    syscalls::{self, SysError},
};

pub enum VChannelAction {
    /// Progress indicates that a higher version of virtual channel may be registered
    Progress {
        old_status: VirtualChannelStatus,
        new_status: VirtualChannelStatus,
    }, // one PCTS input, one PCTS output

    /// Start indicates that a lc channel is being disputed and a vc cell is created for the first time in the outputs
    Start {
        new_vc_status: VirtualChannelStatus,
        old_lc_status: ChannelStatus,
        new_lc_status: ChannelStatus,
    }, // no VCTS input, one VCTS output
    /// Merge indicates that two virtual channels are being merged into a single one
    Merge {
        input_vc_status1: VirtualChannelStatus,
        input_vc_status2: VirtualChannelStatus,
        merged_vc_status: VirtualChannelStatus,
    },
    /// Close1 indicates that one of the parents of the virtual channel is being closed
    Close1 {
        input_vc_status: VirtualChannelStatus,
        output_vc_status: VirtualChannelStatus,
    },
    /// Close2 indicates that 2nd parent of the virtual channel and the virtual channel itself is being closed
    Close2 {
        input_lc_status: ChannelStatus,
        input_vc_status: VirtualChannelStatus,
    },
    // Close indicates that a channel is being closed. This means that a channel's cell is consumed without being
    // recreated in the outputs with updated state. The possible redeemers associated with the Close action are
    // Close, Abort and ForceClose.
    // The channel type script assures that all funds are paid out to the correct parties upon closing.
    //Close { old_status: VirtualChannelStatus }, // one PCTS input, no PCTS output
}

pub enum PChannelAction {
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
    /// The channel type script assures that all funds are paid out to the correct parties upon closing.
    Close { old_status: ChannelStatus }, // one PCTS input , no PCTS output
}

pub fn get_channel_action() -> Result<PChannelAction, Error> {
    let input_status_opt = load_cell_data(0, Source::GroupInput)
        .ok()
        .map(|data| ChannelStatus::from_slice(data.as_slice()))
        .map_or(Ok(None), |v| v.map(Some))?;

    let output_status_opt = load_cell_data(0, Source::GroupOutput)
        .ok()
        .map(|data| ChannelStatus::from_slice(data.as_slice()))
        .map_or(Ok(None), |v| v.map(Some))?;

    debug!("input_status_opt: {:?}", input_status_opt);
    debug!("output_status_opt: {:?}", output_status_opt);

    match (input_status_opt, output_status_opt) {
        (Some(old_status), Some(new_status)) => Ok(PChannelAction::Progress {
            old_status,
            new_status,
        }),
        (Some(old_status), None) => Ok(PChannelAction::Close { old_status }),
        (None, Some(new_status)) => Ok(PChannelAction::Start { new_status }),
        (None, None) => Err(Error::UnableToLoadAnyChannelStatus),
    }
}

///
/// # Arguments
/// * `party_a_unlock_hash` - The lock hash of the unlock script of party A
/// * `party_b_unlock_script_hash` - The lock hash of the unlock script of party B
/// * `source` - the source for data (Input, Output, GroupInput, GroupOutput, etc.)
/// # Returns
/// * `Ok(())` if the input cell with the given lock hash is found
/// * `Err(Error)` if the input cell with the given lock hash is not found
pub fn find_cell_by_lock_hash(
    party_a_unlock_hash: &[u8; 32],
    party_b_unlock_script_hash: &[u8; 32],
    source: Source,
) -> Result<Option<usize>, Error> {
    for i in 0.. {
        let lock_hash = match load_cell_lock_hash(i, source) {
            Ok(lock_hash) => lock_hash,
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };
        if &lock_hash == party_a_unlock_hash || &lock_hash == party_b_unlock_script_hash {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

pub fn find_cell_by_type_hash(
    pcts_hash: &[u8; 32],
    source: Source,
) -> Result<Option<usize>, Error> {
    for i in 0.. {
        let type_hash = match load_cell_type_hash(i, source) {
            Ok(Some(script)) => script,
            Ok(None) => continue,
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };
        if &type_hash == pcts_hash {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

pub fn verify_channel_id_integrity(
    channel_id: &Byte32,
    params: &ChannelParameters,
) -> Result<(), Error> {
    let digest = blake2b256(params.as_slice());
    let channel_id_bytes: [u8; 32] = channel_id.unpack();
    if digest[..] != channel_id_bytes[..] {
        return Err(Error::InvalidChannelId);
    }
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

pub fn verify_time_lock_expired(time_lock: u64) -> Result<(), Error> {
    let old_header = load_header(0, Source::GroupInput)?;
    let old_timestamp: u64 = old_header.raw().timestamp().unpack();
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

// verify_max_one_channel verifies that there is at most one channel in the group input and group output respectively.
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

pub fn unpack_u64<T: Unpack<u64>>(t: &T) -> u64 {
    t.unpack()
}

pub fn unpack_byte32<T: Unpack<[u8; 32]>>(t: &T) -> [u8; 32] {
    t.unpack()
}
