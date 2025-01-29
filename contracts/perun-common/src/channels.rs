use crate::error::Error;
use crate::perun_types::{
    Balances, Bool, BoolUnion, ChannelParameters, ChannelStatus, SEC1EncodedPubKey, SubBalances,
    VirtualChannelStatus,
};

extern crate alloc;

use alloc::{vec, vec::Vec};

// #[cfg(not(feature = "std"))]
// use alloc::{self, vec};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{
        bytes::Bytes,
        packed::{Byte32, Script},
        prelude::*,
    },
    debug,
    high_level::{load_cell_data, load_cell_lock_hash},
    syscalls::{self, SysError},
};

pub enum VChannelAction {
    /// Progress indicates that a channel is being progressed. This means that a channel cell is consumed
    /// in the inputs and the same channel with updated state is progressed in the outputs.
    /// The possible redeemers associated with the Progress action are Fund and Dispute.
    Progress {
        old_status: VirtualChannelStatus,
        new_status: VirtualChannelStatus,
    }, // one PCTS input, one PCTS output

    /// Start indicates that a channel is being started. This means that a **new channel** lives in the
    /// output cells of this transaction. No channel cell is consumed as an input.
    /// As Start does not consume a channel cell, there is no Witness associated with the Start action.
    Start {
        new_vc_status: VirtualChannelStatus,
        old_lc_status: ChannelStatus,
        new_lc_status: ChannelStatus,
    }, // no PCTS input, one PCTS output

    /// Close indicates that a channel is being closed. This means that a channel's cell is consumed without being
    /// recreated in the outputs with updated state. The possible redeemers associated with the Close action are
    /// Close, Abort and ForceClose.
    /// The channel type script assures that all funds are paid out to the correct parties upon closing.
    Close { old_status: VirtualChannelStatus }, // one PCTS input, no PCTS output
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
