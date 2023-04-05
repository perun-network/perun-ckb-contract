// Import from `core` instead of from `std` since we are in no-std mode
use core::{result::Result};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc;

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    debug,
    high_level::{load_script, load_witness_args},
};
use perun_common::perun_types::{ChannelParameters, ChannelState, ChannelWitness, ChannelWitnessUnion, PubKey, Signature};
use crate::error::Error;


enum ChannelAction {
    Progress {old_state: ChannelState, new_state: ChannelState},   // one PCTS input, one PCTS output
    Start {new_state: ChannelState},      // no PCTS input, one PCTS output    
    Close {old_state: ChannelState},      // one PCTS input , no PCTS output
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

    let params = ChannelParameters::from_slice(&args).expect("unable to parse args as ChannelParameters");

    // What if there is only an output?
    let witness_args = load_witness_args(0, Source::GroupInput).unwrap();
    let witness_bytes: Bytes = witness_args.input_type().to_opt().unwrap().unpack();
    let channel_witness = ChannelWitness::from_slice(&witness_bytes).unwrap();

    // Todo: figure out which kind of ChannelAction we are actually dealing with!
    //load_cell_data(0, Source::GroupInput)?;
    //load_cell_data(0, Source::GroupOutput)?;

    let channel_action = ChannelAction::Progress{old_state: ChannelState::default(), new_state: ChannelState::default()};
    match channel_action {
        ChannelAction::Progress{old_state, new_state} => check_valid_progress(&old_state, &new_state, &channel_witness, &params),
        ChannelAction::Start{new_state} => Err(todo!()),
        ChannelAction::Close{old_state} => Err(todo!()),
    }
}

pub fn check_valid_progress(old_state: &ChannelState, new_state: &ChannelState, witness: &ChannelWitness, params: &ChannelParameters) -> Result<(), Error> {
    if old_state.channel_id().as_slice()[..] != new_state.channel_id().as_slice()[..] {
        return Err(Error::ChannelIdMismatch);
    }


    match witness.to_enum() {
        ChannelWitnessUnion::Dispute(d) => {
            check_increasing_version_number(old_state, new_state)?;
            check_valid_state_sig(&d.sig_a(), new_state, &params.participants().nth0().pub_key())?;
            check_valid_state_sig(&d.sig_b(), new_state, &params.participants().nth1().pub_key())?;
            Ok(())
        },
        _ => Err(todo!()),
    }
}

pub fn check_increasing_version_number(old_state: &ChannelState, new_state: &ChannelState) -> Result<(), Error> {
    if u64::from_le_bytes(old_state.version().as_slice().try_into().unwrap()) < u64::from_le_bytes(new_state.version().as_slice().try_into().unwrap()) {
        return Ok(())
    }
    Err(Error::DisputeWithInvalidVersionNumber)
}

pub fn check_valid_state_sig(sig: &Signature, state: &ChannelState, pub_key: &PubKey) -> Result<(), Error> {
    Err(todo!())
}