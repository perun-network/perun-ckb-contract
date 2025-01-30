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
        find_cell_by_lock_hash, find_closest_current_time, verify_thread_token_integrity,
        verify_time_lock_expired, VChannelAction,
    },
    error::Error,
    helpers::blake2b256,
    perun_types::{
        Balances, Bool, ChannelCellData, ChannelConstants, ChannelParameters, ChannelState,
        ChannelStatus, ChannelToken, ChannelWitness, ChannelWitnessUnion, Dispute,
        LedgerChannelOrVirtualChannelUnion, LedgerChannelOrVirtualChannelUnionReader,
        LockedBalances, SEC1EncodedPubKey, SubAlloc, VirtualChannelStatus,
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

    // We verify that there is at most one channel in the GroupInputs and GroupOutputs respectively.

    // this does not need to be the case for vcs  - if there is a dispute, there are two channel cells in the inputs

    // verify_max_one_channel()?;
    // debug!("verify_max_one_channel passed");

    // The channel constants do not change during the lifetime of a channel. They are located in the
    // args field of the pcts.

    let channel_constants =
        ChannelConstants::from_slice(&args).expect("unable to parse args as ChannelConstants");
    debug!("parsing channel constants passed");

    debug!("channel_constants: {:?}", channel_constants);

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
            check_valid_vc_start(&new_vc_status, &channel_constants)
        }
        VChannelAction::Progress {
            old_status,
            new_status,
        } => {
            let channel_witness = load_witness()?;
            debug!("load_witness passed");
            check_valid_vc_progress(
                &old_status,
                &new_status,
                &channel_witness,
                &channel_constants,
            )
        }
        VChannelAction::Close { old_status } => {
            debug!("Close action detected");
            let channel_witness = load_witness()?;
            debug!("load_witness passed");
            check_valid_vc_close(&old_status, &channel_witness, &channel_constants)
        }
    }
}

pub fn check_valid_vc_start(
    new_status: &VirtualChannelStatus,
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

    let vc_chanid = new_status.vcstate().channel_id();

    verify_vchannel_id_integrity(&vc_chanid, &channel_constants.params())?;
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
    verify_vcstate_valid_as_start(
        &new_status.vcstate(),
        channel_constants.pfls_min_capacity().unpack(),
    )?;
    debug!("verify_vcstate_valid_as_start passed");

    // Here we verify that the first party completes its funding and that itsfunds are actually locked to the pfls with correct args.
    verify_funding_in_outputs(
        FUNDER_INDEX,
        &new_status.vcstate().balances().locked(),
        channel_constants,
    )?;
    debug!("verify_vcfunding_in_outputs passed");

    // We check that the funded bit in the channel status is set to true, exactly if the funding is complete.
    verify_funded_vc_status(new_status, true)?;
    debug!("verify_vc_funded_status passed");

    // We verify that the channel status is not disputed upon start.
    verify_vc_status_not_disputed(new_status)?;
    debug!("verify_vc_status_not_disputed passed");
    Ok(())
}

pub fn check_valid_vc_progress(
    old_status: &VirtualChannelStatus,
    new_status: &VirtualChannelStatus,
    witness: &ChannelWitness,
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    debug!("check_valid_vc_progress");

    // At this point we know that the transaction progresses the channel. There are two different
    // kinds of channel progression: Funding and Dispute. Which kind of progression is performed
    // depends on the witness.

    // Some checks are common to both kinds of progression and are performed here.
    // We check that both the old and the new state have the same channel id.
    verify_equal_channel_id(&old_status.vcstate(), &new_status.vcstate())?;
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
            verify_equal_channel_state(&old_status.vcstate(), &new_status.vcstate())?;
            debug!("verify_equal_channel_state passed");

            // Funding an already funded status is invalid.
            verify_vc_status_not_funded(old_status)?;
            debug!("verify_status_not_funded passed");

            verify_funding_in_outputs(
                FUNDER_INDEX,
                &old_status.vcstate().balances().locked(),
                channel_constants,
            )?;
            debug!("verify_funding_in_outputs passed");

            // Funding a disputed status is invalid. This should not be able to happen anyway, but we check
            // it nontheless.
            verify_status_not_disputed(new_status)?;
            debug!("verify_status_not_disputed passed");

            // We check that the funded bit in the channel status is set to true, iff the funding is complete.
            verify_funded_vc_status(&new_status, false)?;
            debug!("verify_funded_status passed");
            Ok(())
        }
        ChannelWitnessUnion::Dispute(d) => {
            debug!("ChannelWitnessUnion::Dispute VC");
            let dispute_mode = get_dispute_mode(old_status, new_status)?;

            match dispute_mode {
                DisputeMode::Normal => verify_normal_dispute(
                    &old_status.lcstatus(),
                    &new_status.lcstatus(),
                    &channel_constants,
                    &d,
                ),
                DisputeMode::VCDisputeStart {
                    old_lc_status,
                    new_lc_status,
                    new_vc_status,
                } => verify_vc_dispute_start(&old_lc_status, &new_lc_status, &new_vc_status, &d),
                DisputeMode::VCDisputeProgress {
                    old_lc_status,
                    old_vc_status,
                    new_lc_status,
                    new_vc_status,
                } => verify_vc_dispute_progress(
                    &old_lc_status,
                    &old_vc_status,
                    &new_lc_status,
                    &new_vc_status,
                    channel_constants,
                    &d,
                ),
            };

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
            verify_channel_state_progression(
                &old_status.lcstatus(),
                &new_status.lcstatus().state(),
            )?;
            debug!("verify_channel_state_progression passed");

            // One cannot dispute if funding is not complete.
            verify_vc_status_funded(&old_status)?;
            debug!("verify_status_funded passed");

            // The disputed flag in the new status must be set. This indicates that the channel can be closed
            // forcibly after the expiration of the challenge duration in a later transaction.
            verify_status_disputed(&new_status.lcstatus())?;
            debug!("verify_status_disputed passed");

            // We verify that the signatures of both parties are valid on the new channel state.
            verify_valid_state_sigs(
                &d.sig_a().unpack(),
                &d.sig_b().unpack(),
                &new_status.lcstatus().state(),
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

pub fn check_valid_vc_close(
    old_status: &VirtualChannelStatus,
    channel_witness: &ChannelWitness,
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    debug!("check_valid_vc_close");

    // At this point we know that this transaction closes the channel. There are three different kinds of
    // closing: Abort, ForceClose and Close. Which kind of closing is performed depends on the witness.
    // Every channel closing transaction must pay out all funds the the channel participants. The amount
    // to be transfered to each party
    let channel_capacity = load_cell_capacity(0, Source::GroupInput)?;
    match channel_witness.to_enum() {
        ChannelWitnessUnion::Abort(_) => {
            const PARTY_B_INDEX: usize = 1;

            debug!("ChannelWitnessUnion::Abort");

            // An abort can be performed at any time by a channel participant on a channel for which funding
            // is not yet complete. It allows the initial party to reclaim its funds if e.g. the other party
            // refuses to fund the channel.
            verify_vc_status_not_funded(old_status)?;
            debug!("verify_vc_status_not_funded passed");

            // We verify that every party is paid the amount of funds that it has locked to the channel so far.
            // If abort is called, Party A must have fully funded the channel and Party B can not have funded
            // the channel because of our funding protocol.
            verify_vc_all_paid(
                &old_status
                    .lcstatus()
                    .state()
                    .balances()
                    .clear_index(PARTY_B_INDEX)?,
                channel_capacity,
                channel_constants,
                true,
            )?;
            debug!("verify_all_paid passed");
            Ok(())
        }
        ChannelWitnessUnion::ForceClose(_) => {
            debug!("ChannelWitnessUnion::ForceClose");
            // A force close can be performed after the channel was disputed and the challenge duration has
            // expired. Upon force close, each party is paid according to the balance distribution in the
            // latest state.
            verify_vc_status_funded(old_status)?;
            debug!("verify_status_funded passed");
            verify_time_lock_expired(channel_constants.params().challenge_duration().unpack())?;
            debug!("verify_time_lock_expired passed");
            verify_vc_status_disputed(old_status)?;
            debug!("verify_status_disputed passed");
            verify_vc_all_paid(
                &old_status.vcstate().balances(),
                channel_capacity,
                channel_constants,
                false,
            )?;
            debug!("verify_all_paid passed");
            Ok(())
        }
        ChannelWitnessUnion::Close(c) => {
            debug!("check_valid_close: Close");

            // A channel can be closed by either party at any time after funding is complete.
            // For this the party needs to provide a final state (final bit set) and signatures
            // by all peers on that state.
            verify_equal_channel_id(&old_status.vcstate(), &c.state())?;
            debug!("check_valid_close: Channel id verified");
            verify_vc_status_funded(old_status)?;
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
            verify_vc_all_paid(
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
    debug!(
        "verify_increasing_version_number old_state disputed:  {}",
        old_status.disputed().to_bool()
    );
    debug!(
        "verify_increasing_version_number old: {},  new: {}",
        old_status.state().version().unpack(),
        new_state.version().unpack()
    );
    // Allow registering initial state
    if !old_status.disputed().to_bool()
        && old_status.state().version().unpack() == 0
        && new_state.version().unpack() == 0
    {
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

pub fn verify_vc_status_funded(status: &VirtualChannelStatus) -> Result<(), Error> {
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
    initial_balance: &LockedBalances, //TODO Check: This has to be SubBalance for VC funding, right?
    channel_constants: &ChannelConstants,
) -> Result<(), Error> {
    let ckbytes_locked_for_sudts = initial_balance
        .get_unchecked(idx)
        .balances()
        .sudts()
        .get_locked_ckbytes(); //sudts().get_locked_ckbytes();
    let to_fund = initial_balance
        .get_unchecked(idx)
        .balances()
        .ckbytes()
        .get(idx)?
        + ckbytes_locked_for_sudts; //.ckbytes().get(idx)? + ckbytes_locked_for_sudts;
    if to_fund == 0 {
        return Ok(());
    }

    let mut udt_sum = vec![
        0u128,
        initial_balance
            .get_unchecked(idx)
            .balances()
            .sudts()
            .len()
            .try_into()
            .unwrap(),
    ]
    .into_boxed_slice();

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
                let (sudt_idx, amount) = get_vc_sudt_amount(
                    initial_balance,
                    i,
                    &output.type_().to_opt().expect("checked above"),
                )?;
                udt_sum[sudt_idx] += amount;
            }
        }
    }
    if capacity_sum != to_fund {
        debug!(
            "verify_funding_in_outputs: capacity_sum: {}, to_fund: {}",
            capacity_sum, to_fund
        );
        return Err(Error::OwnFundingNotInOutputs);
    }
    if !initial_balance
        .get_unchecked(idx)
        .balances()
        .sudts()
        .fully_represented(idx, &udt_sum)?
    {
        return Err(Error::OwnFundingNotInOutputs);
    }

    Ok(())
}

pub fn verify_funded_vc_status(status: &VirtualChannelStatus, is_start: bool) -> Result<(), Error> {
    if !is_start {
        if !status.funded().to_bool() {
            return Err(Error::FundedBitStatusNotCorrect);
        }
        return Ok(());
    }
    if status
        .vcstate()
        .balances()
        .locked()
        .get_unchecked(1)
        .balances()
        .ckbytes()
        .get(1)?
        != 0
    {
        if status.funded().to_bool() {
            return Err(Error::FundedBitStatusNotCorrect);
        }
        return Ok(());
    }
    if status
        .vcstate()
        .balances()
        .locked()
        .get_unchecked(1)
        .balances()
        .sudts()
        .len()
        != 0
    {
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

pub fn verify_vc_status_not_funded(status: &VirtualChannelStatus) -> Result<(), Error> {
    if status.funded().to_bool() {
        return Err(Error::StateIsFunded);
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

pub fn verify_equal_channel_id(
    old_state: &ChannelState,
    new_state: &ChannelState,
) -> Result<(), Error> {
    if old_state.balances().locked().get_unchecked(0).id().unpack()[..]
        != new_state.balances().locked().get_unchecked(0).id().unpack()[..]
    {
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

pub fn verify_vcstate_valid_as_start(
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
    let balance_a = state
        .balances()
        .locked()
        .get_unchecked(0)
        .balances()
        .ckbytes()
        .get(0)?; //virtual channel balances
    let balance_b = state
        .balances()
        .locked()
        .get_unchecked(1)
        .balances()
        .ckbytes()
        .get(1)?;
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

pub fn verify_vc_status_not_disputed(status: &VirtualChannelStatus) -> Result<(), Error> {
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

pub fn verify_status_funded(status: &ChannelStatus) -> Result<(), Error> {
    if !status.funded().to_bool() {
        return Err(Error::ChannelNotFunded);
    }
    Ok(())
}

pub fn verify_vc_status_disputed(status: &VirtualChannelStatus) -> Result<(), Error> {
    if !status.disputed().to_bool() {
        return Err(Error::StatusNotDisputed);
    }
    Ok(())
}

pub fn verify_vc_all_paid(
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
                let (sudt_idx, amount) = get_vc_sudt_amount(
                    &final_balance.locked(),
                    i,
                    &output.type_().to_opt().expect("checked above"),
                )?;
                udt_outputs_a[sudt_idx] += amount;
            }
            ckbytes_outputs_a += output.capacity().unpack();
        }
        if output_lock_script_hash[..] == payment_script_hash_b[..] {
            if output.type_().is_some() {
                let (sudt_idx, amount) = get_vc_sudt_amount(
                    &final_balance.locked(),
                    i,
                    &output.type_().to_opt().expect("checked above"),
                )?;
                udt_outputs_b[sudt_idx] += amount;
            }
            ckbytes_outputs_b += output.capacity().unpack();
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
pub fn get_vchannel_action() -> Result<VChannelAction, Error> {
    // Count the number of input and output cells
    let cell_num_in = count_cells(Source::Input)?;
    let cell_num_out = count_cells(Source::Output)?;

    // If there are exactly two input cells, determine the action based on their data
    if cell_num_in == 2 {
        // Load data for both input cells
        let cell_in0_data = load_cell_data(0, Source::Input).ok();
        let cell_in1_data = load_cell_data(1, Source::Input).ok();

        // Use the helper function to determine the action for two cells
        return determine_channel_action_for_two_cells(cell_in0_data, cell_in1_data, cell_num_out);
    } else if cell_num_in == 1 && cell_num_out == 1 {
        // Progress action: one input and one output
        let cell_input_data = load_cell_data(0, Source::GroupInput)
            .ok()
            .map(|data| VirtualChannelStatus::from_slice(data.as_slice()))
            .map_or(Ok(None), |v| v.map(Some))?
            .ok_or(Error::UnableToLoadAnyChannelStatus)?;
        let cell_output_data = load_cell_data(0, Source::GroupOutput)
            .ok()
            .map(|data| VirtualChannelStatus::from_slice(data.as_slice()))
            .map_or(Ok(None), |v| v.map(Some))?
            .ok_or(Error::UnableToLoadAnyChannelStatus)?;

        return Ok(VChannelAction::Progress {
            old_status: cell_input_data,
            new_status: cell_output_data,
        });
    } else if cell_num_in == 1 && cell_num_out == 0 {
        // Close action: one input and no outputs
        let cell_input_data = load_cell_data(0, Source::GroupInput)
            .ok()
            .map(|data| VirtualChannelStatus::from_slice(data.as_slice()))
            .map_or(Ok(None), |v| v.map(Some))?
            .ok_or(Error::UnableToLoadAnyChannelStatus)?;

        return Ok(VChannelAction::Close {
            old_status: cell_input_data,
        });
    } else {
        // Invalid number of cells
        return Err(Error::UnableToLoadAnyChannelStatus);
    }
}

fn determine_channel_action_for_two_cells(
    cell_in0_data: Option<Vec<u8>>,
    cell_in1_data: Option<Vec<u8>>,
    cell_out_data: usize,
) -> Result<VChannelAction, Error> {
    // Attempt to parse each cell as PCTS or VCTS
    let pcts_opt_0 = cell_in0_data
        .as_ref()
        .and_then(|data| ChannelStatus::from_slice(data).ok());
    let vcts_opt_0 = cell_in0_data
        .as_ref()
        .and_then(|data| VirtualChannelStatus::from_slice(data).ok());

    let pcts_opt_1 = cell_in1_data
        .as_ref()
        .and_then(|data| ChannelStatus::from_slice(data).ok());
    let vcts_opt_1 = cell_in1_data
        .as_ref()
        .and_then(|data| VirtualChannelStatus::from_slice(data).ok());

    // Case 1: One PCTS and no VCTS (Start), then one PCTS, one VCTS as outputs
    if (pcts_opt_0.is_some() && vcts_opt_1.is_none())
        || (pcts_opt_1.is_some() && vcts_opt_0.is_none())
    {
        let new_vc_status = if let Some(ref pcts_status) = pcts_opt_0 {
            build_vchannel_status(pcts_status)
        } else {
            build_vchannel_status(pcts_opt_1.as_ref().unwrap())
        };

        let old_lc_status = if let Some(ref pcts_status) = pcts_opt_0 {
            pcts_status.clone()
        } else {
            pcts_opt_1.unwrap()
        };

        // Simulate fetching new_lc_status (replace this with actual logic)
        let new_lc_status = old_lc_status.clone(); // Replace with actual logic to fetch or compute new_lc_status

        return Ok(VChannelAction::Start {
            new_vc_status,
            old_lc_status,
            new_lc_status,
        });
    }

    // Case 2: Two VCTS and zero PCTS (Progress)
    if vcts_opt_0.is_some() && vcts_opt_1.is_some() {
        // if number of outputs is not 1, return an error
        if cell_out_data != 1 {
            return Err(Error::InvalidNumberOfOutputs);
        }

        let vcell_in0_data = load_cell_data(0, Source::GroupInput)
            .ok()
            .map(|data| VirtualChannelStatus::from_slice(data.as_slice()))
            .map_or(Ok(None), |v| v.map(Some))?
            .ok_or(Error::UnableToLoadAnyChannelStatus)?;
        let vcell_in1_data = load_cell_data(1, Source::GroupInput)
            .ok()
            .map(|data| VirtualChannelStatus::from_slice(data.as_slice()))
            .map_or(Ok(None), |v| v.map(Some))?
            .ok_or(Error::UnableToLoadAnyChannelStatus)?;

        let vcell_out_data = load_cell_data(0, Source::GroupOutput)
            .ok()
            .map(|data| VirtualChannelStatus::from_slice(data.as_slice()))
            .map_or(Ok(None), |v| v.map(Some))?
            .ok_or(Error::UnableToLoadAnyChannelStatus)?;

        let v0 = vcts_opt_0.unwrap().vcstate().version().unpack();
        let v1 = vcts_opt_1.unwrap().vcstate().version().unpack();

        // compare versions, pick the one with higher version as new status
        if v0 > v1 {
            return Ok(VChannelAction::Progress {
                old_status: vcell_in0_data,
                new_status: vcell_out_data,
            });
        } else {
            return Ok(VChannelAction::Progress {
                old_status: vcell_in1_data,
                new_status: vcell_out_data,
            });
        }
    }

    // If no valid case is matched, return an error
    Err(Error::UnableToLoadAnyChannelStatus)
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

// pub fn get_dispute_mode(
//     old_status: &ChannelStatus,
//     new_status: &ChannelStatus,
// ) -> Result<DisputeMode, Error> {
//     // if old_status.item_count() == 1 && new_status.item_count() == 1 {
//     //     return Ok(DisputeMode::Normal);
//     // }

//     if old_status.item_count() == 1 && new_status.item_count() == 2 {
//         let old_state = get_channel_status(&old_status)?;
//         let new_state = get_channel_status(&new_status)?;
//         let new_vc_state = get_virtual_channel_status(&new_status)?;
//         return Ok(DisputeMode::VCDisputeStart {
//             old_lc_status: old_state,
//             new_lc_status: new_state,
//             new_vc_status: new_vc_state,
//         });
//     }

//     if old_status.item_count() == 2 && new_status.item_count() == 2 {
//         return Ok(DisputeMode::VCDisputeProgress {
//             old_lc_status: get_channel_status(&old_status)?,
//             old_vc_status: get_virtual_channel_status(&old_status)?,
//             new_lc_status: get_channel_status(&new_status)?,
//             new_vc_status: get_virtual_channel_status(&new_status)?,
//         });
//     }
//     Err(Error::InvalidDisputeMode)
// }

pub fn verify_vc_dispute_start(
    old_lc_status: &ChannelStatus,
    new_lc_status: &ChannelStatus,
    new_vc_status: &VirtualChannelStatus,
    dispute: &Dispute,
) -> Result<(), Error> {
    // verify that the parents mentioned in the vc status are the two channel cells included in input and output
    verify_parents_of_vc_exist(new_vc_status)?;
    debug!("verify_parents_of_vc_exist passed");

    // verify that both parents in output have the same vc status and the sigs of vc status are valid
    verify_vc_integrity(new_vc_status, dispute)?;
    debug!("verify_vc_integrity passed");

    // verify that funds locked in the parent output cell, is the balance of vc state
    verify_vc_locked_funds(new_lc_status, new_vc_status)?;
    debug!("verify_vc_locked_funds passed");

    //verify third party access
    let third_party_flag = match verify_vc_third_party_access(new_vc_status) {
        Ok(Some(flag)) => flag,
        Ok(None) => return Err(Error::UndefinedBehavior),
        Err(err) => return Err(err),
    };
    debug!("verify_vc_third_party_access passed");

    // verify integrity of ledger channel state
    if third_party_flag {
        verify_lc_channel_state_progression_in_vc_dispute_start_in_case_of_third_party(
            old_lc_status,
            new_lc_status,
            new_vc_status,
        )?;
    } else {
        verify_channel_state_progression(old_lc_status, &new_lc_status.state())?;
    }
    Ok(())
}

// check C_IB's integrity in case Alice posted a VC Dispute Start Tx
pub fn verify_lc_channel_state_progression_in_vc_dispute_start_in_case_of_third_party(
    old_lc_status: &ChannelStatus,
    new_lc_status: &ChannelStatus,
    new_vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    verify_equal_channel_id(&old_lc_status.state(), &new_lc_status.state())?;
    verify_equal_sum_of_balances(
        &old_lc_status.state().balances(),
        &new_lc_status.state().balances(),
    )?;
    verify_state_not_finalized(&old_lc_status.state())?;
    verify_state_finalized(&new_lc_status.state())?;
    // since this the registerer of this Tx is a third party to this channel cell, it cannot change its lc state.
    // However it can add a vc state to indicate a dispute for vc was registered
    // Nevertheless we still verify that the ledger channel has enough funds to cover vc channel's balances, even if the funds were not locked
    verify_vc_unregistered_locked_funds(
        &new_lc_status.state().balances(),
        &new_vc_status.vcstate().balances(),
    );
    if old_lc_status.state().version().unpack() != new_lc_status.state().version().unpack() {
        return Err(Error::ThirdPartyCannotChangeLedgerChannelStateInVCDisputeStart);
    }
    Ok(())
}

pub fn verify_vc_dispute_progress(
    old_lc_status: &ChannelStatus,
    old_vc_status: &VirtualChannelStatus,
    new_lc_status: &ChannelStatus,
    new_vc_status: &VirtualChannelStatus,
    channel_constants: &ChannelConstants,
    dispute: &Dispute,
) -> Result<(), Error> {
    //check if there are any changes made to the state of the ledger channel. If yes then verify its integrity given the vc state
    // if no changes are made to the ledger channel state then only verify the integrity of the vc state
    if old_lc_status.state().as_slice() != new_lc_status.state().as_slice() {
        verify_normal_dispute(old_lc_status, new_lc_status, channel_constants, dispute);
        debug!("lc state was changed. Lc state progression verified");
    }
    // verify that funds locked in both the parent output cells, is the balance of vc state
    verify_vc_locked_funds(new_lc_status, new_vc_status)?;
    debug!("verify_vc_locked_funds passed");

    verify_equal_channel_id(&old_vc_status.vcstate(), &new_vc_status.vcstate())?;
    debug!("vc dispute progress: verify equal channel id passed");

    verify_increasing_version_number_for_vc(&old_vc_status.vcstate(), &new_vc_status.vcstate())?;
    debug!("vc dispute progress: increasing version number passed");

    verify_equal_sum_of_balances(
        &old_lc_status.state().balances(),
        &new_lc_status.state().balances(),
    )?;
    debug!("vc dispute progress: equal sum of balances passed");

    verify_state_not_finalized(&old_vc_status.vcstate())?;
    debug!("vc dispute progress: old vc state not finalized");

    Ok(())
}

pub fn verify_normal_dispute(
    old_ledger_channel_status: &ChannelStatus,
    new_ledger_channel_status: &ChannelStatus,
    channel_constants: &ChannelConstants,
    dispute: &Dispute,
) -> Result<(), Error> {
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
    verify_channel_state_progression(
        old_ledger_channel_status,
        &new_ledger_channel_status.state(),
    )?;
    debug!("verify_channel_state_progression passed");

    // One cannot dispute if funding is not complete.
    verify_status_funded(old_ledger_channel_status)?;
    debug!("verify_status_funded passed");

    // The disputed flag in the new status must be set. This indicates that the channel can be closed
    // forcibly after the expiration of the challenge duration in a later transaction.
    verify_status_disputed(new_ledger_channel_status)?;
    debug!("verify_status_disputed passed");

    // We verify that the signatures of both parties are valid on the new channel state.
    verify_valid_state_sigs(
        &dispute.sig_a().unpack(),
        &dispute.sig_b().unpack(),
        &new_ledger_channel_status.state(),
        &channel_constants.params().party_a().pub_key(),
        &channel_constants.params().party_b().pub_key(),
    )?;
    debug!("verify_valid_state_sigs passed");
    Ok(())
}

/// verifies whether a third party apart from this channel's participatnts is allowed to modify the channel cell
/// # Arguments
/// * `old_lc_status` - The old ledger channel status
/// * `new_lc_status` - The new ledger channel status
/// * `new_vc_status` - The new virtual channel status
///
/// # Returns
/// * `Ok(())` if the third party is allowed to modify the channel cell
/// * `Err(Error)` if the third party is not allowed to modify the channel cell
pub fn verify_vc_third_party_access(
    new_vc_status: &VirtualChannelStatus,
) -> Result<Option<bool>, Error> {
    // check if the channel cell of this type script is being modified by a third party
    // find unlock script hash of the participants of this channel cell
    // look for cells with the same unlock script hash in the inputs
    // if you find any such cell, then it is not third party access and return with success
    // else it is third party access and continue to next logic
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    let channel_constants =
        ChannelConstants::from_slice(&args).expect("unable to parse args as ChannelConstants");
    let unlock_script_a = channel_constants
        .params()
        .party_a()
        .unlock_script_hash()
        .unpack();
    let unlock_script_b = channel_constants
        .params()
        .party_b()
        .unlock_script_hash()
        .unpack();
    match find_cell_by_lock_hash(&unlock_script_a, &unlock_script_b, Source::Input) {
        Ok(Some(_)) => return Ok(Some(false)),
        Ok(None) => (),
        Err(err) => return Err(err.into()),
    }

    // at this point we know that the channel cell is being modified by a third party
    // To verify if third party is allowed to modify the channel cell
    // load the pcts hashes of the parents from vc status.
    // one of them should be equal to the pcts hash of this cell.
    // consider the other pcts hash. load the channel cell with that pcts hash and find its participants unlock script hashes.
    // find an input cell with unlock script hash with either of those participants.
    // if such cells exist then third party access is allowed, else return error

    let parent1_pcts_hash = match new_vc_status.parents().get(0) {
        Some(parent) => parent.pcts_hash().unpack(),
        None => return Err(Error::ParentPCTSHashNotFound),
    };
    let parent2_pcts_hash = match new_vc_status.parents().get(1) {
        Some(parent) => parent.pcts_hash().unpack(),
        None => return Err(Error::ParentPCTSHashNotFound),
    };

    let other_party_pcts_hash = find_other_party(&parent1_pcts_hash, &parent2_pcts_hash)?;

    let other_channel_cell_idx = match find_cell_by_type_hash(&other_party_pcts_hash, Source::Input)
    {
        Ok(Some(idx)) => idx,
        Ok(None) => return Err(Error::InputCellForGivenParticipantNotFound),
        Err(err) => return Err(err.into()),
    };

    let other_party_type_script = load_cell_type(other_channel_cell_idx, Source::Input)?;
    let other_party_args: Bytes = other_party_type_script.unwrap().args().unpack();
    let other_party_constants = ChannelConstants::from_slice(&other_party_args)
        .expect("unable to parse args as channel parameters");
    let other_party_unlock_script_a = other_party_constants
        .params()
        .party_a()
        .unlock_script_hash()
        .unpack();
    let other_party_unlock_script_b = other_party_constants
        .params()
        .party_b()
        .unlock_script_hash()
        .unpack();

    match find_cell_by_lock_hash(
        &other_party_unlock_script_a,
        &other_party_unlock_script_b,
        Source::Input,
    ) {
        Ok(Some(_)) => Ok(Some(true)),
        Ok(None) => Err(Error::InputCellForGivenParticipantNotFound),
        Err(err) => Err(err.into()),
    }
}

pub fn get_dispute_mode(
    old_vc_status: &VirtualChannelStatus,
    new_vc_status: &VirtualChannelStatus,
) -> Result<DisputeMode, Error> {
    if !old_vc_status.lcstatus().disputed().to_bool()
        && !new_vc_status.lcstatus().disputed().to_bool()
    {
        // TODO: think if we need another condition for DisputeMode::Normal
        return Ok(DisputeMode::Normal);
    }

    if !old_vc_status.disputed().to_bool() && new_vc_status.disputed().to_bool() {
        let old_state = old_vc_status.lcstatus();
        let new_state = new_vc_status.lcstatus();

        return Ok(DisputeMode::VCDisputeStart {
            old_lc_status: old_state,
            new_lc_status: new_state,
            new_vc_status: new_vc_status.clone(),
        });
    }

    if old_vc_status.disputed().to_bool() && new_vc_status.disputed().to_bool() {
        return Ok(DisputeMode::VCDisputeProgress {
            old_lc_status: old_vc_status.lcstatus(),
            old_vc_status: old_vc_status.clone(),
            new_lc_status: new_vc_status.lcstatus(),
            new_vc_status: new_vc_status.clone(),
        });
    }
    Err(Error::InvalidDisputeMode)
}

pub fn verify_parents_of_vc_exist(vc_status: &VirtualChannelStatus) -> Result<(), Error> {
    match get_parents_of_vc(vc_status) {
        Ok(_) => Ok(()),
        Err(err) => Err(err),
    }
}

pub fn verify_status_not_disputed(status: &VirtualChannelStatus) -> Result<(), Error> {
    if status.disputed().to_bool() {
        return Err(Error::StatusDisputed);
    }
    Ok(())
}

pub fn get_parents_of_vc(
    vc_status: &VirtualChannelStatus,
) -> Result<
    (
        [Option<ChannelStatus>; 2],
        [Option<VirtualChannelStatus>; 2],
    ),
    Error,
> {
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

    let parents_hashes: [[u8; 32]; 2] = [parent1_hash, parent2_hash];

    let mut parents_output_status: [Option<ChannelStatus>; 2] = [None, None];
    let mut output_vc_statuses: [Option<VirtualChannelStatus>; 2] = [None, None];
    let mut index = 0;
    //iterate through parents pcts hashes
    // find the input parent cell and check that it contains only channel status
    // find the output parent cell and check that it contains a channel status and vc status
    for parent_hash in &parents_hashes {
        let parent_input_idx = match find_cell_by_type_hash(parent_hash, Source::Input) {
            Ok(Some(idx)) => idx,
            Ok(None) => return Err(Error::InputCellForGivenParticipantNotFound),
            Err(err) => return Err(err.into()),
        };

        let parent_output_idx = match find_cell_by_type_hash(parent_hash, Source::Output) {
            Ok(Some(idx)) => idx,
            Ok(None) => return Err(Error::OutputCellForGivenParticipantNotFound),
            Err(err) => return Err(err.into()),
        };

        let parent_input_data = match load_cell_data(parent_input_idx, Source::Input) {
            Ok(data) => ChannelCellData::from_slice(data.as_slice())?,
            Err(_) => return Err(Error::UnableToLoadAnyChannelStatus),
        };
        //check that the input parent cell contains only channel status
        verify_only_channel_status(&parent_input_data)?;

        let output_data = match load_cell_data(parent_output_idx, Source::Output) {
            Ok(data) => ChannelCellData::from_slice(data.as_slice())?,
            Err(_) => return Err(Error::UnableToLoadAnyChannelStatus),
        };
        if output_data.item_count() == 2 {
            return Err(Error::InvalidOutputTxForVCDisputeStart);
        }
        let mut output_lc_status: Option<ChannelStatus> = None;
        let mut output_vc_status: Option<VirtualChannelStatus> = None;
        for i in 0..output_data.item_count() {
            let output_enum = match output_data.get(i) {
                Some(output) => output.to_enum(),
                None => return Err(Error::InvalidOutputTxForVCDisputeStart),
            };
            match output_enum {
                LedgerChannelOrVirtualChannelUnion::ChannelStatus(status) => {
                    output_lc_status = Some(status)
                }
                LedgerChannelOrVirtualChannelUnion::VirtualChannelStatus(status) => {
                    output_vc_status = Some(status)
                }
            }
        }

        if index < 2 {
            parents_output_status[index] = output_lc_status;
            output_vc_statuses[index] = output_vc_status;
            index += 1;
        }
    }
    Ok((parents_output_status, output_vc_statuses))
}

pub fn verify_only_channel_status(cell_data: &ChannelCellData) -> Result<(), Error> {
    match get_channel_status(cell_data) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::OnlyChannelStatusExpectedButThatIsNotTheCase),
    }
}

pub fn verify_vc_unregistered_locked_funds(
    new_lc_balance: &Balances,
    new_vc_balance: &Balances,
) -> Result<(), Error> {
    match new_lc_balance.covers_funds(new_vc_balance) {
        Ok(true) => Ok(()),
        Ok(false) => return Err(Error::LedgerChannelDoesNotHaveEnoughFundsForVC),
        Err(err) => return Err(err),
    }
}

pub fn get_channel_status(cell_data: &ChannelCellData) -> Result<ChannelStatus, Error> {
    if cell_data.as_reader().item_count() == 0 {
        return Err(Error::ChannelCellDataIsEmpty);
    }
    let item = match cell_data.as_reader().get(0) {
        Some(item) => item,
        None => return Err(Error::UnableToLoadAnyChannelStatus),
    };
    match item.to_enum() {
        LedgerChannelOrVirtualChannelUnionReader::ChannelStatus(channel_status) => {
            return Ok(channel_status.to_entity());
        }
        LedgerChannelOrVirtualChannelUnionReader::VirtualChannelStatus(_) => {
            return Err(Error::VirtualChannelStatusInChannelCellWhereChannelStatusExpected);
        }
    }
}

pub fn find_cell_by_type_hash(
    pcts_hash: &[u8; 32],
    source: Source,
) -> Result<Option<usize>, Error> {
    for i in 0.. {
        let type_hash = match load_cell_type_hash(i, source) {
            Ok(Some(script)) => script,
            Ok(None) => panic!("type script not found"),
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };
        if &type_hash == pcts_hash {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// finds the other party's pcts hash
/// # Arguments
/// * `parent1_pcts_hash` - The pcts hash of the first parent
/// * `parent2_pcts_hash` - The pcts hash of the second parent
///
/// # Returns
/// * `Ok([u8;32])` - The pcts hash of the other party
/// * `Err(Error)` - If there is an error while loading the script hash
pub fn find_other_party(
    parent1_pcts_hash: &[u8; 32],
    parent2_pcts_hash: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let current_pcts_hash = &load_script_hash()?;
    if parent1_pcts_hash == current_pcts_hash {
        return Ok(*parent2_pcts_hash);
    } else if parent2_pcts_hash == current_pcts_hash {
        return Ok(*parent1_pcts_hash);
    } else {
        return Err(Error::InvalidParentPCTSHash);
    }
}

pub fn verify_vc_integrity(
    vc_status: &VirtualChannelStatus,
    dispute: &Dispute,
) -> Result<(), Error> {
    let (_, output2) = get_parents_of_vc(vc_status)?;

    // Convert Option to Result for error handling
    let vc_status1 = output2[0].as_ref().unwrap();
    let vc_status2 = output2[1].as_ref().unwrap();

    // both vc states in the output cells must be the same
    if vc_status1.as_slice() != vc_status2.as_slice() {
        return Err(Error::ParentsOfVCInOutputHaveDifferentVCStatus);
    }
    verify_valid_state_sigs(
        &dispute.vc_sigs().sig_a().as_bytes(),
        &dispute.vc_sigs().sig_b().as_bytes(),
        &vc_status.vcstate(),
        &vc_status.params().party_a().pub_key(),
        &vc_status.params().party_b().pub_key(),
    );

    Ok(())
}

pub fn verify_vc_locked_funds(
    lc_status: &ChannelStatus,
    vc_status: &VirtualChannelStatus,
) -> Result<(), Error> {
    let vc_balances = vc_status.vcstate().balances();
    let locked_funds = lc_status.state().balances().locked();

    for sub_alloc in locked_funds.into_iter() {
        if sub_alloc.id().as_slice() == vc_status.vcstate().channel_id().as_slice() {
            let sub_balance = sub_alloc.balances();
            match sub_balance.equal_in_sum(&vc_balances) {
                Ok(false) => {
                    return Err(Error::UnequalBalanceInLockedFundsAndVirtualChannelBalance)
                }
                _ => continue,
            }
        }
    }
    Ok(())
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

pub fn build_vchannel_status(pcts_status: &ChannelStatus) -> VirtualChannelStatus {
    let locked_bals = pcts_status.state().balances().locked().get_unchecked(0);

    let bals = Balances::new_builder()
        .ckbytes(locked_bals.balances().ckbytes().clone())
        .sudts(locked_bals.balances().sudts().clone())
        .build();

    let vc_chanstate = ChannelState::new_builder()
        .version(0u64.pack())
        .balances(bals)
        .is_final(Bool::from_bool(false))
        .build();

    VirtualChannelStatus::new_builder()
        .lcstatus(pcts_status.clone())
        .vcstate(vc_chanstate)
        .disputed(Bool::from_bool(true))
        .funded(Bool::from_bool(true))
        .build()
}
