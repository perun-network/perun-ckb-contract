use ckb_testtool::{
    ckb_types::{
        packed::{Header, OutPoint, RawHeader, Script},
        prelude::{Builder, Entity, Pack, Unpack},
    },
    context::Context,
};
use k256::ecdsa::VerifyingKey;
use perun_common::{
    ctrue,
    perun_types::{ChannelConstants, ChannelState, ChannelStatus},
};

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

use crate::perun::{
    self,
    test::{keys, transaction, Client},
};
use crate::perun::{harness, test};
use ckb_testtool::ckb_types::prelude::IntoHeaderView;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::fmt::Debug;

use super::{
    test::cell::FundingCell,
    virtual_channel::{IdxMapWithDirection, VirtualChannel},
    Account,
};

enum ActionValidity {
    Valid,
    Invalid,
}

/// Channel is a Perun test channel. It handles the state of said channel
/// together with the participants, the current time and surrounding chain
/// context.
pub struct Channel<'a, S>
where
    S: perun::Applyable + Debug + PartialEq,
{
    /// The active party. Actions called on the channel will be issued by this
    /// party henceforth.
    active_part: test::Client,
    /// The id of the channel.
    id: test::ChannelId,
    /// The cell which represents this channel on-chain.
    channel_cell: Option<OutPoint>,
    /// The current state of this channel.
    channel_state: ChannelStatus,
    /// The cells locking funds for this channel.
    funding_cells: Vec<FundingCell>,
    /// The used Perun Channel Type Script.
    pcts: Script,
    /// All available parties.
    parts: HashMap<String, test::Client>,
    /// The surrounding chain context.
    ctx: Rc<Mutex<RefCell<Context>>>,
    /// The intial test harness environment supplying all Perun specific
    /// contracts and functionality for deployment etc.
    env: &'a harness::Env,
    /// The current channel time.
    current_time: u64,
    /// The validity of the next action.
    validity: ActionValidity,
    /// The history of actions performed on this channel.
    history: Vec<perun::Action<S>>,
    /// The currently tracked channel state as produced by the unit under test.
    current_state: S,
}

/// call_action! is a macro that calls the given action on the currently active
/// participant. It also sets the validity of the next action to `Valid`.
macro_rules! call_action {
    ($self:ident, $action:ident $(, $x:expr)*$(,)*) => (
        {
            println!("calling action {} on {}", stringify!($action), $self.active_part.name());
            let ctx = match $self.ctx.try_lock() {
                Ok(lock) => lock,
                Err(_) => panic!("Failed to acquire lock on context"),
            };
            let res = match $self.validity {
                ActionValidity::Valid => $self.active_part.$action(&mut ctx.borrow_mut(), $self.env, $($x),*),
                ActionValidity::Invalid => {
                    let res = $self.active_part.$action(&mut ctx.borrow_mut(), $self.env, $($x),*);
                    match res {
                        Ok(_) => Err(perun::Error::new("action should have failedaction should have failed")),
                        Err(_) => Ok(Default::default()),
                    }
                }
            };
            $self.validity = ActionValidity::Valid;
            res
        }
)
}

impl<'a, S> Channel<'a, S>
where
    S: Default + perun::Applyable + Debug + PartialEq,
{
    pub fn new(
        context: Rc<Mutex<RefCell<Context>>>,
        env: &'a perun::harness::Env,
        parts: &[perun::TestAccount],
    ) -> Self {
        let m_parts: HashMap<_, _> = parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                (
                    p.name().clone(),
                    perun::test::Client::new(i as u8, p.name(), p.sk.clone()),
                )
            })
            .collect();
        let active = m_parts.get(&parts[0].name()).expect("part not found");

        Channel {
            id: test::ChannelId::new(),
            current_time: 0,
            ctx: context,
            env,
            pcts: Script::default(),
            channel_cell: None,
            channel_state: ChannelStatus::default(),
            funding_cells: Vec::new(),
            active_part: active.clone(),
            parts: m_parts.clone(),
            validity: ActionValidity::Valid,
            history: Vec::new(),
            current_state: S::default(),
        }
    }

    /// with sets the currently active participant to the given `part`.
    pub fn with(&mut self, part: &str) -> &mut Self {
        self.active_part = self.parts.get(part).expect("part not found").clone();
        self
    }

    /// delay the environment by the given `duration`, this makes the next
    /// transaction receive a block_header with a timestamp that is `duration`
    /// in the future.
    pub fn delay(&mut self, duration: u64) {
        self.current_time += duration;
    }

    /// open a channel using the currently active participant set by `with(..)`
    /// with the value given in `funding_agreement`.
    pub fn open(&mut self, funding_agreement: &test::FundingAgreement) -> Result<(), perun::Error> {
        let (id, or) = call_action!(self, open, funding_agreement)?;
        self.id = id;
        self.channel_cell = Some(or.channel_cell.clone());
        // Make sure the channel cell is linked to a header with a timestamp.
        self.push_header_with_cell(or.channel_cell);
        let mut fs = self.funding_cells.clone();
        fs.extend(or.funds_cells.iter().cloned());
        self.funding_cells = fs.to_vec();
        self.pcts = or.pcts;
        self.channel_state = or.state;
        Ok(())
    }

    pub fn vc_start(&mut self, vc: &mut VirtualChannel) -> Result<(), perun::Error> {
        let vcts = vc.vcts();
        let vc_status = vc.vc_status();
        self.channel_state = self
            .channel_state
            .clone()
            .as_builder()
            .disputed(ctrue!())
            .vc_disputed(ctrue!())
            .vcts_hash(vcts.calc_script_hash())
            .build();
        let lc_sigs = self.sigs_for_channel_state()?;
        let vc_sigs = vc.sigs_for_vc_status()?;
        let parent_args = transaction::DisputeArgs {
            party_index: self.active_part.index,
            channel_cell: self.channel_cell.clone().expect("no channel cell"),
            state: self.channel_state.clone(),
            sigs: lc_sigs,
            pcts_script: self.pcts.clone(),
        };

        let result = call_action!(
            self,
            vc_start,
            parent_args,
            vc_status.clone(),
            vc_sigs.clone(),
            vcts.clone(),
        )?;
        self.push_header_with_cell(result.vc_cell.clone());
        vc.set_cell(result.vc_cell.clone());
        self.channel_cell = Some(result.parent_lc_cell.clone());
        self.push_header_with_cell(result.parent_lc_cell);
        self.push_header_with_cell(result.vc_cell);
        Ok(())
    }

    fn push_header_with_cell(&mut self, cell: OutPoint) {
        let header = Header::new_builder()
            .raw(
                RawHeader::new_builder()
                    .timestamp(self.current_time.pack())
                    .build(),
            )
            .build()
            .into_view();
        let ctx = match self.ctx.try_lock() {
            Ok(lock) => lock,
            Err(_) => panic!("Failed to acquire lock on context"),
        };
        ctx.borrow_mut().insert_header(header.clone());
        // We will always use 0 as the `tx_index`.
        ctx.borrow_mut()
            .link_cell_with_block(cell, header.hash(), 0);
        drop(ctx);
    }

    /// fund a channel using the currently active participant set by `with(..)`
    /// with the value given in `funding_agreement`.
    pub fn fund(&mut self, funding_agreement: &test::FundingAgreement) -> Result<(), perun::Error> {
        // TODO: Lift this check into the type-system to make this more readable and stick to DRY.
        let res = match &self.channel_cell {
            Some(channel_cell) => {
                call_action!(
                    self,
                    fund,
                    self.id,
                    funding_agreement,
                    channel_cell.clone(),
                    self.channel_state.clone(),
                    self.pcts.clone()
                )
            }
            None => panic!("no channel cell, invalid test setup"),
        }?;
        // TODO: DRY please.
        self.channel_state = res.state;
        self.channel_cell = Some(res.channel_cell.clone());
        self.push_header_with_cell(res.channel_cell);
        let mut fs = self.funding_cells.clone();
        fs.extend(res.funds_cells.iter().cloned());
        self.funding_cells = fs.to_vec();
        Ok(())
    }

    /// send a payment using the currently active participant set by `with(..)`
    /// to the given `to` participant.
    pub fn send<P: perun::Account>(&mut self, to: &P, amount: u64) -> Result<(), perun::Error> {
        let to = self.parts.get(&to.name()).expect("part not found");
        self.active_part.send(self.ctx.clone(), self.env)
    }

    /// dispute a channel using the currently active participant set by
    /// `with(..)`.
    pub fn dispute(&mut self) -> Result<(), perun::Error> {
        self.channel_state = self
            .channel_state
            .clone()
            .as_builder()
            .disputed(ctrue!())
            .build();
        let sigs = self.sigs_for_channel_state()?;
        let res = match &self.channel_cell {
            Some(channel_cell) => {
                call_action!(
                    self,
                    dispute,
                    self.id,
                    channel_cell.clone(),
                    self.channel_state.clone(),
                    self.pcts.clone(),
                    sigs,
                )
            }
            None => panic!("no channel cell, invalid test setup"),
        }?;
        self.channel_cell = Some(res.channel_cell.clone());
        self.push_header_with_cell(res.channel_cell);
        Ok(())
    }

    //register dispute for second lc parent without update on vc
    pub fn vc_progress_no_update(&mut self, vc: &mut VirtualChannel) -> Result<(), perun::Error> {
        let vcts = vc.vcts();
        let vc_status = vc.vc_status();
        self.channel_state = self
            .channel_state
            .clone()
            .as_builder()
            .disputed(ctrue!())
            .vc_disputed(ctrue!())
            .vcts_hash(vcts.calc_script_hash())
            .build();
        let lc_sigs = self.sigs_for_channel_state()?;
        let parent_args = transaction::DisputeArgs {
            party_index: self.active_part.index,
            channel_cell: self.channel_cell.clone().expect("no channel cell"),
            state: self.channel_state.clone(),
            sigs: lc_sigs,
            pcts_script: self.pcts.clone(),
        };

        let result = call_action!(
            self,
            vc_progress_no_update,
            parent_args,
            vc.cell().clone(),
            vc_status.clone(),
            vcts.clone(),
        )?;
        self.channel_cell = Some(result.parent_cell.clone());
        vc.set_cell(result.vc_cell.clone());
        self.push_header_with_cell(result.parent_cell);
        self.push_header_with_cell(result.vc_cell);
        Ok(())
    }

    pub fn vc_update_only(&mut self, vc: &mut VirtualChannel) -> Result<(), perun::Error> {
        let vcts = vc.vcts();
        let vc_status = vc.vc_status();
        let lc_sigs = self.sigs_for_channel_state()?;
        let vc_sigs = vc.sigs_for_vc_status()?;

        let parent_args = transaction::DisputeArgs {
            party_index: self.active_part.index,
            channel_cell: self.channel_cell.clone().expect("no channel cell"),
            state: self.channel_state.clone(),
            sigs: lc_sigs,
            pcts_script: self.pcts.clone(),
        };
        let result = call_action!(
            self,
            vc_update_only,
            parent_args,
            vc.cell().clone(),
            vc_status.clone(),
            vc_sigs.clone(),
            vcts.clone(),
        )?;
        self.channel_cell = Some(result.parent_cell.clone());
        vc.set_cell(result.vc_cell.clone());
        self.push_header_with_cell(result.parent_cell);
        self.push_header_with_cell(result.vc_cell);
        Ok(())
    }

    pub fn vc_lc_update(&mut self, vc: &mut VirtualChannel) -> Result<(), perun::Error> {
        let vcts = vc.vcts();
        let vc_status = vc.vc_status();
        let lc_sigs = self.sigs_for_channel_state()?;
        let vc_sigs = vc.sigs_for_vc_status()?;
        let parent_args = transaction::DisputeArgs {
            party_index: self.active_part.index,
            channel_cell: self.channel_cell.clone().expect("no channel cell"),
            state: self.channel_state.clone(),
            sigs: lc_sigs,
            pcts_script: self.pcts.clone(),
        };
        let result = call_action!(
            self,
            vc_lc_update,
            parent_args,
            vc.cell().clone(),
            vc_status.clone(),
            vc_sigs.clone(),
            vcts.clone(),
        )?;
        self.channel_cell = Some(result.parent_cell.clone());
        vc.set_cell(result.vc_cell.clone());
        self.push_header_with_cell(result.parent_cell);
        self.push_header_with_cell(result.vc_cell);
        Ok(())
    }

    pub fn vc_merge(
        &mut self,
        vc1: &VirtualChannel,
        vc2: &VirtualChannel,
        idx: u8,
    ) -> Result<OutPoint, perun::Error> {
        let result = call_action!(
            self,
            vc_merge,
            vc1.cell().clone(),
            vc2.cell().clone(),
            vc1.vc_status().clone(),
            vc2.vc_status().clone(),
            vc1.vcts().clone(),
            idx,
        )?;
        self.push_header_with_cell(result.final_vc_cell.clone());
        Ok(result.final_vc_cell)
    }

    /// abort a channel using the currently active participant set by
    /// `with(..)`.
    pub fn abort(&mut self) -> Result<(), perun::Error> {
        match &self.channel_cell {
            Some(channel_cell) => {
                call_action!(
                    self,
                    abort,
                    self.id,
                    self.channel_state.clone(),
                    channel_cell.clone(),
                    self.funding_cells.clone()
                )
            }
            None => panic!("no channel cell, invalid test setup"),
        }?;
        Ok(())
    }

    /// finalize finalizes the channel state in use. It has to be called for
    /// before successful close actions. It bumps the version of the channel state.
    pub fn finalize(&mut self) -> &mut Self {
        let status = self.channel_state.clone();
        let old_version: u64 = status.state().version().unpack();
        let state = status
            .state()
            .as_builder()
            .is_final(ctrue!())
            .version((old_version + 1).pack())
            .build();
        self.channel_state = status.as_builder().state(state).build();
        self
    }

    pub fn update(
        &mut self,
        update: impl Fn(&ChannelState) -> Result<ChannelState, perun::Error>,
    ) -> &mut Self {
        let new_state = update(&self.channel_state.state()).expect("update failed");
        self.channel_state = self
            .channel_state
            .clone()
            .as_builder()
            .state(new_state)
            .build();
        self
    }

    /// close a channel using the currently active participant set by
    /// `with(..)`.
    pub fn close(&mut self) -> Result<(), perun::Error> {
        let sigs = self.sigs_for_channel_state()?;
        match self.channel_cell.clone() {
            Some(channel_cell) => call_action!(
                self,
                close,
                self.id,
                channel_cell,
                self.funding_cells.clone(),
                self.channel_state.clone(),
                sigs
            ),
            None => panic!("no channel cell, invalid test setup"),
        }?;
        Ok(())
    }

    fn sigs_for_channel_state(&self) -> Result<[Vec<u8>; 2], perun::Error> {
        // We have to unpack the ChannelConstants like this. Otherwise the molecule header is still
        // part of the slice. On-chain we have no problem due to unpacking the arguments, but this
        // does not seem possible in this scope.
        let bytes = self.pcts.args().raw_data();
        // We want to have the correct order of clients in an array to construct signatures. For
        // consistency we use the ChannelConstants which are also used to construct the channel and
        // look up the participants according to their public key identifier.
        let s = ChannelConstants::from_slice(&bytes)?;
        let resolve_client = |verifying_key_raw: Vec<u8>| -> Result<Client, perun::Error> {
            let verifying_key = VerifyingKey::from_sec1_bytes(verifying_key_raw.as_slice())?;
            let pubkey = keys::verifying_key_to_byte_array(&verifying_key);
            self.parts
                .values()
                .cloned()
                .find(|c| c.pubkey() == pubkey)
                .ok_or("unknown participant in channel parameters".into())
        };
        let clients: Result<Vec<_>, _> = s
            .params()
            .mk_party_pubkeys()
            .iter()
            .cloned()
            .map(resolve_client)
            .collect();
        let sigs: Result<Vec<_>, _> = clients?
            .iter()
            .map(|p| p.sign(self.channel_state.state()))
            .collect();
        let sig_arr: [Vec<u8>; 2] = sigs?.try_into()?;
        Ok(sig_arr)
    }

    /// force_close a channel using the currently active participant set by
    /// `with(..)`.
    pub fn force_close(&mut self) -> Result<(), perun::Error> {
        let h = Header::new_builder()
            .raw(
                RawHeader::new_builder()
                    .timestamp(self.current_time.pack())
                    .build(),
            )
            .build()
            .into_view();
        // Push a header with the current time which can be used in force_close
        // as for time validation purposes.
        let ctx = self.ctx.lock().unwrap();
        ctx.borrow_mut().insert_header(h.clone());
        drop(ctx);
        match self.channel_cell.clone() {
            Some(channel_cell) => call_action!(
                self,
                force_close,
                self.id,
                channel_cell,
                self.funding_cells.clone(),
                self.channel_state.clone(),
            ),
            None => panic!("no channel cell, invalid test setup"),
        }?;
        Ok(())
    }

    pub fn vc_close1(
        &mut self,
        vc: &mut VirtualChannel,
        idx_map: &IdxMapWithDirection,
    ) -> Result<(), perun::Error> {
        let h = Header::new_builder()
            .raw(
                RawHeader::new_builder()
                    .timestamp(self.current_time.pack())
                    .build(),
            )
            .build()
            .into_view();
        let vc_status = vc
            .vc_status()
            .clone()
            .as_builder()
            .first_force_close(ctrue!())
            .build();
        // Push a header with the current time which can be used in force_close
        // as for time validation purposes.
        let ctx = match self.ctx.try_lock() {
            Ok(lock) => lock,
            Err(_) => panic!("Failed to acquire lock on context"),
        };
        ctx.borrow_mut().insert_header(h.clone());
        drop(ctx);
        let result = match &self.channel_cell {
            Some(channel_cell) => call_action!(
                self,
                vc_close1,
                self.id,
                channel_cell.clone(),
                self.funding_cells.clone(),
                self.channel_state.clone(),
                vc.cell().clone(),
                vc_status,
                idx_map.clone(),
                vc.vcts().clone(),
            ),
            None => panic!("no channel cell, invalid test setup"),
        }?;
        self.push_header_with_cell(result.output_vc_cell.clone());
        vc.set_cell(result.output_vc_cell.clone());
        Ok(())
    }

    pub fn vc_close2(
        &mut self,
        vc: &mut VirtualChannel,
        idx_map: &IdxMapWithDirection,
    ) -> Result<(), perun::Error> {
        let h = Header::new_builder()
            .raw(
                RawHeader::new_builder()
                    .timestamp(self.current_time.pack())
                    .build(),
            )
            .build()
            .into_view();
        // Push a header with the current time which can be used in force_close
        // as for time validation purposes.
        let ctx = match self.ctx.try_lock() {
            Ok(lock) => lock,
            Err(_) => panic!("Failed to acquire lock on context"),
        };
        ctx.borrow_mut().insert_header(h.clone());
        drop(ctx);
        match &self.channel_cell {
            Some(channel_cell) => call_action!(
                self,
                vc_close2,
                self.id,
                channel_cell.clone(),
                self.funding_cells.clone(),
                self.channel_state.clone(),
                vc.cell().clone(),
                vc.vc_status().clone(),
                idx_map.clone(),
                vc.vcts().clone(),
            ),
            None => panic!("no channel cell, invalid test setup"),
        }?;
        Ok(())
    }

    /// valid sets the validity of the next action to valid. (default)
    pub fn valid(&mut self) -> &mut Self {
        self.validity = ActionValidity::Valid;
        self
    }

    /// invalid sets the validity of the next action to invalid. It resets to
    /// valid after the next action.
    pub fn invalid(&mut self) -> &mut Self {
        self.validity = ActionValidity::Invalid;
        self
    }

    /// assert asserts that the channel is in a valid state according to all
    /// actions that have been performed on it. This also includes the
    /// surrounding context for this channel.
    ///
    /// If a channel was closed, it will also assert that all participants
    /// were properly paid.
    pub fn assert(&self) {
        let expected_state: S = self
            .history
            .iter()
            .fold(Default::default(), |acc, act| acc.apply(act));
        assert_eq!(expected_state, self.current_state)
    }

    pub fn channel_state(&self) -> &ChannelStatus {
        &self.channel_state
    }

    pub fn pcts(&self) -> &Script {
        &self.pcts
    }
}
