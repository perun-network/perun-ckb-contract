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
    perun_types::{ChannelConstants, VirtualChannelStatus, ChannelState},
};

use crate::perun::{
    self,
    test::{keys, Client},
};
use crate::perun::{harness, test};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::fmt::Debug;

use super::{test::cell::FundingCell, Account};

enum ActionValidity {
    Valid,
    Invalid,
}

/// VirtualChannel is a Perun test virtual channel. It handles the state of said channel
/// together with the participants, the current time and surrounding chain
/// context.
pub struct VirtualChannel<'a, S>
where
    S: perun::Applyable + Debug + PartialEq,
{
    /// The active party. Actions called on the channel will be issued by this
    /// party henceforth.
    active_part: test::Client,
    /// The id of the channel.
    id: test::ChannelId,
    /// The cell which represents this channel on-chain.
    virtual_channel_cell: Option<OutPoint>,
    /// The current state of this channel.
    virtual_channel_state: VirtualChannelStatus,
    /// The parents for this channel.
    parent_channels: [perun::channel::Channel<'a,perun::State>; 2],
    /// The used Perun Channel Type Script.
    vcts: Script,
    /// All available parties.
    parts: HashMap<String, test::Client>,
    /// The surrounding chain context.
    ctx: &'a mut Context,
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
            let res = match $self.validity {
                ActionValidity::Valid => $self.active_part.$action($self.ctx, $self.env, $($x),*),
                ActionValidity::Invalid => {
                    let res = $self.active_part.$action($self.ctx, $self.env, $($x),*);
                    match res {
                        Ok(_) => Err(perun::Error::new("action should have failed")),
                        Err(_) => Ok(Default::default()),
                    }
                }
            };
            $self.validity = ActionValidity::Valid;
            res
        }
)
}

impl<'a, S> VirtualChannel<'a, S>
where
    S: Default + perun::Applyable + Debug + PartialEq,
{
    pub fn new(
        context: &'a mut Context,
        env: &'a perun::harness::Env,
        parts: &[perun::TestAccount],
        parents: &[perun::channel::Channel<perun::State>; 2],
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

        VirtualChannel {
            id: test::ChannelId::new(),
            current_time: 0,
            ctx: context,
            env,
            vcts: Script::default(),
            virtual_channel_cell: None,
            virtual_channel_state: VirtualChannelStatus::default(),
            parent_channels: *parents,
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

    /// open a virtual channel using the currently active participant set by `with(..)`
    /// with the value given in `funding_agreement`.
    pub fn open(&mut self, funding_agreement: &test::FundingAgreement) -> Result<(), perun::Error> {
        let parents_status = self.parent_channels.iter().map(|p| p.channel_state()).collect();
        let parents_pcts = self.parent_channels.iter().map(|p| p.pcts().code_hash()).collect();

        let (id, vcs, locked) = call_action!(self, open_vc, funding_agreement, parents_status, parents_pcts)?;

        self.parent_channels.iter().for_each(|p| p.update_virtual_channel(locked));

        self.id = id;
        self.virtual_channel_state = vcs;
        Ok(())
    } 

    /// finalize finalizes the channel state in use. It has to be called for
    /// before successful close actions. It bumps the version of the channel state.
    pub fn finalize(&mut self) -> &mut Self {
        let status = self.virtual_channel_state.clone();
        let old_version: u64 = status.state().version().unpack();
        let state = status.state().as_builder().is_final(ctrue!()).version((old_version + 1).pack()).build();
        self.virtual_channel_state = status.as_builder().state(state).build();
        self
    }

    /// close a channel using the currently active participant set by
    /// `with(..)`.
    pub fn close(&mut self) -> Result<(), perun::Error> {
        let sigs = self.sigs_for_channel_state()?;
        match self.virtual_channel_cell.clone() {
            Some(channel_cell) => call_action!(
                self,
                close_vc,
                self.id,
                self.virtual_channel_state.clone(),
                sigs
            ),
            None => panic!("no channel cell, invalid test setup"),
        }?;
        let locked = self.get_locked_balances()?;
        self.parent_channels.iter().for_each(|p| p.update_virtual_channel(locked));
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
        self.ctx.insert_header(header.clone());
        // We will always use 0 as the `tx_index`.
        self.ctx.link_cell_with_block(cell, header.hash(), 0);
    }

    fn get_locked_balances(&self) -> Result<perun::LockedBalances, perun::Error> {
        let channel_cell = self.virtual_channel_cell.clone().expect("no channel cell");
        let cell = self.ctx.get_cell(&channel_cell).expect("cell not found");
        let data = cell.data().expect("cell data not found");
        perun::LockedBalances::from_slice(&data.raw_data()).map_err(|_| perun::Error::new("could not parse locked balances"))
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
}
