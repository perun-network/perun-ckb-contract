use ckb_testtool::context::Context;

use crate::perun;
use crate::perun::{harness, test};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::fmt::Debug;

enum ActionValidity {
    Valid,
    Invalid,
}

/// Channel is a Perun test channel. It handles the state of said channel
/// together with the participants, the current time and surrounding chain
/// context.
pub struct Channel<'a, P, S>
where
    S: perun::Applyable + Debug + PartialEq,
{
    /// The active party. Actions called on the channel will be issued by this
    /// party henceforth.
    active_part: &'a test::Client,
    /// The id of the channel.
    id: test::ChannelId,
    /// All available parties.
    parts: HashMap<P, &'a test::Client>,
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
    ($self:ident, $action:ident $(, $x:expr)*) => (
        {
            let res = match $self.validity {
                ActionValidity::Valid => $self.active_part.$action($self.id, $self.ctx, $self.env, $($x),*),
                ActionValidity::Invalid => {
                    let res = $self.active_part.$action($self.id, $self.ctx, $self.env, $($x),*);
                    match res {
                        Ok(_) => Err(perun::Error::new("action should have failed")),
                        Err(_) => Ok(()),
                    }
                }
            };
            $self.validity = ActionValidity::Valid;
            res
        }
)
}

impl<'a, P, S> Channel<'a, P, S>
where
    P: Eq + std::hash::Hash,
    S: Default + perun::Applyable + Debug + PartialEq,
{
    /// with sets the currently active participant to the given `part`.
    pub fn with(&mut self, part: P) -> &mut Self {
        self.active_part = self.parts.get(&part).expect("part not found");
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
        call_action!(self, open, funding_agreement)
    }

    /// fund a channel using the currently active participant set by `with(..)`
    /// with the value given in `funding_agreement`.
    pub fn fund(&mut self, funding_agreement: &test::FundingAgreement) -> Result<(), perun::Error> {
        call_action!(self, fund, funding_agreement)
    }

    /// send a payment using the currently active participant set by `with(..)`
    /// to the given `to` participant.
    pub fn send(&mut self, to: &P, amount: u64) -> Result<(), perun::Error> {
        let to = self.parts.get(to).expect("part not found");
        self.active_part.send(self.ctx, self.env)
    }

    /// dispute a channel using the currently active participant set by
    /// `with(..)`.
    pub fn dispute(&mut self) -> Result<(), perun::Error> {
        call_action!(self, dispute)
    }

    /// abort a channel using the currently active participant set by
    /// `with(..)`.
    pub fn abort(&mut self) -> Result<(), perun::Error> {
        call_action!(self, abort)
    }

    /// close a channel using the currently active participant set by
    /// `with(..)`.
    pub fn close(&mut self) -> Result<(), perun::Error> {
        call_action!(self, close)
    }

    /// force_close a channel using the currently active participant set by
    /// `with(..)`.
    pub fn force_close(&mut self) -> Result<(), perun::Error> {
        call_action!(self, force_close)
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
