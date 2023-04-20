use blake2b_rs::Blake2bBuilder;

#[cfg(feature = "std")]
use {ckb_occupied_capacity::Capacity, ckb_types::packed::*, ckb_types::prelude::*, std::vec::Vec};

#[cfg(not(feature = "std"))]
use {
    ckb_standalone_types::packed::*,
    ckb_standalone_types::prelude::*,
    molecule::prelude::{vec, Vec},
};

use crate::error::Error;
use crate::perun_types::{
    Balances, Bool, BoolUnion, ChannelParameters, ChannelState, ChannelStatus, ParticipantIndex,
    ParticipantIndexUnion, SEC1EncodedPubKey,
};

impl Bool {
    pub fn to_bool(&self) -> bool {
        match self.to_enum() {
            BoolUnion::True(_) => true,
            BoolUnion::False(_) => false,
        }
    }
    pub fn from_bool(b: bool) -> Self {
        if b {
            return ctrue!();
        } else {
            return cfalse!();
        }
    }
}

#[macro_export]
macro_rules! ctrue {
    () => {
        $crate::perun_types::BoolBuilder::default()
            .set($crate::perun_types::BoolUnion::True(
                $crate::perun_types::True::default(),
            ))
            .build()
    };
}
pub(crate) use ctrue;

#[macro_export]
macro_rules! cfalse {
    () => {
        $crate::perun_types::BoolBuilder::default()
            .set($crate::perun_types::BoolUnion::False(
                $crate::perun_types::False::default(),
            ))
            .build()
    };
}
pub(crate) use cfalse;

#[macro_export]
macro_rules! redeemer {
    ($name:ident) => {
        $crate::perun_types::ChannelWitnessBuilder::default()
            .set($crate::perun_types::ChannelWitnessUnion::$name(
                Default::default(),
            ))
            .build()
    };
    ($x:expr) => {
        $crate::perun_types::ChannelWitnessBuilder::default()
            .set($x)
            .build()
    };
}
pub(crate) use redeemer;

#[macro_export]
macro_rules! fund {
    ($index:expr) => {
        $crate::perun_types::ChannelWitnessUnion::Fund(
            $crate::perun_types::Fund::new_builder()
                .index($crate::perun_types::ParticipantIndex::from($index))
                .build(),
        )
    };
}
pub(crate) use fund;

#[macro_export]
macro_rules! close {
    ($state:expr, $siga:expr, $sigb:expr) => {
        $crate::perun_types::ChannelWitnessUnion::Close(
            $crate::perun_types::Close::new_builder()
                .state($state)
                .sig_a($siga)
                .sig_b($sigb)
                .build(),
        )
    };
}
pub(crate) use close;

#[macro_export]
macro_rules! dispute {
    ($siga:expr, $sigb:expr) => {
        $crate::perun_types::ChannelWitnessUnion::Dispute(
            $crate::perun_types::Dispute::new_builder()
                .sig_a($siga)
                .sig_b($sigb)
                .build(),
        )
    };
}
pub(crate) use dispute;

impl ParticipantIndex {
    pub fn to_idx(&self) -> usize {
        match self.to_enum() {
            ParticipantIndexUnion::A(_) => 0,
            ParticipantIndexUnion::B(_) => 1,
        }
    }
    pub fn idx_of_peer(&self) -> usize {
        match self.to_enum() {
            ParticipantIndexUnion::A(_) => 1,
            ParticipantIndexUnion::B(_) => 0,
        }
    }
}

impl From<u8> for ParticipantIndex {
    fn from(idx: u8) -> Self {
        match idx {
            0 => ParticipantIndex::new_builder()
                .set(ParticipantIndexUnion::A(Default::default()))
                .build(),
            1 => ParticipantIndex::new_builder()
                .set(ParticipantIndexUnion::B(Default::default()))
                .build(),
            _ => panic!("Invalid participant index"),
        }
    }
}

impl Balances {
    pub fn sum(&self) -> u64 {
        let a: u64 = self.nth0().unpack();
        let b: u64 = self.nth1().unpack();
        a + b
    }

    pub fn equal(&self, other: &Balances) -> bool {
        self.as_slice()[..] == other.as_slice()[..]
    }

    pub fn get(&self, i: usize) -> Result<u64, Error> {
        match i {
            0 => Ok(self.nth0().unpack()),
            1 => Ok(self.nth1().unpack()),
            _ => Err(Error::IndexOutOfBound),
        }
    }
}

pub fn geq_components(fst: &Balances, snd: &Balances) -> bool {
    let a_fst: u64 = fst.nth0().unpack();
    let a_snd: u64 = snd.nth0().unpack();
    let b_fst: u64 = fst.nth1().unpack();
    let b_snd: u64 = snd.nth1().unpack();
    a_fst >= a_snd && b_fst >= b_snd
}

pub fn is_matching_output(
    output: &CellOutput,
    own_lock_script: &Script,
    own_type_script: &Script,
) -> bool {
    let out_lock = output.lock();
    let out_type = output.type_().to_opt();
    if own_lock_script.as_slice()[..] != out_lock.as_slice()[..] {
        return false;
    }
    if out_type.is_none() {
        return false;
    }
    // This automatically checks the immutablity of the ChannelConstants in the args of the PCTS.
    own_type_script.as_slice()[..] == out_type.unwrap().as_slice()[..]
}

pub const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut blake2b = Blake2bBuilder::new(32)
        //.personal(CKB_HASH_PERSONALIZATION)
        .build();
    blake2b.update(data);
    blake2b.finalize(&mut result);
    result
}

impl ChannelStatus {
    /// set_funded sets the ChannelStatus to funded and fills the balances with the given amount.
    /// NOTE: This function expects the given amount to be for the last index!
    pub fn mk_funded(self, amount: u64) -> ChannelStatus {
        let funding = self.funding().as_builder().nth1(amount.pack()).build();
        self.clone()
            .as_builder()
            .funding(funding)
            .funded(ctrue!())
            .build()
    }

    #[cfg(feature = "std")]
    /// mk_close_outputs creates the outputs for a close transaction according to the current
    /// channel state. It does not matter whether the ChannelState in question is finalized or not.
    pub fn mk_close_outputs(self, mk_lock_script: impl FnMut(u8) -> Script) -> Vec<CellOutput> {
        self.state().mk_close_outputs(mk_lock_script)
    }
}

#[cfg(feature = "std")]
impl ChannelState {
    pub fn mk_close_outputs(self, mk_lock_script: impl FnMut(u8) -> Script) -> Vec<CellOutput> {
        self.balances().mk_close_outputs(mk_lock_script)
    }
}

#[cfg(feature = "std")]
impl Balances {
    pub fn mk_close_outputs(self, mut mk_lock_script: impl FnMut(u8) -> Script) -> Vec<CellOutput> {
        let a = Capacity::shannons(self.nth0().unpack());
        let b = Capacity::shannons(self.nth1().unpack());
        // TODO: Outputs should contain min-capacity for script size...
        vec![
            CellOutput::new_builder()
                .capacity(a.pack())
                .lock(mk_lock_script(0))
                .build(),
            CellOutput::new_builder()
                .capacity(b.pack())
                .lock(mk_lock_script(1))
                .build(),
        ]
    }
}

impl ChannelParameters {
    /// mk_party_pubkeys creates a vector of each participants public key in the correct order.
    pub fn mk_party_pubkeys(self) -> Vec<Vec<u8>> {
        vec![
            self.party_a().pub_key().to_vec(),
            self.party_b().pub_key().to_vec(),
        ]
    }
}

impl SEC1EncodedPubKey {
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}
