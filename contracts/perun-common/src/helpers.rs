use blake2b_rs::Blake2bBuilder;

#[cfg(feature = "std")]
use {ckb_types::packed::*, ckb_types::prelude::*};

#[cfg(not(feature = "std"))]
use {ckb_standalone_types::packed::*, ckb_standalone_types::prelude::*};

use crate::error::Error;
use crate::perun_types::{Balances, Bool, BoolUnion, ParticipantIndex, ParticipantIndexUnion};

impl Bool {
    pub fn to_bool(&self) -> bool {
        match self.to_enum() {
            BoolUnion::True(_) => true,
            BoolUnion::False(_) => false,
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

impl Balances {
    pub fn sum(&self) -> u128 {
        let a = self.nth0().unpack();
        let b = self.nth1().unpack();
        a + b
    }

    pub fn equal(&self, other: &Balances) -> bool {
        self.as_slice()[..] == other.as_slice()[..]
    }

    pub fn get(&self, i: usize) -> Result<u128, Error> {
        match i {
            0 => Ok(self.nth0().unpack()),
            1 => Ok(self.nth1().unpack()),
            _ => Err(Error::IndexOutOfBound),
        }
    }
}

pub fn geq_components(fst: &Balances, snd: &Balances) -> bool {
    let a_fst = fst.nth0().unpack();
    let a_snd = snd.nth0().unpack();
    let b_fst = fst.nth1().unpack();
    let b_snd = snd.nth1().unpack();
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
        .personal(CKB_HASH_PERSONALIZATION)
        .build();
    blake2b.update(data);
    blake2b.finalize(&mut result);
    result
}
