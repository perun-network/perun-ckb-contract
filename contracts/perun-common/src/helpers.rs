use blake2b_rs::Blake2bBuilder;

#[cfg(feature = "std")]
use {
    crate::perun_types::ChannelState, ckb_types::bytes, ckb_types::packed::*,
    ckb_types::prelude::*, std::vec::Vec,
};

#[cfg(not(feature = "std"))]
use {
    ckb_standalone_types::packed::*,
    ckb_standalone_types::prelude::*,
    molecule::prelude::{vec, Vec},
};

use crate::perun_types::{
    Balances, Bool, BoolUnion, ChannelParameters, ChannelStatus, SEC1EncodedPubKey,
};
use crate::{
    error::Error,
    perun_types::{CKByteDistribution, SUDTAllocation, SUDTBalances, SUDTDistribution},
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

#[macro_export]
macro_rules! fund {
    () => {
        $crate::perun_types::ChannelWitnessUnion::Fund($crate::perun_types::Fund::default())
    };
}

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

impl SUDTDistribution {
    pub fn sum(&self) -> u128 {
        let a: u128 = self.nth0().unpack();
        let b: u128 = self.nth1().unpack();
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

    pub fn clear_index(&self, idx: usize) -> Result<SUDTDistribution, Error> {
        match idx {
            0 => Ok(self.clone().as_builder().nth0(0u128.pack()).build()),
            1 => Ok(self.clone().as_builder().nth1(0u128.pack()).build()),
            _ => Err(Error::IndexOutOfBound),
        }
    }

    pub fn from_array(a: [u128; 2]) -> Self {
        SUDTDistribution::new_builder()
            .nth0(a[0].pack())
            .nth1(a[1].pack())
            .build()
    }

    pub fn to_array(&self) -> [u128; 2] {
        [self.nth0().unpack(), self.nth1().unpack()]
    }
}

impl Balances {
    pub fn clear_index(&self, idx: usize) -> Result<Balances, Error> {
        let ckbytes = self.ckbytes().clear_index(idx)?;
        let mut sudts: Vec<SUDTBalances> = Vec::new();
        for sb in self.sudts().into_iter() {
            sudts.push(
                sb.clone()
                    .as_builder()
                    .distribution(sb.distribution().clear_index(idx)?)
                    .build(),
            );
        }
        Ok(self
            .clone()
            .as_builder()
            .ckbytes(ckbytes)
            .sudts(SUDTAllocation::new_builder().set(sudts).build())
            .build())
    }

    pub fn zero_at_index(&self, idx: usize) -> Result<bool, Error> {
        if self.ckbytes().get(idx)? != 0u64 {
            return Ok(false);
        }
        for sb in self.sudts().into_iter() {
            if sb.distribution().get(idx)? != 0u128 {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    pub fn equal_at_index(&self, other: &Balances, idx: usize) -> Result<bool, Error> {
        if self.ckbytes().get(idx)? != other.ckbytes().get(idx)? {
            return Ok(false);
        }
        if self.sudts().len() != other.sudts().len() {
            return Ok(false);
        }
        for (i, sb) in self.sudts().into_iter().enumerate() {
            let other_sb = other.sudts().get(i).ok_or(Error::IndexOutOfBound)?;
            if sb.asset().as_slice() != other_sb.as_slice() {
                return Ok(false);
            }
            if sb.distribution().get(idx)? != other_sb.distribution().get(idx)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    pub fn equal_in_sum(&self, other: &Balances) -> Result<bool, Error> {
        if self.ckbytes().sum() != other.ckbytes().sum() {
            return Ok(false);
        }
        if self.sudts().len() != other.sudts().len() {
            return Ok(false);
        }
        for (i, sb) in self.sudts().into_iter().enumerate() {
            let other_sb = other.sudts().get(i).ok_or(Error::IndexOutOfBound)?;
            if sb.asset().as_slice() != other_sb.asset().as_slice() {
                return Ok(false);
            }
            if sb.distribution().sum() != other_sb.distribution().sum() {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    pub fn equal(&self, other: &Balances) -> bool {
        self.as_slice()[..] == other.as_slice()[..]
    }
}

impl SUDTAllocation {
    pub fn get_locked_ckbytes(&self) -> u64 {
        let mut sum: u64 = 0u64;
        for sudt in self.clone().into_iter() {
            let min_cap: u64 = sudt.asset().max_capacity().unpack();
            sum += min_cap;
        }
        return sum;
    }

    pub fn get_distribution(&self, sudt: &Script) -> Result<(usize, SUDTDistribution), Error> {
        for (i, sb) in self.clone().into_iter().enumerate() {
            if sb.asset().type_script().as_slice() == sudt.as_slice() {
                return Ok((i, sb.distribution()));
            }
        }
        return Err(Error::InvalidSUDT);
    }

    pub fn fully_represented(&self, idx: usize, values: &[u128]) -> Result<bool, Error> {
        if values.len() < self.len() {
            return Ok(false);
        }
        for (i, sb) in self.clone().into_iter().enumerate() {
            let v = sb.distribution().get(idx)?;
            if values[i] < v {
                return Ok(false);
            }
        }
        return Ok(true);
    }
}

impl CKByteDistribution {
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

    pub fn clear_index(&self, idx: usize) -> Result<CKByteDistribution, Error> {
        match idx {
            0 => Ok(self.clone().as_builder().nth0(0u64.pack()).build()),
            1 => Ok(self.clone().as_builder().nth1(0u64.pack()).build()),
            _ => Err(Error::IndexOutOfBound),
        }
    }

    pub fn from_array(array: [u64; 2]) -> Self {
        CKByteDistribution::new_builder()
            .nth0(array[0].pack())
            .nth1(array[1].pack())
            .build()
    }

    pub fn to_array(&self) -> [u64; 2] {
        [self.nth0().unpack(), self.nth1().unpack()]
    }
}

pub fn geq_components(fst: &CKByteDistribution, snd: &CKByteDistribution) -> bool {
    let a_fst: u64 = fst.nth0().unpack();
    let a_snd: u64 = snd.nth0().unpack();
    let b_fst: u64 = fst.nth1().unpack();
    let b_snd: u64 = snd.nth1().unpack();
    a_fst >= a_snd && b_fst >= b_snd
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
    // mk_funded creates a new ChannelStatus with the funded flag set to true.
    pub fn mk_funded(self) -> ChannelStatus {
        self.clone().as_builder().funded(ctrue!()).build()
    }

    #[cfg(feature = "std")]
    /// mk_close_outputs creates the outputs for a close transaction according to the current
    /// channel state. It does not matter whether the ChannelState in question is finalized or not.
    pub fn mk_close_outputs(
        self,
        mk_lock_script: impl FnMut(u8) -> Script,
    ) -> Vec<(CellOutput, bytes::Bytes)> {
        self.state().mk_outputs(mk_lock_script)
    }
}

#[cfg(feature = "std")]
impl ChannelState {
    pub fn mk_outputs(
        self,
        mk_lock_script: impl FnMut(u8) -> Script,
    ) -> Vec<(CellOutput, bytes::Bytes)> {
        return self.balances().mk_outputs(mk_lock_script, vec![0, 1]);
    }
}

#[cfg(feature = "std")]
impl Balances {
    pub fn mk_outputs(
        self,
        mut mk_lock_script: impl FnMut(u8) -> Script,
        indices: Vec<u8>,
    ) -> Vec<(CellOutput, bytes::Bytes)> {
        let mut ckbytes = self
            .ckbytes()
            .mk_outputs(&mut mk_lock_script, indices.clone());
        let mut sudts = self.sudts().mk_outputs(mk_lock_script, indices);
        ckbytes.append(&mut sudts);
        return ckbytes;
    }
}

#[cfg(feature = "std")]
impl CKByteDistribution {
    pub fn mk_outputs(
        self,
        mut mk_lock_script: impl FnMut(u8) -> Script,
        indices: Vec<u8>,
    ) -> Vec<(CellOutput, bytes::Bytes)> {
        // TODO: Outputs should contain min-capacity for script size...
        indices
            .iter()
            .fold(vec![], |mut acc: Vec<(CellOutput, bytes::Bytes)>, index| {
                let cap = self.get(index.clone() as usize).expect("invalid index");
                acc.push((
                    CellOutput::new_builder()
                        .capacity(cap.pack())
                        .lock(mk_lock_script(*index))
                        .build(),
                    bytes::Bytes::new(),
                ));
                acc
            })
    }
}

#[cfg(feature = "std")]
impl SUDTAllocation {
    pub fn mk_outputs(
        self,
        mut mk_lock_script: impl FnMut(u8) -> Script,
        indices: Vec<u8>,
    ) -> Vec<(CellOutput, bytes::Bytes)> {
        let mut outputs: Vec<(CellOutput, bytes::Bytes)> = Vec::new();
        for (i, balance) in self.into_iter().enumerate() {
            let udt_type = balance.asset().type_script();
            let udt_type_opt = ScriptOpt::new_builder().set(Some(udt_type)).build();
            let cap: u64 = balance.asset().max_capacity().unpack();
            for f in indices.iter() {
                if balance
                    .distribution()
                    .get(*f as usize)
                    .expect("invalid index")
                    == 0u128
                {
                    outputs.push((
                        CellOutput::new_builder()
                            .capacity(cap.pack())
                            .lock(mk_lock_script(*f))
                            .build(),
                        bytes::Bytes::new(),
                    ));
                } else {
                    outputs.push((
                        CellOutput::new_builder()
                            .capacity(cap.pack())
                            .lock(mk_lock_script(*f))
                            .type_(udt_type_opt.clone())
                            .build(),
                        bytes::Bytes::from(
                            balance
                                .distribution()
                                .get(*f as usize)
                                .expect("invalid index")
                                .to_le_bytes()
                                .to_vec(),
                        ),
                    ));
                }
            }
        }
        return outputs;
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
