use crate::perun;
use ckb_testtool::ckb_types::prelude::{Unpack, Pack};
use molecule::prelude::{Entity, Builder};
use perun_common::perun_types::{ChannelState, CKByteDistribution, SUDTDistribution};

pub enum Direction {
    AtoB,
    BtoA,
}

/// id returns a mutator that does not change the channel state.
pub fn id() -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    |s| Ok(s.clone())
}

/// bump_version returns a mutator that bumps the version number of the channel state.
pub fn bump_version() -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    |s| Ok(s.clone().as_builder().version((Unpack::<u64>::unpack(&s.version()) + 1u64).pack()).build())
}

/// pay_ckbytes returns a mutator that transfers the given amount of CKBytes from one party to the other according to the
/// specified direction. It also bumps the version number of the channel state.
pub fn pay_ckbytes(direction: Direction, amount: u64) -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    let (sender_index, receiver_index) = get_indices(direction);
    move |s| {
        let s_bumped = bump_version()(s)?;
        let mut distribution = s_bumped.balances().ckbytes().to_array();
        if distribution[sender_index] < amount {
            return Err(perun::Error::new("insufficient funds"));
        }
        distribution[sender_index] -= amount;
        distribution[receiver_index] += amount;
        let balances = s_bumped.balances().clone().as_builder().ckbytes(CKByteDistribution::from_array(distribution)).build();
        Ok(s_bumped.clone().as_builder().balances(balances).build())
    }
}

/// pay_sudt returns a mutator that transfers the given amount of the specified SUDT index from one party to the other according to the
/// specified direction. It also bumps the version number of the channel state.
pub fn pay_sudt(direction:Direction, amount: u128, asset_index: usize)-> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    let (sender_index, receiver_index) = get_indices(direction);
    move |s| {
        let s_bumped = bump_version()(s)?;
        let sudts = s_bumped.balances().sudts().clone();
        if asset_index >= sudts.len() {
            return Err(perun::Error::new("asset index out of bounds"));
        }
        let sudt = sudts.get(asset_index).unwrap();
        let mut distribution = sudt.distribution().to_array();
        if distribution[sender_index] < amount {
            return Err(perun::Error::new("insufficient funds"));
        }
        distribution[sender_index] -= amount;
        distribution[receiver_index] += amount;
        let packed_sudt = sudt.clone().as_builder().distribution(SUDTDistribution::from_array(distribution)).build();
        let mut new_sudts = sudts.clone().as_builder();
        new_sudts.replace(asset_index, packed_sudt).unwrap();
        let balances = s_bumped.balances().clone().as_builder().sudts(new_sudts.build()).build();
        Ok(s_bumped.clone().as_builder().balances(balances).build())
    }
}

/// get_indices returns (sender_index, receiver_index)
fn get_indices(direction: Direction) -> (usize, usize) {
    match direction {
        Direction::AtoB => (0, 1),
        Direction::BtoA => (1, 0),
    }
}