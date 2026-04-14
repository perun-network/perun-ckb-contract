use crate::perun;
use ckb_testtool::ckb_types::prelude::{Pack, Unpack};
use molecule::prelude::{Builder, Entity};
use perun_common::perun_types::{Allocation, AnyBalances, AnyBalancesUnion, CKByteDistribution, ChannelState, ETHDistribution, SUDTDistribution};

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
    |s| {
        Ok(s.clone()
            .as_builder()
            .version((Unpack::<u64>::unpack(&s.version()) + 1u64).pack())
            .build())
    }
}

/// pay_ckbytes returns a mutator that transfers the given amount of CKBytes from one party to the other according to the
/// specified direction. It also bumps the version number of the channel state.
pub fn pay_ckbytes(
    direction: Direction,
    amount: u64,
) -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    let (sender_index, receiver_index) = get_indices(direction);
    move |s| {
        let s_bumped = bump_version()(s)?;
        let mut dist = s_bumped.balances().ckbytes().to_array();
        if dist[sender_index] < amount {
            return Err(perun::Error::new("insufficient funds"));
        }
        dist[sender_index] -= amount;
        dist[receiver_index] += amount;

        let new_ckb = CKByteDistribution::from_array(dist);
        let new_balances = s_bumped.balances().with_ckbytes(new_ckb);

        Ok(s_bumped.clone().as_builder().balances(new_balances).build())
    }
}

/// pay_sudt returns a mutator that transfers the given amount of the specified SUDT index from one party to the other according to the
/// specified direction. It also bumps the version number of the channel state.
pub fn pay_sudt(
    direction: Direction,
    amount: u128,
    asset_index: usize,
) -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    let (sender_index, receiver_index) = get_indices(direction);
    move |s| {
        let s_bumped = bump_version()(s)?;
        let sudts = s_bumped.balances().sudts();
        if asset_index >= sudts.len() {
            return Err(perun::Error::new("asset index out of bounds"));
        }
        let sudt = sudts.get(asset_index).expect("checked len above");

        let mut d = sudt.distribution().to_array();
        if d[sender_index] < amount {
            return Err(perun::Error::new("insufficient funds"));
        }
        d[sender_index] -= amount;
        d[receiver_index] += amount;
        let updated_sudt = sudt
            .clone()
            .as_builder()
            .distribution(SUDTDistribution::from_array(d))
            .build();

        let mut sudts_builder = sudts.clone().as_builder();
        sudts_builder.replace(asset_index, updated_sudt)
            .expect("valid asset_index");
        let new_sudts = sudts_builder.build();

        let new_balances = s_bumped.balances().with_sudts(new_sudts);

        Ok(s_bumped.clone().as_builder().balances(new_balances).build())
    }
}

/// pay_eth returns a mutator that transfers the given amount of ETH for the specified
/// asset index from one party to the other. It also bumps the version number.
pub fn pay_eth(
    direction: Direction,
    amount: u128,
    asset_index: usize,
) -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    let (sender_index, receiver_index) = get_indices(direction);
    move |s| {
        let s_bumped = bump_version()(s)?;
        let balances = s_bumped.balances();
        let eth_rows: Vec<_> = balances.assets().into_iter()
            .filter(|r| r.is_eth_row())
            .collect();
        if asset_index >= eth_rows.len() {
            return Err(perun::Error::new("eth asset index out of bounds"));
        }
        let eth = eth_rows[asset_index].as_eth().expect("is_eth_row");
        let mut d = eth.distribution().to_array();
        if d[sender_index] < amount {
            return Err(perun::Error::new("insufficient eth funds"));
        }
        d[sender_index] -= amount;
        d[receiver_index] += amount;
        let updated_eth = eth
            .clone()
            .as_builder()
            .distribution(ETHDistribution::from_array(d))
            .build();

        // Rebuild assets, replacing the matching eth row
        let mut new_rows = Vec::new();
        let mut eth_idx = 0usize;
        for row in balances.assets().into_iter() {
            if row.is_eth_row() {
                if eth_idx == asset_index {
                    new_rows.push(
                        row.clone()
                            .as_builder()
                            .set(AnyBalancesUnion::ETHBalances(updated_eth.clone()))
                            .build(),
                    );
                } else {
                    new_rows.push(row);
                }
                eth_idx += 1;
            } else {
                new_rows.push(row);
            }
        }
        let new_balances = s_bumped
            .balances()
            .clone()
            .as_builder()
            .assets(Allocation::new_builder().set(new_rows).build())
            .locked(s_bumped.balances().locked())
            .build();
        Ok(s_bumped.clone().as_builder().balances(new_balances).build())
    }
}

/// inflate_ckbytes returns a mutator that adds the given amount to one party's CKBytes
/// WITHOUT removing it from the other. This creates an invalid state (sum changed).
pub fn inflate_ckbytes(
    party_index: usize,
    amount: u64,
) -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    move |s| {
        let s_bumped = bump_version()(s)?;
        let mut dist = s_bumped.balances().ckbytes().to_array();
        dist[party_index] += amount;
        let new_ckb = CKByteDistribution::from_array(dist);
        let new_balances = s_bumped.balances().with_ckbytes(new_ckb);
        Ok(s_bumped.clone().as_builder().balances(new_balances).build())
    }
}

/// regress_version returns a mutator that sets the version to a specific value.
pub fn set_version(
    version: u64,
) -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    move |s| {
        Ok(s.clone()
            .as_builder()
            .version(version.pack())
            .build())
    }
}

/// get_indices returns (sender_index, receiver_index)
fn get_indices(direction: Direction) -> (usize, usize) {
    match direction {
        Direction::AtoB => (0, 1),
        Direction::BtoA => (1, 0),
    }
}
