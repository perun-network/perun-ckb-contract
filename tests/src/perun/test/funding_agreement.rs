use ckb_occupied_capacity::Capacity;
use ckb_testtool::ckb_types::packed::{Byte as PackedByte, Script};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;
use ckb_types::bytes::Bytes;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;

use perun_common::perun_types::{
    self, Allocation, AnyBalances, AnyBalancesUnion, Balances, CKByteDistribution, ETHAsset,
    ETHBalances, ETHDistribution, LockedBalances, ParticipantBuilder, SEC1EncodedPubKeyBuilder,
    SUDTAllocation, SUDTAsset, SUDTBalances, SUDTDistribution, SubAlloc, SubBalances,
};
use sha3::Digest;

use crate::perun;
use crate::perun::test::ChannelId;

#[derive(Debug, Clone)]
pub struct FundingAgreement {
    entries: Vec<FundingAgreementEntry>,
    register: AssetRegister,
}

impl FundingAgreement {
    pub fn register(&self) -> &AssetRegister {
        &self.register
    }

    pub fn has_udts(&self) -> bool {
        self.register.len() > 0
    }

    pub fn new_with_capacities_and_assets<P: perun::Account>(
        caps: Vec<(P, u64)>,
        sudt_script: &Script,
        sudt_max_cap: u64,
        sudt_asset_amt: Vec<(P, u128)>,
        eth_chain_id: u128,
        eth_asset_amt: Vec<(P, u128)>,
    ) -> Self {
        let mut r = AssetRegister::new();

        let sudt_index = r.register_asset(
            SUDTAsset::new_builder()
                .type_script(sudt_script.clone())
                .max_capacity(sudt_max_cap.pack())
                .build(),
        );

        let eth_index = r.register_eth_asset(
            ETHAsset::new_builder()
                .chain_id(eth_chain_id.pack())
                .build(),
        );

        FundingAgreement {
            entries: caps
                .iter()
                .enumerate()
                .map(|(i, (acc, c))| FundingAgreementEntry {
                    ckbytes: *c,
                    sudts: vec![(sudt_index, sudt_asset_amt.get(i).unwrap().1)],
                    eth_asset: vec![(eth_index, eth_asset_amt.get(i).unwrap().1)],
                    index: i as u8,
                    pub_key: acc.public_key(),
                    eth_pubkey: acc.eth_pub_key(),
                })
                .collect(),
            register: r,
        }
    }

    pub fn new_with_capacities<P: perun::Account>(caps: Vec<(P, u64)>) -> Self {
        FundingAgreement {
            entries: caps
                .iter()
                .enumerate()
                .map(|(i, (acc, c))| FundingAgreementEntry {
                    ckbytes: *c,
                    sudts: Vec::new(),
                    eth_asset: Vec::new(),
                    index: i as u8,
                    pub_key: acc.public_key(),
                    eth_pubkey: acc.eth_pub_key(),
                })
                .collect(),
            register: AssetRegister::new(),
        }
    }

    pub fn new_with_capacities_and_sudt<P: perun::Account>(
        caps: Vec<(P, u64)>,
        asset: &Script,
        max_cap: u64,
        asset_amt: Vec<(P, u128)>,
    ) -> Self {
        let mut r = AssetRegister::new();
        let a = r.register_asset(
            SUDTAsset::new_builder()
                .type_script(asset.clone())
                .max_capacity(max_cap.pack())
                .build(),
        );
        FundingAgreement {
            entries: caps
                .iter()
                .enumerate()
                .map(|(i, (acc, c))| FundingAgreementEntry {
                    ckbytes: *c,
                    sudts: vec![(a, asset_amt.get(i).unwrap().1)],
                    eth_asset: Vec::new(),
                    index: i as u8,
                    pub_key: acc.public_key(),
                    eth_pubkey: acc.eth_pub_key(),
                })
                .collect(),
            register: r,
        }
    }

    pub fn content(&self) -> &Vec<FundingAgreementEntry> {
        &self.entries
    }

    pub fn mk_participants(
        &self,
        ctx: &mut Context,
        env: &perun::harness::Env,
        payment_min_capacity: Capacity,
    ) -> Vec<perun_types::Participant> {
        self.entries
            .iter()
            .map(|entry| {
                let sec1_encoded_bytes: Vec<_> = entry
                    .pub_key
                    .to_encoded_point(true)
                    .as_bytes()
                    .iter()
                    .map(|b| PackedByte::new(*b))
                    .collect();
                let sec1_pub_key = SEC1EncodedPubKeyBuilder::default()
                    .set(sec1_encoded_bytes.try_into().unwrap())
                    .build();
                let unlock_script = ctx
                    .build_script(
                        &env.always_success_out_point,
                        Bytes::from(vec![entry.index]),
                    )
                    .expect("script");
                let unlock_script_hash = unlock_script.calc_script_hash();
                ParticipantBuilder::default()
                    .payment_script_hash(unlock_script_hash.clone())
                    .payment_min_capacity(payment_min_capacity.pack())
                    .unlock_script_hash(unlock_script_hash.clone())
                    .pub_key(sec1_pub_key)
                    .build()
            })
            .collect()
    }

    pub fn mk_balances(&self, indices: Vec<u8>) -> Result<Balances, perun::Error> {
        let mut ckbytes = [0u64; 2];
        let sudts = self.register.get_sudtassets();
        let mut sudt_dist: Vec<[u128; 2]> = vec![[0u128, 0]; sudts.len()];
        let eth_assets = self.register.get_eth_assets();
        let mut eth_dist: Vec<[u128; 2]> = vec![[0u128, 0]; eth_assets.len()];

        for fae in self.entries.iter() {
            if indices.iter().find(|&&i| i == fae.index).is_none() {
                continue;
            }
            ckbytes[fae.index as usize] = fae.ckbytes;
            for (asset, amount) in fae.sudts.iter() {
                sudt_dist[asset.0 as usize][fae.index as usize] = *amount;
            }
            for (asset, amount) in fae.eth_asset.iter() {
                eth_dist[asset.0 as usize][fae.index as usize] = *amount;
            }
        }

        let ckb_dist = AnyBalancesUnion::CKByteDistribution(
            CKByteDistribution::new_builder()
                .nth0(ckbytes[0].pack())
                .nth1(ckbytes[1].pack())
                .build(),
        );

        let mut alloc_builder =
            Allocation::new_builder().push(AnyBalances::new_builder().set(ckb_dist).build());

        for (i, asset) in sudts.iter().enumerate() {
            let dist = SUDTDistribution::new_builder()
                .nth0(sudt_dist[i][0].pack())
                .nth1(sudt_dist[i][1].pack())
                .build();
            let sudt_bal = AnyBalancesUnion::SUDTBalances(
                SUDTBalances::new_builder()
                    .asset(asset.clone())
                    .distribution(dist)
                    .build(),
            );
            alloc_builder = alloc_builder.push(AnyBalances::new_builder().set(sudt_bal).build());
        }

        for (i, asset) in eth_assets.iter().enumerate() {
            let dist = ETHDistribution::new_builder()
                .nth0(eth_dist[i][0].pack())
                .nth1(eth_dist[i][1].pack())
                .build();
            let eth_bal = AnyBalancesUnion::ETHBalances(
                ETHBalances::new_builder()
                    .asset(asset.clone())
                    .distribution(dist)
                    .build(),
            );
            alloc_builder = alloc_builder.push(AnyBalances::new_builder().set(eth_bal).build());
        }

        Ok(Balances::new_builder()
            .assets(alloc_builder.build())
            .build())
    }

    pub fn mk_locked_balances(&self, id: ChannelId) -> Result<LockedBalances, perun::Error> {
        let mut ckbytes = [0u64; 2];
        let sudts = self.register.get_sudtassets();
        let mut sudt_dist: Vec<[u128; 2]> = vec![[0u128; 2]; sudts.len()];
        // FIX: was get_ethassets() — correct method is get_eth_assets()
        let eths = self.register.get_eth_assets();
        let mut eth_dist: Vec<[u128; 2]> = vec![[0u128; 2]; eths.len()];

        for fae in self.entries.iter() {
            ckbytes[fae.index as usize] = fae.ckbytes;
            for (asset, amount) in fae.sudts.iter() {
                sudt_dist[asset.0 as usize][fae.index as usize] = *amount;
            }
            // FIX: was fae.eths — correct field is fae.eth_asset
            for (asset, amount) in fae.eth_asset.iter() {
                eth_dist[asset.0 as usize][fae.index as usize] = *amount;
            }
        }

        // SubBalances is flat vector<Uint128>: one entry per asset,
        // ordered CKBytes → SUDTs → ETH, matching parent Balances ordering.
        // Each entry is the sum across both participants for that asset.
        let mut sub_balances_builder = SubBalances::new_builder();

        let ckb_total: u128 = ckbytes[0] as u128 + ckbytes[1] as u128;
        sub_balances_builder = sub_balances_builder.push(ckb_total.pack());

        for dist in sudt_dist.iter() {
            let total: u128 = dist[0] + dist[1];
            sub_balances_builder = sub_balances_builder.push(total.pack());
        }

        for dist in eth_dist.iter() {
            let total: u128 = dist[0] + dist[1];
            sub_balances_builder = sub_balances_builder.push(total.pack());
        }

        Ok(LockedBalances::new_builder()
            .push(
                SubAlloc::new_builder()
                    .id(id.to_byte32())
                    .balances(sub_balances_builder.build())
                    .build(),
            )
            .build())
    }

    pub fn expected_ckbytes_funding_for(&self, index: u8) -> Result<u64, perun::Error> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.index == index)
            .ok_or("unknown index")?;
        Ok(entry.ckbytes)
    }

    pub fn sudt_max_cap_sum(&self) -> u64 {
        self.register
            .get_sudtassets()
            .iter()
            .fold(0u64, |old, asset| {
                old + Capacity::shannons(asset.max_capacity().unpack()).as_u64()
            })
    }

    pub fn expected_sudts_funding_for(
        &self,
        index: u8,
    ) -> Result<Vec<(Script, Capacity, u128)>, perun::Error> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.index == index)
            .ok_or("unknown index")?;
        entry
            .sudts
            .iter()
            .map(|(asset, amount)| {
                let sudt_asset = self.register.get_sudtasset(asset).ok_or("unknown asset")?;
                let sudt_script = sudt_asset.type_script();
                let sudt_capacity = Capacity::shannons(sudt_asset.max_capacity().unpack());
                Ok((sudt_script, sudt_capacity, *amount))
            })
            .collect::<Result<Vec<(Script, Capacity, u128)>, perun::Error>>()
    }
}

#[derive(Debug, Clone)]
pub struct FundingAgreementEntry {
    pub ckbytes: u64,
    pub sudts: Vec<(Asset, u128)>,
    pub eth_asset: Vec<(EthAsset, u128)>,
    pub index: u8,
    pub pub_key: PublicKey,
    pub eth_pubkey: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Asset(pub u32);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EthAsset(pub u32);

impl Asset {
    pub fn _new() -> Self {
        Asset(0)
    }
}

impl Default for Asset {
    fn default() -> Self {
        Asset(0)
    }
}

impl EthAsset {
    pub fn _new() -> Self {
        EthAsset(0)
    }
}

impl Default for EthAsset {
    fn default() -> Self {
        EthAsset(0)
    }
}

#[derive(Debug, Clone)]
pub struct AssetRegister {
    assets: Vec<(Asset, SUDTAsset)>,
    eth_assets: Vec<(EthAsset, ETHAsset)>,
}

impl AssetRegister {
    fn new() -> Self {
        AssetRegister {
            assets: Vec::new(),
            eth_assets: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.assets.len()
    }

    pub fn register_asset(&mut self, sudt_asset: SUDTAsset) -> Asset {
        let asset = Asset(self.assets.len() as u32);
        self.assets.push((asset, sudt_asset));
        asset
    }

    pub fn register_eth_asset(&mut self, eth_asset: ETHAsset) -> EthAsset {
        let asset = EthAsset(self.eth_assets.len() as u32);
        self.eth_assets.push((asset, eth_asset));
        asset
    }

    pub fn get_sudtasset(&self, asset: &Asset) -> Option<&SUDTAsset> {
        match self.assets.get(asset.0 as usize) {
            Some((_, sudt_asset)) => Some(sudt_asset),
            None => None,
        }
    }

    pub fn get_eth_asset(&self, asset: &EthAsset) -> Option<&ETHAsset> {
        match self.eth_assets.get(asset.0 as usize) {
            Some((_, eth_asset)) => Some(eth_asset),
            None => None,
        }
    }

    pub fn get_asset(&self, sudt_asset: SUDTAsset) -> Option<&Asset> {
        match self
            .assets
            .iter()
            .find(|(_, a)| a.as_slice()[..] == sudt_asset.as_slice()[..])
        {
            Some((asset, _)) => Some(asset),
            None => None,
        }
    }

    pub fn guess_asset_from_script(&self, script: &Script) -> Option<&Asset> {
        match self.assets.iter().find(|(_, sudt_asset)| {
            sudt_asset.type_script().as_slice()[..] == script.as_slice()[..]
        }) {
            Some((asset, _)) => Some(asset),
            None => None,
        }
    }

    pub fn get_sudtassets(&self) -> Vec<SUDTAsset> {
        self.assets.iter().map(|(_, a)| a.clone()).collect()
    }

    pub fn get_eth_assets(&self) -> Vec<ETHAsset> {
        self.eth_assets.iter().map(|(_, a)| a.clone()).collect()
    }
}
