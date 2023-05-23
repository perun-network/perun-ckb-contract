use std::collections::HashMap;

use ckb_occupied_capacity::Capacity;
use ckb_testtool::ckb_types::packed::{Byte as PackedByte, Byte32, Uint64, Script};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;
use ckb_types::bytes::Bytes;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use perun_common::perun_types::{
    self, Balances, BalancesBuilder, ParticipantBuilder, SEC1EncodedPubKeyBuilder, CKByteDistribution, SUDTAsset, SUDTAllocation, SUDTBalances, SUDTDistribution,
};

use crate::perun;

#[derive(Debug, Clone)]
pub struct FundingAgreement{
    entries: Vec<FundingAgreementEntry>, 
    register: AssetRegister,
}

impl FundingAgreement {
    pub fn new_with_capacities<P: perun::Account>(caps: Vec<(P, u64)>) -> Self {
        FundingAgreement{
            entries: caps.iter()
                .enumerate()
                .map(|(i, (acc, c))| FundingAgreementEntry {
                    ckbytes: *c,
                    sudts: Vec::new(),
                    index: i as u8,
                    pub_key: acc.public_key(),
                })
                .collect(),
            register: AssetRegister::new(),
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
                        // NOTE: To be able to make sure we can distinguish between the payout of
                        // the participants, we will pass their corresponding index as an argument.
                        // This will have no effect on the execution of the always_success_script,
                        // because it does not bother checking its arguments, but will allow us to
                        // assert the correct indices once a channel is concluded.
                        Bytes::from(vec![entry.index]),
                    )
                    .expect("script");
                let unlock_script_hash = unlock_script.calc_script_hash();
                ParticipantBuilder::default()
                    // The payment script hash used to lock the funds after a channel close for
                    // this party.
                    .payment_script_hash(unlock_script_hash.clone())
                    // The minimum capacity required for the payment cell to be valid.
                    .payment_min_capacity(payment_min_capacity.pack())
                    // The unlock script hash used to identify this party. Normally this would be
                    // the lock args for a secp256k1 script or similar. Since we use the always
                    // success script, we will use the hash of said script parameterized by the
                    // party index.
                    .unlock_script_hash(unlock_script_hash.clone())
                    .pub_key(sec1_pub_key)
                    .build()
            })
            .collect()
    }

    /// mk_balances creates a Balances object from the funding agreement where the given indices
    /// already funded their part.
    pub fn mk_balances(&self, indices: Vec<u8>) -> Result<Balances, perun::Error> {
        let mut ckbytes = [0u64; 2];
        let sudts = self.register.get_SUDTAssets();
        let mut sudt_dist: Vec<[u128; 2]> = Vec::new();
        for _ in 0..sudts.len() {
            sudt_dist.push([0u128, 0]);
        }
        for fae in self.entries.iter() {
            if indices.iter().find(|&&i| i == fae.index).is_none() {
                continue;
            }

            ckbytes[fae.index as usize] = fae.ckbytes;
            for (asset, amount) in fae.sudts.iter() {
                sudt_dist[asset.0 as usize][fae.index as usize] = *amount;
            }
        }
        let mut sudt_alloc: Vec<SUDTBalances> = Vec::new();
        for (i, asset) in sudts.iter().enumerate() {
            sudt_alloc.push(SUDTBalances::new_builder()
            .asset(asset.clone())
            .distribution(SUDTDistribution::new_builder()
                .nth0(sudt_dist[i][0].pack())
                .nth1(sudt_dist[i][1].pack())
                .build())
            .build());
        }
        
        println!("mkbalances ckbytes: {:?}", ckbytes);

        Ok(Balances::new_builder()
            .ckbytes(CKByteDistribution::new_builder()
                        .nth0(ckbytes[0].pack())
                        .nth1(ckbytes[1].pack())
                        .build())
            .sudts(SUDTAllocation::new_builder().set(sudt_alloc).build())
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
    pub fn expected_sudts_funding_for(&self, index: u8) -> Result<Vec<(Script, Capacity, u128)>, perun::Error> {
        let entry = self.entries
            .iter()
            .find(|entry| entry.index == index)
            .ok_or("unknown index")?;
        entry.sudts.iter().map(|(asset, amount)| {
            let sudt_asset = self.register.get_SUDTAsset(asset).ok_or("unknown asset")?;
            let sudt_script = sudt_asset.type_script();
            let sudt_capacity = Capacity::shannons(sudt_asset.max_capacity().unpack());
            Ok((sudt_script, sudt_capacity, *amount))
        }).collect::<Result<Vec<(Script, Capacity, u128)>, perun::Error>>()
    }

}

#[derive(Debug, Clone)]
pub struct FundingAgreementEntry {
    pub ckbytes: u64,
    pub sudts: Vec<(Asset, u128)>,
    pub index: u8,
    pub pub_key: PublicKey,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Asset(pub u32);

impl Asset {
    pub fn new() -> Self {
        Asset(0)
    }
}

impl Default for Asset {
    fn default() -> Self {
        Asset(0)
    }
}

#[derive(Debug, Clone)]
struct AssetRegister {
    counter: u32,
    map: HashMap<Asset, SUDTAsset>,
}

impl AssetRegister {
    fn new() -> Self {
        AssetRegister {
            counter: 0,
            map: HashMap::new(),
        }
    }

    pub fn register_asset(&mut self, sudt_asset: SUDTAsset) -> Asset {
        let asset = Asset(self.counter);
        self.map.insert(asset, sudt_asset);
        self.counter += 1;
        return asset;
    }
    pub fn get_SUDTAsset(&self, asset: &Asset) -> Option<&SUDTAsset> {
        self.map.get(asset)
    }

    pub fn get_SUDTAssets(&self) -> Vec<SUDTAsset> {
        self.map.values().cloned().collect()
    }
} 