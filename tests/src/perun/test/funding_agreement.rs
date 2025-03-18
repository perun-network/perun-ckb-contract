use ckb_occupied_capacity::Capacity;
use ckb_testtool::ckb_types::packed::{Byte as PackedByte, Script};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;
use ckb_types::bytes::Bytes;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use perun_common::perun_types::{
    self, Balances, CKByteDistribution, ParticipantBuilder,
    SEC1EncodedPubKeyBuilder, SUDTAllocation, SUDTAsset, SUDTBalances, SUDTDistribution,
};

use crate::perun;

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

    pub fn new_with_capacities<P: perun::Account>(caps: Vec<(P, u64)>) -> Self {
        FundingAgreement {
            entries: caps
                .iter()
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
                    index: i as u8,
                    pub_key: acc.public_key(),
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
        let sudts = self.register.get_sudtassets();
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
            sudt_alloc.push(
                SUDTBalances::new_builder()
                    .asset(asset.clone())
                    .distribution(
                        SUDTDistribution::new_builder()
                            .nth0(sudt_dist[i][0].pack())
                            .nth1(sudt_dist[i][1].pack())
                            .build(),
                    )
                    .build(),
            );
        }

        println!("mkbalances ckbytes: {:?}", ckbytes);

        Ok(Balances::new_builder()
            .ckbytes(
                CKByteDistribution::new_builder()
                    .nth0(ckbytes[0].pack())
                    .nth1(ckbytes[1].pack())
                    .build(),
            )
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

    pub fn sudt_max_cap_sum(&self) -> u64 {
        self.register.get_sudtassets().iter().fold(0u64, |old, asset| {
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
pub struct AssetRegister {
    assets: Vec<(Asset, SUDTAsset)>,
}

impl AssetRegister {
    fn new() -> Self {
        AssetRegister {
            assets: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.assets.len()
    }

    pub fn register_asset(&mut self, sudt_asset: SUDTAsset) -> Asset {
        let asset = Asset(self.assets.len() as u32);
        self.assets.push((asset, sudt_asset));
        return asset;
    }
    pub fn get_sudtasset(&self, asset: &Asset) -> Option<&SUDTAsset> {
        match self.assets.get(asset.0 as usize) {
            Some((_, sudt_asset)) => Some(sudt_asset),
            None => None,
        }
    }

    pub fn get_asset(&self, sudt_asset: SUDTAsset) -> Option<&Asset> {
        match self.assets.iter().find(|(_, a)| a.as_slice()[..] == sudt_asset.as_slice()[..]) {
            Some((asset, _)) => Some(asset),
            None => None,
        }
    }

    pub fn guess_asset_from_script(&self, script: &Script) -> Option<&Asset> {
        match self
            .assets
            .iter()
            .find(|(_, sudt_asset)| sudt_asset.type_script().as_slice()[..] == script.as_slice()[..])
        {
            Some((asset, _)) => Some(asset),
            None => None,
        }
    }

    pub fn get_sudtassets(&self) -> Vec<SUDTAsset> {
        self.assets.iter().map(|(_, a)| a.clone()).collect()
    }
}
