use ckb_occupied_capacity::Capacity;
use ckb_testtool::ckb_types::packed::{Byte as PackedByte, Byte32, BytesBuilder};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;
use ckb_types::bytes::Bytes;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use perun_common::perun_types::{
    self, Balances, BalancesBuilder, ParticipantBuilder, SEC1EncodedPubKeyBuilder,
};

use crate::perun;

#[derive(Clone)]
pub struct FundingAgreement(Vec<FundingAgreementEntry>);

impl FundingAgreement {
    pub fn new_with_capacities<P: perun::Account>(caps: Vec<(P, u64)>) -> Self {
        FundingAgreement(
            caps.iter()
                .enumerate()
                .map(|(i, (acc, c))| FundingAgreementEntry {
                    amounts: vec![(Asset::default(), *c)],
                    index: i as u8,
                    pub_key: acc.public_key(),
                })
                .collect(),
        )
    }

    pub fn content(&self) -> &Vec<FundingAgreementEntry> {
        &self.0
    }

    pub fn mk_participants(
        &self,
        ctx: &mut Context,
        env: &perun::harness::Env,
        payment_lock_script: Byte32,
        payment_min_capacity: Capacity,
    ) -> Vec<perun_types::Participant> {
        self.0
            .iter()
            .map(|entry| {
                let sec1_encoded_bytes: Vec<_> = entry
                    .pub_key
                    .to_encoded_point(false)
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
                ParticipantBuilder::default()
                    // The payment script hash used to lock the funds after a channel close for
                    // this party.
                    .payment_script_hash(payment_lock_script.clone())
                    // The minimum capacity required for the payment cell to be valid.
                    .payment_min_capacity(payment_min_capacity.pack())
                    // The unlock script hash used to identify this party. Normally this would be
                    // the lock args for a secp256k1 script or similar. Since we use the always
                    // success script, we will use the hash of said script parameterized by the
                    // party index.
                    .unlock_script_hash(unlock_script.calc_script_hash())
                    .pub_key(sec1_pub_key)
                    .build()
            })
            .collect()
    }

    /// mk_balances creates a Balances object from the funding agreement where the given indices
    /// already funded their part.
    pub fn mk_balances(&self, indices: Vec<u8>) -> Result<Balances, perun::Error> {
        let uint128_balances = self.0.iter().fold(Ok(vec![]), |acc, entry| {
            match acc {
                Ok(mut acc) => {
                    match indices.iter().find(|&&i| i == entry.index) {
                        Some(_) => {
                            // We found the index in the list of funded indices, we expect the required
                            // amount for assets to be funded.
                            if let Some((Asset(0), amount)) = entry.amounts.iter().next() {
                                let amount128: u128 = (*amount).into();
                                acc.push(amount128.pack());
                                return Ok(acc);
                            } else {
                                return Err(perun::Error::from("unknown asset"));
                            };
                        }
                        None => {
                            // We did not find the index in the list of funded indices, the client
                            // identified by this index did not fund, yet.
                            acc.push(0u128.pack());
                            Ok(acc)
                        }
                    }
                }
                e => e,
            }
        })?;
        let bals = match uint128_balances.try_into() {
            Ok(bals) => bals,
            Err(_) => return Err(perun::Error::from("could not convert balances")),
        };
        Ok(BalancesBuilder::default().set(bals).build())
    }

    pub fn expected_funding_for(&self, index: u8) -> Result<u64, perun::Error> {
        let entry = self
            .0
            .iter()
            .find(|entry| entry.index == index)
            .ok_or("unknown index")?;
        entry
            .amounts
            .iter()
            .find_map(|e| {
                if let (Asset(0), amount) = e {
                    Some(*amount)
                } else {
                    None
                }
            })
            .ok_or("unsupported asset".into())
    }
}

#[derive(Clone)]
pub struct FundingAgreementEntry {
    pub amounts: Vec<(Asset, u64)>,
    pub index: u8,
    pub pub_key: PublicKey,
}

#[derive(Copy, Clone)]
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
