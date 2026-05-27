use ckb_testtool::{
    ckb_types::{
        packed::{OutPoint, Script},
        prelude::{Builder, Entity, Pack, Unpack},
    },
    context::Context,
};
use k256::ecdsa::VerifyingKey;
use perun_common::{
    cfalse, ctrue,
    perun_types::{
        ChannelParametersBuilder, ChannelState, IndexMapBuilder, ParentDataBuilder,
        ParentsVecBuilder, Participant, SUDTAllocation, VCChannelConstants,
        VCChannelConstantsBuilder, VirtualChannelStatus,
    },
    sol::convert_params,
};

use super::test::FundingAgreement;
use super::Account;
use crate::perun::{
    self,
    test::{keys, ChannelId, Client},
};
use crate::perun::{channel::Channel, test};
use perun_common::perun_types::{Allocation, AnyBalances, AnyBalancesUnion};
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct VirtualChannel {
    // acitve_part: test::Client
    vc_status: VirtualChannelStatus,
    id: ChannelId,
    vcts: Script,
    vcls: Script,
    /// All available parties.
    parts: HashMap<String, test::Client>,
    idx_map: VCIndexMap,

    /// vc cell
    cell: OutPoint,
}

#[derive(Debug, Clone)]
pub enum IdxMapDirection {
    LedgerChannelToVirtualChannel,
    VirtualChannelToLedgerChannel,
}

#[derive(Debug, Clone)]
pub struct IdxMapWithDirection {
    pub idx_map: [u8; 2],
    pub direction: IdxMapDirection,
}
#[derive(Debug, Clone)]
pub struct VCIndexMap {
    pub parent1: [u8; 2],
    pub parent2: [u8; 2],
}

impl VCIndexMap {
    pub fn invert_map(&self, parent: usize) -> [u8; 2] {
        let parent_map = self.get(parent).expect("no parent").clone();
        let mut inverted = [0u8; 2];
        inverted[parent_map[0 as usize] as usize] = 0;
        inverted[parent_map[1 as usize] as usize] = 1;
        inverted
    }

    pub fn get(&self, parent: usize) -> Option<&[u8; 2]> {
        match parent {
            0 => Some(&self.parent1),
            1 => Some(&self.parent2),
            _ => None,
        }
    }
}

impl VirtualChannel {
    pub fn new(
        context: &mut Context,
        env: &perun::harness::Env,
        parts: &[perun::TestAccount],
        funding_agreement: &FundingAgreement,
        chan_ai: &Channel<perun::State>,
        chan_bi: &Channel<perun::State>,
        idx_map: &VCIndexMap,
        nonce: &[u8; 32],
        owner: &Participant,
    ) -> Self {
        let m_parts: HashMap<_, _> = parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                (
                    p.name().clone(),
                    perun::test::Client::new(i as u8, p.name(), p.sk.clone()),
                )
            })
            .collect();
        let parties_vc =
            funding_agreement.mk_participants(context, &env, env.min_capacity_no_script);
        let vc_chan_params = ChannelParametersBuilder::default()
            .party_a(parties_vc[0].clone())
            .party_b(parties_vc[1].clone())
            .nonce(nonce.clone().pack())
            .challenge_duration(env.challenge_duration.pack())
            .app(Default::default())
            .is_ledger_channel(cfalse!())
            .is_virtual_channel(ctrue!())
            .build();
        // VC channel ID = Keccak256(abi_encode(convert_vc_params(params))),
        // matching the on-chain check in verify_vchannel_id_integrity.
        use alloy_sol_types::SolValue;
        use sha3::{Digest, Keccak256};
        let params_sol = convert_params(&vc_chan_params);
        let encoded = params_sol.abi_encode();
        let cid_raw: [u8; 32] = Keccak256::digest(&encoded).into();
        let cid = ChannelId::from(cid_raw);

        let parents_builder = ParentsVecBuilder::default();
        let parent1 = ParentDataBuilder::default()
            .pcts_hash(chan_ai.pcts().calc_script_hash())
            .idx_map(
                IndexMapBuilder::default()
                    .nth0(idx_map.parent1[0].clone().into())
                    .nth1(idx_map.parent1[1].clone().into())
                    .build(),
            )
            .build();
        let parent2 = ParentDataBuilder::default()
            .pcts_hash(chan_bi.pcts().calc_script_hash())
            .idx_map(
                IndexMapBuilder::default()
                    .nth0(idx_map.parent2[0].clone().into())
                    .nth1(idx_map.parent2[1].clone().into())
                    .build(),
            )
            .build();
        let parents = parents_builder.push(parent1).push(parent2).build();
        let first_force_close = false;
        // Build VirtualChannelStatus
        let vc_status = match env.build_virtual_channel_state(
            &cid,
            &funding_agreement,
            &parents,
            first_force_close,
            owner.clone(),
        ) {
            Ok(vc_status) => vc_status,
            Err(e) => panic!("Error building virtual channel state: {}", e),
        };

        let vc_channel_constants = VCChannelConstantsBuilder::default()
            .params(vc_chan_params.clone())
            .vcls_code_hash(env.get_vcls_().calc_script_hash())
            .vcls_hash_type(env.get_vcls_().hash_type().clone())
            .build();
        let vcts = env.build_vcts(context, vc_channel_constants.as_bytes());

        VirtualChannel {
            vc_status: vc_status,
            vcts: vcts,
            id: cid,
            vcls: env.get_vcls_().clone(),
            parts: m_parts,
            idx_map: idx_map.clone(),
            cell: OutPoint::default(),
        }
    }

    pub fn vc_status(&self) -> &VirtualChannelStatus {
        &self.vc_status
    }

    pub fn vcts(&self) -> &Script {
        &self.vcts
    }

    pub fn vcls(&self) -> &Script {
        &self.vcls
    }

    pub fn id(&self) -> &ChannelId {
        &self.id
    }

    pub fn cell(&self) -> &OutPoint {
        &self.cell
    }
    pub fn set_cell(&mut self, cell: OutPoint) {
        self.cell = cell;
    }

    pub fn update(
        &mut self,
        update: impl Fn(&ChannelState) -> Result<ChannelState, perun::Error>,
    ) -> &mut Self {
        let new_state = update(&self.vc_status.vcstate()).expect("update failed");
        self.vc_status = self
            .vc_status
            .clone()
            .as_builder()
            .vcstate(new_state)
            .build();
        self
    }

    pub fn sigs_for_vc_status(&self) -> Result<[Vec<u8>; 2], perun::Error> {
        // We have to unpack the ChannelConstants like this. Otherwise the molecule header is still
        // part of the slice. On-chain we have no problem due to unpacking the arguments, but this
        // does not seem possible in this scope.
        let bytes = self.vcts.args().raw_data();
        // We want to have the correct order of clients in an array to construct signatures. For
        // consistency we use the ChannelConstants which are also used to construct the channel and
        // look up the participants according to their public key identifier.
        let s = VCChannelConstants::from_slice(&bytes)?;
        let resolve_client = |verifying_key_raw: Vec<u8>| -> Result<Client, perun::Error> {
            let verifying_key = VerifyingKey::from_sec1_bytes(verifying_key_raw.as_slice())?;
            let pubkey = keys::verifying_key_to_byte_array(&verifying_key);
            self.parts
                .values()
                .cloned()
                .find(|c| c.pubkey() == pubkey)
                .ok_or("unknown participant in channel parameters".into())
        };
        let clients: Result<Vec<_>, _> = s
            .params()
            .mk_party_pubkeys()
            .iter()
            .cloned()
            .map(resolve_client)
            .collect();
        let sigs: Result<Vec<_>, _> = clients?
            .iter()
            .map(|p| p.sign(self.vc_status.vcstate()))
            .collect();
        let sig_arr: [Vec<u8>; 2] = sigs?.try_into()?;
        Ok(sig_arr)
    }
}

pub fn update_virtual_channel<'a>(
    fa: &'a FundingAgreement,
    vc_id: ChannelId,
    vc_to_lc_idx_map: &'a [u8; 2],
) -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> + 'a {
    move |s| {
        let locked = fa.mk_locked_balances(vc_id)?;
        let vc_alloc = locked.get(0).expect("no 0th in SubAlloc: no funds locked");
        let vc_sub_bals = vc_alloc.balances();
        let entry0 = &fa.content()[0];
        let entry1 = &fa.content()[1];

        let mut allocation_builder = Allocation::new_builder();
        let mut sudt_asset_idx = 0usize;
        let mut eth_asset_idx = 0usize;

        for row in s.balances().assets().into_iter() {
            if row.is_ckb_row() {
                let old_0: u64 = s
                    .balances()
                    .ckbytes()
                    .get(vc_to_lc_idx_map[0] as usize)
                    .expect("no ckbytes at idx 0");
                let old_1: u64 = s
                    .balances()
                    .ckbytes()
                    .get(vc_to_lc_idx_map[1] as usize)
                    .expect("no ckbytes at idx 1");
                let locked_0 = entry0.ckbytes;
                let locked_1 = entry1.ckbytes;

                let updated_dist = s
                    .balances()
                    .ckbytes()
                    .clone()
                    .as_builder()
                    .nth0((old_0 - locked_0).pack())
                    .nth1((old_1 - locked_1).pack())
                    .build();

                allocation_builder = allocation_builder.push(
                    AnyBalances::new_builder()
                        .set(AnyBalancesUnion::CKByteDistribution(updated_dist))
                        .build(),
                );
            } else if row.is_sudt_row() {
                let lc_sudt = row.as_sudt().unwrap();
                let locked_0 = entry0
                    .sudts
                    .get(sudt_asset_idx)
                    .expect("missing SUDT funding entry for participant 0")
                    .1;
                let locked_1 = entry1
                    .sudts
                    .get(sudt_asset_idx)
                    .expect("missing SUDT funding entry for participant 1")
                    .1;

                let old_0: u128 = lc_sudt
                    .distribution()
                    .get(vc_to_lc_idx_map[0] as usize)
                    .expect("no sudt dist at idx 0");
                let old_1: u128 = lc_sudt
                    .distribution()
                    .get(vc_to_lc_idx_map[1] as usize)
                    .expect("no sudt dist at idx 1");

                let updated_dist = lc_sudt
                    .distribution()
                    .clone()
                    .as_builder()
                    .nth0((old_0 - locked_0).pack())
                    .nth1((old_1 - locked_1).pack())
                    .build();
                let updated_bals = lc_sudt
                    .clone()
                    .as_builder()
                    .distribution(updated_dist)
                    .build();

                allocation_builder = allocation_builder.push(
                    AnyBalances::new_builder()
                        .set(AnyBalancesUnion::SUDTBalances(updated_bals))
                        .build(),
                );
                sudt_asset_idx += 1;
            } else if row.is_eth_row() {
                let lc_eth = row.as_eth().unwrap();
                let locked_0 = entry0
                    .eth_asset
                    .get(eth_asset_idx)
                    .expect("missing ETH funding entry for participant 0")
                    .1;
                let locked_1 = entry1
                    .eth_asset
                    .get(eth_asset_idx)
                    .expect("missing ETH funding entry for participant 1")
                    .1;

                let old_0: u128 = lc_eth
                    .distribution()
                    .get(vc_to_lc_idx_map[0] as usize)
                    .expect("no eth dist at idx 0");
                let old_1: u128 = lc_eth
                    .distribution()
                    .get(vc_to_lc_idx_map[1] as usize)
                    .expect("no eth dist at idx 1");

                let updated_dist = lc_eth
                    .distribution()
                    .clone()
                    .as_builder()
                    .nth0((old_0 - locked_0).pack())
                    .nth1((old_1 - locked_1).pack())
                    .build();
                let updated_bals = lc_eth
                    .clone()
                    .as_builder()
                    .distribution(updated_dist)
                    .build();

                allocation_builder = allocation_builder.push(
                    AnyBalances::new_builder()
                        .set(AnyBalancesUnion::ETHBalances(updated_bals))
                        .build(),
                );
                eth_asset_idx += 1;
            }
        }

        Ok(s.clone()
            .as_builder()
            .version((Unpack::<u64>::unpack(&s.version()) + 1u64).pack())
            .balances(
                s.balances()
                    .clone()
                    .as_builder()
                    .assets(allocation_builder.build())
                    .locked(locked)
                    .build(),
            )
            .build())
    }
}
