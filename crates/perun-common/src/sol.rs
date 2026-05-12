// Copyright 2025 - See NOTICE file for copyright holders.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use crate::perun_types::ChannelState;
use alloy_primitives::{Address, Bytes as PrimBytes, FixedBytes, U256};
use alloy_sol_types::sol;
use alloy_sol_types::SolValue;
use ckb_std::ckb_types::bytes;
use k256::{ecdsa::VerifyingKey, elliptic_curve::sec1::EncodedPoint, Secp256k1};
use sha3::{Digest, Keccak256};

use molecule::prelude::*;

use crate::{
    helpers::{bytes_to_u128, bytes_to_u64},
    perun_types::{ChannelParameters, Participant},
};
const BACKEND_ID_CKB: u64 = 3;
const BACKEND_ID_ETH: u64 = 1;
const CKBYTE_MAGIC: u8 = 0x00;
const SUDT_MAGIC: u8 = 0x01;
sol! {
    struct ParticipantSol {
        address ethAddress;
        bytes ccAddress;
    }

    struct ParamsSol {
        uint256 challengeDuration;
        uint256 nonce;
        ParticipantSol[] participants;
        address app;
        bool ledgerChannel;
        bool virtualChannel;
    }
    #[derive(Debug)]

    struct StateSol {
        bytes32 channelID;
        uint64 version;
        AllocationSol outcome;
        bytes appData;
        bool isFinal;
    }

    #[derive(Debug)]

    struct AssetSol {
        uint256 chainID;
        address ethHolder;
        bytes ccHolder;
    }
    #[derive(Debug)]

    struct AllocationSol {
        AssetSol[] assets;
        uint256[] backends;
        // Outer dimension are assets, inner dimension are the participants.
        uint256[][] balances;
        SubAllocSol[] locked;
    }
    #[derive(Debug)]

    struct SubAllocSol {
        // ID is the channelID of the subchannel
        bytes32[] ID; // solhint-disable-line var-name-mixedcase
        // balances holds the total balance of the subchannel of every asset.
        uint256[] balances;
        // indexMap maps each sub-channel participant to a parent channel
        // participant such that subPart[i] == parentPart[indexMap[i]].
        uint16[] indexMap;
    }

}

pub struct Chain(u64);

impl Chain {
    pub fn new(value: u64) -> Self {
        Chain(value)
    }
    pub fn as_u64(&self) -> u64 {
        // Use `u64` here to avoid data loss
        self.0
    }
}

pub fn convert_ckb_state(state: &ChannelState) -> StateSol {
    let channel_id_alloy: FixedBytes<32> = FixedBytes::from_slice(state.channel_id().as_slice());

    let version_alloy = bytes_to_u64(state.version().as_slice());

    let balances = state.balances();
    let mut assets = vec![];
    let mut backends = vec![];
    let mut balances_sol = vec![];

    for row in state.balances().assets().clone().into_iter() {
        let is_ckb = row.is_ckb_row();
        let is_sudt = row.is_sudt_row();
        let is_eth = row.is_eth_row();

        if is_ckb {
            if let Some(ckbytes) = row.as_ckb() {
                assets.push(AssetSol {
                    chainID: U256::from(BACKEND_ID_CKB),
                    ethHolder: Address::from_slice(&[0u8; 20]),
                    ccHolder: PrimBytes::copy_from_slice(&[CKBYTE_MAGIC]),
                });

                let ckb_user0 = ckbytes.nth0();

                let ckb_user0_bytes = ckb_user0.as_slice();
                assert_eq!(
                    ckb_user0_bytes.len(),
                    8,
                    "CKBytes distribution must be exactly 8 bytes"
                );
                let ckb_user0_u256 = U256::from(u64::from_le_bytes(ckb_user0_bytes.try_into().unwrap()));

                let ckb_user1 = ckbytes.nth1();
                let ckb_user1_bytes = ckb_user1.as_slice();
                assert_eq!(
                    ckb_user1_bytes.len(),
                    8,
                    "CKBytes distribution must be exactly 8 bytes"
                );
                let ckb_user1_u256 = U256::from(u64::from_le_bytes(ckb_user1_bytes.try_into().unwrap()));

                backends.push(U256::from(BACKEND_ID_CKB));
                balances_sol.push(vec![ckb_user0_u256, ckb_user1_u256]);
            }

        } else if is_sudt {
            if let Some(sudt) = row.as_sudt() {
                let asset_bytes = bytes::Bytes::from(sudt.asset().as_bytes());
                let mut encoded_bytes = Vec::with_capacity(asset_bytes.len() + 1);
                encoded_bytes.push(SUDT_MAGIC);
                encoded_bytes.extend_from_slice(&asset_bytes);
                assets.push(AssetSol {
                    chainID: U256::from(BACKEND_ID_CKB),
                    ethHolder: Address::from_slice(&[0u8; 20]),
                    ccHolder: PrimBytes::copy_from_slice(&encoded_bytes),
                });
                backends.push(U256::from(BACKEND_ID_CKB));
                balances_sol.push(vec![
                    U256::from(bytes_to_u128(sudt.distribution().nth0().as_slice())),
                    U256::from(bytes_to_u128(sudt.distribution().nth1().as_slice())),
                ]);
            }

        } else if is_eth {
            if let Some(eth) = row.as_eth() {
                let chain_id = U256::from(u128::from_le_bytes({
                    let cid = eth.asset().chain_id();
                    let mut le = [0u8; 16];
                    le.copy_from_slice(cid.as_slice());
                    le
                }));
                assets.push(AssetSol {
                    chainID: chain_id,
                    ethHolder: Address::from_slice(eth.asset().asset_address().as_slice()),
                    ccHolder: PrimBytes::copy_from_slice(&[0u8; 32]),
                });
                backends.push(U256::from(BACKEND_ID_ETH));
                balances_sol.push(vec![
                    U256::from(bytes_to_u128(eth.distribution().nth0().as_slice())),
                    U256::from(bytes_to_u128(eth.distribution().nth1().as_slice())),
                ]);
            }

        } else {
            unreachable!()
        }
    }

    let locked = vec![];

    let outcome = AllocationSol {
        assets: assets,
        backends: backends,
        balances: balances_sol,
        locked,
    };

    let app_data_alloy = PrimBytes::copy_from_slice(&[]);

    let is_final = state.is_final().to_bool();

    StateSol {
        channelID: channel_id_alloy,
        version: version_alloy,
        outcome,
        appData: app_data_alloy,
        isFinal: is_final,
    }
}

pub fn convert_participant(participant: Participant) -> ParticipantSol {
    let eth_address = eth_address_from_sec1_pubkey(participant.pub_key().as_slice())
        .expect("unable to derive eth address from pub_key");

    ParticipantSol {
        ethAddress: eth_address,
        ccAddress: PrimBytes::copy_from_slice(participant.as_slice()),
    }
}

pub fn convert_params(params: &ChannelParameters) -> ParamsSol {
    let part_a = params.party_a();
    let part_b = params.party_b();

    let part_sol_a = convert_participant(part_a);
    let part_sol_b = convert_participant(part_b);
    let participants_sol = [part_sol_a, part_sol_b].to_vec();

    let nonce = params.nonce();
    let nonce_slice = nonce.as_slice();

    let nonce_array: [u8; 32] = nonce_slice
        .try_into()
        .expect("nonce must be exactly 32 bytes");

    let nonce_alloy = U256::from_be_bytes(nonce_array);

    let chall_duration_native = params.challenge_duration();
    let chall_duration_slice = chall_duration_native.as_slice();
    let chall_duration_array: [u8; 8] = chall_duration_slice
        .try_into()
        .expect("challenge duration must be exactly 64 bytes");
    let chall_duration_u64 = u64::from_le_bytes(chall_duration_array);
    let chall_duration = U256::from(chall_duration_u64);
    let app_alloy = Address::from_slice(&[0u8; 20]);

    ParamsSol {
        challengeDuration: chall_duration,
        nonce: nonce_alloy,
        participants: participants_sol,
        app: app_alloy,
        ledgerChannel: true,
        virtualChannel: false,
    }
}

pub fn eth_address_from_sec1_pubkey(sec1_pubkey: &[u8]) -> Result<Address, &'static str> {
    let encoded_point = EncodedPoint::<Secp256k1>::from_bytes(sec1_pubkey)
        .map_err(|_| "Invalid sec1 encoded public key")?;

    let verifying_key =
        VerifyingKey::from_encoded_point(&encoded_point).map_err(|_| "Invalid encoded point")?;

    let uncompressed = verifying_key.to_encoded_point(false);
    let pubkey_bytes = uncompressed.as_bytes();

    let pubkey_no_prefix = &pubkey_bytes[1..];

    let mut hasher = Keccak256::new();
    hasher.update(pubkey_no_prefix);
    let hash = hasher.finalize();

    // Create Address directly from last 20 bytes slice
    let eth_addr_bytes = &hash[12..];
    let eth_address = Address::from_slice(eth_addr_bytes);

    Ok(eth_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;
    use alloy_sol_types::SolValue;
    use ckb_gen_types::{
        packed::{Byte, Byte32, Uint128},
        prelude::Pack,
    };
    use molecule::prelude::{Builder, Entity};
    use crate::perun_types::{
        AnyBalances, AnyBalancesUnion, Allocation, Balances, Bool, ChannelState,
        CKByteDistribution, ETHAsset, ETHBalances, ETHDistribution, EthAddress, LockedBalances,
    };

    // ── helpers ────────────────────────────────────────────────────────────

    fn uint128(v: u128) -> Uint128 {
        Uint128::new_unchecked(molecule::bytes::Bytes::from(v.to_le_bytes().to_vec()))
    }

    fn eth_addr(bytes: [u8; 20]) -> EthAddress {
        EthAddress::new_builder().set(bytes.map(Byte::from)).build()
    }

    fn make_ckb_state(cid: [u8; 32], version: u64, is_final: bool, a: u64, b: u64) -> ChannelState {
        let ckb = AnyBalancesUnion::CKByteDistribution(
            CKByteDistribution::new_builder().set([a.pack(), b.pack()]).build(),
        );
        let balances = Balances::new_builder()
            .assets(Allocation::new_builder().push(AnyBalances::new_builder().set(ckb).build()).build())
            .locked(LockedBalances::default())
            .build();
        ChannelState::new_builder()
            .channel_id(Byte32::from_slice(&cid).unwrap())
            .balances(balances)
            .is_final(
                if is_final {
                    Bool::default()
                } else {
                    Bool::new_builder().set(False::default()).build()
                },
            )
            .version(version.pack())
            .build()
    }

    fn make_ckb_eth_state(
        cid: [u8; 32], version: u64, is_final: bool,
        ckb_a: u64, ckb_b: u64,
        chain_id: u128, addr: [u8; 20], eth_a: u128, eth_b: u128,
    ) -> ChannelState {
        let ckb = AnyBalancesUnion::CKByteDistribution(
            CKByteDistribution::new_builder().set([ckb_a.pack(), ckb_b.pack()]).build(),
        );
        let eth = AnyBalancesUnion::ETHBalances(
            ETHBalances::new_builder()
                .asset(ETHAsset::new_builder().chain_id(uint128(chain_id)).asset_address(eth_addr(addr)).build())
                .distribution(ETHDistribution::new_builder().nth0(uint128(eth_a)).nth1(uint128(eth_b)).build())
                .build(),
        );
        let balances = Balances::new_builder()
            .assets(
                Allocation::new_builder()
                    .push(AnyBalances::new_builder().set(ckb).build())
                    .push(AnyBalances::new_builder().set(eth).build())
                    .build(),
            )
            .locked(LockedBalances::default())
            .build();
        ChannelState::new_builder()
            .channel_id(Byte32::from_slice(&cid).unwrap())
            .balances(balances)
            .is_final(
                if is_final {
                    Bool::default()
                } else {
                    Bool::new_builder().set(False::default()).build()
                },
            )
            .version(version.pack())
            .build()
    }

    fn encode(state: &ChannelState) -> Vec<u8> {
        convert_ckb_state(state).abi_encode()
    }

    // baseline values shared across mutation tests
    const CID: [u8; 32] = [1u8; 32];
    const VER: u64 = 1;
    const CKB_A: u64 = 1_000_000_000;
    const CKB_B: u64 = 2_000_000_000;
    const CHAIN: u128 = 1337;
    const ADDR: [u8; 20] = [0xABu8; 20];
    const ETH_A: u128 = 1_000_000_000_000_000_000;
    const ETH_B: u128 = 500_000_000_000_000_000;

    // ── mutation tests ────────────────────────────────────────────────────

    #[test]
    fn mutate_channel_id() {
        let base    = make_ckb_state(CID,        VER, false, CKB_A, CKB_B);
        let mutated = make_ckb_state([2u8; 32],  VER, false, CKB_A, CKB_B);
        assert_ne!(encode(&base), encode(&mutated));
    }

    #[test]
    fn mutate_version() {
        let base    = make_ckb_state(CID, VER,     false, CKB_A, CKB_B);
        let mutated = make_ckb_state(CID, VER + 1, false, CKB_A, CKB_B);
        assert_ne!(encode(&base), encode(&mutated));
    }

    #[test]
    fn mutate_is_final() {
        let base    = make_ckb_state(CID, VER, false, CKB_A, CKB_B);
        let mutated = make_ckb_state(CID, VER, true,  CKB_A, CKB_B);
        assert_ne!(encode(&base), encode(&mutated));
    }

    #[test]
    fn mutate_ckb_balance_a() {
        let base    = make_ckb_state(CID, VER, false, CKB_A,     CKB_B);
        let mutated = make_ckb_state(CID, VER, false, CKB_A + 1, CKB_B);
        assert_ne!(encode(&base), encode(&mutated));
    }

    #[test]
    fn mutate_ckb_balance_b() {
        let base    = make_ckb_state(CID, VER, false, CKB_A, CKB_B);
        let mutated = make_ckb_state(CID, VER, false, CKB_A, CKB_B + 1);
        assert_ne!(encode(&base), encode(&mutated));
    }

    #[test]
    fn mutate_eth_balance_a() {
        let base    = make_ckb_eth_state(CID, VER, false, CKB_A, CKB_B, CHAIN, ADDR, ETH_A,     ETH_B);
        let mutated = make_ckb_eth_state(CID, VER, false, CKB_A, CKB_B, CHAIN, ADDR, ETH_A + 1, ETH_B);
        assert_ne!(encode(&base), encode(&mutated));
    }

    #[test]
    fn mutate_eth_balance_b() {
        let base    = make_ckb_eth_state(CID, VER, false, CKB_A, CKB_B, CHAIN, ADDR, ETH_A, ETH_B);
        let mutated = make_ckb_eth_state(CID, VER, false, CKB_A, CKB_B, CHAIN, ADDR, ETH_A, ETH_B + 1);
        assert_ne!(encode(&base), encode(&mutated));
    }

    #[test]
    fn mutate_eth_chain_id() {
        let base    = make_ckb_eth_state(CID, VER, false, CKB_A, CKB_B, CHAIN,     ADDR, ETH_A, ETH_B);
        let mutated = make_ckb_eth_state(CID, VER, false, CKB_A, CKB_B, CHAIN + 1, ADDR, ETH_A, ETH_B);
        assert_ne!(encode(&base), encode(&mutated));
    }

    #[test]
    fn mutate_eth_asset_address() {
        let mut other = ADDR;
        other[0] ^= 0xFF;
        let base    = make_ckb_eth_state(CID, VER, false, CKB_A, CKB_B, CHAIN, ADDR,  ETH_A, ETH_B);
        let mutated = make_ckb_eth_state(CID, VER, false, CKB_A, CKB_B, CHAIN, other, ETH_A, ETH_B);
        assert_ne!(encode(&base), encode(&mutated));
    }

    #[test]
    fn test_structs_and_fixedbytes() {
        // Initialize ParticipantSol
        let mut participant = ParticipantSol {
            ethAddress: Address::default(),
            ccAddress: PrimBytes::default(),
        };

        // Modify ParticipantSol fields
        // Use a fixed 20-byte array for ethAddress (Address uses 20 bytes internally)
        let eth_addr_bytes = [1u8; 20];
        participant.ethAddress = Address::from_slice(&eth_addr_bytes);

        // Use FixedBytes for ccAddress (assuming ccAddress is bytes type, 32 bytes here)
        let mut cc_addr_fb = FixedBytes::<32>::default();
        for i in 0..32 {
            cc_addr_fb[i] = i as u8;
        }
        participant.ccAddress = cc_addr_fb.into();

        // Initialize ParamsSol
        let mut params = ParamsSol {
            challengeDuration: U256::from(100u64),
            nonce: U256::from(42u64),
            participants: vec![participant],
            app: Address::default(),
            ledgerChannel: false,
            virtualChannel: true,
        };

        // Modify ParamsSol fields
        params.challengeDuration = U256::from(200u64);
        params.ledgerChannel = true;

        // Initialize FixedBytes directly and modify
        let mut fb = FixedBytes::<16>::default();
        for j in 0..16 {
            fb[j] = (j * 2) as u8;
        }
    }
}
