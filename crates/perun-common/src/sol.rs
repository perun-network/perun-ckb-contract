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
use ckb_std::ckb_types::bytes;
use k256::{ecdsa::VerifyingKey, elliptic_curve::sec1::EncodedPoint, Secp256k1};
use sha3::{Digest, Keccak256};

use molecule::prelude::*;

use crate::{
    helpers::{bytes_to_u256, bytes_to_u64},
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

    // outer dimension are assets, inner dimension are participants
    let ckbytes = balances.ckbytes();

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

    for sudt_balance in balances.sudts().clone() {
        let asset_bytes = bytes::Bytes::from(sudt_balance.asset().as_bytes());
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
            bytes_to_u256(sudt_balance.distribution().nth0().as_slice()),
            bytes_to_u256(sudt_balance.distribution().nth1().as_slice()),
        ]);
    }

    for eth in balances.eth_assets().clone() {
        let chain_id = U256::from(u128::from_le_bytes({
            let cid = eth.asset().chain_id();
            let mut le = [0u8; 16];
            le.copy_from_slice(cid.as_slice());
            le
        }));
        assets.push(AssetSol {
            chainID: chain_id,
            ethHolder: Address::from_slice(eth.asset().asset_address().as_slice()),
            ccHolder: PrimBytes::default(),
        });

        balances_sol.push(vec![
            bytes_to_u256(eth.distribution().nth0().as_slice()),
            bytes_to_u256(eth.distribution().nth1().as_slice()),
        ]);
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
    let sec1_encoded_pubkey = participant.pub_key();
    let pubkey_bytes = sec1_encoded_pubkey.as_slice();
    let encoded_point = EncodedPoint::<Secp256k1>::from_bytes(pubkey_bytes)
        .expect("unable to decode SEC1EncodedPubKey bytes");

    let ecdsa_pubkey =
        VerifyingKey::from_encoded_point(&encoded_point).expect("unable to parse public key");

    let pubkey_uncompressed = ecdsa_pubkey.to_encoded_point(false);
    let pubkey_uncompressed_bytes = pubkey_uncompressed.as_bytes();

    let pubkey_no_prefix = &pubkey_uncompressed_bytes[1..];
    let mut hasher = Keccak256::new();
    hasher.update(pubkey_no_prefix);
    let eth_hash = hasher.finalize();
    let eth_address_bytes = &eth_hash[12..32];
    let eth_address = Address::from_slice(&eth_address_bytes);
    let cc_identity_bytes = participant.as_slice();

    ParticipantSol {
        ethAddress: eth_address,
        ccAddress: PrimBytes::copy_from_slice(cc_identity_bytes),
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;

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
