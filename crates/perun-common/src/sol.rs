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

use alloy_primitives::{Address, Bytes as PrimBytes, U256};
use alloy_sol_types::sol;
use ckb_std::ckb_types::packed::Byte32;
use molecule::prelude::*;

use crate::{
    helpers::blake2b256,
    perun_types::{ChannelParameters, Participant},
};
use alloy_sol_types::SolValue;
// use ckb_types::prelude::Entity;

sol! {
    struct ParticipantSol {
        address ethAddress;
        bytes ccIdentity;
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

pub fn convert_participant(participant: Participant) -> ParticipantSol {
    let ckb_pubkey = participant.pub_key();
    let ckb_pubkey_bytes = ckb_pubkey.as_slice();
    let ckb_pay_min_capacity = participant.payment_min_capacity();
    let ckb_pay_min_capacity_bytes = ckb_pay_min_capacity.as_slice();
    let ckb_pay_script_hash = participant.payment_script_hash();
    let ckb_pay_script_hash_bytes = ckb_pay_script_hash.as_slice();

    let ckb_unlock_script_hash = participant.unlock_script_hash();
    let ckb_unlock_script_hash_bytes = ckb_unlock_script_hash.as_slice();

    let cc_eth_addr = participant.eth_address();
    let cc_eth_addr_bytes = cc_eth_addr.as_slice();

    let total_len = ckb_pubkey_bytes.len()
        + ckb_pay_min_capacity_bytes.len()
        + ckb_pay_script_hash_bytes.len()
        + ckb_unlock_script_hash_bytes.len();
    let mut cc_identity_bytes = Vec::with_capacity(total_len);
    cc_identity_bytes.extend_from_slice(ckb_pubkey_bytes);
    cc_identity_bytes.extend_from_slice(ckb_pay_min_capacity_bytes);
    cc_identity_bytes.extend_from_slice(ckb_pay_script_hash_bytes);
    cc_identity_bytes.extend_from_slice(ckb_unlock_script_hash_bytes);

    let ethaddr = Address::from_slice(cc_eth_addr_bytes);

    ParticipantSol {
        ethAddress: ethaddr,
        ccIdentity: PrimBytes::copy_from_slice(&cc_identity_bytes),
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
    // let chall_duration = U256::from_be_bytes(chall_duration_array);
    let chall_duration_u64 = u64::from_be_bytes(chall_duration_array);
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

pub fn get_channel_id_cross(params: &ChannelParameters) -> Byte32 {
    let params_sol = convert_params(params);

    let encoded_data = params_sol.abi_encode();

    let digest = blake2b256(&encoded_data);
    let byte32_digest =
        Byte32::from_slice(&digest).expect("Failed to create Byte32 from digest slice");
    return byte32_digest;
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
            ccIdentity: PrimBytes::default(),
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
        participant.ccIdentity = cc_addr_fb.into();

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
