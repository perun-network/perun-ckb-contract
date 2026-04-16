use crate::error::Error;
use crate::liquidity_pool_types as lp_types;

use molecule::prelude::{Builder, Entity};

extern crate alloc;
use alloc::vec::Vec;

pub const MAGIC_LP_CELL: &[u8; 4] = b"LPLC";

pub const LP_CELL_SIZE: usize = 153;
const LP_OFFSET_POOL_ID: usize = 4;
const LP_OFFSET_OWNER_LOCK_HASH: usize = LP_OFFSET_POOL_ID + 32;
const LP_OFFSET_OPERATOR_LOCK_HASH: usize = LP_OFFSET_OWNER_LOCK_HASH + 32;
const LP_OFFSET_AVAILABLE_CKB: usize = LP_OFFSET_OPERATOR_LOCK_HASH + 32;
const LP_OFFSET_RESERVED_CKB: usize = LP_OFFSET_AVAILABLE_CKB + 8;
const LP_OFFSET_CUMULATIVE_FEES: usize = LP_OFFSET_RESERVED_CKB + 8;
const LP_OFFSET_MAX_TRADING_VOLUME: usize = LP_OFFSET_CUMULATIVE_FEES + 8;
const LP_OFFSET_FEE_RATE_BPS: usize = LP_OFFSET_MAX_TRADING_VOLUME + 8;
const LP_OFFSET_POLICY_FLAGS: usize = LP_OFFSET_FEE_RATE_BPS + 4;
const LP_OFFSET_POLICY_VERSION: usize = LP_OFFSET_POLICY_FLAGS + 4;
const LP_OFFSET_NONCE: usize = LP_OFFSET_POLICY_VERSION + 4;
const LP_OFFSET_ACTIVE: usize = LP_OFFSET_NONCE + 8;

const LP_END_POOL_ID: usize = LP_OFFSET_POOL_ID + 32;
const LP_END_OWNER_LOCK_HASH: usize = LP_OFFSET_OWNER_LOCK_HASH + 32;
const LP_END_OPERATOR_LOCK_HASH: usize = LP_OFFSET_OPERATOR_LOCK_HASH + 32;
const LP_END_AVAILABLE_CKB: usize = LP_OFFSET_AVAILABLE_CKB + 8;
const LP_END_RESERVED_CKB: usize = LP_OFFSET_RESERVED_CKB + 8;
const LP_END_CUMULATIVE_FEES: usize = LP_OFFSET_CUMULATIVE_FEES + 8;
const LP_END_MAX_TRADING_VOLUME: usize = LP_OFFSET_MAX_TRADING_VOLUME + 8;
const LP_END_FEE_RATE_BPS: usize = LP_OFFSET_FEE_RATE_BPS + 4;
const LP_END_POLICY_FLAGS: usize = LP_OFFSET_POLICY_FLAGS + 4;
const LP_END_POLICY_VERSION: usize = LP_OFFSET_POLICY_VERSION + 4;
const LP_END_NONCE: usize = LP_OFFSET_NONCE + 8;
const LP_END_ACTIVE: usize = LP_OFFSET_ACTIVE + 1;

const _: [(); LP_CELL_SIZE] = [(); LP_END_ACTIVE];
const _: [(); 4] = [(); MAGIC_LP_CELL.len()];

const WITNESS_LEN_LP_DEPOSIT: usize = 1;
const WITNESS_LEN_LP_WITHDRAW: usize = 9;
const WITNESS_LEN_FUND_CHANNEL_EXTRACT: usize = 73;
const WITNESS_LEN_SETTLE_CHANNEL_INSERT: usize = 97;
const WITNESS_LEN_CANCEL_RESERVATION: usize = 65;
const WITNESS_LEN_ROTATE_OPERATOR: usize = 33;

const WITNESS_OFFSET_CHANNEL_ID: usize = 1;
const WITNESS_OFFSET_WITHDRAW_CKB_OUT: usize = 1;
const WITNESS_OFFSET_CONTRIBUTION_ID: usize = WITNESS_OFFSET_CHANNEL_ID + 32;
const WITNESS_OFFSET_U64_A: usize = WITNESS_OFFSET_CONTRIBUTION_ID + 32;
const WITNESS_OFFSET_U64_B: usize = WITNESS_OFFSET_U64_A + 8;
const WITNESS_OFFSET_U128: usize = WITNESS_OFFSET_U64_B + 8;
const WITNESS_OFFSET_ROTATE_OPERATOR: usize = 1;

const WITNESS_END_CHANNEL_ID: usize = WITNESS_OFFSET_CHANNEL_ID + 32;
const WITNESS_END_WITHDRAW_CKB_OUT: usize = WITNESS_OFFSET_WITHDRAW_CKB_OUT + 8;
const WITNESS_END_CONTRIBUTION_ID: usize = WITNESS_OFFSET_CONTRIBUTION_ID + 32;
const WITNESS_END_U64_A: usize = WITNESS_OFFSET_U64_A + 8;
const WITNESS_END_U64_B: usize = WITNESS_OFFSET_U64_B + 8;
const WITNESS_END_U128: usize = WITNESS_OFFSET_U128 + 16;
const WITNESS_END_ROTATE_OPERATOR: usize = WITNESS_OFFSET_ROTATE_OPERATOR + 32;

const _: [(); WITNESS_LEN_LP_WITHDRAW] = [(); WITNESS_END_WITHDRAW_CKB_OUT];
const _: [(); WITNESS_LEN_FUND_CHANNEL_EXTRACT] = [(); WITNESS_END_U64_A];
const _: [(); WITNESS_LEN_SETTLE_CHANNEL_INSERT] = [(); WITNESS_END_U128];
const _: [(); WITNESS_LEN_CANCEL_RESERVATION] = [(); WITNESS_END_CONTRIBUTION_ID];
const _: [(); WITNESS_LEN_ROTATE_OPERATOR] = [(); WITNESS_END_ROTATE_OPERATOR];

pub mod op {
    pub const LP_DEPOSIT: u8 = 0x41;
    pub const LP_WITHDRAW: u8 = 0x42;
    pub const FUND_CHANNEL_EXTRACT: u8 = 0x43;
    pub const SETTLE_CHANNEL_INSERT: u8 = 0x44;
    pub const CANCEL_RESERVATION: u8 = 0x45;
    pub const ROTATE_OPERATOR: u8 = 0x46;
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LPPolicyFlag {
    EnforceMaxFee = 1 << 0,
    EnforceMinFee = 1 << 1,
    RequirePrice = 1 << 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LPPolicyFlags(u32);

impl LPPolicyFlags {
    pub const ALLOWED_MASK: u32 = (LPPolicyFlag::EnforceMaxFee as u32)
        | (LPPolicyFlag::EnforceMinFee as u32)
        | (LPPolicyFlag::RequirePrice as u32);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn with(self, flag: LPPolicyFlag) -> Self {
        Self(self.0 | (flag as u32))
    }

    pub const fn contains(self, flag: LPPolicyFlag) -> bool {
        (self.0 & (flag as u32)) != 0
    }

    pub const fn has_unknown_bits(self) -> bool {
        (self.0 & !Self::ALLOWED_MASK) != 0
    }
}

#[derive(Clone, Debug)]
pub struct LPPolicy {
    pub max_trading_volume: u64,
    pub fee_rate_bps: u32,
    pub policy_flags: u32,
    pub policy_version: u32,
}

#[derive(Clone, Debug)]
pub struct LPCell {
    pub pool_id: [u8; 32],
    pub owner_lock_hash: [u8; 32],
    pub operator_lock_hash: [u8; 32],
    pub available_ckb: u64,
    pub reserved_ckb: u64,
    pub cumulative_fees_earned_ckb: u64,
    pub policy: LPPolicy,
    pub nonce: u64,
    pub active: bool,
}

impl LPCell {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(LP_CELL_SIZE);
        b.extend_from_slice(MAGIC_LP_CELL);
        b.extend_from_slice(&self.pool_id);
        b.extend_from_slice(&self.owner_lock_hash);
        b.extend_from_slice(&self.operator_lock_hash);
        b.extend_from_slice(&self.available_ckb.to_le_bytes());
        b.extend_from_slice(&self.reserved_ckb.to_le_bytes());
        b.extend_from_slice(&self.cumulative_fees_earned_ckb.to_le_bytes());
        b.extend_from_slice(&self.policy.max_trading_volume.to_le_bytes());
        b.extend_from_slice(&self.policy.fee_rate_bps.to_le_bytes());
        b.extend_from_slice(&self.policy.policy_flags.to_le_bytes());
        b.extend_from_slice(&self.policy.policy_version.to_le_bytes());
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b.push(if self.active { 1 } else { 0 });
        b
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() != LP_CELL_SIZE {
            return Err(Error::Encoding);
        }
        if &data[0..LP_OFFSET_POOL_ID] != MAGIC_LP_CELL {
            return Err(Error::PoolInvalidCellMagic);
        }
        let pool_id: [u8; 32] = data[LP_OFFSET_POOL_ID..LP_END_POOL_ID].try_into().unwrap();
        let owner_lock_hash: [u8; 32] = data[LP_OFFSET_OWNER_LOCK_HASH..LP_END_OWNER_LOCK_HASH]
            .try_into()
            .unwrap();
        let operator_lock_hash: [u8; 32] = data
            [LP_OFFSET_OPERATOR_LOCK_HASH..LP_END_OPERATOR_LOCK_HASH]
            .try_into()
            .unwrap();
        let available_ckb = u64::from_le_bytes(
            data[LP_OFFSET_AVAILABLE_CKB..LP_END_AVAILABLE_CKB]
                .try_into()
                .unwrap(),
        );
        let reserved_ckb = u64::from_le_bytes(
            data[LP_OFFSET_RESERVED_CKB..LP_END_RESERVED_CKB]
                .try_into()
                .unwrap(),
        );
        let cumulative_fees_earned_ckb = u64::from_le_bytes(
            data[LP_OFFSET_CUMULATIVE_FEES..LP_END_CUMULATIVE_FEES]
                .try_into()
                .unwrap(),
        );
        let max_trading_volume = u64::from_le_bytes(
            data[LP_OFFSET_MAX_TRADING_VOLUME..LP_END_MAX_TRADING_VOLUME]
                .try_into()
                .unwrap(),
        );
        let fee_rate_bps = u32::from_le_bytes(
            data[LP_OFFSET_FEE_RATE_BPS..LP_END_FEE_RATE_BPS]
                .try_into()
                .unwrap(),
        );
        let policy_flags = u32::from_le_bytes(
            data[LP_OFFSET_POLICY_FLAGS..LP_END_POLICY_FLAGS]
                .try_into()
                .unwrap(),
        );
        let policy_version = u32::from_le_bytes(
            data[LP_OFFSET_POLICY_VERSION..LP_END_POLICY_VERSION]
                .try_into()
                .unwrap(),
        );
        let nonce = u64::from_le_bytes(data[LP_OFFSET_NONCE..LP_END_NONCE].try_into().unwrap());
        let active = data[LP_OFFSET_ACTIVE] != 0;

        Ok(Self {
            pool_id,
            owner_lock_hash,
            operator_lock_hash,
            available_ckb,
            reserved_ckb,
            cumulative_fees_earned_ckb,
            policy: LPPolicy {
                max_trading_volume,
                fee_rate_bps,
                policy_flags,
                policy_version,
            },
            nonce,
            active,
        })
    }

    pub fn is_lp_cell(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == MAGIC_LP_CELL
    }
}

pub enum PoolWitness {
    LPDeposit,
    LPWithdraw {
        ckb_out: u64,
    },
    FundChannelExtract {
        channel_id: [u8; 32],
        contribution_id: [u8; 32],
        extract_ckb: u64,
    },
    SettleChannelInsert {
        channel_id: [u8; 32],
        contribution_id: [u8; 32],
        principal_returned: u64,
        fee_ckb: u64,
        price_x64: u128,
    },
    CancelReservation {
        channel_id: [u8; 32],
        contribution_id: [u8; 32],
    },
    RotateOperator {
        new_operator_lock_hash: [u8; 32],
    },
}

impl PoolWitness {
    fn canonicalize_via_generated(self) -> Result<Self, Error> {
        let molecule_entity = self.to_generated_entity();
        Self::from_generated_entity(&molecule_entity)
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::PoolWitnessMissing);
        }
        let decoded = match data[0] {
            op::LP_DEPOSIT => {
                if data.len() != WITNESS_LEN_LP_DEPOSIT {
                    return Err(Error::PoolWitnessInvalid);
                }
                Ok(Self::LPDeposit)
            }
            op::LP_WITHDRAW => {
                if data.len() != WITNESS_LEN_LP_WITHDRAW {
                    return Err(Error::PoolWitnessInvalid);
                }
                let ckb_out = u64::from_le_bytes(
                    data[WITNESS_OFFSET_WITHDRAW_CKB_OUT..WITNESS_END_WITHDRAW_CKB_OUT]
                        .try_into()
                        .unwrap(),
                );
                Ok(Self::LPWithdraw { ckb_out })
            }
            op::FUND_CHANNEL_EXTRACT => {
                if data.len() != WITNESS_LEN_FUND_CHANNEL_EXTRACT {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id = data[WITNESS_OFFSET_CHANNEL_ID..WITNESS_END_CHANNEL_ID]
                    .try_into()
                    .unwrap();
                let contribution_id = data
                    [WITNESS_OFFSET_CONTRIBUTION_ID..WITNESS_END_CONTRIBUTION_ID]
                    .try_into()
                    .unwrap();
                let extract_ckb = u64::from_le_bytes(
                    data[WITNESS_OFFSET_U64_A..WITNESS_END_U64_A]
                        .try_into()
                        .unwrap(),
                );
                Ok(Self::FundChannelExtract {
                    channel_id,
                    contribution_id,
                    extract_ckb,
                })
            }
            op::SETTLE_CHANNEL_INSERT => {
                if data.len() != WITNESS_LEN_SETTLE_CHANNEL_INSERT {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id = data[WITNESS_OFFSET_CHANNEL_ID..WITNESS_END_CHANNEL_ID]
                    .try_into()
                    .unwrap();
                let contribution_id = data
                    [WITNESS_OFFSET_CONTRIBUTION_ID..WITNESS_END_CONTRIBUTION_ID]
                    .try_into()
                    .unwrap();
                let principal_returned = u64::from_le_bytes(
                    data[WITNESS_OFFSET_U64_A..WITNESS_END_U64_A]
                        .try_into()
                        .unwrap(),
                );
                let fee_ckb = u64::from_le_bytes(
                    data[WITNESS_OFFSET_U64_B..WITNESS_END_U64_B]
                        .try_into()
                        .unwrap(),
                );
                let price_x64 = u128::from_le_bytes(
                    data[WITNESS_OFFSET_U128..WITNESS_END_U128]
                        .try_into()
                        .unwrap(),
                );
                Ok(Self::SettleChannelInsert {
                    channel_id,
                    contribution_id,
                    principal_returned,
                    fee_ckb,
                    price_x64,
                })
            }
            op::CANCEL_RESERVATION => {
                if data.len() != WITNESS_LEN_CANCEL_RESERVATION {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id = data[WITNESS_OFFSET_CHANNEL_ID..WITNESS_END_CHANNEL_ID]
                    .try_into()
                    .unwrap();
                let contribution_id = data
                    [WITNESS_OFFSET_CONTRIBUTION_ID..WITNESS_END_CONTRIBUTION_ID]
                    .try_into()
                    .unwrap();
                Ok(Self::CancelReservation {
                    channel_id,
                    contribution_id,
                })
            }
            op::ROTATE_OPERATOR => {
                if data.len() != WITNESS_LEN_ROTATE_OPERATOR {
                    return Err(Error::PoolWitnessInvalid);
                }
                let new_operator_lock_hash = data
                    [WITNESS_OFFSET_ROTATE_OPERATOR..WITNESS_END_ROTATE_OPERATOR]
                    .try_into()
                    .unwrap();
                Ok(Self::RotateOperator {
                    new_operator_lock_hash,
                })
            }
            _ => Err(Error::PoolWitnessInvalid),
        }?;
        decoded.canonicalize_via_generated()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Self::LPDeposit => b.push(op::LP_DEPOSIT),
            Self::LPWithdraw { ckb_out } => {
                b.push(op::LP_WITHDRAW);
                b.extend_from_slice(&ckb_out.to_le_bytes());
            }
            Self::FundChannelExtract {
                channel_id,
                contribution_id,
                extract_ckb,
            } => {
                b.push(op::FUND_CHANNEL_EXTRACT);
                b.extend_from_slice(channel_id);
                b.extend_from_slice(contribution_id);
                b.extend_from_slice(&extract_ckb.to_le_bytes());
            }
            Self::SettleChannelInsert {
                channel_id,
                contribution_id,
                principal_returned,
                fee_ckb,
                price_x64,
            } => {
                b.push(op::SETTLE_CHANNEL_INSERT);
                b.extend_from_slice(channel_id);
                b.extend_from_slice(contribution_id);
                b.extend_from_slice(&principal_returned.to_le_bytes());
                b.extend_from_slice(&fee_ckb.to_le_bytes());
                b.extend_from_slice(&price_x64.to_le_bytes());
            }
            Self::CancelReservation {
                channel_id,
                contribution_id,
            } => {
                b.push(op::CANCEL_RESERVATION);
                b.extend_from_slice(channel_id);
                b.extend_from_slice(contribution_id);
            }
            Self::RotateOperator {
                new_operator_lock_hash,
            } => {
                b.push(op::ROTATE_OPERATOR);
                b.extend_from_slice(new_operator_lock_hash);
            }
        }
        b
    }

    fn to_generated_entity(&self) -> lp_types::PoolWitness {
        match self {
            Self::LPDeposit => lp_types::PoolWitness::new_builder()
                .set(lp_types::LPDepositWitness::new_builder().build())
                .build(),
            Self::LPWithdraw { ckb_out } => lp_types::PoolWitness::new_builder()
                .set(
                    lp_types::LPWithdrawWitness::new_builder()
                        .ckb_out((*ckb_out).to_le_bytes().into())
                        .build(),
                )
                .build(),
            Self::FundChannelExtract {
                channel_id,
                contribution_id,
                extract_ckb,
            } => lp_types::PoolWitness::new_builder()
                .set(
                    lp_types::FundChannelExtractWitness::new_builder()
                        .channel_id((*channel_id).into())
                        .contribution_id((*contribution_id).into())
                        .extract_ckb((*extract_ckb).to_le_bytes().into())
                        .build(),
                )
                .build(),
            Self::SettleChannelInsert {
                channel_id,
                contribution_id,
                principal_returned,
                fee_ckb,
                price_x64,
            } => lp_types::PoolWitness::new_builder()
                .set(
                    lp_types::SettleChannelInsertWitness::new_builder()
                        .channel_id((*channel_id).into())
                        .contribution_id((*contribution_id).into())
                        .principal_returned((*principal_returned).to_le_bytes().into())
                        .fee_ckb((*fee_ckb).to_le_bytes().into())
                        .price_x64((*price_x64).to_le_bytes().into())
                        .build(),
                )
                .build(),
            Self::CancelReservation {
                channel_id,
                contribution_id,
            } => lp_types::PoolWitness::new_builder()
                .set(
                    lp_types::CancelReservationWitness::new_builder()
                        .channel_id((*channel_id).into())
                        .contribution_id((*contribution_id).into())
                        .build(),
                )
                .build(),
            Self::RotateOperator {
                new_operator_lock_hash,
            } => lp_types::PoolWitness::new_builder()
                .set(
                    lp_types::RotateOperatorWitness::new_builder()
                        .new_operator_lock_hash((*new_operator_lock_hash).into())
                        .build(),
                )
                .build(),
        }
    }

    fn from_generated_entity(entity: &lp_types::PoolWitness) -> Result<Self, Error> {
        use lp_types::PoolWitnessUnion;

        match entity.to_enum() {
            PoolWitnessUnion::LPDepositWitness(_) => Ok(Self::LPDeposit),
            PoolWitnessUnion::LPWithdrawWitness(w) => {
                let ckb_out: [u8; 8] = w.ckb_out().into();
                Ok(Self::LPWithdraw {
                    ckb_out: u64::from_le_bytes(ckb_out),
                })
            }
            PoolWitnessUnion::FundChannelExtractWitness(w) => {
                let channel_id: [u8; 32] = w.channel_id().into();
                let contribution_id: [u8; 32] = w.contribution_id().into();
                let extract_ckb: [u8; 8] = w.extract_ckb().into();
                Ok(Self::FundChannelExtract {
                    channel_id,
                    contribution_id,
                    extract_ckb: u64::from_le_bytes(extract_ckb),
                })
            }
            PoolWitnessUnion::SettleChannelInsertWitness(w) => {
                let channel_id: [u8; 32] = w.channel_id().into();
                let contribution_id: [u8; 32] = w.contribution_id().into();
                let principal_returned: [u8; 8] = w.principal_returned().into();
                let fee_ckb: [u8; 8] = w.fee_ckb().into();
                let price_x64: [u8; 16] = w.price_x64().into();
                Ok(Self::SettleChannelInsert {
                    channel_id,
                    contribution_id,
                    principal_returned: u64::from_le_bytes(principal_returned),
                    fee_ckb: u64::from_le_bytes(fee_ckb),
                    price_x64: u128::from_le_bytes(price_x64),
                })
            }
            PoolWitnessUnion::CancelReservationWitness(w) => {
                let channel_id: [u8; 32] = w.channel_id().into();
                let contribution_id: [u8; 32] = w.contribution_id().into();
                Ok(Self::CancelReservation {
                    channel_id,
                    contribution_id,
                })
            }
            PoolWitnessUnion::RotateOperatorWitness(w) => {
                let new_operator_lock_hash: [u8; 32] = w.new_operator_lock_hash().into();
                Ok(Self::RotateOperator {
                    new_operator_lock_hash,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample_cell() -> LPCell {
        LPCell {
            pool_id: [1u8; 32],
            owner_lock_hash: [2u8; 32],
            operator_lock_hash: [3u8; 32],
            available_ckb: 100,
            reserved_ckb: 10,
            cumulative_fees_earned_ckb: 7,
            policy: LPPolicy {
                max_trading_volume: 500,
                fee_rate_bps: 25,
                policy_flags: 1,
                policy_version: 1,
            },
            nonce: 9,
            active: true,
        }
    }

    #[test]
    fn roundtrip_lp_cell() {
        let c = sample_cell();
        let enc = c.encode();
        assert_eq!(enc.len(), LP_CELL_SIZE);
        let dec = LPCell::decode(&enc).unwrap();
        assert_eq!(dec.pool_id, c.pool_id);
        assert_eq!(dec.owner_lock_hash, c.owner_lock_hash);
        assert_eq!(dec.operator_lock_hash, c.operator_lock_hash);
        assert_eq!(dec.available_ckb, 100);
        assert_eq!(dec.reserved_ckb, 10);
        assert_eq!(dec.cumulative_fees_earned_ckb, 7);
        assert_eq!(dec.policy.max_trading_volume, 500);
        assert_eq!(dec.policy.fee_rate_bps, 25);
        assert_eq!(dec.policy.policy_flags, 1);
        assert_eq!(dec.policy.policy_version, 1);
        assert_eq!(dec.nonce, 9);
        assert!(dec.active);
    }

    #[test]
    fn lp_cell_decode_rejects_bad_magic_and_short_input() {
        let mut enc = sample_cell().encode();
        enc[0] = b'X';
        assert!(matches!(
            LPCell::decode(&enc),
            Err(Error::PoolInvalidCellMagic)
        ));

        let short = vec![0u8; LP_CELL_SIZE - 1];
        assert!(matches!(LPCell::decode(&short), Err(Error::Encoding)));

        let mut with_trailing = sample_cell().encode();
        with_trailing.push(0);
        assert!(matches!(
            LPCell::decode(&with_trailing),
            Err(Error::Encoding)
        ));
    }

    #[test]
    fn lp_cell_decode_rejects_non_lp_magic_and_version_prefix() {
        let mut non_lp_like = vec![0u8; LP_CELL_SIZE];
        non_lp_like[0..4].copy_from_slice(b"POOL");
        // Non-LP payload hint: bytes 4..8 are populated like an external format version field.
        non_lp_like[4..8].copy_from_slice(&1u32.to_le_bytes());

        assert!(!LPCell::is_lp_cell(&non_lp_like));
        assert!(matches!(
            LPCell::decode(&non_lp_like),
            Err(Error::PoolInvalidCellMagic)
        ));
    }

    #[test]
    fn is_lp_cell_checks_magic_prefix_only() {
        let enc = sample_cell().encode();
        assert!(LPCell::is_lp_cell(&enc));

        let non_lp = vec![0u8; 8];
        assert!(!LPCell::is_lp_cell(&non_lp));
    }

    #[test]
    fn roundtrip_witness_all_variants() {
        let cases = vec![
            PoolWitness::LPDeposit,
            PoolWitness::LPWithdraw { ckb_out: 777 },
            PoolWitness::FundChannelExtract {
                channel_id: [4u8; 32],
                contribution_id: [5u8; 32],
                extract_ckb: 42,
            },
            PoolWitness::SettleChannelInsert {
                channel_id: [6u8; 32],
                contribution_id: [7u8; 32],
                principal_returned: 123,
                fee_ckb: 9,
                price_x64: 99,
            },
            PoolWitness::CancelReservation {
                channel_id: [8u8; 32],
                contribution_id: [9u8; 32],
            },
            PoolWitness::RotateOperator {
                new_operator_lock_hash: [10u8; 32],
            },
        ];

        for w in cases {
            let enc = w.encode();
            let dec = PoolWitness::decode(&enc).unwrap();
            let enc2 = dec.encode();
            assert_eq!(enc, enc2);
        }
    }

    #[test]
    fn witness_decode_rejects_invalid_opcode_or_short_payload() {
        assert!(matches!(
            PoolWitness::decode(&[]),
            Err(Error::PoolWitnessMissing)
        ));

        // Reserve low opcode range as a non-LP namespace for boundary safety.
        assert!(matches!(
            PoolWitness::decode(&[0x01]),
            Err(Error::PoolWitnessInvalid)
        ));

        assert!(matches!(
            PoolWitness::decode(&[0xFF]),
            Err(Error::PoolWitnessInvalid)
        ));

        assert!(matches!(
            PoolWitness::decode(&[op::LP_WITHDRAW, 1, 2, 3]),
            Err(Error::PoolWitnessInvalid)
        ));

        assert!(matches!(
            PoolWitness::decode(&vec![op::FUND_CHANNEL_EXTRACT; 72]),
            Err(Error::PoolWitnessInvalid)
        ));

        assert!(matches!(
            PoolWitness::decode(&vec![op::SETTLE_CHANNEL_INSERT; 96]),
            Err(Error::PoolWitnessInvalid)
        ));

        assert!(matches!(
            PoolWitness::decode(&vec![op::CANCEL_RESERVATION; 64]),
            Err(Error::PoolWitnessInvalid)
        ));

        assert!(matches!(
            PoolWitness::decode(&vec![op::ROTATE_OPERATOR; 32]),
            Err(Error::PoolWitnessInvalid)
        ));

        assert!(matches!(
            PoolWitness::decode(&[op::LP_DEPOSIT, 0]),
            Err(Error::PoolWitnessInvalid)
        ));

        let mut long_withdraw = vec![op::LP_WITHDRAW];
        long_withdraw.extend_from_slice(&7u64.to_le_bytes());
        long_withdraw.push(0);
        assert!(matches!(
            PoolWitness::decode(&long_withdraw),
            Err(Error::PoolWitnessInvalid)
        ));

        assert!(matches!(
            PoolWitness::decode(&[0x47]),
            Err(Error::PoolWitnessInvalid)
        ));

        assert!(matches!(
            PoolWitness::decode(&[0x48]),
            Err(Error::PoolWitnessInvalid)
        ));
    }

    #[test]
    fn opcode_values_are_frozen_for_mvp() {
        assert_eq!(op::LP_DEPOSIT, 0x41);
        assert_eq!(op::LP_WITHDRAW, 0x42);
        assert_eq!(op::FUND_CHANNEL_EXTRACT, 0x43);
        assert_eq!(op::SETTLE_CHANNEL_INSERT, 0x44);
        assert_eq!(op::CANCEL_RESERVATION, 0x45);
        assert_eq!(op::ROTATE_OPERATOR, 0x46);
    }
}
