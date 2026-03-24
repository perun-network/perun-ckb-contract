use crate::error::Error;

extern crate alloc;
use alloc::vec::Vec;

pub const MAGIC_LP_CELL: &[u8; 4] = b"LPLC";

pub const LP_CELL_SIZE: usize = 153;

pub mod op {
    pub const LP_DEPOSIT: u8 = 0x41;
    pub const LP_WITHDRAW: u8 = 0x42;
    pub const FUND_CHANNEL_EXTRACT: u8 = 0x43;
    pub const SETTLE_CHANNEL_INSERT: u8 = 0x44;
    pub const CANCEL_RESERVATION: u8 = 0x45;
    pub const ROTATE_OPERATOR: u8 = 0x46;
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
        if data.len() < LP_CELL_SIZE {
            return Err(Error::Encoding);
        }
        if &data[0..4] != MAGIC_LP_CELL {
            return Err(Error::PoolInvalidCellMagic);
        }
        let pool_id: [u8; 32] = data[4..36].try_into().unwrap();
        let owner_lock_hash: [u8; 32] = data[36..68].try_into().unwrap();
        let operator_lock_hash: [u8; 32] = data[68..100].try_into().unwrap();
        let available_ckb = u64::from_le_bytes(data[100..108].try_into().unwrap());
        let reserved_ckb = u64::from_le_bytes(data[108..116].try_into().unwrap());
        let cumulative_fees_earned_ckb = u64::from_le_bytes(data[116..124].try_into().unwrap());
        let max_trading_volume = u64::from_le_bytes(data[124..132].try_into().unwrap());
        let fee_rate_bps = u32::from_le_bytes(data[132..136].try_into().unwrap());
        let policy_flags = u32::from_le_bytes(data[136..140].try_into().unwrap());
        let policy_version = u32::from_le_bytes(data[140..144].try_into().unwrap());
        let nonce = u64::from_le_bytes(data[144..152].try_into().unwrap());
        let active = data[152] != 0;

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
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::PoolWitnessMissing);
        }
        match data[0] {
            op::LP_DEPOSIT => Ok(Self::LPDeposit),
            op::LP_WITHDRAW => {
                if data.len() < 9 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let ckb_out = u64::from_le_bytes(data[1..9].try_into().unwrap());
                Ok(Self::LPWithdraw { ckb_out })
            }
            op::FUND_CHANNEL_EXTRACT => {
                if data.len() < 73 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id = data[1..33].try_into().unwrap();
                let contribution_id = data[33..65].try_into().unwrap();
                let extract_ckb = u64::from_le_bytes(data[65..73].try_into().unwrap());
                Ok(Self::FundChannelExtract {
                    channel_id,
                    contribution_id,
                    extract_ckb,
                })
            }
            op::SETTLE_CHANNEL_INSERT => {
                if data.len() < 97 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id = data[1..33].try_into().unwrap();
                let contribution_id = data[33..65].try_into().unwrap();
                let principal_returned = u64::from_le_bytes(data[65..73].try_into().unwrap());
                let fee_ckb = u64::from_le_bytes(data[73..81].try_into().unwrap());
                let price_x64 = u128::from_le_bytes(data[81..97].try_into().unwrap());
                Ok(Self::SettleChannelInsert {
                    channel_id,
                    contribution_id,
                    principal_returned,
                    fee_ckb,
                    price_x64,
                })
            }
            op::CANCEL_RESERVATION => {
                if data.len() < 65 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id = data[1..33].try_into().unwrap();
                let contribution_id = data[33..65].try_into().unwrap();
                Ok(Self::CancelReservation {
                    channel_id,
                    contribution_id,
                })
            }
            op::ROTATE_OPERATOR => {
                if data.len() < 33 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let new_operator_lock_hash = data[1..33].try_into().unwrap();
                Ok(Self::RotateOperator {
                    new_operator_lock_hash,
                })
            }
            _ => Err(Error::PoolWitnessInvalid),
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_lp_cell() {
        let c = LPCell {
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
        };
        let enc = c.encode();
        assert_eq!(enc.len(), LP_CELL_SIZE);
        let dec = LPCell::decode(&enc).unwrap();
        assert_eq!(dec.available_ckb, 100);
        assert_eq!(dec.policy.fee_rate_bps, 25);
        assert!(dec.active);
    }

    #[test]
    fn roundtrip_witness_extract() {
        let w = PoolWitness::FundChannelExtract {
            channel_id: [4u8; 32],
            contribution_id: [5u8; 32],
            extract_ckb: 42,
        };
        let enc = w.encode();
        match PoolWitness::decode(&enc).unwrap() {
            PoolWitness::FundChannelExtract { extract_ckb, .. } => assert_eq!(extract_ckb, 42),
            _ => panic!("unexpected witness variant"),
        }
    }
}
