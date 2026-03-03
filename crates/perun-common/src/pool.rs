/// pool.rs – shared data structures, serialisation helpers and AMM math
/// for the dual-asset CKB-ETH liquidity pool.
///
/// Mirrors the invariants enforced by LiquidityPool.sol on the CKB side.
///
/// # Wire format  (fixed-size, little-endian, no Molecule codegen needed)
///
/// ## PoolState  (168 bytes, magic b"PLST")
/// ```text
/// [0..4]    magic              "PLST"
/// [4..36]   operator_lock_hash (32 bytes)
/// [36..68]  pool_id            (32 bytes)
/// [68..76]  ckb_reserve        (u64 LE)
/// [76..92]  eth_reserve        (u128 LE)
/// [92..108] lp_token_supply    (u128 LE)
/// [108..112] swap_fee_bps      (u32 LE)
/// [112..120] ckb_reserved      (u64 LE) – locked in active channels
/// [120..136] eth_reserved      (u128 LE)
/// [136..144] accumulated_fee_ckb (u64 LE)
/// [144..160] accumulated_fee_eth (u128 LE)
/// [160..168] swap_count        (u64 LE)
/// ```
///
/// ## LPPosition  (141 bytes, magic b"LPPS")
/// ```text
/// [0..4]    magic              "LPPS"
/// [4..36]   pool_id            (32 bytes)
/// [36..68]  owner_lock_hash    (32 bytes)
/// [68..84]  lp_amount          (u128 LE)
/// [84..92]  ckb_amount         (u64 LE) – CKB principal deposited
/// [92..108] eth_amount         (u128 LE) – ETH-side principal
/// [108..116] accumulated_fees_ckb (u64 LE)
/// [116..132] accumulated_fees_eth (u128 LE)
/// [132..140] entry_timestamp   (u64 LE)
/// [140]     active             (u8: 0=inactive, 1=active)
/// ```
///
/// ## ChannelReservation  (101 bytes, magic b"CHRV")
/// ```text
/// [0..4]    magic   "CHRV"
/// [4..36]   pool_id      (32 bytes)
/// [36..68]  channel_id   (32 bytes)
/// [68..76]  ckb_reserved (u64 LE)
/// [76..92]  eth_reserved (u128 LE)
/// [92..100] timestamp    (u64 LE)
/// [100]     active       (u8: 0=inactive, 1=active)
/// ```
use crate::error::Error;

extern crate alloc;
use alloc::vec::Vec;

// ── Magic bytes ──────────────────────────────────────────────────────────────

pub const MAGIC_POOL_STATE: &[u8; 4] = b"PLST";
pub const MAGIC_LP_POSITION: &[u8; 4] = b"LPPS";
pub const MAGIC_CHANNEL_RES: &[u8; 4] = b"CHRV";

// ── Size constants ────────────────────────────────────────────────────────────

pub const POOL_STATE_SIZE: usize = 168;
pub const LP_POSITION_SIZE: usize = 141;
pub const CHANNEL_RES_SIZE: usize = 101;

// ── Pool-wide constants (mirror Solidity) ────────────────────────────────────

pub const MIN_LIQUIDITY: u64 = 1_000;
pub const FEE_DENOMINATOR: u64 = 10_000;
pub const MAX_RESERVATION_BLOCKS: u64 = 24 * 60 * 10; // ≈24 h at 10s/block

// ── Op codes ─────────────────────────────────────────────────────────────────

pub mod op {
    pub const INIT_POOL: u8 = 0x01;
    pub const ADD_LIQUIDITY: u8 = 0x02;
    pub const REMOVE_LIQUIDITY: u8 = 0x03;
    pub const OPERATOR_UPDATE: u8 = 0x04;
    pub const OPERATOR_CKB_OUT: u8 = 0x05;
    pub const OPERATOR_CKB_IN: u8 = 0x06;
    pub const RESERVE_FOR_CHANNEL: u8 = 0x07;
    pub const EXTRACT_TO_HUB: u8 = 0x08;
    pub const CANCEL_RESERVATION: u8 = 0x09;
    pub const REDISTRIBUTE_SETTLEMENT: u8 = 0x0A;
    pub const RECORD_SWAP: u8 = 0x0B;
    pub const CLAIM_FEES: u8 = 0x0C;
    pub const EMERGENCY_WITHDRAW: u8 = 0x0D;
}

// ── PoolState ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PoolState {
    pub pool_id: [u8; 32],
    pub operator_lock_hash: [u8; 32],
    pub ckb_reserve: u64,
    pub eth_reserve: u128,
    pub lp_token_supply: u128,
    pub swap_fee_bps: u32,
    /// CKB locked in active Perun channels (mirrors totalCKBReserved).
    pub ckb_reserved: u64,
    /// ETH locked in active channels (mirrors totalETHReserved).
    pub eth_reserved: u128,
    /// Undistributed CKB swap fees (mirrors accumulated fees).
    pub accumulated_fee_ckb: u64,
    /// Undistributed ETH-side fees.
    pub accumulated_fee_eth: u128,
    /// Total recorded swaps (monotone counter).
    pub swap_count: u64,
}

impl PoolState {
    /// CKB available for new reservations or withdrawals.
    pub fn available_ckb(&self) -> u64 {
        self.ckb_reserve.saturating_sub(self.ckb_reserved)
    }

    /// ETH available (mirrored).
    pub fn available_eth(&self) -> u128 {
        self.eth_reserve.saturating_sub(self.eth_reserved)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(POOL_STATE_SIZE);
        b.extend_from_slice(MAGIC_POOL_STATE);
        b.extend_from_slice(&self.operator_lock_hash);
        b.extend_from_slice(&self.pool_id);
        b.extend_from_slice(&self.ckb_reserve.to_le_bytes());
        b.extend_from_slice(&self.eth_reserve.to_le_bytes());
        b.extend_from_slice(&self.lp_token_supply.to_le_bytes());
        b.extend_from_slice(&self.swap_fee_bps.to_le_bytes());
        b.extend_from_slice(&self.ckb_reserved.to_le_bytes());
        b.extend_from_slice(&self.eth_reserved.to_le_bytes());
        b.extend_from_slice(&self.accumulated_fee_ckb.to_le_bytes());
        b.extend_from_slice(&self.accumulated_fee_eth.to_le_bytes());
        b.extend_from_slice(&self.swap_count.to_le_bytes());
        b
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < POOL_STATE_SIZE {
            return Err(Error::PoolStateTooShort);
        }
        if &data[0..4] != MAGIC_POOL_STATE {
            return Err(Error::PoolInvalidCellMagic);
        }
        let operator_lock_hash: [u8; 32] = data[4..36].try_into().unwrap();
        let pool_id: [u8; 32] = data[36..68].try_into().unwrap();
        let ckb_reserve = u64::from_le_bytes(data[68..76].try_into().unwrap());
        let eth_reserve = u128::from_le_bytes(data[76..92].try_into().unwrap());
        let lp_token_supply = u128::from_le_bytes(data[92..108].try_into().unwrap());
        let swap_fee_bps = u32::from_le_bytes(data[108..112].try_into().unwrap());
        let ckb_reserved = u64::from_le_bytes(data[112..120].try_into().unwrap());
        let eth_reserved = u128::from_le_bytes(data[120..136].try_into().unwrap());
        let accumulated_fee_ckb = u64::from_le_bytes(data[136..144].try_into().unwrap());
        let accumulated_fee_eth = u128::from_le_bytes(data[144..160].try_into().unwrap());
        let swap_count = u64::from_le_bytes(data[160..168].try_into().unwrap());
        Ok(Self {
            pool_id,
            operator_lock_hash,
            ckb_reserve,
            eth_reserve,
            lp_token_supply,
            swap_fee_bps,
            ckb_reserved,
            eth_reserved,
            accumulated_fee_ckb,
            accumulated_fee_eth,
            swap_count,
        })
    }

    pub fn is_pool_state(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == MAGIC_POOL_STATE
    }
}

// ── LPPosition ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct LPPosition {
    pub pool_id: [u8; 32],
    pub owner_lock_hash: [u8; 32],
    pub lp_amount: u128,
    pub ckb_amount: u64,
    pub eth_amount: u128,
    pub accumulated_fees_ckb: u64,
    pub accumulated_fees_eth: u128,
    pub entry_timestamp: u64,
    pub active: bool,
}

impl LPPosition {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(LP_POSITION_SIZE);
        b.extend_from_slice(MAGIC_LP_POSITION);
        b.extend_from_slice(&self.pool_id);
        b.extend_from_slice(&self.owner_lock_hash);
        b.extend_from_slice(&self.lp_amount.to_le_bytes());
        b.extend_from_slice(&self.ckb_amount.to_le_bytes());
        b.extend_from_slice(&self.eth_amount.to_le_bytes());
        b.extend_from_slice(&self.accumulated_fees_ckb.to_le_bytes());
        b.extend_from_slice(&self.accumulated_fees_eth.to_le_bytes());
        b.extend_from_slice(&self.entry_timestamp.to_le_bytes());
        b.push(if self.active { 1 } else { 0 });
        b
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < LP_POSITION_SIZE {
            return Err(Error::LPPositionTooShort);
        }
        if &data[0..4] != MAGIC_LP_POSITION {
            return Err(Error::PoolInvalidCellMagic);
        }
        let pool_id: [u8; 32] = data[4..36].try_into().unwrap();
        let owner_lock_hash: [u8; 32] = data[36..68].try_into().unwrap();
        let lp_amount = u128::from_le_bytes(data[68..84].try_into().unwrap());
        let ckb_amount = u64::from_le_bytes(data[84..92].try_into().unwrap());
        let eth_amount = u128::from_le_bytes(data[92..108].try_into().unwrap());
        let accumulated_fees_ckb = u64::from_le_bytes(data[108..116].try_into().unwrap());
        let accumulated_fees_eth = u128::from_le_bytes(data[116..132].try_into().unwrap());
        let entry_timestamp = u64::from_le_bytes(data[132..140].try_into().unwrap());
        let active = data[140] != 0;
        Ok(Self {
            pool_id,
            owner_lock_hash,
            lp_amount,
            ckb_amount,
            eth_amount,
            accumulated_fees_ckb,
            accumulated_fees_eth,
            entry_timestamp,
            active,
        })
    }

    pub fn is_lp_position(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == MAGIC_LP_POSITION
    }
}

// ── ChannelReservation ────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ChannelReservation {
    pub pool_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub ckb_reserved: u64,
    pub eth_reserved: u128,
    pub timestamp: u64,
    pub active: bool,
}

impl ChannelReservation {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(CHANNEL_RES_SIZE);
        b.extend_from_slice(MAGIC_CHANNEL_RES);
        b.extend_from_slice(&self.pool_id);
        b.extend_from_slice(&self.channel_id);
        b.extend_from_slice(&self.ckb_reserved.to_le_bytes());
        b.extend_from_slice(&self.eth_reserved.to_le_bytes());
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b.push(if self.active { 1 } else { 0 });
        b
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < CHANNEL_RES_SIZE {
            return Err(Error::Encoding);
        }
        if &data[0..4] != MAGIC_CHANNEL_RES {
            return Err(Error::PoolInvalidCellMagic);
        }
        let pool_id: [u8; 32] = data[4..36].try_into().unwrap();
        let channel_id: [u8; 32] = data[36..68].try_into().unwrap();
        let ckb_reserved = u64::from_le_bytes(data[68..76].try_into().unwrap());
        let eth_reserved = u128::from_le_bytes(data[76..92].try_into().unwrap());
        let timestamp = u64::from_le_bytes(data[92..100].try_into().unwrap());
        let active = data[100] != 0;
        Ok(Self {
            pool_id,
            channel_id,
            ckb_reserved,
            eth_reserved,
            timestamp,
            active,
        })
    }

    pub fn is_channel_reservation(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == MAGIC_CHANNEL_RES
    }
}

// ── PoolWitness ───────────────────────────────────────────────────────────────

pub enum PoolWitness {
    // Original ops
    InitPool {
        initial_eth_reserve: u128,
        swap_fee_bps: u32,
    },
    AddLiquidity {
        eth_in: u128,
        min_lp_out: u128,
    },
    RemoveLiquidity {
        min_ckb_out: u64,
        min_eth_out: u128,
    },
    OperatorUpdate {
        new_eth_reserve: u128,
        new_fee_bps: u32,
    },
    OperatorCKBOut {
        ckb_out: u64,
        new_eth_reserve: u128,
    },
    OperatorCKBIn {
        ckb_in: u64,
        new_eth_reserve: u128,
    },
    // Channel ops (dual-yield)
    ReserveForChannel {
        channel_id: [u8; 32],
        ckb_delta: u64,
        eth_delta: u128,
    },
    ExtractToHub {
        channel_id: [u8; 32],
    },
    CancelReservation {
        channel_id: [u8; 32],
    },
    RedistributeSettlement {
        channel_id: [u8; 32],
        ckb_returned: u64,
        eth_returned: u128,
        fee_ckb: u64,
        fee_eth: u128,
    },
    RecordSwap {
        channel_id: [u8; 32],
    },
    ClaimFees,
    EmergencyWithdraw,
}

impl PoolWitness {
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::PoolWitnessMissing);
        }
        match data[0] {
            op::INIT_POOL => {
                if data.len() < 1 + 16 + 4 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let initial_eth_reserve = u128::from_le_bytes(data[1..17].try_into().unwrap());
                let swap_fee_bps = u32::from_le_bytes(data[17..21].try_into().unwrap());
                Ok(Self::InitPool {
                    initial_eth_reserve,
                    swap_fee_bps,
                })
            }
            op::ADD_LIQUIDITY => {
                if data.len() < 1 + 16 + 16 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let eth_in = u128::from_le_bytes(data[1..17].try_into().unwrap());
                let min_lp_out = u128::from_le_bytes(data[17..33].try_into().unwrap());
                Ok(Self::AddLiquidity { eth_in, min_lp_out })
            }
            op::REMOVE_LIQUIDITY => {
                if data.len() < 1 + 8 + 16 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let min_ckb_out = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let min_eth_out = u128::from_le_bytes(data[9..25].try_into().unwrap());
                Ok(Self::RemoveLiquidity {
                    min_ckb_out,
                    min_eth_out,
                })
            }
            op::OPERATOR_UPDATE => {
                if data.len() < 1 + 16 + 4 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let new_eth_reserve = u128::from_le_bytes(data[1..17].try_into().unwrap());
                let new_fee_bps = u32::from_le_bytes(data[17..21].try_into().unwrap());
                Ok(Self::OperatorUpdate {
                    new_eth_reserve,
                    new_fee_bps,
                })
            }
            op::OPERATOR_CKB_OUT => {
                if data.len() < 1 + 8 + 16 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let ckb_out = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let new_eth_reserve = u128::from_le_bytes(data[9..25].try_into().unwrap());
                Ok(Self::OperatorCKBOut {
                    ckb_out,
                    new_eth_reserve,
                })
            }
            op::OPERATOR_CKB_IN => {
                if data.len() < 1 + 8 + 16 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let ckb_in = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let new_eth_reserve = u128::from_le_bytes(data[9..25].try_into().unwrap());
                Ok(Self::OperatorCKBIn {
                    ckb_in,
                    new_eth_reserve,
                })
            }
            op::RESERVE_FOR_CHANNEL => {
                if data.len() < 1 + 32 + 8 + 16 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id: [u8; 32] = data[1..33].try_into().unwrap();
                let ckb_delta = u64::from_le_bytes(data[33..41].try_into().unwrap());
                let eth_delta = u128::from_le_bytes(data[41..57].try_into().unwrap());
                Ok(Self::ReserveForChannel {
                    channel_id,
                    ckb_delta,
                    eth_delta,
                })
            }
            op::EXTRACT_TO_HUB => {
                if data.len() < 1 + 32 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id: [u8; 32] = data[1..33].try_into().unwrap();
                Ok(Self::ExtractToHub { channel_id })
            }
            op::CANCEL_RESERVATION => {
                if data.len() < 1 + 32 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id: [u8; 32] = data[1..33].try_into().unwrap();
                Ok(Self::CancelReservation { channel_id })
            }
            op::REDISTRIBUTE_SETTLEMENT => {
                if data.len() < 1 + 32 + 8 + 16 + 8 + 16 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id: [u8; 32] = data[1..33].try_into().unwrap();
                let ckb_returned = u64::from_le_bytes(data[33..41].try_into().unwrap());
                let eth_returned = u128::from_le_bytes(data[41..57].try_into().unwrap());
                let fee_ckb = u64::from_le_bytes(data[57..65].try_into().unwrap());
                let fee_eth = u128::from_le_bytes(data[65..81].try_into().unwrap());
                Ok(Self::RedistributeSettlement {
                    channel_id,
                    ckb_returned,
                    eth_returned,
                    fee_ckb,
                    fee_eth,
                })
            }
            op::RECORD_SWAP => {
                if data.len() < 1 + 32 {
                    return Err(Error::PoolWitnessInvalid);
                }
                let channel_id: [u8; 32] = data[1..33].try_into().unwrap();
                Ok(Self::RecordSwap { channel_id })
            }
            op::CLAIM_FEES => Ok(Self::ClaimFees),
            op::EMERGENCY_WITHDRAW => Ok(Self::EmergencyWithdraw),
            _ => Err(Error::PoolWitnessInvalid),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Self::InitPool {
                initial_eth_reserve,
                swap_fee_bps,
            } => {
                b.push(op::INIT_POOL);
                b.extend_from_slice(&initial_eth_reserve.to_le_bytes());
                b.extend_from_slice(&swap_fee_bps.to_le_bytes());
            }
            Self::AddLiquidity { eth_in, min_lp_out } => {
                b.push(op::ADD_LIQUIDITY);
                b.extend_from_slice(&eth_in.to_le_bytes());
                b.extend_from_slice(&min_lp_out.to_le_bytes());
            }
            Self::RemoveLiquidity {
                min_ckb_out,
                min_eth_out,
            } => {
                b.push(op::REMOVE_LIQUIDITY);
                b.extend_from_slice(&min_ckb_out.to_le_bytes());
                b.extend_from_slice(&min_eth_out.to_le_bytes());
            }
            Self::OperatorUpdate {
                new_eth_reserve,
                new_fee_bps,
            } => {
                b.push(op::OPERATOR_UPDATE);
                b.extend_from_slice(&new_eth_reserve.to_le_bytes());
                b.extend_from_slice(&new_fee_bps.to_le_bytes());
            }
            Self::OperatorCKBOut {
                ckb_out,
                new_eth_reserve,
            } => {
                b.push(op::OPERATOR_CKB_OUT);
                b.extend_from_slice(&ckb_out.to_le_bytes());
                b.extend_from_slice(&new_eth_reserve.to_le_bytes());
            }
            Self::OperatorCKBIn {
                ckb_in,
                new_eth_reserve,
            } => {
                b.push(op::OPERATOR_CKB_IN);
                b.extend_from_slice(&ckb_in.to_le_bytes());
                b.extend_from_slice(&new_eth_reserve.to_le_bytes());
            }
            Self::ReserveForChannel {
                channel_id,
                ckb_delta,
                eth_delta,
            } => {
                b.push(op::RESERVE_FOR_CHANNEL);
                b.extend_from_slice(channel_id);
                b.extend_from_slice(&ckb_delta.to_le_bytes());
                b.extend_from_slice(&eth_delta.to_le_bytes());
            }
            Self::ExtractToHub { channel_id } => {
                b.push(op::EXTRACT_TO_HUB);
                b.extend_from_slice(channel_id);
            }
            Self::CancelReservation { channel_id } => {
                b.push(op::CANCEL_RESERVATION);
                b.extend_from_slice(channel_id);
            }
            Self::RedistributeSettlement {
                channel_id,
                ckb_returned,
                eth_returned,
                fee_ckb,
                fee_eth,
            } => {
                b.push(op::REDISTRIBUTE_SETTLEMENT);
                b.extend_from_slice(channel_id);
                b.extend_from_slice(&ckb_returned.to_le_bytes());
                b.extend_from_slice(&eth_returned.to_le_bytes());
                b.extend_from_slice(&fee_ckb.to_le_bytes());
                b.extend_from_slice(&fee_eth.to_le_bytes());
            }
            Self::RecordSwap { channel_id } => {
                b.push(op::RECORD_SWAP);
                b.extend_from_slice(channel_id);
            }
            Self::ClaimFees => b.push(op::CLAIM_FEES),
            Self::EmergencyWithdraw => b.push(op::EMERGENCY_WITHDRAW),
        }
        b
    }
}

// ── AMM helpers ───────────────────────────────────────────────────────────────

/// Integer square root (Babylonian / Newton's method).
/// Mirrors the Solidity sqrt() used in LiquidityPool.sol for initial LP shares.
pub fn isqrt(y: u128) -> u128 {
    if y > 3 {
        let mut z = y;
        let mut x = y / 2 + 1;
        while x < z {
            z = x;
            x = (y / x + x) / 2;
        }
        z
    } else if y > 0 {
        1
    } else {
        0
    }
}

/// LP tokens minted for initial deposit: `sqrt(ckb_in * eth_in)`.
/// Returns None if the result would be < MIN_LIQUIDITY.
pub fn initial_lp_shares(ckb_in: u64, eth_in: u128) -> Option<u128> {
    let product = (ckb_in as u128).checked_mul(eth_in)?;
    let shares = isqrt(product);
    if shares >= MIN_LIQUIDITY as u128 {
        Some(shares)
    } else {
        None
    }
}

/// LP tokens minted for a subsequent dual-asset deposit.
/// Mirrors Solidity: `min(ckbShares, ethShares)` where each is
///   `amount * totalSupply / reserve`.
pub fn lp_tokens_for_deposit(
    ckb_in: u64,
    eth_in: u128,
    ckb_reserve: u64,
    eth_reserve: u128,
    lp_supply: u128,
) -> Option<u128> {
    if lp_supply == 0 || ckb_reserve == 0 || eth_reserve == 0 {
        return initial_lp_shares(ckb_in, eth_in);
    }
    let ckb_shares = (ckb_in as u128)
        .checked_mul(lp_supply)?
        .checked_div(ckb_reserve as u128)?;
    let eth_shares = eth_in.checked_mul(lp_supply)?.checked_div(eth_reserve)?;
    let shares = ckb_shares.min(eth_shares);
    if shares == 0 {
        None
    } else {
        Some(shares)
    }
}

/// CKB returned when burning `lp_burned` shares.
/// Uses *available* CKB (total − reserved) so channel-locked funds are safe.
pub fn ckb_for_lp_burn(lp_burned: u128, ckb_available: u64, lp_supply: u128) -> Option<u64> {
    if lp_supply == 0 {
        return None;
    }
    let n = lp_burned.checked_mul(ckb_available as u128)?;
    u64::try_from(n.checked_div(lp_supply)?).ok()
}

/// ETH returned when burning `lp_burned` shares (mirrored).
pub fn eth_for_lp_burn(lp_burned: u128, eth_available: u128, lp_supply: u128) -> Option<u128> {
    if lp_supply == 0 {
        return None;
    }
    lp_burned.checked_mul(eth_available)?.checked_div(lp_supply)
}

/// Constant-product swap output with fee deducted from input.
/// Mirrors `calculateSwapOutput` in LiquidityPool.sol:
///   fee        = input * fee_bps / FEE_DENOMINATOR
///   net_input  = input − fee
///   output     = (net_input * reserve_out) / (reserve_in + net_input)
pub struct SwapResult {
    pub output: u64,
    pub fee: u64,
}

pub fn calculate_swap_output(
    input_amount: u64,
    reserve_in: u64,  // available (total − reserved)
    reserve_out: u64, // available
    fee_bps: u32,
) -> Option<SwapResult> {
    if reserve_in == 0 || reserve_out == 0 {
        return None;
    }
    let fee = (input_amount as u128)
        .checked_mul(fee_bps as u128)?
        .checked_div(FEE_DENOMINATOR as u128)?;
    let fee = u64::try_from(fee).ok()?;
    let net_input = (input_amount as u128).checked_sub(fee as u128)?;
    let numerator = net_input.checked_mul(reserve_out as u128)?;
    let denominator = (reserve_in as u128).checked_add(net_input)?;
    let output = u64::try_from(numerator.checked_div(denominator)?).ok()?;
    if output >= reserve_out {
        return None;
    } // would drain reserve
    Some(SwapResult { output, fee })
}

/// Apply fee deduction to an amount (used for OperatorCKBOut).
pub fn apply_fee(amount: u64, fee_bps: u32) -> Option<u64> {
    let num = amount as u128 * (10_000 - fee_bps as u128);
    Some((num / 10_000) as u64)
}

/// LP fees claimable by one position.
/// Mirrors `calculateClaimableFees`:
///   fees = accumulated_pool_fees * lp_shares / lp_supply
pub fn claimable_fees(
    pool_fee_ckb: u64,
    pool_fee_eth: u128,
    lp_shares: u128,
    lp_supply: u128,
) -> Option<(u64, u128)> {
    if lp_supply == 0 {
        return Some((0, 0));
    }
    let ckb = u64::try_from(
        (pool_fee_ckb as u128)
            .checked_mul(lp_shares)?
            .checked_div(lp_supply)?,
    )
    .ok()?;
    let eth = pool_fee_eth
        .checked_mul(lp_shares)?
        .checked_div(lp_supply)?;
    Some((ckb, eth))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pool_state() -> PoolState {
        PoolState {
            pool_id: [0xAB; 32],
            operator_lock_hash: [0xCD; 32],
            ckb_reserve: 1_000_000_000,
            eth_reserve: 500_000_000_000_000_000,
            lp_token_supply: 1_000_000_000,
            swap_fee_bps: 30,
            ckb_reserved: 100_000_000,
            eth_reserved: 50_000_000_000_000_000,
            accumulated_fee_ckb: 5_000,
            accumulated_fee_eth: 2_500,
            swap_count: 42,
        }
    }

    #[test]
    fn roundtrip_pool_state() {
        let ps = dummy_pool_state();
        let enc = ps.encode();
        assert_eq!(enc.len(), POOL_STATE_SIZE);
        let dec = PoolState::decode(&enc).unwrap();
        assert_eq!(dec.pool_id, ps.pool_id);
        assert_eq!(dec.ckb_reserve, ps.ckb_reserve);
        assert_eq!(dec.eth_reserve, ps.eth_reserve);
        assert_eq!(dec.lp_token_supply, ps.lp_token_supply);
        assert_eq!(dec.swap_fee_bps, ps.swap_fee_bps);
        assert_eq!(dec.ckb_reserved, ps.ckb_reserved);
        assert_eq!(dec.accumulated_fee_ckb, ps.accumulated_fee_ckb);
        assert_eq!(dec.accumulated_fee_eth, ps.accumulated_fee_eth);
        assert_eq!(dec.swap_count, ps.swap_count);
    }

    #[test]
    fn pool_state_available() {
        let ps = dummy_pool_state(); // ckb_reserve=1e9, ckb_reserved=1e8
        assert_eq!(ps.available_ckb(), 900_000_000);
    }

    #[test]
    fn roundtrip_lp_position() {
        let lp = LPPosition {
            pool_id: [0x42; 32],
            owner_lock_hash: [0x11; 32],
            lp_amount: 999_888_777,
            ckb_amount: 500_000_000,
            eth_amount: 250_000_000_000_000_000,
            accumulated_fees_ckb: 100,
            accumulated_fees_eth: 50,
            entry_timestamp: 1_700_000_000,
            active: true,
        };
        let enc = lp.encode();
        assert_eq!(enc.len(), LP_POSITION_SIZE);
        let dec = LPPosition::decode(&enc).unwrap();
        assert_eq!(dec.pool_id, lp.pool_id);
        assert_eq!(dec.owner_lock_hash, lp.owner_lock_hash);
        assert_eq!(dec.lp_amount, lp.lp_amount);
        assert_eq!(dec.ckb_amount, lp.ckb_amount);
        assert_eq!(dec.accumulated_fees_ckb, lp.accumulated_fees_ckb);
        assert!(dec.active);
    }

    #[test]
    fn roundtrip_channel_reservation() {
        let cr = ChannelReservation {
            pool_id: [0x01; 32],
            channel_id: [0x02; 32],
            ckb_reserved: 200_000_000,
            eth_reserved: 100_000_000_000_000_000,
            timestamp: 1_000,
            active: true,
        };
        let enc = cr.encode();
        assert_eq!(enc.len(), CHANNEL_RES_SIZE);
        let dec = ChannelReservation::decode(&enc).unwrap();
        assert_eq!(dec.channel_id, cr.channel_id);
        assert_eq!(dec.ckb_reserved, cr.ckb_reserved);
        assert!(dec.active);
    }

    #[test]
    fn initial_lp_shares_sqrt() {
        // sqrt(1000 * 1000) = 1000, which equals MIN_LIQUIDITY
        assert_eq!(initial_lp_shares(1_000, 1_000), Some(1_000));
    }

    #[test]
    fn lp_proportional_deposit() {
        // Pool 10_000 ckb / 10_000 eth / 10_000 lp → deposit 1_000/1_000 → mint 1_000
        let minted = lp_tokens_for_deposit(1_000, 1_000, 10_000, 10_000, 10_000).unwrap();
        assert_eq!(minted, 1_000);
    }

    #[test]
    fn ckb_for_lp_burn_proportional() {
        // 10_000 ckb available, 10_000 lp; burn 2_000 → get 2_000
        assert_eq!(ckb_for_lp_burn(2_000, 10_000, 10_000), Some(2_000));
    }

    #[test]
    fn swap_output_basic() {
        let r = calculate_swap_output(1_000, 100_000, 100_000, 30).unwrap();
        // fee = 3; net = 997; out = 997*100000/(100000+997) ≈ 987
        assert_eq!(r.fee, 3);
        assert!(r.output < 1_000);
        assert!(r.output > 900);
    }

    #[test]
    fn apply_fee_30bps() {
        assert_eq!(apply_fee(1_000_000, 30), Some(997_000));
    }

    #[test]
    fn claimable_fees_proportional() {
        // Pool has 10_000 fee ckb, LP holds 5_000/10_000 shares → claim 5_000
        let (ckb, _) = claimable_fees(10_000, 0, 5_000, 10_000).unwrap();
        assert_eq!(ckb, 5_000);
    }

    #[test]
    fn witness_roundtrip_reserve_for_channel() {
        let ch = [0xFFu8; 32];
        let w = PoolWitness::ReserveForChannel {
            channel_id: ch,
            ckb_delta: 500,
            eth_delta: 250,
        };
        let enc = w.encode();
        match PoolWitness::decode(&enc).unwrap() {
            PoolWitness::ReserveForChannel {
                channel_id,
                ckb_delta,
                eth_delta,
            } => {
                assert_eq!(channel_id, ch);
                assert_eq!(ckb_delta, 500);
                assert_eq!(eth_delta, 250);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn witness_roundtrip_redistribute_settlement() {
        let ch = [0xAAu8; 32];
        let w = PoolWitness::RedistributeSettlement {
            channel_id: ch,
            ckb_returned: 1_000,
            eth_returned: 2_000,
            fee_ckb: 10,
            fee_eth: 20,
        };
        let enc = w.encode();
        match PoolWitness::decode(&enc).unwrap() {
            PoolWitness::RedistributeSettlement {
                fee_ckb, fee_eth, ..
            } => {
                assert_eq!(fee_ckb, 10);
                assert_eq!(fee_eth, 20);
            }
            _ => panic!("wrong variant"),
        }
    }
}
