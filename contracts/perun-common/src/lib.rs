#![no_std]

use ckb_std::ckb_types::bytes::Bytes;

// Create a struct
#[derive(Debug)]
pub struct ChannelParameters {
    // Participants is an array of addresses.
    pub participants: [Address; 2],
    pub nonce: Bytes,
}

pub type Address = [u8; 32];
