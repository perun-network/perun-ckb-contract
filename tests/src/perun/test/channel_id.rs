use ckb_testtool::ckb_types::{
    packed::{Byte, Byte32, Byte32Builder},
    prelude::Builder,
};
use rand::Rng;

#[derive(Debug, Clone, Copy)]
pub struct ChannelId([u8; 32]);

impl ChannelId {
    pub fn new() -> Self {
        ChannelId(Default::default())
    }

    pub fn new_random() -> Self {
        ChannelId(rand::thread_rng().gen())
    }

    pub fn to_byte32(&self) -> Byte32 {
        let mut byte32: [Byte; 32] = [0u8.into(); 32];
        let x = self.0;
        let y = x.iter().map(|x| (*x).into()).collect::<Vec<Byte>>();
        byte32.copy_from_slice(&y);
        Byte32Builder::default().set(byte32).build()
    }
}

impl From<[u8; 32]> for ChannelId {
    fn from(bytes: [u8; 32]) -> Self {
        ChannelId(bytes)
    }
}

impl Default for ChannelId {
    fn default() -> Self {
        ChannelId([0u8; 32])
    }
}
