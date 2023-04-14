use ckb_testtool::ckb_types::{
    packed::{Byte, Byte32, Byte32Builder},
    prelude::Builder,
};
use rand::Rng;

#[derive(Clone, Copy)]
pub struct ChannelId(u32);

impl ChannelId {
    pub fn new() -> Self {
        ChannelId(0)
    }

    pub fn new_random() -> Self {
        ChannelId(rand::thread_rng().gen())
    }

    pub fn to_byte32(&self) -> Byte32 {
        let mut byte32: [Byte; 32] = [0u8.into(); 32];
        let x = self.0.to_le_bytes();
        let y = x.iter().map(|x| (*x).into()).collect::<Vec<Byte>>();
        byte32[..4].copy_from_slice(&y);
        Byte32Builder::default().set(byte32).build();
        Default::default()
    }
}
