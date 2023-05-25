use crate::perun;
use ckb_testtool::ckb_types::prelude::{Unpack, Pack};
use molecule::prelude::{Entity, Builder};
use perun_common::perun_types::ChannelState;


pub fn id() -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    |s| Ok(s.clone())
}

pub fn bump_version() -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    |s| Ok(s.clone().as_builder().version((Unpack::<u64>::unpack(&s.version()) + 1u64).pack()).build())
}