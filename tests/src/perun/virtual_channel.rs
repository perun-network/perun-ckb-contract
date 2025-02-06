use ckb_testtool::{
    ckb_types::{
        packed::{Header, OutPoint, RawHeader, Script},
        prelude::{Builder, Entity, Pack, Unpack},
    },
    context::Context,
};
use k256::ecdsa::VerifyingKey;
use perun_common::{
    ctrue,
    perun_types::{ChannelConstants, VirtualChannelStatus, ChannelState, SubBalances, LockedBalances, SubAlloc, Balances},
};

use crate::perun::{
    self,
    test::{keys, Client, ChannelId},
};
use crate::perun::{harness, test};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::fmt::Debug;
use super::test::FundingAgreement;
use super::{test::cell::FundingCell, Account};


pub fn update_virtual_channel<'a>(fa: &'a FundingAgreement, cid: ChannelId) 
    -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> + 'a {
    move |s| { 
        let locked = fa.mk_locked_balances(cid)?;
        
        Ok(s.clone().as_builder()
                    .version((Unpack::<u64>::unpack(&s.version()) + 1u64).pack())
                    .balances(s.balances().as_builder().locked(locked).build())
                    .build())
    }
}

pub fn resolve_virtual_channel() -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> {
    |s| { 
        let locked = &s.balances().locked();

        let old_ckbytes = &s.balances().ckbytes(); 

        let locked_balance_a = locked.get(0).expect("no 0th").balances().ckbytes().get(1).expect("no ckbytes");
        let locked_balance_b = locked.get(0).expect("no 1st").balances().ckbytes().get(0).expect("no ckbytes");
        let diff = locked_balance_b - locked_balance_a;

        let new_ckbytes = &old_ckbytes.clone().as_builder()
                                    .nth0((old_ckbytes.get(0).expect("no 0th") + diff).pack())
                                    .nth1((old_ckbytes.get(1).expect("no 1st") - diff).pack())
                                    .build();   

        let new_balances = Balances::new_builder()
            .ckbytes(new_ckbytes.clone())
            .sudts(s.balances().sudts())
            .build();


        Ok(s.clone().as_builder()
                    .version((Unpack::<u64>::unpack(&s.version()) + 1u64).pack())
                    .balances(new_balances)
                    .build())
    }
}