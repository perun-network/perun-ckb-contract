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
    perun_types::{Balances, ChannelConstants, ChannelState, LockedBalances, SUDTAllocation, SubAlloc, SubBalances, VirtualChannelStatus},
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


pub fn update_virtual_channel<'a>(fa: &'a FundingAgreement, cid: ChannelId, vc_to_lc_idx_map:&'a[u8;2]) 
    -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> + 'a {
    move |s| {
        // create a function for current balances of a lc, which takes another funding agreement with its locked 
        let locked = fa.mk_locked_balances(cid)?;
        let vc_alloc = locked.get(0).expect("no 0th in SubAlloc: no funds locked");
        // instead of creating locked balances, directly create balances and pass it to the new state.
        let locked_ckb_1 = vc_alloc.balances().ckbytes().get(0).expect("no ckbytes");
        let locked_ckb_2 = vc_alloc.balances().ckbytes().get(1).expect("no ckbytes");
        
        // let bals = s.clone().balances();
        let old_ckb_1 = s.balances().ckbytes().clone().get(vc_to_lc_idx_map[0].into()).expect("no ckbytes");
        let updated_ckb = old_ckb_1 - locked_ckb_1;
        
        let old_ckb_2 = s.balances().ckbytes().clone().get(vc_to_lc_idx_map[1].into()).expect("no ckbytes");
        let updated_ckb_2 = old_ckb_2 - locked_ckb_2;

        let updated_ckb_dist = s.balances().ckbytes().clone().as_builder()
            .nth0(updated_ckb.pack())
            .nth1(updated_ckb_2.pack())
            .build();
        

        let mut sudt_allocation_builder = SUDTAllocation::new_builder();

        for (_, vc_sudt_bals) in vc_alloc.balances().sudts().clone().into_iter().enumerate(){
            for(_, lc_sudt_bals) in s.balances().sudts().clone().into_iter().enumerate(){
                if vc_sudt_bals.asset().type_script().as_slice() == lc_sudt_bals.asset().type_script().as_slice(){
                    let locked_sudt_bals1 = vc_sudt_bals.distribution().get(0).expect("no 0th");
                    let locked_sudt_bals2 = vc_sudt_bals.distribution().get(1).expect("no 1st");
                    
                    let old_sudt_bals1 = lc_sudt_bals.distribution().get(vc_to_lc_idx_map[0].into()).expect("no 0th");
                    let old_sudt_bals2 = lc_sudt_bals.distribution().get(vc_to_lc_idx_map[1].into()).expect("no 1st");

                    let udpated_sudt_bals1 = old_sudt_bals1 - locked_sudt_bals1;
                    let udpated_sudt_bals2 = old_sudt_bals2 - locked_sudt_bals2;

                    let updated_sudt_dist = lc_sudt_bals.distribution().clone().as_builder()
                        .nth0(udpated_sudt_bals1.pack())
                        .nth1(udpated_sudt_bals2.pack())
                        .build();
                    let updated_sudt_bals = lc_sudt_bals.clone().as_builder()
                        .distribution(updated_sudt_dist)
                        .build();
                    sudt_allocation_builder = sudt_allocation_builder.push(updated_sudt_bals);
                }
            }
        }
        let sudt_alloc = sudt_allocation_builder.build();

        Ok(s.clone().as_builder()
                    .version((Unpack::<u64>::unpack(&s.version()) + 1u64).pack())
                    .balances(s.balances().clone().as_builder()
                        .ckbytes(updated_ckb_dist).sudts(sudt_alloc).locked(locked).build())
                    .build())
    }
}

// Need to pass the final state of the virtual channel
pub fn resolve_virtual_channel(vc_to_lc_idx_map:&[u8;2]) -> impl Fn(&ChannelState) -> Result<ChannelState, perun::Error> + use<'_> {
    |s| { 
        let locked = &s.balances().locked().get(0).expect("no funds locked");
        let old_ckbytes = &s.balances().ckbytes();
        // I need to return a state (ChannelState) with a balance that has nothing in the locked funds. 
        // The locked funds should be distributed according to the final balance in the virtual channel.
        
        let locked_balance_a = locked.balances().ckbytes().get(0).expect("no ckbytes locked");
        let locked_balance_b = locked.balances().ckbytes().get(1).expect("no ckbytes locked");
        // let diff = locked_balance_b - locked_balance_a;

        let new_ckbytes = &old_ckbytes.clone().as_builder()
                                    .nth0((old_ckbytes.get(0).expect("no 0th") + locked_balance_a).pack())
                                    .nth1((old_ckbytes.get(1).expect("no 1st") + locked_balance_b).pack())
                                    .build();   

        let mut sudt_allocation_builder = SUDTAllocation::new_builder();

        for(_, locked_sudt) in locked.balances().sudts().clone().into_iter().enumerate(){
            for (_, lc_sudt) in s.balances().sudts().clone().into_iter().enumerate(){
                if locked_sudt.asset().type_script().as_slice() == lc_sudt.asset().type_script().as_slice(){
                    let locked_sudt_bals1 = locked_sudt.distribution().get(0).expect("no 0th");
                    let locked_sudt_bals2 = locked_sudt.distribution().get(1).expect("no 1st");

                    let old_sudt_bals1 = lc_sudt.distribution().get(vc_to_lc_idx_map[0].into()).expect("no 0th");
                    let old_sudt_bals2 = lc_sudt.distribution().get(vc_to_lc_idx_map[1].into()).expect("no 1st");

                    let updated_sudt_bals1 = old_sudt_bals1 + locked_sudt_bals1;
                    let updated_sudt_bals2 = old_sudt_bals2 + locked_sudt_bals2;

                    let updated_sudt_dist = lc_sudt.distribution().clone().as_builder()
                        .nth0(updated_sudt_bals1.pack())
                        .nth1(updated_sudt_bals2.pack())
                        .build();
                    let updated_sudt_bals = lc_sudt.clone().as_builder()
                        .distribution(updated_sudt_dist)
                        .build();
                    sudt_allocation_builder = sudt_allocation_builder.push(updated_sudt_bals);
                }
            }
        }
        
        let sudt_alloc = sudt_allocation_builder.build();

        let new_balances = s.balances().clone().as_builder()
            .ckbytes(new_ckbytes.clone())
            .sudts(sudt_alloc)
            .locked(LockedBalances::new_builder().build())
            .build();

        Ok(s.clone().as_builder()
                    .version((Unpack::<u64>::unpack(&s.version()) + 1u64).pack())
                    .balances(new_balances)
                    .build())
    }
}