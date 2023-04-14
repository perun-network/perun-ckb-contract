use crate::perun;
use crate::Loader;
use ckb_occupied_capacity::{Capacity, IntoCapacity};
use ckb_testtool::{
    builtin::ALWAYS_SUCCESS,
    ckb_types::{bytes::Bytes, packed::*, prelude::*},
    context::Context,
};
use perun_common::cfalse;
use perun_common::perun_types::ChannelStateBuilder;
use perun_common::perun_types::ChannelStatusBuilder;
use perun_common::perun_types::{self, ChannelStatus, ChannelToken};

use super::test::Asset;
use super::test::ChannelId;
use super::test::FundingAgreement;
use super::test::FundingAgreementEntry;

// Env contains all chain information required for running Perun
// tests.
pub struct Env {
    // Perun contracts.
    pub pcls_out_point: OutPoint,
    pub pcts_out_point: OutPoint,
    pub pfls_out_point: OutPoint,
    // Auxiliary contracts.
    pub always_success_out_point: OutPoint,
    // Perun scripts.
    pub pcls_script: Script,
    pub pcts_script: Script,
    pub pfls_script: Script,
    pub pcls_script_dep: CellDep,
    pub pcts_script_dep: CellDep,
    pub pfls_script_dep: CellDep,
    // Auxiliary scripts.
    pub always_success_script: Script,
    pub always_success_script_dep: CellDep,
    // Maximum amount of cycles used when verifying TXs.
    pub max_cycles: u64,
    pub min_capacity_no_script: Capacity,
    pub min_capacity_pfls: Capacity,
    pub challenge_duration: u64,
}

impl Env {
    // prepare_env prepares the given context to be used for running Perun
    // tests.
    pub fn new(
        context: &mut Context,
        max_cycles: u64,
        challenge_duration: u64,
    ) -> Result<Env, perun::error::Error> {
        // Perun contracts.
        let pcls: Bytes = Loader::default().load_binary("perun-channel-lockscript");
        let pcts: Bytes = Loader::default().load_binary("perun-channel-typescript");
        let pfls: Bytes = Loader::default().load_binary("perun-funds-lockscript");
        // Deploying the contracts returns the cell they are deployed in.
        let pcls_out_point = context.deploy_cell(pcls);
        let pcts_out_point = context.deploy_cell(pcts);
        let pfls_out_point = context.deploy_cell(pfls);
        // Auxiliary contracts.
        let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

        // Prepare scripts.
        // Perun scripts.
        let pcls_script = context
            .build_script(&pcls_out_point, Default::default())
            .ok_or("perun-channel-lockscript")?;
        let pcts_script = context
            .build_script(
                &pcts_out_point,
                perun_types::ChannelConstants::default().as_bytes(),
            )
            .ok_or("perun-channel-typescript")?;
        let pfls_script = context
            .build_script(&pfls_out_point, perun_types::PFLSArgs::default().as_bytes())
            .ok_or("perun-funds-lockscript")?;
        let pcls_script_dep = CellDep::new_builder()
            .out_point(pcls_out_point.clone())
            .build();
        let pcts_script_dep = CellDep::new_builder()
            .out_point(pcts_out_point.clone())
            .build();
        let pfls_script_dep = CellDep::new_builder()
            .out_point(pfls_out_point.clone())
            .build();
        // Auxiliary scripts.
        let always_success_script = context
            .build_script(&always_success_out_point, Default::default())
            .expect("always_success");
        let always_success_script_dep = CellDep::new_builder()
            .out_point(always_success_out_point.clone())
            .build();

        // Calculate minimum amount of capacity required for a cell using the always success script.
        let tmp_output = CellOutput::new_builder()
            .capacity(0u64.pack())
            .lock(always_success_script.clone())
            .build();
        let min_capacity_no_script = tmp_output.occupied_capacity(0u64.into_capacity())?;

        // Calculate minimum amount of capacity required for a cell using the PFLS script.
        let tmp_output = CellOutput::new_builder()
            .capacity(0u64.pack())
            .lock(pfls_script.clone())
            .build();
        let pfls_args_capacity = perun_types::PFLSArgs::default().as_bytes().len() as u64;
        let min_capacity_pfls = tmp_output.occupied_capacity(pfls_args_capacity.into_capacity())?;

        Ok(Env {
            pcls_out_point,
            pcts_out_point,
            pfls_out_point,
            always_success_out_point,
            pcls_script,
            pcts_script,
            pfls_script,
            pcls_script_dep,
            pcts_script_dep,
            pfls_script_dep,
            always_success_script,
            always_success_script_dep,
            max_cycles,
            min_capacity_no_script,
            min_capacity_pfls,
            challenge_duration,
        })
    }

    pub fn build_pcls(&self, context: &mut Context, args: Bytes) -> Script {
        let pcls_out_point = &self.pcls_out_point;
        context
            .build_script(pcls_out_point, args)
            .expect("perun-channel-lockscript")
    }

    pub fn build_pcts(&self, context: &mut Context, args: Bytes) -> Script {
        let pcts_out_point = &self.pcts_out_point;
        context
            .build_script(pcts_out_point, args)
            .expect("perun-channel-typescript")
    }

    pub fn build_pfls(&self, context: &mut Context, args: Bytes) -> Script {
        let pfls_out_point = &self.pfls_out_point;
        context
            .build_script(pfls_out_point, args)
            .expect("perun-funds-lockscript")
    }

    pub fn min_capacity_for_channel(&self, cs: ChannelStatus) -> Result<Capacity, perun::Error> {
        let tmp_output = CellOutput::new_builder()
            .capacity(0u64.pack())
            .lock(self.pcls_script.clone())
            .type_(Some(self.pcts_script.clone()).pack())
            .build();
        let cs_capacity = Capacity::bytes(cs.as_bytes().len())?;
        let min_capacity = tmp_output.occupied_capacity(cs_capacity)?;
        Ok(min_capacity)
    }

    pub fn create_channel_token(&self, context: &mut Context) -> (ChannelToken, OutPoint) {
        let channel_token_outpoint = context.create_cell(
            CellOutput::new_builder()
                .capacity(self.min_capacity_no_script.pack())
                .lock(self.always_success_script.clone())
                .build(),
            Bytes::default(),
        );
        let packed_outpoint = OutPointBuilder::default()
            .tx_hash(channel_token_outpoint.tx_hash())
            .index(channel_token_outpoint.index())
            .build();
        (
            perun_types::ChannelTokenBuilder::default()
                .out_point(packed_outpoint.clone())
                .build(),
            packed_outpoint,
        )
    }

    pub fn create_funds_for_index(
        &self,
        context: &mut Context,
        party_index: u8,
        funding_agreement: &FundingAgreement,
    ) -> Result<(OutPoint, Capacity), perun::Error> {
        let wanted_amounts = funding_agreement
            .content()
            .iter()
            .find_map(
                |FundingAgreementEntry {
                     amounts,
                     index,
                     pub_key: _,
                 }| {
                    if *index == party_index {
                        Some(amounts.clone())
                    } else {
                        None
                    }
                },
            )
            .ok_or("invalid FundingAgreement")?;
        let required_funds = {
            // NOTE: Placeholder, we will assume we only handle CKBytes for now.
            match wanted_amounts
                .iter()
                .next()
                .ok_or("funding agreement contained no funds for client")?
            {
                (Asset(0), amount) => *amount,
                _else => return Err("invalid asset in FundingAgreement".into()),
            }
        };
        // Create cell containing the required funds for this party.
        let cell = context.create_cell(
            CellOutput::new_builder()
                .capacity(required_funds.pack())
                .lock(self.always_success_script.clone())
                .build(),
            Bytes::default(),
        );
        Ok((cell, required_funds.into_capacity()))
    }

    pub fn build_initial_channel_state(
        &self,
        channel_id: ChannelId,
        client_index: u8,
        funding_agreement: &FundingAgreement,
    ) -> Result<ChannelStatus, perun::Error> {
        let all_indices = funding_agreement
            .content()
            .iter()
            .map(|FundingAgreementEntry { index, .. }| *index)
            .collect::<Vec<_>>();
        let channel_balances = funding_agreement.mk_balances(all_indices)?;
        let channel_state = ChannelStateBuilder::default()
            .channel_id(channel_id.to_byte32())
            .balances(channel_balances)
            .version(Default::default())
            .is_final(cfalse!())
            .build();
        let funding_bals = funding_agreement.mk_balances([client_index].to_vec())?;
        let channel_status = ChannelStatusBuilder::default()
            .state(channel_state)
            .funded(cfalse!())
            .disputed(cfalse!())
            .funding(funding_bals)
            .build();
        Ok(channel_status)
    }
}
