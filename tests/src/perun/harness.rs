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
    pub sample_udt_out_point: OutPoint,

    // Perun scripts.
    pcls_script: Script,
    pcts_script: Script,
    pfls_script: Script,
    pub pcls_script_dep: CellDep,
    pub pcts_script_dep: CellDep,
    pub pfls_script_dep: CellDep,
    // Auxiliary scripts.
    pub always_success_script: Script,
    pub always_success_script_dep: CellDep,
    pub sample_udt_script: Script,
    pub sample_udt_script_dep: CellDep,
    // Maximum amount of cycles used when verifying TXs.
    pub max_cycles: u64,
    pub min_capacity_no_script: Capacity,
    pub min_capacity_pfls: Capacity,
    pub sample_udt_max_cap: Capacity,
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
        let sample_udt: Bytes = Loader::default().load_binary("sample-udt");
        // Deploying the contracts returns the cell they are deployed in.
        let pcls_out_point = context.deploy_cell(pcls);
        let pcts_out_point = context.deploy_cell(pcts);
        let pfls_out_point = context.deploy_cell(pfls);
        let sample_udt_out_point = context.deploy_cell(sample_udt);
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
            .build_script(&pfls_out_point, Default::default())
            .ok_or("perun-funds-lockscript")?;
        let sample_udt_script = context
            .build_script(&sample_udt_out_point, Default::default())
            .ok_or("sample-udt")?;
        let pcls_script_dep = CellDep::new_builder()
            .out_point(pcls_out_point.clone())
            .build();
        let pcts_script_dep = CellDep::new_builder()
            .out_point(pcts_out_point.clone())
            .build();
        let pfls_script_dep = CellDep::new_builder()
            .out_point(pfls_out_point.clone())
            .build();
        let sample_udt_script_dep = CellDep::new_builder()
            .out_point(sample_udt_out_point.clone())
            .build();
        let sample_udt_max_cap = sample_udt_script.occupied_capacity()?.safe_mul(Capacity::shannons(10))?;
        // Auxiliary scripts.
        let always_success_script = context
            .build_script(&always_success_out_point, Bytes::from(vec![0]))
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
        let pfls_args_capacity = pcts_script.calc_script_hash().as_bytes().len() as u64;
        let min_capacity_pfls = tmp_output.occupied_capacity(pfls_args_capacity.into_capacity())?;
        println!("pfls code hash: {}", pfls_script.code_hash());
        println!("asset code hash: {}", sample_udt_script.code_hash());
        println!("pcts code hash: {}", pcts_script.code_hash());
        println!("pcls code hash: {}", pcls_script.code_hash());
        println!("always_success code hash: {}", always_success_script.code_hash());
        Ok(Env {
            pcls_out_point,
            pcts_out_point,
            pfls_out_point,
            always_success_out_point,
            sample_udt_out_point,
            pcls_script,
            pcts_script,
            pfls_script,
            pcls_script_dep,
            pcts_script_dep,
            pfls_script_dep,
            always_success_script,
            always_success_script_dep,
            sample_udt_script,
            sample_udt_script_dep,
            max_cycles,
            min_capacity_no_script,
            min_capacity_pfls,
            sample_udt_max_cap,
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

    pub fn build_lock_script(&self, context: &mut Context, args: Bytes) -> Script {
        let always_success_out_point = &self.always_success_out_point;
        context
            .build_script(always_success_out_point, args)
            .expect("always_success")
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

    /// create_funds_from_agreement creates a new cell with the funds for the given party index locked
    /// by the always_success_script parameterized on the party index.
    pub fn create_funds_from_agreement(
        &self,
        context: &mut Context,
        party_index: u8,
        funding_agreement: &FundingAgreement,
    ) -> Result<Vec<(OutPoint, Capacity)>, perun::Error> {
        let mut funds = self.create_ckbytes_funds_for_index(context, party_index, funding_agreement.expected_ckbytes_funding_for(party_index)?)?;
        funds.append(self.create_sudts_funds_for_index(context, party_index, funding_agreement.expected_sudts_funding_for(party_index)?)?.as_mut());
        return Ok(funds);
    }

    pub fn create_ckbytes_funds_for_index(
        &self,
        context: &mut Context,
        party_index: u8,
        required_funds: u64,
    ) -> Result<Vec<(OutPoint, Capacity)>, perun::Error> {
        // Create cell containing the required funds for this party.
        let my_output = CellOutput::new_builder()
            .capacity(required_funds.pack())
            // Lock cell using the correct party index.
            .lock(self.build_lock_script(context, Bytes::from(vec![party_index])))
            .build();
        let cell = context.create_cell(my_output.clone(), Bytes::default());
        Ok(vec![(cell, required_funds.into_capacity())])
    }

    pub fn create_sudts_funds_for_index(&self, context: &mut Context, party_index: u8, required_funds: Vec<(Script, Capacity, u128)>) -> Result<Vec<(OutPoint, Capacity)>, perun::Error> {
        let mut outs: Vec<(OutPoint, Capacity)> = Vec::new();
        for (sudt_script, capacity, amount) in required_funds {
            let my_output = CellOutput::new_builder()
                .capacity(capacity.pack())
                // Lock cell using the correct party index.
                .lock(self.build_lock_script(context, Bytes::from(vec![party_index])))
                .type_(Some(sudt_script).pack())
                .build();
            let cell = context.create_cell(my_output.clone(), Bytes::from(amount.to_le_bytes().to_vec()));
            outs.push((cell, capacity));
        }
        Ok(outs)
    }

    pub fn create_min_cell_for_index(&self, context: &mut Context, party_index: u8) -> OutPoint {
        self.create_ckbytes_funds_for_index(context, party_index, self.min_capacity_no_script.as_u64())
            .unwrap()
            .get(0).unwrap().clone().0
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
        let channel_status = ChannelStatusBuilder::default()
            .state(channel_state)
            .funded(cfalse!())
            .disputed(cfalse!())
            .build();
        Ok(channel_status)
    }
}
