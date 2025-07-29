use ckb_testtool::ckb_traits::CellDataProvider;

use ckb_testtool::ckb_types::core::ScriptHashType;
use ckb_testtool::ckb_types::packed::{OutPoint, Script};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;

use k256::ecdsa::signature::hazmat::PrehashSigner;
use perun_common::*;

use perun_common::helpers::blake2b256;
use perun_common::perun_types::{ChannelState, ChannelStatus, VirtualChannelStatus};

use crate::perun;
use crate::perun::harness;
use crate::perun::random;
use crate::perun::test;
use crate::perun::test::transaction::{
    mk_vc_lc_update, mk_vc_merge, mk_vc_progress_no_update, mk_vc_update_only, AbortArgs,
    OpenResult, VCLCUpdateArgs, VCMergeArgs, VCProgressNoUpdateArgs, VCStartArgs, VCUpdateOnlyArgs,
};
use crate::perun::test::{keys, transaction};

use k256::ecdsa::{Signature, SigningKey};

use super::cell::FundingCell;
use super::transaction::{
    VCLCUpdateResult, VCMergeResult, VCProgressNoUpdateResult, VCUpdateOnlyResult,
};
use super::ChannelId;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct Client {
    pub index: u8,
    signing_key: SigningKey,
    name: String,
}

impl Client {
    pub fn new(idx: u8, name: String, sk: SigningKey) -> Client {
        Client {
            index: idx,
            name,
            signing_key: sk,
        }
    }

    // pubkey returns the public key of the client as a SEC1 encoded byte
    // array.
    pub fn pubkey(&self) -> [u8; 33] {
        keys::verifying_key_to_byte_array(&self.signing_key.verifying_key())
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn open(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        funding_agreement: &test::FundingAgreement,
    ) -> Result<(ChannelId, OpenResult), perun::Error> {
        // Prepare environment so that this party has the required funds.
        let inputs = env.create_funds_from_agreement(ctx, self.index, funding_agreement)?;
        // Create the channel token.
        let (channel_token, channel_token_outpoint) = env.create_channel_token(ctx);

        let pcls = env.build_pcls(ctx, Default::default());
        let pcls_code_hash = pcls.code_hash();
        let pfls_code_hash = ctx
            .get_cell_data_hash(&env.pfls_out_point)
            .expect("pfls hash");

        let parties = funding_agreement.mk_participants(ctx, env, env.min_capacity_no_script);

        let chan_params = perun_types::ChannelParametersBuilder::default()
            .party_a(parties[0].clone())
            .party_b(parties[1].clone())
            .nonce(random::nonce().pack())
            .challenge_duration(env.challenge_duration.pack())
            .app(Default::default())
            .is_ledger_channel(ctrue!())
            .is_virtual_channel(cfalse!())
            .build();
        let cid_raw = blake2b256(chan_params.as_slice());
        let cid = ChannelId::from(cid_raw);
        let chan_const = perun_types::ChannelConstantsBuilder::default()
            .params(chan_params)
            .pfls_code_hash(pfls_code_hash.clone())
            .pfls_hash_type(ScriptHashType::Data1.into())
            .pfls_min_capacity(env.min_capacity_pfls.pack())
            .pcls_code_hash(pcls_code_hash.clone())
            .pcls_hash_type(ScriptHashType::Data1.into())
            .thread_token(channel_token.clone())
            .build();

        let pcts = env.build_pcts(ctx, chan_const.as_bytes());
        let pfls = env.build_pfls(ctx, pcts.calc_script_hash().as_bytes());

        let args = transaction::OpenArgs {
            cid,
            funding_agreement: funding_agreement.clone(),
            channel_token_outpoint: channel_token_outpoint.clone(),
            inputs: inputs,
            party_index: self.index,
            pcls_script: pcls,
            pcts_script: pcts,
            pfls_script: pfls,
        };
        let or = transaction::mk_open(ctx, env, args)?;

        let cycles = ctx.verify_tx(&or.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok((cid, or))
    }

    pub fn fund(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        _cid: test::ChannelId,
        funding_agreement: &test::FundingAgreement,
        channel_cell: OutPoint,
        channel_state: ChannelStatus,
        pcts: Script,
    ) -> Result<transaction::FundResult, perun::Error> {
        // Prepare environment so that this party has the required funds.
        let inputs = env.create_funds_from_agreement(ctx, self.index, funding_agreement)?;
        let fr = transaction::mk_fund(
            ctx,
            env,
            transaction::FundArgs {
                channel_cell,
                funding_agreement: funding_agreement.clone(),
                party_index: self.index,
                state: channel_state,
                inputs,
                pcts,
            },
        )?;
        let cycles = ctx.verify_tx(&fr.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(fr)
    }

    pub fn send(
        &self,
        _ctx: Rc<Mutex<RefCell<Context>>>,
        _env: &harness::Env,
    ) -> Result<(), perun::Error> {
        Ok(())
    }

    pub fn sign(&self, state: ChannelState) -> Result<Vec<u8>, perun::Error> {
        let s: Signature = self
            .signing_key
            .sign_prehash(&perun_common::sig::ethereum_message_hash(state.as_slice()))?;
        Ok(Vec::from(s.to_der().as_bytes()))
    }

    pub fn dispute(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        _cid: test::ChannelId,
        channel_cell: OutPoint,
        channel_state: ChannelStatus,
        pcts: Script,
        sigs: [Vec<u8>; 2],
    ) -> Result<transaction::DisputeResult, perun::Error> {
        let dr = transaction::mk_dispute(
            ctx,
            env,
            transaction::DisputeArgs {
                channel_cell,
                state: channel_state,
                party_index: self.index,
                pcts_script: pcts,
                sigs,
            },
        )?;
        let cycles = ctx.verify_tx(&dr.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(dr)
    }

    pub fn vc_start(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        lc_dispute_args: transaction::DisputeArgs,
        vc_status: VirtualChannelStatus,
        sigs: [Vec<u8>; 2],
        vcts: Script,
    ) -> Result<transaction::VCStartResult, perun::Error> {
        let vcsr = transaction::mk_vc_start(
            ctx,
            env,
            VCStartArgs {
                parent_args: lc_dispute_args,
                vc_status: vc_status,
                sigs: sigs,
                vcts_script: vcts,
                party_index: self.index,
            },
        )?;
        let cycles = ctx.verify_tx(&vcsr.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(vcsr)
    }

    pub fn vc_progress_no_update(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        lc_dispute_args: transaction::DisputeArgs,
        vc_cell: OutPoint,
        vc_status: VirtualChannelStatus,
        vcts_script: Script,
    ) -> Result<VCProgressNoUpdateResult, perun::Error> {
        let vcp_no_update = mk_vc_progress_no_update(
            ctx,
            env,
            VCProgressNoUpdateArgs {
                parent_args: lc_dispute_args,
                vc_cell: vc_cell,
                vc_status: vc_status,
                vcts_script: vcts_script,
                party_index: self.index,
            },
        )?;
        let cycles = ctx.verify_tx(&vcp_no_update.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(vcp_no_update)
    }

    pub fn vc_update_only(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        lc_dispute_args: transaction::DisputeArgs,
        vc_cell: OutPoint,
        vc_status: VirtualChannelStatus,
        vc_sigs: [Vec<u8>; 2],
        vcts_script: Script,
    ) -> Result<VCUpdateOnlyResult, perun::Error> {
        //make tx
        let vc_update_only_result = mk_vc_update_only(
            ctx,
            env,
            VCUpdateOnlyArgs {
                parent_args: lc_dispute_args,
                vc_cell: vc_cell,
                vc_status: vc_status,
                sigs: vc_sigs,
                vcts_script: vcts_script,
                party_index: self.index,
            },
        )?;
        let cycles = ctx.verify_tx(&vc_update_only_result.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(vc_update_only_result)
    }

    pub fn vc_lc_update(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        lc_dispute_args: transaction::DisputeArgs,
        vc_cell: OutPoint,
        vc_status: VirtualChannelStatus,
        vc_sigs: [Vec<u8>; 2],
        vcts_script: Script,
    ) -> Result<VCLCUpdateResult, perun::Error> {
        //make tx
        let vc_lc_result = mk_vc_lc_update(
            ctx,
            env,
            VCLCUpdateArgs {
                parent_args: lc_dispute_args,
                vc_cell: vc_cell,
                vc_status: vc_status,
                sigs: vc_sigs,
                vcts_script: vcts_script,
                party_index: self.index,
            },
        )?;
        let cycles = ctx.verify_tx(&vc_lc_result.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(vc_lc_result)
    }

    pub fn vc_merge(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        vc_cell1: OutPoint,
        vc_cell2: OutPoint,
        vc_status1: VirtualChannelStatus,
        vc_status2: VirtualChannelStatus,
        vcts_script: Script,
        index: u8,
    ) -> Result<VCMergeResult, perun::Error> {
        //make tx
        let vc_merge_result = mk_vc_merge(
            ctx,
            env,
            VCMergeArgs {
                vc_cell1: vc_cell1,
                vc_cell2: vc_cell2,
                party_index: index,
                vc_status1: vc_status1,
                vc_status2: vc_status2,
                vcts_script: vcts_script,
            },
        )?;
        let cycles = ctx.verify_tx(&vc_merge_result.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(vc_merge_result)
    }

    pub fn abort(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        _cid: test::ChannelId,
        state: ChannelStatus,
        channel_cell: OutPoint,
        funds: Vec<FundingCell>,
    ) -> Result<transaction::AbortResult, perun::Error> {
        let ar = transaction::mk_abort(
            ctx,
            env,
            AbortArgs {
                channel_cell,
                funds,
                state,
                party_index: self.index,
            },
        )?;
        let cycles = ctx.verify_tx(&ar.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(ar)
    }

    pub fn close(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        _cid: test::ChannelId,
        channel_cell: OutPoint,
        funds_cells: Vec<FundingCell>,
        state: ChannelStatus,
        sigs: [Vec<u8>; 2],
    ) -> Result<transaction::CloseResult, perun::Error> {
        let cr = transaction::mk_close(
            ctx,
            env,
            transaction::CloseArgs {
                channel_cell,
                funds_cells,
                party_index: self.index,
                state,
                sigs,
            },
        )?;
        let cycles = ctx.verify_tx(&cr.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(cr)
    }

    pub fn force_close(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        _cid: test::ChannelId,
        channel_cell: OutPoint,
        funds_cells: Vec<FundingCell>,
        state: ChannelStatus,
    ) -> Result<transaction::ForceCloseResult, perun::Error> {
        // We will pass all available headers to the force close transaction.
        let hs = ctx.headers.keys().cloned().collect();
        let fcr = transaction::mk_force_close(
            ctx,
            env,
            transaction::ForceCloseArgs {
                headers: hs,
                channel_cell,
                party_index: self.index,
                funds_cells,
                state,
            },
        )?;
        let cycles = ctx.verify_tx(&fcr.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(fcr)
    }

    pub fn vc_close1(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        _cid: test::ChannelId,
        parent_cell: OutPoint,
        fund_cells: Vec<FundingCell>,
        parent_state: ChannelStatus,
        vc_cell: OutPoint,
        vc_status: VirtualChannelStatus,
        idx_map: perun::virtual_channel::IdxMapWithDirection,
        vcts: Script,
    ) -> Result<transaction::VCClose1Result, perun::Error> {
        let hs = ctx.headers.keys().cloned().collect();
        let vcc1r = transaction::mk_vc_close1(
            ctx,
            env,
            transaction::VCClose1Args {
                parent_args: transaction::ForceCloseArgs {
                    channel_cell: parent_cell,
                    headers: hs,
                    funds_cells: fund_cells,
                    state: parent_state,
                    party_index: self.index,
                },
                vc_cell: vc_cell,
                vc_status: vc_status,
                idx_map_with_direction: idx_map,
                vcts_script: vcts,
            },
        )?;
        let cycles = ctx.verify_tx(&vcc1r.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(vcc1r)
    }

    pub fn vc_close2(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        _cid: test::ChannelId,
        parent_cell: OutPoint,
        fund_cells: Vec<FundingCell>,
        parent_state: ChannelStatus,
        vc_cell: OutPoint,
        vc_status: VirtualChannelStatus,
        idx_map: perun::virtual_channel::IdxMapWithDirection,
        vcts: Script,
    ) -> Result<transaction::VCClose2Result, perun::Error> {
        let hs = ctx.headers.keys().cloned().collect();
        let vcc2r = transaction::mk_vc_close2(
            ctx,
            env,
            transaction::VCClose2Args {
                parent_args: transaction::ForceCloseArgs {
                    channel_cell: parent_cell,
                    headers: hs,
                    funds_cells: fund_cells,
                    state: parent_state,
                    party_index: self.index,
                },
                vc_cell: vc_cell,
                vc_status: vc_status,
                idx_map_with_direction: idx_map,
                vcts_script: vcts,
            },
        )?;
        let cycles = ctx.verify_tx(&vcc2r.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(vcc2r)
    }
}
