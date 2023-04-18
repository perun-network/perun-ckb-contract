use ckb_testtool::ckb_traits::CellDataProvider;
use ckb_testtool::ckb_types::bytes::Bytes;
use ckb_testtool::ckb_types::core::{ScriptHashType, TransactionBuilder};
use ckb_testtool::ckb_types::packed::{
    Byte32, Bytes as PackedBytes, BytesBuilder, CellInput, CellOutput, OutPoint, OutPointBuilder,
    Script, ScriptOptBuilder,
};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;

use k256::ecdsa::signature::hazmat::PrehashSigner;
use perun_common::*;

use ckb_occupied_capacity::{Capacity, IntoCapacity};
use perun_common::helpers::blake2b256;
use perun_common::perun_types::{ChannelState, ChannelStatus};

use crate::perun;
use crate::perun::harness;
use crate::perun::random;
use crate::perun::test::transaction::{AbortArgs, OpenResult};
use crate::perun::test::{self, Asset};
use crate::perun::test::{keys, transaction};

use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    SecretKey,
};

use super::cell::FundingCell;
use super::transaction::FundResult;
use super::ChannelId;

#[derive(Clone, Debug)]
pub struct Client {
    index: u8,
    signing_key: SigningKey,
}

impl Client {
    pub fn new(idx: u8, sk: SigningKey) -> Client {
        Client {
            index: idx,
            signing_key: sk,
        }
    }

    // pubkey returns the public key of the client as a SEC1 encoded byte
    // array.
    pub fn pubkey(&self) -> [u8; 65] {
        keys::verifying_key_to_byte_array(&self.signing_key.verifying_key())
    }

    pub fn open(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        funding_agreement: &test::FundingAgreement,
    ) -> Result<(ChannelId, OpenResult), perun::Error> {
        // Prepare environment so that this party has the required funds.
        let (my_funds_outpoint, my_funds) =
            env.create_funds_for_index(ctx, self.index, funding_agreement)?;
        // Create the channel token.
        let (channel_token, channel_token_outpoint) = env.create_channel_token(ctx);

        let pcls = env.build_pcls(ctx, Default::default());
        let pcls_code_hash = ctx
            .get_cell_data_hash(&env.pcls_out_point)
            .expect("pcls hash");
        let pfls_code_hash = ctx
            .get_cell_data_hash(&env.pfls_out_point)
            .expect("pfls hash");
        let always_success_hash = ctx
            .get_cell_data_hash(&env.always_success_out_point)
            .expect("always success hash");

        let parties = funding_agreement.mk_participants(
            ctx,
            env,
            always_success_hash.clone(),
            env.min_capacity_no_script,
        );

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
            my_funds_outpoint: my_funds_outpoint.clone(),
            my_available_funds: my_funds,
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
    ) -> Result<FundResult, perun::Error> {
        // Prepare environment so that this party has the required funds.
        let (my_funds_outpoint, my_available_funds) =
            env.create_funds_for_index(ctx, self.index, funding_agreement)?;
        let fr = transaction::mk_fund(
            ctx,
            env,
            transaction::FundArgs {
                channel_cell,
                funding_agreement: funding_agreement.clone(),
                party_index: self.index,
                state: channel_state,
                my_funds_outpoint,
                my_available_funds,
                pcts,
            },
        )?;
        let cycles = ctx.verify_tx(&fr.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(fr)
    }

    pub fn send(&self, ctx: &mut Context, env: &harness::Env) -> Result<(), perun::Error> {
        Ok(())
    }

    pub fn sign(&self, state: ChannelState) -> Result<Vec<u8>, perun::Error> {
        let s: Signature = self
            .signing_key
            .sign_prehash(&blake2b256(state.as_slice()))?;
        Ok(Vec::from(s.to_der().as_bytes()))
    }

    pub fn dispute(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        cid: test::ChannelId,
    ) -> Result<(), perun::Error> {
        Ok(())
    }

    pub fn abort(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        _cid: test::ChannelId,
        channel_cell: OutPoint,
        funds: Vec<FundingCell>,
    ) -> Result<(), perun::Error> {
        let ar = transaction::mk_abort(
            ctx,
            env,
            AbortArgs {
                channel_cell,
                funds,
            },
        )?;
        let cycles = ctx.verify_tx(&ar.tx, env.max_cycles)?;
        println!("consumed cycles: {}", cycles);
        Ok(())
    }

    pub fn close(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        cid: test::ChannelId,
    ) -> Result<(), perun::Error> {
        Ok(())
    }

    pub fn force_close(
        &self,
        ctx: &mut Context,
        env: &harness::Env,
        cid: test::ChannelId,
    ) -> Result<(), perun::Error> {
        Ok(())
    }
}
