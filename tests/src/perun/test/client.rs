use ckb_testtool::ckb_traits::CellDataProvider;
use ckb_testtool::ckb_types::bytes::Bytes;
use ckb_testtool::ckb_types::core::TransactionBuilder;
use ckb_testtool::ckb_types::packed::{
    Byte32, Bytes as PackedBytes, BytesBuilder, CellInput, CellOutput, OutPointBuilder,
    ScriptOptBuilder,
};
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;

use perun_common::*;

use ckb_occupied_capacity::{Capacity, IntoCapacity};

use crate::perun;
use crate::perun::harness;
use crate::perun::random;
use crate::perun::test::{self, Asset};
use crate::perun::test::{keys, transaction};

use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    SecretKey,
};

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
        cid: test::ChannelId,
        ctx: &mut Context,
        env: &harness::Env,
        funding_agreement: &test::FundingAgreement,
    ) -> Result<(), perun::Error> {
        // Prepare environment so that this party has the required funds.
        let (my_funds_outpoint, my_funds) =
            env.create_funds_for_index(ctx, self.index, funding_agreement)?;
        // Create the channel token.
        let (channel_token, channel_token_outpoint) = env.create_channel_token(ctx);

        let pcls_hash = ctx
            .get_cell_data_hash(&env.pcls_out_point)
            .expect("pcls hash");
        let pcts_hash = ctx
            .get_cell_data_hash(&env.pcts_out_point)
            .expect("pcts hash");
        let pfls_hash = ctx
            .get_cell_data_hash(&env.pfls_out_point)
            .expect("pfls hash");
        let always_success_hash = ctx
            .get_cell_data_hash(&env.always_success_out_point)
            .expect("always success hash");

        let parties = funding_agreement
            .mk_participants(always_success_hash.clone(), env.min_capacity_no_script);

        let chan_params = perun_types::ChannelParametersBuilder::default()
            .party_a(parties[0].clone())
            .party_b(parties[1].clone())
            .nonce(random::nonce().pack())
            .challenge_duration(env.challenge_duration.pack())
            .app(Default::default())
            .is_ledger_channel(ctrue!())
            .is_virtual_channel(cfalse!())
            .build();
        let chan_const = perun_types::ChannelConstantsBuilder::default()
            .params(chan_params)
            .pfls_hash(pfls_hash.clone())
            .pcls_hash(pcls_hash.clone())
            // We use inputs guarded with the always success script..
            .pcls_unlock_script_hash(always_success_hash.clone())
            .pfls_min_capacity(env.min_capacity_pfls.pack())
            .thread_token(channel_token.clone())
            .build();

        let pcls = env.build_pcls(ctx, Default::default());
        let pcts = env.build_pcts(ctx, chan_const.as_bytes());

        let pfls_args = perun_types::PFLSArgsBuilder::default()
            .pcts_hash(pcts_hash.clone())
            .thread_token(channel_token.clone())
            .build();
        let pfls = env.build_pfls(ctx, pfls_args.as_bytes());

        let args = transaction::OpenArgs {
            cid,
            funding_agreement: funding_agreement.clone(),
            channel_token_outpoint: channel_token_outpoint.clone(),
            my_funds_outpoint: my_funds_outpoint.clone(),
            my_available_funds: my_funds,
            party_index: self.index,
            pcls_hash,
            pcls_script: pcls,
            pcts_hash,
            pcts_script: pcts,
            pfls_hash,
            pfls_script: pfls,
        };
        let rtx = transaction::mk_open(ctx, env, args)?;
        let tx = ctx.complete_tx(rtx);

        let cycles = ctx
            .verify_tx(&tx, env.max_cycles)
            .expect("pass verification");
        println!("consumed cycles: {}", cycles);
        Ok(())
    }

    pub fn fund(
        &self,
        cid: test::ChannelId,
        ctx: &mut Context,
        env: &harness::Env,
        funding_agreement: &test::FundingAgreement,
    ) -> Result<(), perun::Error> {
        Ok(())
    }

    pub fn send(&self, ctx: &mut Context, env: &harness::Env) -> Result<(), perun::Error> {
        Ok(())
    }

    pub fn dispute(
        &self,
        cid: test::ChannelId,
        ctx: &mut Context,
        env: &harness::Env,
    ) -> Result<(), perun::Error> {
        Ok(())
    }

    pub fn abort(
        &self,
        cid: test::ChannelId,
        ctx: &mut Context,
        env: &harness::Env,
    ) -> Result<(), perun::Error> {
        Ok(())
    }

    pub fn close(
        &self,
        cid: test::ChannelId,
        ctx: &mut Context,
        env: &harness::Env,
    ) -> Result<(), perun::Error> {
        Ok(())
    }

    pub fn force_close(
        &self,
        cid: test::ChannelId,
        ctx: &mut Context,
        env: &harness::Env,
    ) -> Result<(), perun::Error> {
        Ok(())
    }
}
