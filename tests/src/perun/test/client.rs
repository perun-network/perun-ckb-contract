use ckb_testtool::ckb_traits::CellDataProvider;
use ckb_testtool::ckb_types::bytes::Bytes;
use ckb_testtool::ckb_types::packed::Byte32;
use ckb_testtool::ckb_types::packed::CellOutput;
use ckb_testtool::ckb_types::packed::OutPointBuilder;
use ckb_testtool::ckb_types::prelude::*;
use ckb_testtool::context::Context;

use ckb_types::packed::Byte;
use perun_common::*;

use crate::perun;
use crate::perun::harness;
use crate::perun::test;
use crate::perun::test::keys;

use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    SecretKey,
};
use rand_core::OsRng;

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
        let channel_token_outpoint = ctx.create_cell(
            CellOutput::new_builder()
                .capacity(1000u64.pack())
                .lock(env.always_success_script.clone())
                .build(),
            Bytes::default(),
        );
        let packed_outpoint = OutPointBuilder::default()
            .tx_hash(channel_token_outpoint.tx_hash())
            .index(channel_token_outpoint.index())
            .build();
        let channel_token = perun_types::ChannelTokenBuilder::default()
            .out_point(packed_outpoint)
            .build();

        let pcls_hash = ctx
            .get_cell_data_hash(&env.pcls_out_point)
            .expect("pcls hash");
        let pcts_hash = ctx
            .get_cell_data_hash(&env.pcts_out_point)
            .expect("pcts hash");
        let pfls_hash = ctx
            .get_cell_data_hash(&env.pfls_out_point)
            .expect("pfls hash");

        // let parties: Vec<perun_types::Participant> = funding_agreement
        //     .content()
        //     .iter()
        //     .map(
        //         |test::FundingAgreementEntry {
        //              amounts,
        //              index,
        //              pub_key,
        //          }| {
        //             let sec1_pub_key = perun_types::SEC1EncodedPubKeyBuilder::default()
        //                 .set(*pub_key)
        //                 .build();
        //             let payment_args = Bytes::from_slice(&[self.index]).expect("payment args");
        //             perun_types::ParticipantBuilder::default()
        //                 // The tests use always success scripts.
        //                 .unlock_args(Bytes::default())
        //                 // The tests will pay out to an address encoded by the index of each
        //                 // participant for simplicity.
        //                 .payment_args(payment_args)
        //                 .pub_key(sec1_pub_key)
        //                 .build()
        //         },
        //     )
        //     .collect();

        // let chan_params = perun_types::ChannelParametersBuilder::default()
        //     .party_a(parties[0].clone())
        //     .party_b(parties[1].clone())
        //     .nonce(Byte32::default())
        //     .challenge_duration(Uint64::from(1000))
        //     .app(Default::default())
        //     .is_ledger_channel(ctrue!())
        //     .is_virtual_channel(cfalse!())
        //     .build();
        // let chan_const = perun_types::ChannelConstantsBuilder::default()
        //     .params(chan_params)
        //     .pfls_hash(pfls_hash)
        //     .pcls_hash(pcls_hash)
        //     .pcls_unlock_script_hash(Byte32::default())
        //     .payment_lock_hash(Byte32::default())
        //     .thread_token(channel_token)
        //     .build();

        // let pcls = env.build_pcls(ctx, Default::default());
        // let pcts = env.build_pcts(ctx, Default::default());
        // let pfls = env.build_pfls(ctx, Default::default());
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
