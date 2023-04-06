use ckb_testtool::context::Context;

use crate::perun;
use crate::perun::harness;
use crate::perun::test;

pub struct Client {}

impl Client {
    pub fn new() -> Self {
        Self {}
    }

    pub fn open(
        &self,
        cid: test::ChannelId,
        ctx: &mut Context,
        env: &harness::Env,
        funding_agreement: &test::FundingAgreement,
    ) -> Result<(), perun::Error> {
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
