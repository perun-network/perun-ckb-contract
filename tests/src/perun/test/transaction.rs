use ckb_occupied_capacity::{Capacity, IntoCapacity};
use ckb_testtool::ckb_types::core::{TransactionBuilder, TransactionView};
use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        packed::{Byte32, CellInput, CellOutput, OutPoint, Script},
        prelude::Pack,
    },
    context::Context,
};
use ckb_types::prelude::*;

use crate::perun::{self, harness};

use super::{ChannelId, FundingAgreement};

#[derive(Clone)]
pub struct OpenArgs {
    pub cid: ChannelId,
    pub funding_agreement: FundingAgreement,
    pub channel_token_outpoint: OutPoint,
    pub my_funds_outpoint: OutPoint,
    pub my_available_funds: Capacity,
    pub party_index: u8,
    pub pcls_hash: Byte32,
    pub pcls_script: Script,
    pub pcts_hash: Byte32,
    pub pcts_script: Script,
    pub pfls_hash: Byte32,
    pub pfls_script: Script,
}

pub fn mk_open(
    ctx: &mut Context,
    env: &harness::Env,
    args: OpenArgs,
) -> Result<TransactionView, perun::Error> {
    let inputs = vec![
        CellInput::new_builder()
            .previous_output(args.channel_token_outpoint)
            .build(),
        CellInput::new_builder()
            .previous_output(args.my_funds_outpoint)
            .build(),
    ];
    let initial_cs =
        env.build_initial_channel_state(args.cid, args.party_index, &args.funding_agreement)?;
    let capacity_for_cs = env.min_capacity_for_channel(initial_cs.clone())?;
    let channel_cell = CellOutput::new_builder()
        .capacity(capacity_for_cs.pack())
        .lock(args.pcls_script.clone())
        .type_(Some(args.pcts_script.clone()).pack())
        .build();
    let wanted = args
        .funding_agreement
        .expected_funding_for(args.party_index)?;
    let exchange_cell = create_funding_from(args.my_available_funds, wanted.into_capacity())?;
    let outputs = vec![
        (channel_cell, initial_cs.as_bytes()),
        // Funds cell.
        (
            CellOutput::new_builder()
                .capacity(wanted.into_capacity().pack())
                .lock(args.pfls_script)
                .build(),
            Bytes::new(),
        ),
        // Exchange cell.
        (
            CellOutput::new_builder()
                .capacity(exchange_cell.pack())
                .lock(env.always_success_script.clone())
                .build(),
            Bytes::new(),
        ),
    ];
    let outputs_data: Vec<_> = outputs.iter().map(|o| o.1.clone()).collect();
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|o| o.0.clone()))
        .outputs_data(outputs_data.pack())
        .build();
    Ok(ctx.complete_tx(tx))
}

fn create_funding_from(
    available_capacity: Capacity,
    wanted_capacity: Capacity,
) -> Result<Capacity, perun::Error> {
    Ok(available_capacity.safe_sub(wanted_capacity)?)
}
