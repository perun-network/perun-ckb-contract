use ckb_occupied_capacity::{Capacity, IntoCapacity};
use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        packed::{CellInput, CellOutput, OutPoint, Script},
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::perun_types::ChannelStatus;

use crate::perun::{
    self, harness,
    test::{cell::FundingCell, ChannelId, FundingAgreement},
};

use super::common::{create_cells, create_funding_from};

#[derive(Clone)]
pub struct OpenArgs {
    pub cid: ChannelId,
    pub funding_agreement: FundingAgreement,
    pub channel_token_outpoint: OutPoint,
    pub my_funds_outpoint: OutPoint,
    pub my_available_funds: Capacity,
    pub party_index: u8,
    pub pcls_script: Script,
    pub pcts_script: Script,
    pub pfls_script: Script,
}

pub struct OpenResult {
    pub tx: TransactionView,
    pub channel_cell: OutPoint,
    pub funds_cells: Vec<FundingCell>,
    pub pcts: Script,
    pub state: ChannelStatus,
}

impl Default for OpenResult {
    fn default() -> Self {
        OpenResult {
            tx: TransactionBuilder::default().build(),
            channel_cell: OutPoint::default(),
            funds_cells: Vec::new(),
            pcts: Script::default(),
            state: ChannelStatus::default(),
        }
    }
}

pub fn mk_open(
    ctx: &mut Context,
    env: &harness::Env,
    args: OpenArgs,
) -> Result<OpenResult, perun::Error> {
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
    // TODO: Make sure enough funds available all cells!
    let fund_cell = CellOutput::new_builder()
        .capacity(wanted.into_capacity().pack())
        .lock(args.pfls_script)
        .build();
    let exchange_cell = create_funding_from(args.my_available_funds, wanted.into_capacity())?;
    // NOTE: The ORDER here is important. We need to reference the outpoints later on by using the
    // correct index in the output array of the transaction we build.
    let outputs = vec![
        (channel_cell.clone(), initial_cs.as_bytes()),
        (fund_cell.clone(), Bytes::new()),
        // Exchange cell.
        (
            CellOutput::new_builder()
                .capacity(exchange_cell.pack())
                .lock(env.build_lock_script(ctx, Bytes::from(vec![args.party_index])))
                .build(),
            Bytes::new(),
        ),
    ];
    let outputs_data: Vec<_> = outputs.iter().map(|o| o.1.clone()).collect();
    let cell_deps = vec![
        env.always_success_script_dep.clone(),
        env.pcts_script_dep.clone(),
    ];
    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|o| o.0.clone()))
        .outputs_data(outputs_data.pack())
        .cell_deps(cell_deps)
        .build();
    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs);
    Ok(OpenResult {
        // See NOTE above for magic indices.
        channel_cell: OutPoint::new(tx.hash(), 0),
        funds_cells: vec![FundingCell {
            index: args.party_index,
            amount: wanted,
            out_point: OutPoint::new(tx.hash(), 1),
        }],
        tx,
        pcts: args.pcts_script,
        state: initial_cs,
    })
}
