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
use perun_common::{fund, perun_types::ChannelStatus, redeemer};

use crate::perun::{
    self, harness,
    test::{cell::FundingCell, FundingAgreement},
};

use super::common::{channel_witness, create_funding_from};

#[derive(Debug, Clone)]
pub struct FundArgs {
    pub channel_cell: OutPoint,
    pub funding_agreement: FundingAgreement,
    pub party_index: u8,
    pub my_funds_outpoint: OutPoint,
    pub my_available_funds: Capacity,
    pub pcts: Script,
    pub state: ChannelStatus,
}

#[derive(Debug, Clone)]
pub struct FundResult {
    pub tx: TransactionView,
    pub channel_cell: OutPoint,
    pub funds_cells: Vec<FundingCell>,
    pub state: ChannelStatus,
}

impl Default for FundResult {
    fn default() -> Self {
        FundResult {
            tx: TransactionBuilder::default().build(),
            channel_cell: OutPoint::default(),
            funds_cells: vec![],
            state: ChannelStatus::default(),
        }
    }
}

pub fn mk_fund(
    ctx: &mut Context,
    env: &harness::Env,
    args: FundArgs,
) -> Result<FundResult, perun::Error> {
    let fund_action = redeemer!(fund!(args.party_index));
    let witness_args = channel_witness!(fund_action);
    let wanted = args
        .funding_agreement
        .expected_funding_for(args.party_index)?;
    let pfls = env.build_pfls(ctx, args.pcts.calc_script_hash().as_bytes());
    // TODO: Make sure enough funds available all cells!
    let fund_cell = CellOutput::new_builder()
        .capacity(wanted.into_capacity().pack())
        .lock(pfls)
        .build();
    let exchange_cell = create_funding_from(args.my_available_funds, wanted.into_capacity())?;
    let inputs = vec![
        CellInput::new_builder()
            .previous_output(args.channel_cell)
            .build(),
        CellInput::new_builder()
            .previous_output(args.my_funds_outpoint)
            .build(),
    ];
    // NOTE: mk_fund currently expects the be called for the last party funding the channel.
    // Otherwise the call to `mk_funded` returns a wrong channel state.
    let updated_cs = args.state.mk_funded(wanted);
    let capacity_for_new_cs = env.min_capacity_for_channel(updated_cs.clone())?;
    let pcls = env.build_pcls(ctx, Default::default());
    let new_channel_cell = CellOutput::new_builder()
        .capacity(capacity_for_new_cs.pack())
        .lock(pcls.clone())
        .type_(Some(args.pcts.clone()).pack())
        .build();
    let outputs = vec![
        (new_channel_cell.clone(), updated_cs.as_bytes()),
        (fund_cell, Bytes::new()),
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
        env.pcls_script_dep.clone(),
    ];
    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .witness(witness_args.as_bytes().pack())
        .outputs(outputs.into_iter().map(|o| o.0.clone()))
        .outputs_data(outputs_data.pack())
        .cell_deps(cell_deps)
        .build();
    let tx = ctx.complete_tx(rtx);
    Ok(FundResult {
        channel_cell: OutPoint::new(tx.hash(), 0),
        funds_cells: vec![FundingCell {
            index: args.party_index,
            amount: wanted,
            out_point: OutPoint::new(tx.hash(), 1),
        }],
        state: updated_cs,
        tx,
    })
}
