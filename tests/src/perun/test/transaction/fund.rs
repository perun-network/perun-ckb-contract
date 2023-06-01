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
    test::{cell::{FundingCell, mk_funding_cell}, FundingAgreement},
};

use super::common::{channel_witness, create_cells, create_funding_from};

#[derive(Debug, Clone)]
pub struct FundArgs {
    pub channel_cell: OutPoint,
    pub funding_agreement: FundingAgreement,
    pub party_index: u8,
    pub inputs: Vec<(OutPoint, Capacity)>,
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
    let fund_action = redeemer!(fund!());
    let witness_args = channel_witness!(fund_action);
    let wanted = args
        .funding_agreement
        .expected_ckbytes_funding_for(args.party_index)?;
    let pfls = env.build_pfls(ctx, args.pcts.calc_script_hash().as_bytes());
    // TODO: Make sure enough funds available all cells!

    // Note: we do not really need to shrink the balances to only contain the party's balances, as balances.mk_outputs will do so anyway.
    let balances = args.funding_agreement.mk_balances(vec![args.party_index])?;
    let pfls = |_| pfls.clone();
    let mut outputs = balances.mk_outputs(pfls, vec![1]);
    let num_fund_ouputs = outputs.len();

    let my_available_funds = Capacity::shannons(args.inputs.iter().map(|(_, c)| c.as_u64()).sum());
    let exchange_cell = create_funding_from(my_available_funds, (wanted + args.funding_agreement.sudt_max_cap_sum()).into_capacity())?;
    let mut inputs = vec![
        CellInput::new_builder()
            .previous_output(args.channel_cell)
            .build(),
    ];
    for (outpoint, _) in args.inputs.iter() {
        inputs.push(CellInput::new_builder().previous_output(outpoint.clone()).build());
    }
    // NOTE: mk_fund currently expects the be called for the last party funding the channel.
    // Otherwise the call to `mk_funded` returns a wrong channel state.
    let updated_cs = args.state.mk_funded();
    let capacity_for_new_cs = env.min_capacity_for_channel(updated_cs.clone())?;
    let pcls = env.build_pcls(ctx, Default::default());
    let new_channel_cell = CellOutput::new_builder()
        .capacity(capacity_for_new_cs.pack())
        .lock(pcls.clone())
        .type_(Some(args.pcts.clone()).pack())
        .build();
    outputs.append(&mut vec![
        (new_channel_cell.clone(), updated_cs.as_bytes()),
        (
            CellOutput::new_builder()
                .capacity(exchange_cell.pack())
                .lock(env.build_lock_script(ctx, Bytes::from(vec![args.party_index])))
                .build(),
            Bytes::new(),
        ),
    ]);
    let outputs_data: Vec<_> = outputs.iter().map(|o| o.1.clone()).collect();
    let cell_deps = vec![
        env.always_success_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.pcls_script_dep.clone(),
        env.sample_udt_script_dep.clone(), // TODO: Make this generic
    ];
    let headers: Vec<_> = ctx.headers.keys().cloned().collect();
    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .witness(witness_args.as_bytes().pack())
        .outputs(outputs.clone().into_iter().map(|o| o.0.clone()))
        .outputs_data(outputs_data.pack())
        .cell_deps(cell_deps)
        .header_deps(headers)
        .build();
    let tx = ctx.complete_tx(rtx); 
    create_cells(ctx, tx.hash(), outputs.clone());
    Ok(FundResult {
        channel_cell: OutPoint::new(tx.hash(), num_fund_ouputs as u32),
        funds_cells: outputs[..num_fund_ouputs].iter().enumerate().map(|(i, (co, bytes))| 
            mk_funding_cell(args.party_index, OutPoint::new(tx.hash(), i as u32), co, bytes.clone(), args.funding_agreement.register())).collect(),
        state: updated_cs,
        tx,
    })
}
