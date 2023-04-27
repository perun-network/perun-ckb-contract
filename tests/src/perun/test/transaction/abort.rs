use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        packed::{CellInput, CellOutput, OutPoint},
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::{perun_types::ChannelStatus, redeemer};

use crate::perun::{self, harness, test::cell::FundingCell};

use super::common::{channel_witness, create_cells};

#[derive(Debug, Clone)]
pub struct AbortArgs {
    pub channel_cell: OutPoint,
    pub funds: Vec<FundingCell>,
    pub state: ChannelStatus,
    pub party_index: u8,
}

#[derive(Debug, Clone)]
pub struct AbortResult {
    pub tx: TransactionView,
}

impl Default for AbortResult {
    fn default() -> Self {
        AbortResult {
            tx: TransactionBuilder::default().build(),
        }
    }
}

pub fn mk_abort(
    ctx: &mut Context,
    env: &harness::Env,
    args: AbortArgs,
) -> Result<AbortResult, perun::Error> {
    let payment_input = env.create_min_cell_for_index(ctx, args.party_index);
    let abort_action = redeemer!(Abort);
    let witness_args = channel_witness!(abort_action);
    let mut inputs = vec![
        CellInput::new_builder()
            .previous_output(args.channel_cell)
            .build(),
        CellInput::new_builder()
            .previous_output(payment_input)
            .build(),
    ];
    inputs.extend(args.funds.iter().cloned().map(|op| {
        CellInput::new_builder()
            .previous_output(op.out_point)
            .build()
    }));

    let headers: Vec<_> = ctx.headers.keys().cloned().collect();
    // TODO: We are expecting the output amounts to be greater than the minimum amount necessary to
    // accomodate the space required for each output cell.
    let outputs: Vec<_> = args
        .funds
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, f)| {
            let min_amount = env.min_capacity_for_channel(args.state.clone())?;
            let amount = match i {
                0 => f.amount + min_amount.as_u64(),
                _ => f.amount,
            };
            Ok((
                CellOutput::new_builder()
                    .capacity(amount.pack())
                    .lock(env.build_lock_script(ctx, Bytes::from(vec![f.index])))
                    .build(),
                Bytes::new(),
            ))
        })
        .collect::<Result<Vec<_>, perun::Error>>()?;
    let outputs_data: Vec<_> = outputs.iter().map(|o| o.1.clone()).collect();

    let cell_deps = vec![
        env.pcls_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.always_success_script_dep.clone(),
    ];

    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().cloned().map(|o| o.0))
        .outputs_data(outputs_data.pack())
        .cell_deps(cell_deps)
        .header_deps(headers)
        .witness(witness_args.as_bytes().pack())
        .build();
    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs);
    Ok(AbortResult { tx })
}
