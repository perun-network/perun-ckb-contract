use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        packed::{CellInput, CellOutput, OutPoint},
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::redeemer;

use crate::perun::{self, harness, test::cell::FundingCell};

use super::common::channel_witness;

#[derive(Debug, Clone)]
pub struct AbortArgs {
    pub channel_cell: OutPoint,
    pub funds: Vec<FundingCell>,
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
    let abort_action = redeemer!(Abort);
    let witness_args = channel_witness!(abort_action);
    let mut inputs = vec![CellInput::new_builder()
        .previous_output(args.channel_cell)
        .build()];
    inputs.extend(args.funds.iter().cloned().map(|op| {
        CellInput::new_builder()
            .previous_output(op.out_point)
            .build()
    }));

    // TODO: We are expecting the output amounts to be greater than the minimum amount necessary to
    // accomodate the space required for each output cell.
    let outputs = args.funds.iter().cloned().map(|f| {
        CellOutput::new_builder()
            .capacity(f.amount.pack())
            .lock(env.build_lock_script(ctx, Bytes::from(vec![f.index])))
            .build()
    });

    let cell_deps = vec![
        env.pcls_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.always_success_script_dep.clone(),
    ];
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .cell_deps(cell_deps)
        .witness(witness_args.as_bytes().pack())
        .build();
    Ok(AbortResult {
        tx: ctx.complete_tx(tx),
    })
}
