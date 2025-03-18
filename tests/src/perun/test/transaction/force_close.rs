use ckb_testtool::{
    ckb_types::packed::{CellInput, OutPoint},
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        packed::Byte32,
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::{perun_types::ChannelStatus, redeemer};

use crate::perun::{
    self, harness,
    test::{cell::FundingCell, transaction::common::channel_witness},
};

use super::common::{create_cells, add_cap_to_a};

#[derive(Debug, Clone)]
pub struct ForceCloseArgs {
    /// The channel cell which tracks the channel on-chain.
    pub channel_cell: OutPoint,
    /// The latest headers for the chain containing some timestamps.
    pub headers: Vec<Byte32>,
    /// All funding cells used to initially fund the channel.
    pub funds_cells: Vec<FundingCell>,
    /// The channel state which shall be used for closing.
    pub state: ChannelStatus,
    pub party_index: u8,
}

#[derive(Debug, Clone)]
pub struct ForceCloseResult {
    pub tx: TransactionView,
}

impl Default for ForceCloseResult {
    fn default() -> Self {
        ForceCloseResult {
            tx: TransactionBuilder::default().build(),
        }
    }
}

pub fn mk_force_close(
    ctx: &mut Context,
    env: &harness::Env,
    args: ForceCloseArgs,
) -> Result<ForceCloseResult, perun::Error> {
    let payment_input = env.create_min_cell_for_index(ctx, args.party_index);
    let mut inputs = vec![
        CellInput::new_builder()
            .previous_output(args.channel_cell)
            .build(),
        CellInput::new_builder()
            .previous_output(payment_input)
            .build(),
    ];
    inputs.extend(args.funds_cells.iter().cloned().map(|f| {
        CellInput::new_builder()
            .previous_output(f.outpoint())
            .build()
    }));

    let cell_deps = vec![
        env.pcls_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.pfls_script_dep.clone(),
        env.always_success_script_dep.clone(),
    ];

    // Rust...
    let channel_cap = env.min_capacity_for_channel(args.state.clone())?;
    let balances = add_cap_to_a(&args.state.state().balances(), channel_cap);
    let f = |idx| env.build_lock_script(ctx, Bytes::from(vec![idx]));
    let outputs = balances.mk_outputs(f, vec![0, 1]);
    let outputs_data: Vec<_> = outputs.iter().map(|o| o.1.clone()).collect();

    let force_close_action = redeemer!(ForceClose);
    let witness_args = channel_witness!(force_close_action);

    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|o| o.0.clone()))
        .outputs_data(outputs_data.pack())
        .header_deps(args.headers)
        .witness(witness_args.as_bytes().pack())
        .cell_deps(cell_deps)
        .build();
    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs);
    Ok(ForceCloseResult { tx })
}
