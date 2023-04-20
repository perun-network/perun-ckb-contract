use ckb_testtool::{
    ckb_types::packed::{CellInput, OutPoint},
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::{close, perun_types::ChannelState, redeemer};

use crate::perun::{
    self, harness,
    test::{cell::FundingCell, transaction::common::channel_witness},
};

use super::common::create_cells;

#[derive(Debug, Clone)]
pub struct CloseArgs {
    /// The channel cell which tracks the channel on-chain.
    pub channel_cell: OutPoint,
    /// All funding cells used to initially fund the channel.
    pub funds_cells: Vec<FundingCell>,
    /// The channel state which shall be used for closing.
    pub state: ChannelState,
    /// The DER encoded signatures for the channel state in proper order of parties.
    pub sigs: [Vec<u8>; 2],
    pub party_index: u8,
}

#[derive(Debug, Clone)]
pub struct CloseResult {
    pub tx: TransactionView,
}

impl Default for CloseResult {
    fn default() -> Self {
        CloseResult {
            tx: TransactionBuilder::default().build(),
        }
    }
}

pub fn mk_close(
    ctx: &mut Context,
    env: &harness::Env,
    args: CloseArgs,
) -> Result<CloseResult, perun::Error> {
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
            .previous_output(f.out_point)
            .build()
    }));

    let cell_deps = vec![
        env.pcls_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.pfls_script_dep.clone(),
        env.always_success_script_dep.clone(),
    ];

    // Rust...
    let f = |idx| env.build_lock_script(ctx, Bytes::from(vec![idx]));
    let outputs = args.state.clone().mk_close_outputs(f);
    let outputs_data: Vec<_> = outputs.iter().map(|o| o.1.clone()).collect();

    let close_action = redeemer!(close!(args.state, args.sigs[0].pack(), args.sigs[1].pack()));
    let witness_args = channel_witness!(close_action);

    let headers: Vec<_> = ctx.headers.keys().cloned().collect();
    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|o| o.0.clone()))
        .outputs_data(outputs_data.pack())
        .witness(witness_args.as_bytes().pack())
        .cell_deps(cell_deps)
        .header_deps(headers)
        .build();
    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs);
    Ok(CloseResult { tx })
}
