use std::sync::{Arc, Mutex};

use ckb_testtool::{
    ckb_types::packed::{CellInput, OutPoint},
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::{
    close,
    perun_types::{ChannelState, ChannelStatus, ChannelWitnessUnion, Close},
    redeemer,
};

use crate::perun::{
    self, harness,
    test::{cell::FundingCell, transaction::common::channel_witness},
};

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
    let mut inputs = vec![CellInput::new_builder()
        .previous_output(args.channel_cell)
        .build()];
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

    let close_action = redeemer!(close!(args.state, args.sigs[0].pack(), args.sigs[1].pack()));
    let witness_args = channel_witness!(close_action);

    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .witness(witness_args.as_bytes().pack())
        .cell_deps(cell_deps)
        .build();
    Ok(CloseResult {
        tx: ctx.complete_tx(rtx),
    })
}
