use ckb_testtool::{
    ckb_types::packed::{CellInput, CellOutput, OutPoint},
    ckb_types::{
        core::{TransactionBuilder, TransactionView},
        packed::Script,
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::{dispute, perun_types::ChannelStatus, redeemer};

use crate::perun::{self, harness, test::transaction::common::channel_witness};

#[derive(Debug, Clone)]
pub struct DisputeArgs {
    /// The channel cell which tracks the channel on-chain.
    pub channel_cell: OutPoint,
    /// The channel state which shall be used for closing.
    pub state: ChannelStatus,
    /// The DER encoded signatures for the channel state in proper order of parties.
    pub sigs: [Vec<u8>; 2],
    /// The Perun channel type script used for the current channel.
    pub pcts_script: Script,
}

#[derive(Debug, Clone)]
pub struct DisputeResult {
    pub tx: TransactionView,
    pub channel_cell: OutPoint,
}

impl Default for DisputeResult {
    fn default() -> Self {
        DisputeResult {
            tx: TransactionBuilder::default().build(),
            channel_cell: OutPoint::default(),
        }
    }
}

pub fn mk_dispute(
    ctx: &mut Context,
    env: &harness::Env,
    args: DisputeArgs,
) -> Result<DisputeResult, perun::Error> {
    let inputs = vec![CellInput::new_builder()
        .previous_output(args.channel_cell)
        .build()];

    let cell_deps = vec![
        env.pcls_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.pfls_script_dep.clone(),
        env.always_success_script_dep.clone(),
    ];

    let pcls_script = env.build_pcls(ctx, Default::default());
    let capacity_for_cs = env.min_capacity_for_channel(args.state.clone())?;
    let channel_cell = CellOutput::new_builder()
        .capacity(capacity_for_cs.pack())
        .lock(pcls_script.clone())
        .type_(Some(args.pcts_script.clone()).pack())
        .build();
    let outputs = vec![(channel_cell.clone(), args.state.as_bytes())];
    let outputs_data: Vec<_> = outputs.iter().map(|e| e.1.clone()).collect();

    let dispute_action = redeemer!(dispute!(args.sigs[0].pack(), args.sigs[1].pack()));
    let witness_args = channel_witness!(dispute_action);

    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|e| e.0.clone()))
        .outputs_data(outputs_data.pack())
        .witness(witness_args.as_bytes().pack())
        .cell_deps(cell_deps)
        .build();
    Ok(DisputeResult {
        channel_cell: OutPoint::new(rtx.hash(), 0),
        tx: ctx.complete_tx(rtx),
    })
}
