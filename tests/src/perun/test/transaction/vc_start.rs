use ckb_testtool::{
    ckb_types::{
        core::{TransactionBuilder, TransactionView},
        packed::{CellInput, CellOutput, OutPoint, Script},
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::{perun_types::VirtualChannelStatus, redeemer, vc_dispute};

use crate::perun::{self, harness, test::transaction::common::channel_witness};

use super::{common::create_cells, DisputeArgs};

#[derive(Debug, Clone)]
pub struct VCStartArgs {
    /// Parent Cell dispute args
    pub parent_args: DisputeArgs,

    pub vc_status: VirtualChannelStatus,
    /// The DER encoded signatures for the virtual channel state in proper order of parties.
    pub sigs: [Vec<u8>; 2],
    /// The Perun virtual channel type script used for the current channel.
    pub vcts_script: Script,
    pub party_index: u8,
}

#[derive(Debug, Clone)]
pub struct VCStartResult {
    pub tx: TransactionView,
    pub vc_cell: OutPoint,
    pub parent_lc_cell: OutPoint,
}

impl Default for VCStartResult {
    fn default() -> Self {
        VCStartResult {
            tx: TransactionBuilder::default().build(),
            vc_cell: OutPoint::default(),
            parent_lc_cell: OutPoint::default(),
        }
    }
}

pub fn mk_vc_start(
    ctx: &mut Context,
    env: &harness::Env,
    args: VCStartArgs,
) -> Result<VCStartResult, perun::Error> {
    //input cell for gas fees
    let payment_input = env.create_min_cell_for_index(ctx, args.parent_args.party_index);

    // add inputs to tx
    // first parent lc cell and then payment input
    let inputs = vec![
        CellInput::new_builder()
            .previous_output(args.parent_args.channel_cell)
            .build(),
        CellInput::new_builder()
            .previous_output(payment_input)
            .build(),
    ];

    let cell_deps = vec![
        env.pcls_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.pfls_script_dep.clone(),
        env.always_success_script_dep.clone(),
        env.vcts_script_dep.clone(),
        env.vcls_script_dep.clone(),
    ];

    let pcls_script = env.build_pcls(ctx, Default::default());
    let vcls_script = env.build_vcls(ctx, Default::default());
    let capacity_for_cs = env.min_capacity_for_channel(args.parent_args.state.clone())?;
    let parent_channel_cell = CellOutput::new_builder()
        .capacity(capacity_for_cs.pack())
        .lock(pcls_script.clone())
        .type_(Some(args.parent_args.pcts_script.clone()).pack())
        .build();

    // create vc cell for outputs
    let initial_vc = args.vc_status.clone();
    let capacity_for_vc = env.min_capacity_for_vc_channel(initial_vc.clone())?;
    let vc_cell = CellOutput::new_builder()
        .capacity(capacity_for_vc.pack())
        .lock(vcls_script.clone())
        .type_(Some(args.vcts_script.clone()).pack())
        .build();

    // add cells to outputs
    //first lc cell and then vc cell
    let outputs = vec![
        (
            parent_channel_cell.clone(),
            args.parent_args.state.as_bytes(),
        ),
        (vc_cell.clone(), args.vc_status.as_bytes()),
    ];
    let outputs_data: Vec<_> = outputs.iter().map(|e| e.1.clone()).collect();

    // add witness args
    let dispute_action = redeemer!(vc_dispute!(
        args.sigs[0].pack(),
        args.sigs[1].pack(),
        args.parent_args.sigs[0].pack(),
        args.parent_args.sigs[1].pack()
    ));
    let witness_args = channel_witness!(dispute_action);

    // witnesses.push(witness_args.as_bytes());
    let headers: Vec<_> = ctx.headers.keys().cloned().collect();
    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|e| e.0.clone()))
        .outputs_data(outputs_data.pack())
        .header_deps(headers)
        .witness(witness_args.as_bytes().pack())
        .cell_deps(cell_deps)
        .build();
    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs);
    Ok(VCStartResult {
        parent_lc_cell: OutPoint::new(tx.hash(), 0),
        vc_cell: OutPoint::new(tx.hash(), 1),
        tx,
    })
}
