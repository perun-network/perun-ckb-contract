use ckb_testtool::{
    ckb_types::{
        core::{TransactionBuilder, TransactionView},
        packed::{CellInput, CellOutput, OutPoint, Script},
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};

use crate::perun::{self, harness, test::transaction::common::channel_witness};
use perun_common::{dispute, perun_types::VirtualChannelStatus, redeemer};

use super::{common::create_cells, DisputeArgs};

pub struct VCUpdateOnlyArgs {
    pub parent_args: DisputeArgs,
    pub vc_cell: OutPoint,
    pub vc_status: VirtualChannelStatus,
    pub sigs: [Vec<u8>; 2],
    pub vcts_script: Script,
    pub party_index: u8,
}

pub struct VCUpdateOnlyResult {
    pub tx: TransactionView,
    pub parent_cell: OutPoint,
    pub vc_cell: OutPoint,
}

impl Default for VCUpdateOnlyResult {
    fn default() -> Self {
        VCUpdateOnlyResult {
            tx: TransactionBuilder::default().build(),
            parent_cell: OutPoint::default(),
            vc_cell: OutPoint::default(),
        }
    }
}

pub fn mk_vc_update_only(
    ctx: &mut Context,
    env: &harness::Env,
    args: VCUpdateOnlyArgs,
) -> Result<VCUpdateOnlyResult, perun::Error> {
    let payment_input = env.create_min_cell_for_index(ctx, args.parent_args.party_index);
    //add inputs to tx
    //1. parent lc cell, 2. vc cell, 3. payment input
    let inputs = vec![
        CellInput::new_builder()
            .previous_output(args.parent_args.channel_cell)
            .build(),
        CellInput::new_builder()
            .previous_output(args.vc_cell)
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

    // create cells for outputs
    let parent_channel_cell = CellOutput::new_builder()
        .capacity(capacity_for_cs.pack())
        .lock(pcls_script.clone())
        .type_(Some(args.parent_args.pcts_script.clone()).pack())
        .build();
    let vc_status = args.vc_status.clone();
    let capacity_for_vc = env.min_capacity_for_vc_channel(vc_status.clone())?;
    let vc_cell = CellOutput::new_builder()
        .capacity(capacity_for_vc.pack())
        .lock(vcls_script.clone())
        .type_(Some(args.vcts_script.clone()).pack())
        .build();

    // add cells to outputs
    // 1. parent lc cell 2. vc cell
    let outputs = vec![
        (
            parent_channel_cell.clone(),
            args.parent_args.state.as_bytes(),
        ),
        (vc_cell.clone(), args.vc_status.as_bytes()),
    ];
    let outputs_data: Vec<_> = outputs.iter().map(|e| e.1.clone()).collect();

    // add witness args
    let lc_dispute_action = channel_witness!(redeemer!(dispute!(
        args.parent_args.sigs[0].pack(),
        args.parent_args.sigs[1].pack()
    )));
    let vc_dispute_action = channel_witness!(redeemer!(dispute!(
        args.sigs[0].pack(),
        args.sigs[1].pack()
    )));
    let witness_vec = vec![
        (lc_dispute_action.clone(), lc_dispute_action.as_bytes()),
        (vc_dispute_action.clone(), vc_dispute_action.as_bytes()),
    ];
    let witness_args: Vec<_> = witness_vec.iter().map(|e| e.1.clone()).collect();

    let headers: Vec<_> = ctx.headers.keys().cloned().collect();
    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|e| e.0.clone()))
        .outputs_data(outputs_data.pack())
        .header_deps(headers)
        .witnesses(witness_args.pack())
        .cell_deps(cell_deps)
        .build();

    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs);
    Ok(VCUpdateOnlyResult {
        parent_cell: OutPoint::new(tx.hash(), 0),
        vc_cell: OutPoint::new(tx.hash(), 1),
        tx,
    })
}
