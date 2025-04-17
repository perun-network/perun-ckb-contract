use crate::perun::{self, harness};
use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        packed::{CellInput, CellOutput, OutPoint, Script},
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::perun_types::VirtualChannelStatus;

use super::common::create_cells;

pub struct VCMergeArgs {
    pub vc_cell1: OutPoint,
    pub vc_cell2: OutPoint,
    pub party_index: u8,
    pub vc_status1: VirtualChannelStatus,
    pub vc_status2: VirtualChannelStatus,
    pub vcts_script: Script,
}

#[derive(Debug, Clone)]
pub struct VCMergeResult {
    pub tx: TransactionView,
    pub final_vc_cell: OutPoint,
}

impl Default for VCMergeResult {
    fn default() -> Self {
        VCMergeResult {
            tx: TransactionBuilder::default().build(),
            final_vc_cell: OutPoint::default(),
        }
    }
}

pub fn mk_vc_merge(
    ctx: &mut Context,
    env: &harness::Env,
    args: VCMergeArgs,
) -> Result<VCMergeResult, perun::Error> {
    let payment_input = env.create_min_cell_for_index(ctx, args.party_index);

    let inputs = vec![
        CellInput::new_builder()
            .previous_output(args.vc_cell1)
            .build(),
        CellInput::new_builder()
            .previous_output(args.vc_cell2)
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

    let vcls_script = env.build_vcls(ctx, Default::default());
    let vc_status2 = args.vc_status2.clone();
    let capacity_for_vc2 = env.min_capacity_for_vc_channel(vc_status2.clone())?;
    let vc_cell2 = CellOutput::new_builder()
        .capacity(capacity_for_vc2.pack())
        .lock(vcls_script.clone())
        .type_(Some(args.vcts_script.clone()).pack())
        .build();
    let owner_idx: u8 = 0;
    let onwer_vc_rent_payout = CellOutput::new_builder()
        .capacity(capacity_for_vc2.pack())
        .lock(env.build_lock_script(ctx, Bytes::from(vec![owner_idx])))
        .build();
    let outputs = vec![
        (vc_cell2.clone(), vc_status2.as_bytes()),
        (onwer_vc_rent_payout, Bytes::new()),
    ];
    let outputs_data: Vec<_> = outputs.iter().map(|e| e.1.clone()).collect();

    let headers: Vec<_> = ctx.headers.keys().cloned().collect();
    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|e| e.0.clone()))
        .outputs_data(outputs_data.pack())
        .header_deps(headers)
        .cell_deps(cell_deps)
        .build();

    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs);

    Ok(VCMergeResult {
        final_vc_cell: OutPoint::new(tx.hash(), 0),
        tx,
    })
}
