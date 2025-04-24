use ckb_testtool::{
    ckb_types::packed::{CellInput, CellOutput, OutPoint, Script},
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        prelude::{Builder, Entity, Pack},
    },
    context::Context,
};
use perun_common::{perun_types::VirtualChannelStatus, redeemer};

use crate::perun::{
    self, harness,
    test::transaction::common::channel_witness,
    virtual_channel::{IdxMapDirection, IdxMapWithDirection},
};

use super::{
    common::{add_cap_to_a, create_cells},
    ForceCloseArgs,
};

pub struct VCClose1Args {
    pub parent_args: ForceCloseArgs,
    pub vc_cell: OutPoint,
    pub vc_status: VirtualChannelStatus,
    pub idx_map_with_direction: IdxMapWithDirection,
    pub vcts_script: Script,
}

#[derive(Debug, Clone)]
pub struct VCClose1Result {
    pub tx: TransactionView,
    pub output_vc_cell: OutPoint,
}

impl Default for VCClose1Result {
    fn default() -> Self {
        VCClose1Result {
            tx: TransactionBuilder::default().build(),
            output_vc_cell: OutPoint::default(),
        }
    }
}

pub fn mk_vc_close1(
    ctx: &mut Context,
    env: &harness::Env,
    args: VCClose1Args,
) -> Result<VCClose1Result, perun::Error> {
    let payment_input = env.create_min_cell_for_index(ctx, args.parent_args.party_index);
    let mut inputs = vec![
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
    inputs.extend(args.parent_args.funds_cells.iter().cloned().map(|f| {
        CellInput::new_builder()
            .previous_output(f.outpoint())
            .build()
    }));

    let cell_deps = vec![
        env.pcls_script_dep.clone(),
        env.pcts_script_dep.clone(),
        env.pfls_script_dep.clone(),
        env.always_success_script_dep.clone(),
        env.vcts_script_dep.clone(),
        env.vcls_script_dep.clone(),
    ];
    let channel_cap = env.min_capacity_for_channel(args.parent_args.state.clone())?;
    let balances = add_cap_to_a(&args.parent_args.state.state().balances(), channel_cap); // give ckbytes locked for channel cell to first party
    let f = |idx| env.build_lock_script(ctx, Bytes::from(vec![idx]));
    match args.idx_map_with_direction.direction {
        IdxMapDirection::LedgerChannelToVirtualChannel => {}
        _ => panic!("Invalid direction for idx_map"),
    }
    let mut outputs = balances.mk_unlocked_outputs(
        f,
        vec![0, 1],
        &args.idx_map_with_direction.idx_map,
        &args.vc_status.vcstate().balances(),
    );
    let mut outputs_data: Vec<_> = outputs.iter().map(|o| o.1.clone()).collect();

    let vcls_script = env.build_vcls(ctx, Default::default());
    let vc_status = args.vc_status.clone();
    let capacity_for_vc = env.min_capacity_for_vc_channel(vc_status.clone())?;
    let vc_cell = CellOutput::new_builder()
        .capacity(capacity_for_vc.pack())
        .lock(vcls_script.clone())
        .type_(Some(args.vcts_script.clone()).pack())
        .build();
    outputs.push((vc_cell.clone(), vc_status.as_bytes()));
    outputs_data.push(vc_status.as_bytes());
    let _output_vc_status =
        VirtualChannelStatus::from_slice(&outputs_data[outputs.len() - 1]).unwrap();
    let force_close_action = redeemer!(ForceClose);
    let witness_args = channel_witness!(force_close_action);

    let rtx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs.iter().map(|o| o.0.clone()))
        .outputs_data(outputs_data.pack())
        .header_deps(args.parent_args.headers)
        .witness(witness_args.as_bytes().pack())
        .cell_deps(cell_deps)
        .build();
    let tx = ctx.complete_tx(rtx);
    create_cells(ctx, tx.hash(), outputs.clone());
    Ok(VCClose1Result {
        output_vc_cell: OutPoint::new(tx.hash(), (outputs.len() - 1) as u32), //vc cell is the last cell in the outputs
        tx,
    })
}
