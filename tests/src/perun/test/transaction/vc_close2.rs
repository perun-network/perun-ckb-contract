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

pub struct VCClose2Args {
    pub parent_args: ForceCloseArgs,
    pub vc_cell: OutPoint,
    pub vc_status: VirtualChannelStatus,
    pub idx_map_with_direction: IdxMapWithDirection,
    pub vcts_script: Script,
}

#[derive(Debug, Clone)]
pub struct VCClose2Result {
    pub tx: TransactionView,
}

impl Default for VCClose2Result {
    fn default() -> Self {
        VCClose2Result {
            tx: TransactionBuilder::default().build(),
        }
    }
}

pub fn mk_vc_close2(
    ctx: &mut Context,
    env: &harness::Env,
    args: VCClose2Args,
) -> Result<VCClose2Result, perun::Error> {
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

    let vc_cell_cap = env.min_capacity_for_vc_channel(args.vc_status.clone())?;
    let owner_idx: u8 = 0;
    let onwer_vc_rent_payout = CellOutput::new_builder()
        .capacity(vc_cell_cap.pack())
        .lock(env.build_lock_script(ctx, Bytes::from(vec![owner_idx])))
        .build();

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
    outputs.push((onwer_vc_rent_payout, Bytes::new()));
    let outputs_data: Vec<_> = outputs.iter().map(|o| o.1.clone()).collect();

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
    create_cells(ctx, tx.hash(), outputs);
    Ok(VCClose2Result { tx })
}
