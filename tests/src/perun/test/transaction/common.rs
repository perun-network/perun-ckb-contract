use ckb_occupied_capacity::Capacity;
use ckb_testtool::{
    bytes,
    ckb_types::{
        packed::{Byte32, CellOutput, OutPoint},
        prelude::{Pack, Unpack},
    },
    context::Context,
};
use molecule::prelude::{Builder, Entity};
use perun_common::perun_types::{Balances, AnyBalances, SUDTBalances, CKByteDistribution, ETHBalances, Allocation};

use crate::perun;

/// Build witness args containing the given action.
macro_rules! channel_witness {
    ($action:expr) => {
        ckb_testtool::ckb_types::packed::WitnessArgsBuilder::default()
            .input_type(Some($action.as_bytes()).pack())
            .build()
    };
}
pub(crate) use channel_witness;

pub fn create_funding_from(
    available_capacity: Capacity,
    wanted_capacity: Capacity,
) -> Result<Capacity, perun::Error> {
    Ok(available_capacity.safe_sub(wanted_capacity)?)
}

pub fn create_cells(ctx: &mut Context, hash: Byte32, outputs: Vec<(CellOutput, bytes::Bytes)>) {
    for (i, (output, data)) in outputs.into_iter().enumerate() {
        let out_point = OutPoint::new(hash.clone(), i as u32);
        ctx.create_cell_with_out_point(out_point, output, data);
    }
}

pub fn add_cap_to_a(balances: &Balances, cap: Capacity) -> Balances {
    let mut dist = balances.ckbytes().to_array();
    dist[0] = dist[0]
        .checked_add(cap.as_u64())
        .expect("capacity overflow");
    let updated_ckb = CKByteDistribution::from_array(dist);

    let mut rows = Vec::new();
    let mut replaced = false;

    for row in balances.assets().clone().into_iter() {
        if row.is_ckb_row() {
            rows.push(
                AnyBalances::new_builder()
                    .ckb(updated_ckb.clone())
                    .sudt(SUDTBalances::default())
                    .eth(ETHBalances::default())
                    .build(),
            );
            replaced = true;
        } else {
            rows.push(row);
        }
    }

    if !replaced {
        rows.insert(
            0,
            AnyBalances::new_builder()
                .ckb(updated_ckb)
                .sudt(SUDTBalances::default())
                .eth(ETHBalances::default())
                .build(),
        );
    }

    let new_assets = Allocation::new_builder().set(rows).build();

    balances
        .clone()
        .as_builder()
        .assets(new_assets)
        .locked(balances.locked())
        .build()
}
