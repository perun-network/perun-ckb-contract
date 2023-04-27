use ckb_occupied_capacity::Capacity;
use ckb_testtool::{
    bytes,
    ckb_types::packed::{Byte32, CellOutput, OutPoint},
    context::Context,
};

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
