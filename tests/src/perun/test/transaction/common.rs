use ckb_occupied_capacity::Capacity;

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
