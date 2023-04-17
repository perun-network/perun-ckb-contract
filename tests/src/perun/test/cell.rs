use ckb_testtool::ckb_types::packed::OutPoint;

#[derive(Debug, Clone)]
pub struct FundingCell {
    // Index of the party whose initial funds are contained in this cell.
    pub index: u8,
    // The amount of funding for the party given by index.
    pub amount: u64,
    // The outpoint of the cell containing the funds.
    pub out_point: OutPoint,
}

impl Default for FundingCell {
    fn default() -> Self {
        FundingCell {
            index: 0,
            amount: 0,
            out_point: OutPoint::default(),
        }
    }
}
