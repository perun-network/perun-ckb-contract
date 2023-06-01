use ckb_testtool::{ckb_types::{packed::{OutPoint, CellOutput}, prelude::{Unpack, Pack}}};
use ckb_types::bytes;
use molecule::prelude::{Entity, Builder};

use super::{Asset, AssetRegister};


#[derive(Debug, Clone)]

pub enum FundingCell {
    FundingCellCKBytes(FundingCellCKBytes),
    FundingCellSUDT(FundingCellSUDT),
}

#[derive(Debug, Clone)]
pub struct FundingCellCKBytes {
    // Index of the party whose initial funds are contained in this cell.
    pub index: u8,
    // The amount of funding for the party given by index.
    pub cap: u64,
    // The outpoint of the cell containing the funds.
    pub out_point: OutPoint,
}

#[derive(Debug, Clone)]
pub struct FundingCellSUDT {
    // Index of the party whose initial funds are contained in this cell.
    pub index: u8,
    // The amount of funding for the party given by index.
    pub cap: u64,
    // The outpoint of the cell containing the funds.
    pub out_point: OutPoint,
    pub asset: Asset,
    pub asset_amount: u128,
}

impl Default for FundingCell {
    fn default() -> Self {
        FundingCell::FundingCellCKBytes(FundingCellCKBytes {
            index: 0,
            cap: 0,
            out_point: OutPoint::default(),
        })
    }
}

pub fn mk_funding_cell(party_index: u8, out_point: OutPoint, cell_output: &CellOutput, data: bytes::Bytes, register: &AssetRegister) -> FundingCell {
    if cell_output.type_().is_some(){
        let asset = register.guess_asset_from_script(&cell_output.type_().to_opt().unwrap()).unwrap();
        FundingCell::FundingCellSUDT(FundingCellSUDT {
            index: party_index,
            cap: cell_output.capacity().unpack(),
            out_point,
            asset: asset.clone(),
            asset_amount: u128::from_le_bytes(data.to_vec().as_slice().try_into().unwrap()),
        })
    } else {
        FundingCell::FundingCellCKBytes(FundingCellCKBytes {
            index: party_index,
            cap: cell_output.capacity().unpack(),
            out_point,
        })
    }

}

impl FundingCell {
    pub fn outpoint(&self) -> OutPoint {
        match self {
            FundingCell::FundingCellCKBytes(f) => f.out_point.clone(),
            FundingCell::FundingCellSUDT(f) => f.out_point.clone(),
        }
    }
}