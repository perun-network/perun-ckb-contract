use ckb_types::packed::Byte as PackedByte;

pub struct FundingAgreement(Vec<FundingAgreementEntry>);

impl FundingAgreement {
    pub fn new(n: usize) -> Self {
        FundingAgreement(vec![FundingAgreementEntry::default(); n])
    }

    pub fn content(&self) -> &Vec<FundingAgreementEntry> {
        &self.0
    }
}

impl Default for FundingAgreement {
    fn default() -> Self {
        FundingAgreement(vec![FundingAgreementEntry::default()])
    }
}

#[derive(Clone)]
pub struct FundingAgreementEntry {
    pub amounts: Vec<(Asset, u128)>,
    pub index: u8,
    pub pub_key: [PackedByte; 65],
}

impl Default for FundingAgreementEntry {
    fn default() -> Self {
        FundingAgreementEntry {
            amounts: vec![(Asset::default(), 100)],
            index: 0,
            pub_key: [PackedByte::default(); 65],
        }
    }
}

pub struct Asset(u32);

impl Asset {
    pub fn new() -> Self {
        Asset(0)
    }
}

impl Default for Asset {
    fn default() -> Self {
        Asset(0)
    }
}

impl Clone for Asset {
    fn clone(&self) -> Self {
        Asset(self.0)
    }
}
