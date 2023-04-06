pub struct FundingAgreement(Vec<FundingAgreementEntry>);

impl FundingAgreement {
    pub fn new(n: usize) -> Self {
        FundingAgreement(vec![FundingAgreementEntry::default(); n])
    }
}

impl Default for FundingAgreement {
    fn default() -> Self {
        FundingAgreement(vec![FundingAgreementEntry::default()])
    }
}

pub struct FundingAgreementEntry(u64);

impl Default for FundingAgreementEntry {
    fn default() -> Self {
        FundingAgreementEntry(100)
    }
}

impl Clone for FundingAgreementEntry {
    fn clone(&self) -> Self {
        FundingAgreementEntry(self.0)
    }
}
