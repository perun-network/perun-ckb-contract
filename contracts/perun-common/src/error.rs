use core::fmt::Debug;

use ckb_std::error::SysError;
use molecule::error::VerificationError;

/// Error
#[derive(Debug)]
#[repr(i8)]
pub enum Error {
    // System Errors
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Verification Errors
    TotalSizeNotMatch,
    HeaderIsBroken,
    UnknownItem,
    OffsetsNotMatch,
    FieldCountNotMatch,
    // Add customized errors here...
    NoArgs,
    NoWitness,
    ChannelIdMismatch,
    VersionNumberNotIncreasing,
    StateIsFinal,
    StateNotFinal,
    ChannelNotFunded,
    NotParticipant,
    BalancesNotEqual,
    OwnIndexNotFound,
    ChannelDoesNotContinue,
    MultipleMatchingOutputs,
    FundsInInputs,
    AppChannelsNotSupported,
    NonLedgerChannelsNotSupported,
    VirtualChannelsNotSupported,
    ChannelStateNotEqual,
    FundingChanged,
    FundingNotInStatus,
    OwnFundingNotInOutputs,
    FundedBitStatusNotCorrect,
    StateIsFunded,

    ChannelFundWithoutChannelOutput,
    ChannelDisputeWithoutChannelOutput,
    ChannelCloseWithChannelOutput,
    ChannelForceCloseWithChannelOutput,
    ChannelAbortWithChannelOutput,

    InvalidThreadToken,
    InvalidChannelId,
    StartWithNonZeroVersion,
    StartWithFinalizedState,
    InvalidPCLSHash,
    PCLSWithArgs,
    StatusDisputed,
    StatusNotDisputed,
    FundingNotZero,
    NotAllPayed,
    TimeLockNotExpired,
    InvalidTimestamp,
    UnableToLoadAnyChannelStatus
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

impl From<VerificationError> for Error {
    fn from(err: VerificationError) -> Self {
        use VerificationError::*;
        match err {
            TotalSizeNotMatch(_, _, _) => Self::TotalSizeNotMatch,
            HeaderIsBroken(_, _, _) => Self::HeaderIsBroken,
            UnknownItem(_, _, _) => Self::UnknownItem,
            OffsetsNotMatch(_) => Self::OffsetsNotMatch,
            FieldCountNotMatch(_, _, _) => Self::FieldCountNotMatch,
        }
    }
}