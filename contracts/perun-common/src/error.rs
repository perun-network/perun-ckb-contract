use core::fmt::Debug;

use ckb_std::error::SysError;
use k256::ecdsa::Error as SigError;
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

    // Signature Errors
    SignatureVerificationError,

    // Add customized errors here...
    NoArgs,
    NoWitness,
    ChannelIdMismatch,
    VersionNumberNotIncreasing,
    StateIsFinal,
    StateNotFinal,
    ChannelNotFunded,
    NotParticipant,
    SumOfBalancesNotEqual,
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
    InvalidPCLSCodeHash,
    InvalidPCLSHashType,
    PCLSWithArgs,
    StatusDisputed,
    StatusNotDisputed,
    FundingNotZero,
    NotAllPayed,
    TimeLockNotExpired,
    InvalidTimestamp,
    UnableToLoadAnyChannelStatus,
    InvalidSignature,
    InvalidMessage,
    InvalidPFLSInOutputs,
    PCTSNotFound,
    FoundDifferentChannel,
    MoreThanOneChannel,
    BalanceBelowPFLSMinCapacity,
    SamePaymentAddress,
    TypeScriptInPaymentOutput,
    TypeScriptInPFLSOutput,
    InvalidSUDT,
    InvalidSUDTDataLength,
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

impl From<SigError> for Error {
    fn from(_: SigError) -> Self {
        return Self::SignatureVerificationError;
    }
}
