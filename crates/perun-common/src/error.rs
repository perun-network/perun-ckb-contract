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
    WaitFailure,
    InvalidFd,
    OtherEndClosed,
    MaxVmsSpawned,
    MaxFdsCreated,
    UnexpectedSysError,
    TypeIDError,
    // Verification Errors
    InvalidDisputeMode,
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
    UndefinedBehavior,
    ChannelCellDataIsEmpty,
    // NonLedgerChannelsNotSupported,
    // VirtualChannelsNotSupported,
    ChannelStateNotEqual,
    FundingChanged,
    InvalidParentPCTSHash,
    TypeHashNotFound,
    LedgerChannelDoesNotHaveEnoughFundsForVC,
    UnequalBalanceInLockedFundsAndVirtualChannelBalance,
    ParentsOfVCInOutputHaveDifferentVCStatus,
    InvalidOutputTxForVCDisputeStart,
    OnlyChannelStatusExpectedButThatIsNotTheCase,
    InputCellForGivenParticipantNotFound,
    FundingNotInStatus,
    OwnFundingNotInOutputs,
    FundedBitStatusNotCorrect,
    StateIsFunded,
    ParentPCTSHashNotFound,
    ChannelFundWithoutChannelOutput,
    ChannelDisputeWithoutChannelOutput,
    ChannelCloseWithChannelOutput,
    ChannelForceCloseWithChannelOutput,
    ChannelAbortWithChannelOutput,
    InvalidParentsCountForVC,
    OutputCellForGivenParticipantNotFound,
    InvalidThreadToken,
    InvalidChannelId,
    StartWithNonZeroVersion,
    StartWithFinalizedState,
    InvalidPCLSCodeHash,
    InvalidPCLSHashType,
    PCLSWithArgs,
    VCLSWithArgs,
    StatusDisputed,
    StatusNotDisputed,
    FundingNotZero,
    NotAllPaid,
    TimeLockNotExpired,
    InvalidTimestamp,
    UnableToLoadAnyChannelStatus,
    UnableToLoadVirtualChannelStatus,
    InvalidSignature,
    InvalidMessage,
    InvalidPFLSInOutputs,
    InvalidNumberOfOutputs,
    PCTSNotFound,
    FoundDifferentChannel,
    MoreThanOneChannel,
    BalanceBelowPFLSMinCapacity,
    SamePaymentAddress,
    TypeScriptInPaymentOutput,
    TypeScriptInPFLSOutput,
    InvalidSUDT,
    InvalidSUDTDataLength,
    DecreasingAmount,
    WrongChannelType,
    InvalidVCTx,
    InvalidVCTxStart,
    ParentsOfVCNotFound,
    VCInputCellMissingInMergeTx,
    FundsForVCNotLocked,
    InvalidVCMergeTx,
    FirstForceCloseFlagSet,
    FirstForceCloseFlagNotSet,
    InvalidVCLockScript,
    ParentNotFoundInOutputs,
    InvalidVersionNumberVCProgressTx,
    InvalidVCClose1Tx,
    ParentsLengthMismatch,
    ParentsMismatch,
    ParentNotInForceClose,
    VCInputCellMissingInClose1Tx,
    VCParticipantIdxNotFound,
    InvalidVCParentData,
    SUDTAllocationLengthMismatch,
    VCOutputCellMissingIngStartTx,
    VCDisputeWithoutChannelOutput,
    VCStatusNotEqual,
    NoVCRentPayoutCell,
    InvalidVCRentPayoutCell,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            MaxFdsCreated => Self::MaxFdsCreated,
            MaxVmsSpawned => Self::MaxVmsSpawned,
            OtherEndClosed => Self::OtherEndClosed,
            InvalidFd => Self::InvalidFd,
            WaitFailure => Self::WaitFailure,
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
            _TypeIDError => Self::TypeIDError,
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
