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
    LedgerChannelHasLockedFunds,
    InvalidDummyEntry,

    // ── Liquidity Pool Errors (negative codes to avoid i8 overflow) ──────
    /// Pool lockscript args are missing or the wrong length.
    PoolLSNoArgs = -1,
    /// The pool typescript was not found among inputs (needed by lockscript).
    PoolTypescriptNotFound = -2,
    /// Pool cell data has an unrecognized or missing magic prefix.
    PoolInvalidCellMagic = -3,
    /// Pool cell data is too short to be a valid PoolState / LPPosition.
    PoolStateTooShort = -4,
    /// LP position cell data is too short.
    LPPositionTooShort = -5,
    /// No pool-state cell found in transaction inputs.
    PoolStateInputMissing = -6,
    /// No pool-state cell found in transaction outputs.
    PoolStateOutputMissing = -7,
    /// Input pool_id does not match the typescript args.
    PoolIdMismatch = -8,
    /// CKB reserve in pool state cell doesn't match cell capacity delta.
    PoolReserveMismatch = -9,
    /// LP token arithmetic overflow or underflow.
    LPArithmetic = -10,
    /// The slippage tolerance was exceeded (min_lp_out / min_ckb_out).
    SlippageExceeded = -11,
    /// Operator lock hash was not found among input cells.
    OperatorNotSigning = -12,
    /// The LP position cell was not found in inputs.
    LPPositionInputMissing = -13,
    /// The LP position pool_id doesn't match the pool.
    LPPositionPoolIdMismatch = -14,
    /// The LP position amount is zero.
    LPAmountZero = -15,
    /// lp_token_supply is zero when it should be positive (division by zero).
    LPSupplyZero = -16,
    /// Pool witness is missing from WitnessArgs.input_type.
    PoolWitnessMissing = -17,
    /// Pool witness has an unknown or invalid union item id.
    PoolWitnessInvalid = -18,
    /// Unexpected multiple pool-state cells encountered.
    MultiplePoolStateCells = -19,
    /// The ckb_reserve field does not match what is expected from capacity.
    PoolCKBReserveInconsistent = -20,
    /// The ckb_out / ckb_in value is zero.
    PoolCKBAmountZero = -21,
    /// InitPool: pool state already exists in inputs (re-init).
    PoolAlreadyInitialised = -22,
    /// InitPool: pool_id in cell data does not match expected hash.
    PoolIdInitMismatch = -23,

    // ── Channel reservation errors ────────────────────────────────────────
    /// A reservation for this channel_id already exists.
    ChannelAlreadyReserved = -24,
    /// No active reservation found for the given channel_id.
    ChannelNotReserved = -25,
    /// The reservation has exceeded MAX_RESERVATION_SECS.
    ReservationExpired = -26,
    /// Available CKB (total − reserved) is too low for the requested amount.
    InsufficientCKBLiquidity = -27,
    /// Available ETH mirror (total − reserved) is too low.
    InsufficientETHLiquidity = -28,
    /// Reservation-cell state after the tx is inconsistent with the operation.
    InvalidReservationState = -29,

    // ── Settlement / redistribution errors ───────────────────────────────
    /// Settlement amounts or cell layout is invalid.
    InvalidSettlement = -30,
    /// Swap output does not satisfy the constant-product invariant.
    InvalidSwapOutput = -31,
    /// Fee accumulator fields are inconsistent.
    InvalidFeeAccounting = -32,

    // ── LP position errors ────────────────────────────────────────────────
    /// The LP position cell is missing or inactive.
    NoActivePosition = -33,
    /// The LP has no fees to claim.
    NoFeesToClaim = -34,
    /// Pool does not have enough *available* liquidity to execute the swap.
    InsufficientLiquidityForSwap = -35,
}
impl From<Error> for i8 {
    #[inline]
    fn from(e: Error) -> i8 {
        e as i8
    }
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
