#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::all)]

mod host_error;
mod nan_preserving_float;
mod trap;
mod units;
mod untyped;
mod value;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std as alloc;

use self::value::{
    ArithmeticOps,
    ExtendInto,
    Float,
    Integer,
    LittleEndianConvert,
    SignExtendFrom,
    TruncateSaturateInto,
    TryTruncateInto,
    WrapInto,
};
pub use self::{
    host_error::HostError,
    nan_preserving_float::{F32, F64},
    trap::{Trap, TrapCode},
    units::Pages,
    untyped::{
        effective_address,
        DecodeUntypedSlice,
        EncodeUntypedSlice,
        UntypedError,
        UntypedValue,
    },
    value::ValueType,
};
