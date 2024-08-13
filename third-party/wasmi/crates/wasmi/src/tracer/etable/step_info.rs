use serde::{Deserialize, Serialize};

use crate::mtable::{MemoryReadSize, MemoryStoreSize, VarType};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum StepInfo {
    Br {
        offset: u64,
    },
    BrIfEqz {
        condition: u64,
        offset: u64,
    },
    BrIfNez {
        condition: u64,
        offset: u64,
    },
    BrAdjustIfNez,
    BrAdjust {
        offset: u64,
    },
    Return {
        drop: u32,
        keep_values: Vec<u64>,
    },
    Drop,
    Select {
        val1: u64,
        val2: u64,
        cond: u64,
        result: u64,
    },
    CallInternal {
        args: Vec<u64>,
    },
    Call {
        args: Vec<u64>,
    },
    CallIndirect {
        func_index: u32,
    },
    LocalGet {
        depth: usize,
        value: u64,
    },
    SetLocal {
        depth: usize,
        value: u64,
    },
    TeeLocal {
        depth: usize,
        value: u64,
    },
    GetGlobal {
        idx: u32,
        value: u64,
    },
    SetGlobal {
        idx: u32,
        value: u64,
    },
    Load {
        vtype: VarType,
        load_size: MemoryReadSize,
        offset: u32,
        raw_address: u32,
        effective_address: usize,
        value: u64,
        block_value1: u64,
        block_value2: u64,
    },
    Store {
        vtype: VarType,
        store_size: MemoryStoreSize,
        offset: u32,
        raw_address: u32,
        effective_address: usize,
        pre_block_value1: u64,
        updated_block_value1: u64,
        pre_block_value2: u64,
        updated_block_value2: u64,
        value: u64,
    },
    MemorySize,
    MemoryGrow {
        grow_size: i32,
        result: i32,
        current_pages: u32,
    },

    I32Const {
        value: i32,
    },
    Const32 {
        value: u32,
    },
    ConstRef {
        value: u64,
    },
    I64Const {
        value: i64,
    },

    I32BinOp {
        class: BinOp,
        left: i32,
        right: i32,
        value: i32,
    },
    I32BinShiftOp {
        class: ShiftOp,
        left: i32,
        right: i32,
        value: i32,
    },
    I32BinBitOp {
        class: BitOp,
        left: i32,
        right: i32,
        value: i32,
    },

    I64BinOp {
        class: BinOp,
        left: i64,
        right: i64,
        value: i64,
    },
    I64BinShiftOp {
        class: ShiftOp,
        left: i64,
        right: i64,
        value: i64,
    },
    I64BinBitOp {
        class: BitOp,
        left: i64,
        right: i64,
        value: i64,
    },

    UnaryOp {
        class: UnaryOp,
        vtype: VarType,
        operand: u64,
        result: u64,
    },
    CompZ {
        vtype: VarType,
        value: u64,
        result: i32,
    },
    I32Comp {
        class: RelOp,
        left: i32,
        right: i32,
        value: bool,
    },
    I64Comp {
        class: RelOp,
        left: i64,
        right: i64,
        value: bool,
    },
    I32WrapI64 {
        value: i64,
        result: i32,
    },
    I64ExtendI32 {
        value: u64,
        result: i64,
        sign: bool,
    },
    I32SignExtendI8 {
        value: u64,
        result: u64,
    },
    I32SignExtendI16 {
        value: u64,
        result: u64,
    },
    I64SignExtendI8 {
        value: u64,
        result: u64,
    },
    I64SignExtendI16 {
        value: u64,
        result: u64,
    },
    I64SignExtendI32 {
        value: u64,
        result: u64,
    },
    I32TruncF32 {
        value: u64,
        result: i32,
        sign: bool,
    },
    I32TruncF64 {
        value: u64,
        result: i32,
        sign: bool,
    },
    I64TruncF32 {
        value: u64,
        result: i64,
        sign: bool,
    },
    I64TruncF64 {
        value: u64,
        result: i64,
        sign: bool,
    },

    F32ConvertI32 {
        value: u64,
        result: u64,
        sign: bool,
    },

    F32ConvertI64 {
        value: u64,
        result: u64,
        sign: bool,
    },

    F64ConvertI32 {
        value: u64,
        result: u64,
        sign: bool,
    },

    F64ConvertI64 {
        value: u64,
        result: u64,
        sign: bool,
    },

    I32ReinterpretF32 {
        value: u64,
        result: i32,
    },
    I64ReinterpretF64 {
        value: u64,
        result: i64,
    },
    F32ReinterpretI32 {
        value: i32,
        result: u64,
    },

    F64ReinterpretI64 {
        value: i64,
        result: u64,
    },

    F32DemoteF64 {
        value: u64,
        result: u64,
    },
    F64PromoteF32 {
        value: u64,
        result: u64,
    },

    F32Const {
        value: u64,
    },

    F64Const {
        value: u64,
    },
    F32Comp {
        class: RelOp,
        left: u64,
        right: u64,
        value: bool,
    },
    F64Comp {
        class: RelOp,
        left: u64,
        right: u64,
        value: bool,
    },
    F32BinOp {
        class: BinOp,
        left: u64,
        right: u64,
        value: u64,
    },

    F64BinOp {
        class: BinOp,
        left: u64,
        right: u64,
        value: u64,
    },
    MemoryFill {
        value: u64,
        size: u64,
        offset: u64,
        prev_val_vec: Vec<u64>,
        new_val_vec: Vec<u64>,
    },
    MemoryCopy {
        num_bytes_to_copy: u64,
        src: u64,
        destination: u64,
        prev_val_vec: Vec<u64>,
        new_val_vec: Vec<u64>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum UnaryOp {
    Ctz,
    Clz,
    Popcnt,
    Abs,
    Neg,
    Ceil,
    Floor,
    Trunc,
    Nearest,
    Sqrt,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Min,
    Max,
    Copysign,
    UnsignedDiv,
    UnsignedRem,
    SignedDiv,
    SignedRem,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum ShiftOp {
    Shl,
    UnsignedShr,
    SignedShr,
    Rotl,
    Rotr,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum BitOp {
    And = 0,
    Or = 1,
    Xor = 2,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum RelOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    SignedGt,
    UnsignedGt,
    SignedGe,
    UnsignedGe,
    SignedLt,
    UnsignedLt,
    SignedLe,
    UnsignedLe,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum TestOp {
    Eqz,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum ConversionOp {
    I32WrapI64,
    I64ExtendI32s,
    I64ExtendI32u,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
    I32TruncSF32,
    I32TruncUF32,
    I32TruncSF64,
    I32TruncUF64,
    I64TruncSF32,
    I64TruncUF32,
    I64TruncSF64,
    I64TruncUF64,
    F32ConvertSI32,
    F32ConvertUI32,
    F32ConvertSI64,
    F32ConvertUI64,
    F64ConvertSI32,
    F64ConvertUI32,
    F64ConvertSI64,
    F64ConvertUI64,
    I32ReinterpretF32,
    I64ReinterpretF64,
    F32ReinterpretI32,
    F64ReinterpretI64,
    F32DemoteF64,
    F64PromoteF32,
}
