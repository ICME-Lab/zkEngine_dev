use serde::{Deserialize, Serialize};
use wasmi_core::UntypedValue;

use crate::mtable::{MemoryReadSize, MemoryStoreSize, VarType};

#[derive(Deserialize, Serialize)]
pub enum RunInstructionTracePre {
    BrIfEqz {
        condition: u64,
    },
    BrIfNez {
        condition: u64,
    },
    BrTable {
        index: u64,
    },
    Return {
        drop: u32,
        keep_values: Vec<u64>,
    },
    CallInternal {
        args: Vec<UntypedValue>,
    },
    CallIndirect {
        idx: u32,
    },
    SetLocal {
        depth: usize,
        value: UntypedValue,
    },
    SetGlobal {
        idx: u32,
        value: UntypedValue,
    },
    Load {
        offset: u32,
        raw_address: u32,
        effective_address: Option<usize>, // use option in case of memory out of bound
        vtype: VarType,
        load_size: MemoryReadSize,
    },
    Store {
        offset: u32,
        raw_address: u32,
        effective_address: Option<usize>,
        value: u64,
        vtype: VarType,
        store_size: MemoryStoreSize,
        pre_block_value1: Option<u64>,
        pre_block_value2: Option<u64>,
    },
    GrowMemory {
        grow_size: u32,
        pages: u32,
    },

    I32BinOp {
        left: i32,
        right: i32,
    },
    I32BinShiftOp {
        left: u64,
        right: u64,
    },

    I64BinOp {
        left: i64,
        right: i64,
    },

    I32Single(i32),
    I32Comp {
        left: i32,
        right: i32,
    },
    I64Single(i64),
    I64Comp {
        left: i64,
        right: i64,
    },

    I32WrapI64 {
        value: i64,
    },
    I64ExtendI32 {
        value: i32,
        sign: bool,
    },
    I32SignExtendI8 {
        value: i32,
    },
    I32SignExtendI16 {
        value: i32,
    },
    I64SignExtendI8 {
        value: i64,
    },
    I64SignExtendI16 {
        value: i64,
    },
    I64SignExtendI32 {
        value: i64,
    },

    I32TruncF32 {
        value: f32,
        sign: bool,
    },

    I32TruncF64 {
        value: f64,
        sign: bool,
    },

    I64TruncF32 {
        value: f32,
        sign: bool,
    },

    I64TruncF64 {
        value: f64,
        sign: bool,
    },

    F32ConvertI32 {
        value: i32,
        sign: bool,
    },
    F32ConvertI64 {
        value: i64,
        sign: bool,
    },
    F64ConvertI32 {
        value: i32,
        sign: bool,
    },
    F64ConvertI64 {
        value: u64,
        sign: bool,
    },
    I32ReinterpretF32 {
        value: f32,
    },
    I64ReinterpretF64 {
        value: f64,
    },
    F32ReinterpretI32 {
        value: i32,
    },
    F64ReinterpretI64 {
        value: i64,
    },
    F32DemoteF64 {
        value: f64,
    },
    F64PromoteF32 {
        value: f32,
    },
    UnaryOp {
        operand: u64,
        vtype: VarType,
    },
    Drop,
    Select {
        val1: u64,
        val2: u64,
        cond: u64,
    },

    F32Comp {
        left: f32,
        right: f32,
    },

    F64Comp {
        left: f64,
        right: f64,
    },

    F32BinOp {
        left: f32,
        right: f32,
    },

    F64BinOp {
        left: u64,
        right: u64,
    },
    MemoryFill {
        offset: u64,
        value: u64,
        size: u64,
        val_vec: Vec<u64>,
    },
    MemoryCopy {
        num_bytes_to_copy: u64,
        src: u64,
        destination: u64,
        val_vec: Vec<u64>,
    },
}
