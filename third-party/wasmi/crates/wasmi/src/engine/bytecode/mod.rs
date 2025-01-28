//! The instruction architecture of the `wasmi` interpreter.

mod utils;

#[cfg(test)]
mod tests;

pub use self::utils::{
    AddressOffset, BlockFuel, BranchOffset, BranchTableTargets, DataSegmentIdx, DropKeep,
    DropKeepError, ElementSegmentIdx, F64Const32, FuncIdx, GlobalIdx, LocalDepth, SignatureIdx,
    TableIdx,
};
use super::{const_pool::ConstRef, CompiledFunc, TranslationError};
use core::fmt::Debug;
use wasmi_core::F32;

/// The internal `wasmi` bytecode that is stored for Wasm functions.
///
/// # Note
///
/// This representation slightly differs from WebAssembly instructions.
///
/// For example the `BrTable` instruction is unrolled into separate instructions
/// each representing either the `BrTable` head or one of its branching targets.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum Instruction {
    LocalGet(LocalDepth),
    LocalSet(LocalDepth),
    LocalTee(LocalDepth),
    /// An unconditional branch.
    Br(BranchOffset),
    /// Branches if the top-most stack value is equal to zero.
    BrIfEqz(BranchOffset),
    /// Branches if the top-most stack value is _not_ equal to zero.
    BrIfNez(BranchOffset),
    /// An unconditional branch.
    ///
    /// This operation also adjust the underlying value stack if necessary.
    ///
    /// # Encoding
    ///
    /// This [`Instruction`] must be followed by a [`Instruction::Return`]
    /// which stores information about the [`DropKeep`] behavior of the
    /// [`Instruction::Br`]. The [`Instruction::Return`] will never be executed
    /// and only acts as parameter storage for this instruction.
    BrAdjust(BranchOffset),
    /// Branches if the top-most stack value is _not_ equal to zero.
    ///
    /// This operation also adjust the underlying value stack if necessary.
    ///
    /// # Encoding
    ///
    /// This [`Instruction`] must be followed by a [`Instruction::Return`]
    /// which stores information about the [`DropKeep`] behavior of the
    /// [`Instruction::BrIfNez`]. The [`Instruction::Return`] will never be executed
    /// and only acts as parameter storage for this instruction.
    BrAdjustIfNez(BranchOffset),
    /// Branch table with a set number of branching targets.
    ///
    /// # Encoding
    ///
    /// This [`Instruction`] must be followed by exactly as many unconditional
    /// branch instructions as determined by [`BranchTableTargets`]. Branch
    /// instructions that may follow are [`Instruction::Br] and [`Instruction::Return`].
    BrTable(BranchTableTargets),
    #[default]
    Unreachable,
    ConsumeFuel(BlockFuel),
    Return(DropKeep),
    ReturnIfNez(DropKeep),
    /// Tail calls an internal (compiled) function.
    ///
    /// # Note
    ///
    /// This instruction can be used for calls to functions that are engine internal
    /// (or compiled) and acts as an optimization for those common cases.
    ///
    /// # Encoding
    ///
    /// This [`Instruction`] must be followed by an [`Instruction::Return`] that
    /// encodes the [`DropKeep`] parameter. Note that the [`Instruction::Return`]
    /// only acts as a storage for the parameter of the [`Instruction::ReturnCall`]
    /// and will never be executed by itself.
    ReturnCallInternal(CompiledFunc),
    /// Tail calling `func`.
    ///
    /// # Note
    ///
    /// Since [`Instruction::ReturnCallInternal`] should be used for all functions internal
    /// (or compiled) to the engine this instruction should mainly be used for tail calling
    /// imported functions. However, it is a general form that can technically be used
    /// for both.
    ///
    /// # Encoding
    ///
    /// This [`Instruction`] must be followed by an [`Instruction::Return`] that
    /// encodes the [`DropKeep`] parameter. Note that the [`Instruction::Return`]
    /// only acts as a storage for the parameter of the [`Instruction::ReturnCall`]
    /// and will never be executed by itself.
    ReturnCall(FuncIdx),
    /// Tail calling a function indirectly.
    ///
    /// # Encoding
    ///
    /// This [`Instruction`] must be followed by an [`Instruction::Return`] that
    /// encodes the [`DropKeep`] parameter as well as an [`Instruction::TableGet`]
    /// that encodes the [`TableIdx`] parameter. Note that both, [`Instruction::Return`]
    /// and [`Instruction::TableGet`] only act as a storage for parameters to the
    /// [`Instruction::ReturnCallIndirect`] and will never be executed by themselves.
    ReturnCallIndirect(SignatureIdx),
    /// Calls an internal (compiled) function.
    ///
    /// # Note
    ///
    /// This instruction can be used for calls to functions that are engine internal
    /// (or compiled) and acts as an optimization for those common cases.
    CallInternal(CompiledFunc),
    /// Calls the function.
    ///
    /// # Note
    ///
    /// Since [`Instruction::CallInternal`] should be used for all functions internal
    /// (or compiled) to the engine this instruction should mainly be used for calling
    /// imported functions. However, it is a general form that can technically be used
    /// for both.
    Call(FuncIdx),
    /// Calling a function indirectly.
    ///
    /// # Encoding
    ///
    /// This [`Instruction`] must be followed by an [`Instruction::TableGet`]
    /// that encodes the [`TableIdx`] parameter. Note that the [`Instruction::TableGet`]
    /// only acts as a storage for the parameter of the [`Instruction::CallIndirect`]
    /// and will never be executed by itself.
    CallIndirect(SignatureIdx),
    Drop,
    Select,
    GlobalGet(GlobalIdx),
    GlobalSet(GlobalIdx),
    I32Load(AddressOffset),
    I64Load(AddressOffset),
    F32Load(AddressOffset),
    F64Load(AddressOffset),

    I32Load8S(AddressOffset),
    I32Load8U(AddressOffset),
    I32Load16S(AddressOffset),
    I32Load16U(AddressOffset),

    I64Load8S(AddressOffset),
    I64Load8U(AddressOffset),
    I64Load16S(AddressOffset),
    I64Load16U(AddressOffset),
    I64Load32S(AddressOffset),
    I64Load32U(AddressOffset),

    I32Store(AddressOffset),
    I64Store(AddressOffset),
    F32Store(AddressOffset),
    F64Store(AddressOffset),
    I32Store8(AddressOffset),
    I32Store16(AddressOffset),
    I64Store8(AddressOffset),
    I64Store16(AddressOffset),
    I64Store32(AddressOffset),
    MemorySize,
    MemoryGrow,
    MemoryFill,
    MemoryCopy,
    MemoryInit(DataSegmentIdx),
    DataDrop(DataSegmentIdx),
    TableSize(TableIdx),
    TableGrow(TableIdx),
    TableFill(TableIdx),
    TableGet(TableIdx),
    TableSet(TableIdx),
    /// Copies elements from one table to another.
    ///
    /// # Note
    ///
    /// It is also possible to copy elements within the same table.
    ///
    /// # Encoding
    ///
    /// The [`TableIdx`] referred to by the [`Instruction::TableCopy`]
    /// represents the `dst` (destination) table. The [`Instruction::TableCopy`]
    /// must be followed by an [`Instruction::TableGet`] which stores a
    /// [`TableIdx`] that refers to the `src` (source) table.
    TableCopy(TableIdx),
    /// Initializes a table given an [`ElementSegmentIdx`].
    ///
    /// # Encoding
    ///
    /// The [`Instruction::TableInit`] must be followed by an
    /// [`Instruction::TableGet`] which stores a [`TableIdx`]
    /// that refers to the table to be initialized.
    TableInit(ElementSegmentIdx),
    ElemDrop(ElementSegmentIdx),
    RefFunc(FuncIdx),
    /// A 32-bit constant value.
    Const32([u8; 4]),
    /// A 64-bit integer value losslessly encoded as 32-bit integer.
    ///
    /// Upon execution the 32-bit integer is sign-extended to the 64-bit integer.
    ///
    /// # Note
    ///
    /// This is a space-optimized variant of [`Instruction::ConstRef`] but can
    /// only used for small integer values that fit into a 32-bit integer value.
    I64Const32(i32),
    /// A 64-bit float value losslessly encoded as 32-bit float.
    ///
    /// Upon execution the 32-bit float is promoted to the 64-bit float.
    ///
    /// # Note
    ///
    /// This is a space-optimized variant of [`Instruction::ConstRef`] but can
    /// only used for certain float values that fit into a 32-bit float value.
    F64Const32(F64Const32),
    /// Pushes a constant value onto the stack.
    ///
    /// The constant value is referred to indirectly by the [`ConstRef`].
    ConstRef(ConstRef),
    I32Eqz,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,

    // i64
    // comparisons
    I64Eqz,
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU,
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,

    // f32
    // binary comparisons
    F32Eq,
    F32Ne,
    F32Lt,
    F32Gt,
    F32Le,
    F32Ge,
    F64Eq,
    F64Ne,
    F64Lt,
    F64Gt,
    F64Le,
    F64Ge,

    I32Clz,
    I32Ctz,
    I32Popcnt,

    // i32
    // binary
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I32Rotl,
    I32Rotr,

    // i64
    I64Clz,
    I64Ctz,
    I64Popcnt,
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrS,
    I64ShrU,
    I64Rotl,
    I64Rotr,

    // unary
    F32Abs,
    F32Neg,
    F32Ceil,
    F32Floor,
    F32Trunc,
    F32Nearest,
    F32Sqrt,

    // binary
    F32Add,
    F32Sub,
    F32Mul,
    F32Div,
    F32Min,
    F32Max,
    F32Copysign,

    // unary
    F64Abs,
    F64Neg,
    F64Ceil,
    F64Floor,
    F64Trunc,
    F64Nearest,
    F64Sqrt,

    // binary
    F64Add,
    F64Sub,
    F64Mul,
    F64Div,
    F64Min,
    F64Max,
    F64Copysign,

    // unary
    I32WrapI64,
    I32TruncF32S,
    I32TruncF32U,
    I32TruncF64S,
    I32TruncF64U,
    I64ExtendI32S,
    I64ExtendI32U,
    I64TruncF32S,
    I64TruncF32U,
    I64TruncF64S,
    I64TruncF64U,
    F32ConvertI32S,
    F32ConvertI32U,
    F32ConvertI64S,
    F32ConvertI64U,
    F32DemoteF64,
    F64ConvertI32S,
    F64ConvertI32U,
    F64ConvertI64S,
    F64ConvertI64U,
    F64PromoteF32,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
    I32TruncSatF32S,
    I32TruncSatF32U,
    I32TruncSatF64S,
    I32TruncSatF64U,
    I64TruncSatF32S,
    I64TruncSatF32U,
    I64TruncSatF64S,
    I64TruncSatF64U,

    // Used for zkWASM
    DropKeep,
    MemoryCopyStep,
    MemoryFillStep,
    HostCallStep,
    HostCallStackStep,
    // Special instruction to trace the zero writes to the stack when vm is preparing for a function call
    CallZeroWrite,
}

impl std::hash::Hash for Instruction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.index_j().hash(state);
    }
}

impl Instruction {
    /// Creates an [`Instruction::Const32`] from the given `i32` constant value.
    pub fn i32_const(value: i32) -> Self {
        Self::Const32(value.to_ne_bytes())
    }

    /// Creates an [`Instruction::Const32`] from the given `f32` constant value.
    pub fn f32_const(value: F32) -> Self {
        Self::Const32(value.to_bits().to_ne_bytes())
    }

    /// Creates a new `local.get` instruction from the given local depth.
    ///
    /// # Errors
    ///
    /// If the `local_depth` is out of bounds as local depth index.
    pub fn local_get(local_depth: u32) -> Result<Self, TranslationError> {
        Ok(Self::LocalGet(LocalDepth::from(local_depth)))
    }

    /// Creates a new `local.set` instruction from the given local depth.
    ///
    /// # Errors
    ///
    /// If the `local_depth` is out of bounds as local depth index.
    pub fn local_set(local_depth: u32) -> Result<Self, TranslationError> {
        Ok(Self::LocalSet(LocalDepth::from(local_depth)))
    }

    /// Creates a new `local.tee` instruction from the given local depth.
    ///
    /// # Errors
    ///
    /// If the `local_depth` is out of bounds as local depth index.
    pub fn local_tee(local_depth: u32) -> Result<Self, TranslationError> {
        Ok(Self::LocalTee(LocalDepth::from(local_depth)))
    }

    /// Convenience method to create a new `ConsumeFuel` instruction.
    pub fn consume_fuel(amount: u64) -> Result<Self, TranslationError> {
        let block_fuel = BlockFuel::try_from(amount)?;
        Ok(Self::ConsumeFuel(block_fuel))
    }

    /// Increases the fuel consumption of the [`ConsumeFuel`] instruction by `delta`.
    ///
    /// # Panics
    ///
    /// - If `self` is not a [`ConsumeFuel`] instruction.
    /// - If the new fuel consumption overflows the internal `u64` value.
    ///
    /// [`ConsumeFuel`]: Instruction::ConsumeFuel
    pub fn bump_fuel_consumption(&mut self, delta: u64) -> Result<(), TranslationError> {
        match self {
            Self::ConsumeFuel(block_fuel) => block_fuel.bump_by(delta),
            instr => panic!("expected Instruction::ConsumeFuel but found: {instr:?}"),
        }
    }
}

impl Instruction {
    pub const MAX_J: u64 = 52;

    /// Get an index for each instruction to constrain the zkVM's computation result at the end of each zkVM cycle.
    /// To elaborate the zkVM multiplexer circuit has to perform all computation instructions and at then end of the circuit
    /// we use this index to constraint the right computation result for the corresponding instruction getting executed.
    pub fn index_j(&self) -> u64 {
        match self {
            Self::Unreachable => 0,
            Self::I64Const32(..)
            | Self::Const32(..)
            | Self::ConstRef(..)
            | Self::F64Const32(..) => 1,
            Self::LocalGet(..) => 2,
            Self::I64Add => 3,
            Self::I64Mul => 4,
            Self::I64And | Self::I64Xor | Self::I64Or => 5,
            Self::BrIfEqz(..) => 6,
            Self::LocalSet(..) => 7,
            Self::Br(..) => 8,
            Self::BrIfNez(..) => 9,
            Self::DropKeep => 10,

            // Store opcodes
            Self::I32Store(..)
            | Self::I32Store8(..)
            | Self::I32Store16(..)
            | Self::F32Store(..)
            | Self::F64Store(..)
            | Self::I64Store(..)
            | Self::I64Store8(..)
            | Self::I64Store16(..)
            | Self::I64Store32(..) => 11,

            // Load opcodes
            Self::I32Load(..)
            | Self::I32Load8U(..)
            | Self::I32Load8S(..)
            | Self::I32Load16U(..)
            | Self::I32Load16S(..)
            | Self::F32Load(..)
            | Self::F64Load(..)
            | Self::I64Load(..)
            | Self::I64Load8S(..)
            | Self::I64Load8U(..)
            | Self::I64Load16S(..)
            | Self::I64Load16U(..)
            | Self::I64Load32S(..)
            | Self::I64Load32U(..) => 12,

            Self::LocalTee(..) => 13,

            Self::I64Popcnt | Self::I64Clz | Self::I64Ctz => 14,

            // visit_unary
            Self::F32Abs
            | Self::F32Neg
            | Self::F32Ceil
            | Self::F32Floor
            | Self::F32Trunc
            | Self::F32Nearest
            | Self::F32Sqrt
            | Self::F64Abs
            | Self::F64Neg
            | Self::F64Ceil
            | Self::F64Floor
            | Self::F64Trunc
            | Self::F64Nearest
            | Self::F64Sqrt
            | Self::I32WrapI64
            | Self::I32TruncF32S
            | Self::I32TruncF32U
            | Self::I32TruncF64S
            | Self::I32TruncF64U
            | Self::I64ExtendI32S
            | Self::I64ExtendI32U
            | Self::I64TruncF32S
            | Self::I64TruncF32U
            | Self::I64TruncF64S
            | Self::I64TruncF64U
            | Self::F32ConvertI32S
            | Self::F32ConvertI32U
            | Self::F32ConvertI64S
            | Self::F32ConvertI64U
            | Self::F32DemoteF64
            | Self::F64ConvertI32S
            | Self::F64ConvertI32U
            | Self::F64ConvertI64S
            | Self::F64ConvertI64U
            | Self::F64PromoteF32
            | Self::I32Extend8S
            | Self::I32Extend16S
            | Self::I64Extend8S
            | Self::I64Extend16S
            | Self::I64Extend32S
            | Self::I32TruncSatF32S
            | Self::I32TruncSatF32U
            | Self::I32TruncSatF64S
            | Self::I32TruncSatF64U
            | Self::I64TruncSatF32S
            | Self::I64TruncSatF32U
            | Self::I64TruncSatF64S
            | Self::I64TruncSatF64U => 19,

            // visit_binary
            Self::F32Eq
            | Self::F32Ne
            | Self::F32Lt
            | Self::F32Gt
            | Self::F32Le
            | Self::F32Ge
            | Self::F64Eq
            | Self::F64Ne
            | Self::F64Lt
            | Self::F64Gt
            | Self::F64Le
            | Self::F64Ge
            | Self::F32Add
            | Self::F32Sub
            | Self::F32Mul
            | Self::F32Div
            | Self::F32Min
            | Self::F32Max
            | Self::F32Copysign
            | Self::F64Add
            | Self::F64Sub
            | Self::F64Mul
            | Self::F64Div
            | Self::F64Min
            | Self::F64Max
            | Self::F64Copysign => 20,

            Self::I64Sub => 21,

            Self::I64Shl | Self::I64ShrU | Self::I64ShrS | Self::I64Rotl | Self::I64Rotr => 22,

            // i32
            Self::I32Add => 15,
            Self::I32Mul => 16,
            Self::I32Sub => 17,

            Self::I32DivS | Self::I32RemS => 18,
            Self::I32DivU | Self::I32RemU => 23,

            Self::I32And | Self::I32Xor | Self::I32Or => 24,
            Self::I32Popcnt | Self::I32Clz | Self::I32Ctz => 25,

            Self::I32LtS | Self::I32LtU | Self::I32GeS | Self::I32GeU => 26,
            Self::I32GtS | Self::I32GtU | Self::I32LeS | Self::I32LeU => 29,

            Self::I32Shl | Self::I32ShrU | Self::I32ShrS | Self::I32Rotl | Self::I32Rotr => 30,

            // done
            Self::I64DivS | Self::I64RemS => 27,
            Self::I64DivU | Self::I64RemU => 28,

            Self::I64Eqz | Self::I32Eqz => 31,

            Self::Select => 32,
            Self::GlobalGet(..) => 33,
            Self::GlobalSet(..) => 34,
            Self::BrTable(..) => 35,
            Self::BrAdjust(..) => 36,
            Self::MemoryCopy => 37,
            Self::MemoryFill => 38,
            Self::MemoryGrow => 39,
            Self::MemorySize => 40,
            Self::MemoryCopyStep => 41,
            Self::MemoryFillStep => 42,
            Self::HostCallStep => 43,
            Self::HostCallStackStep => 44,
            Self::CallZeroWrite => 45,

            Self::I64Eq | Self::I32Eq => 46,
            Self::I64Ne | Self::I32Ne => 47,

            Self::I64LtS | Self::I64LtU | Self::I64GeS | Self::I64GeU => 48,
            Self::I64GtS | Self::I64GtU | Self::I64LeS | Self::I64LeU => 49,
            Self::CallInternal(..) => 50,
            Self::CallIndirect(..) | Self::Call(..) => 0, // TODO: all 0 J_indexes
            Self::Drop => 51,
            Self::Return(..) => Self::MAX_J,
            _ => {
                println!("{:?}", self);
                unimplemented!()
            }
        }
    }
}
