#![allow(non_snake_case)]

use crate::{engine::bytecode::Instruction, AsContext, Global, Memory};
use core::cmp;
use wasmi_core::UntypedValue;

#[derive(Debug, Clone, Default)]
/// Hold the execution trace from VM execution and manages other miscellaneous
/// information needed by the zkWASM
pub struct Tracer {
    /// Holds the VM state at each timestamp of the execution
    pub(crate) execution_trace: Vec<WitnessVM>,
    /// This is used to maintain the max stack address. We use this to
    /// construct the IS for MCC
    max_sp: usize,
    /// Stack Initial Set for MCC
    IS_stack: Vec<(usize, u64, u64)>,
    /// Linear memory initial set
    IS_mem: Vec<(usize, u64, u64)>,
    /// Initial set of globals
    IS_globals: Vec<(usize, u64, u64)>,
}

impl Tracer {
    /// Creates a new [`TracerV0`] for generating execution trace during VM
    /// execution
    pub fn new() -> Self {
        Tracer::default()
    }

    /// Get len of execution trace
    pub fn len(&self) -> usize {
        self.execution_trace.len()
    }

    /// Get last instruction traced
    pub fn last(&self) -> Option<Instruction> {
        self.execution_trace.last().map(|witness| witness.instr)
    }

    /// Extract the execution trace from the tracer
    pub fn into_execution_trace(self) -> Vec<WitnessVM> {
        self.execution_trace
    }

    /// Getter for max_sp
    pub fn max_sp(&self) -> usize {
        self.max_sp
    }

    /// Setter for max_sp
    pub fn set_max_sp(&mut self, sp: usize) {
        self.max_sp = cmp::max(self.max_sp, sp);
    }

    /// Getter for IS_stack
    pub fn IS_stack(&self) -> Vec<(usize, u64, u64)> {
        let mut IS_stack = self.IS_stack.to_vec();
        if self.max_sp() > IS_stack.len() {
            IS_stack.extend((IS_stack.len()..=self.max_sp()).map(|i| (i, 0, 0)));
        }
        IS_stack
    }

    /// Setter for IS
    pub(crate) fn set_IS_stack(&mut self, stack: &[UntypedValue]) {
        self.IS_stack = stack
            .iter()
            .enumerate()
            .map(|(i, v)| (i, (*v).into(), 0))
            .collect();
    }

    /// Get IS_stack len
    pub fn IS_stack_len(&self) -> usize {
        self.IS_stack().len()
    }

    /// Get IS_mem len
    pub fn IS_mem_len(&self) -> usize {
        self.IS_mem.len()
    }

    /// Getter for initial zkvm memory
    pub fn init_memory(&self) -> Vec<(usize, u64, u64)> {
        let mut IS = self.IS_stack();
        let stack_len = IS.len();
        let linear_mem_len = self.IS_mem.len();
        IS.extend(self.IS_mem.iter().map(|(i, v, _)| (*i + stack_len, *v, 0)));
        IS.extend(
            self.IS_globals
                .iter()
                .map(|(i, v, _)| (*i + stack_len + linear_mem_len, *v, 0)),
        );

        IS
    }

    /// Truncate unused linear memory address
    pub fn truncate_unuesed_mem(&mut self) {
        let highest_address = self
            .execution_trace
            .iter()
            .filter_map(|vm| match vm.instr {
                Instruction::I32Load(_offset)
                | Instruction::I64Load(_offset)
                | Instruction::F32Load(_offset)
                | Instruction::F64Load(_offset)
                | Instruction::I32Load8S(_offset)
                | Instruction::I32Load8U(_offset)
                | Instruction::I32Load16S(_offset)
                | Instruction::I32Load16U(_offset)
                | Instruction::I64Load8S(_offset)
                | Instruction::I64Load8U(_offset)
                | Instruction::I64Load16S(_offset)
                | Instruction::I64Load16U(_offset)
                | Instruction::I64Load32S(_offset)
                | Instruction::I64Load32U(_offset)
                | Instruction::I32Store(_offset)
                | Instruction::I64Store(_offset)
                | Instruction::F32Store(_offset)
                | Instruction::F64Store(_offset)
                | Instruction::I32Store8(_offset)
                | Instruction::I32Store16(_offset)
                | Instruction::I64Store8(_offset)
                | Instruction::I64Store16(_offset)
                | Instruction::I64Store32(_offset) => Some(vm.I),

                Instruction::MemoryFill | Instruction::MemoryCopy => {
                    let size = vm.I;
                    let offset = vm.X;
                    Some(offset + size)
                }
                Instruction::MemoryInit(data_segment_index)
                | Instruction::DataDrop(data_segment_index) => {
                    println!("MemoryInit and DataDrop are not supported");
                    println!(
                        "memory.init or datadrop: {:?}, data_segment_index: {:?}",
                        vm.I, data_segment_index
                    );
                    unimplemented!();
                }
                _ => None,
            })
            .max();

        // Truncate to the largest 8-byte chunk that can accommodate the used highest address.
        let new_len = highest_address.map_or(0, |addr| (addr / 7) + 1);
        self.IS_mem.truncate(new_len as usize);
    }

    /// Push initial heap/linear WASM memory to tracer for MCC
    pub fn push_init_memory(&mut self, memref: Memory, context: impl AsContext) {
        let pages: u32 = memref.ty(&context).initial_pages().into();
        for i in 0..(pages * 8192) {
            let mut buf = [0u8; 8];
            memref
                .read(&context, (i * 8).try_into().unwrap(), &mut buf)
                .unwrap();
            self.IS_mem.push((i as usize, u64::from_le_bytes(buf), 0));
        }
    }

    /// Grow linear memory
    pub fn memory_grow(&mut self, pages: u64) {
        let curr_mem_size = self.IS_mem.len();
        for i in 0..(pages * 8192) {
            self.IS_mem.push((i as usize + curr_mem_size, 0, 0));
        }
    }

    /// Push globals
    pub fn push_global(&mut self, globalidx: usize, globalref: &Global, context: impl AsContext) {
        let value = UntypedValue::from(globalref.get(&context));
        self.IS_globals.push((globalidx, value.to_bits(), 0));
    }
}

/// The VM state at each step of execution
#[derive(Clone, Debug, Default, Copy)]
pub struct WitnessVM {
    /// Stack pointer before execution
    pub pre_sp: usize,
    /// Program counter ([`InstructionPtr`]) before execution
    pub pc: usize,
    /// Explict trace of instruction. Used to determine read and write for MCC
    pub instr: Instruction,
    /// Unique index for the opcode type
    pub J: u64,
    /// Immediate instruction value
    pub I: u64,
    /// First argument value. Holds an instructions"read" value.
    pub X: u64,
    /// Second argument value.Holds an instructions"read" value.
    pub Y: u64,
    /// Result of instuction. Used to hold the result of a computation instruction.
    /// Also is used to hold an instructions "write" value.
    pub Z: u64,
    /// This can hold a read, write or immediate value
    pub P: u64,
    /// This can hold a read, write or immediate value
    pub Q: u64,
    /// post stack pointer
    pub post_sp: usize,
    /// post program counter
    pub post_pc: usize,
}
