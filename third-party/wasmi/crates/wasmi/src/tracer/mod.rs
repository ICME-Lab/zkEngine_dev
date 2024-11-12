#![allow(non_snake_case)]

use wasmi_core::UntypedValue;

use crate::{engine::bytecode::Instruction, AsContext, Memory};

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
}

impl Tracer {
    /// Creates a new [`TracerV0`] for generating execution trace during VM
    /// execution
    pub fn new() -> Self {
        Tracer::default()
    }

    /// Extract the execution trace from the tracer
    pub fn into_execution_trace(self) -> Vec<WitnessVM> {
        self.execution_trace
    }

    /// Getter for max_sp
    pub fn max_sp(&self) -> usize {
        self.max_sp
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
        self.IS_stack.len()
    }

    /// Getter for IS
    pub fn IS(&self) -> Vec<(usize, u64, u64)> {
        let mut IS = self.IS_stack.to_vec();
        let stack_len = IS.len();
        IS.extend(self.IS_mem.iter().map(|(i, v, _)| (*i + stack_len, *v, 0)));
        IS
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
}

/// The VM state at each step of execution
#[derive(Clone, Debug, Default)]
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
    /// Holds a "push" or "write" value, for example when an instruction pushes a value on the stack
    pub P: u64,
    /// Holds a "push" or "write" value, for example when an instruction pushes a value on the stack
    pub Q: u64,
}
