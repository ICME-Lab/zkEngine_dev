#![allow(non_snake_case)]
use core::cmp;

use wasmi_core::UntypedValue;

use crate::engine::bytecode::Instruction;

#[derive(Debug, Clone, Default)]
/// Hold the execution trace from VM execution and manages other miscellaneous
/// information needed by the zkWASM
pub struct Tracer {
    /// Holds the VM state at each timestamp of the execution
    pub(crate) execution_trace: Vec<WitnessVM>,
    /// This is used to maintain the max stack address. We use this to
    /// construct the IS for MCC
    max_sp: usize,
    /// Initial Set for MCC
    IS: Vec<(u64, u64)>,
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

    /// Check if executions step sp is greater than maintained tracers max_sp.
    /// If so update tracers max sp
    pub(crate) fn set_max_sp(&mut self, max_sp: usize) {
        self.max_sp = max_sp
    }

    /// Getter for max_sp
    pub fn max_sp(&self) -> usize {
        self.max_sp
    }

    /// Setter for IS
    pub(crate) fn set_IS<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = UntypedValue>,
    {
        self.IS = vec![(0, 0); self.max_sp + 1];
        for (i, uv) in iter.into_iter().enumerate() {
            self.IS[i] = (uv.into(), 0);
        }
    }

    /// Getter for IS
    pub fn IS(&self) -> Vec<(u64, u64)> {
        self.IS.to_vec()
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
}
