pub mod continuations;
pub mod etable;
pub mod mtable;

use crate::{AsContext, Global, Memory};
use mtable::imtable::IMTable;
use wasmi_core::UntypedValue;

use self::{
    continuations::{ImageID, MemorySnapshot},
    etable::ETable,
    mtable::{memory_event_of_step, LocationType, MTable},
};

/// Represents a slice range of the execution trace
///
/// Also used to store the start and end indexes of the memory snapshot
#[derive(Debug, Clone, Default, Copy)]
pub struct TraceSliceValues {
    /// Start opcode
    pub(crate) start: usize,
    /// End opcode
    pub(crate) end: usize,
}

impl TraceSliceValues {
    /// Build new `TraceSliceValues`
    pub fn new(start: usize, end: usize) -> Self {
        TraceSliceValues { start, end }
    }

    /// Get start value
    pub fn start(&self) -> usize {
        self.start
    }

    /// Get end value
    pub fn end(&self) -> usize {
        self.end
    }

    /// Setter for start value
    pub fn set_start(&mut self, start: usize) {
        self.start = start;
    }

    /// Setter for end value
    pub fn set_end(&mut self, end: usize) {
        self.end = end;
    }
}

/// Builds execution trace
#[derive(Debug)]
pub struct Tracer {
    /// Initial memory table
    imtable: IMTable,
    /// Execution table
    pub etable: ETable,
    /// Function inputs used for memory trace initialization
    pub fn_inputs: Vec<UntypedValue>,
    /// Stores memory snapshot at specified points in the execution trace.
    ///
    /// Used for continuations.
    pub memory_snapshot: MemorySnapshot,
}

impl Tracer {
    // Initialize execution trace builder
    pub fn new(trace_slice_values: TraceSliceValues) -> Self {
        // Build memory snapshot with slice values
        // Which end and start opcodes to take snapshot at
        let memory_snapshot = MemorySnapshot::new(trace_slice_values);

        // Build init tracer
        Tracer {
            imtable: IMTable::default(),
            etable: ETable::default(),
            fn_inputs: Vec::new(),
            memory_snapshot,
        }
    }

    /// Push initial heap/linear WASM memory to tracer for MCC
    pub fn push_init_memory(&mut self, memref: Memory, context: impl AsContext) {
        let pages: u32 = memref.ty(&context).initial_pages().into();
        for i in 0..(pages * 8192) {
            let mut buf = [0u8; 8];
            memref
                .read(&context, (i * 8).try_into().unwrap(), &mut buf)
                .unwrap();
            self.imtable
                .push(i as usize, u64::from_le_bytes(buf), LocationType::Heap);
        }
    }

    /// Push global memory values to tracer for MCC
    pub fn push_global(&mut self, globalidx: usize, globalref: &Global, context: impl AsContext) {
        let value = UntypedValue::from(globalref.get(&context));
        self.imtable
            .push(globalidx, value.to_bits(), LocationType::Global);
    }

    /// Push local memory values to tracer for MCC
    pub fn push_len_locals(&mut self, len_locals: usize, pre_sp: usize) {
        let n = len_locals + self.fn_inputs.len();
        for i in 0..n {
            if i < self.fn_inputs.len() {
                self.imtable
                    .push(pre_sp + i, self.fn_inputs[i].to_bits(), LocationType::Stack);
            } else {
                self.imtable.push(pre_sp + i, 0, LocationType::Stack);
            }
        }
    }

    /// Set WASM function inputs for MCC
    pub fn set_inputs(&mut self, inputs: Vec<UntypedValue>) {
        self.fn_inputs = inputs;
    }

    /// Get memory trace from execution trace
    pub fn mtable(&self) -> MTable {
        let mentries = self
            .etable
            .entries()
            .iter()
            .map(|eentry| memory_event_of_step(eentry, &mut 1))
            .collect::<Vec<Vec<_>>>()
            .concat();

        MTable::new_with_imtable(mentries, &self.imtable)
    }

    /// Getter for shard start value
    pub fn shard_start(&self) -> usize {
        self.memory_snapshot.start()
    }

    /// Getter for shard end value
    pub fn shard_end(&self) -> usize {
        self.memory_snapshot.end()
    }

    /// Setter for memory snapshot input ImageID
    pub fn set_memory_snapshot_input(&mut self, input: ImageID) {
        self.memory_snapshot.set_system_state_input(input);
    }

    /// Setter for memory snapshot ouput ImageID
    pub fn set_memory_snapshot_output(&mut self, output: ImageID) {
        self.memory_snapshot.set_system_state_output(output);
    }

    /// Getter for memory snapshot output ImageID
    pub fn memory_snapshot_output(&self) -> &ImageID {
        self.memory_snapshot.system_state_output()
    }

    /// Getter for memory snapshot
    pub fn memory_snapshot(&self) -> &MemorySnapshot {
        &self.memory_snapshot
    }

    /// Get Execution Table
    ///
    /// Performs a clone
    pub fn etable(&self) -> ETable {
        self.etable.clone()
    }

    /// Get reference to `IMTable`
    pub fn imtable(&self) -> &IMTable {
        &self.imtable
    }
}
