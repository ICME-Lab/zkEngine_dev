//! Module containing data structures and methods to prepare execution trace for distribution.
use serde::{Deserialize, Serialize};

use super::TraceSliceValues;

/// Represents the start and end values of a shards execution
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MemorySnapshot {
    /// Start opcode to take snapshot at
    start: usize,
    /// End opcode to take snapshot at
    end: usize,
    /// The preimage of the snapshot
    system_state: SystemState,
}

impl MemorySnapshot {
    /// Build new `MemorySnapshot`
    pub fn new(slice_values: TraceSliceValues) -> Self {
        MemorySnapshot {
            start: slice_values.start(),
            end: slice_values.end(),
            system_state: SystemState::default(),
        }
    }
}

impl MemorySnapshot {
    /// Get start value
    pub fn start(&self) -> usize {
        self.start
    }

    /// Get end value
    pub fn end(&self) -> usize {
        self.end
    }

    /// Setter for system state input
    pub fn set_system_state_input(&mut self, input: ImageID) {
        self.system_state.set_input(input);
    }

    /// Setter for system state output
    pub fn set_system_state_output(&mut self, output: ImageID) {
        self.system_state.set_output(output);
    }

    /// Getter for system state input
    pub fn system_state_input(&self) -> &ImageID {
        &self.system_state.input()
    }

    /// Getter for system state output
    pub fn system_state_output(&self) -> &ImageID {
        &self.system_state.output()
    }

    /// Getter for system state
    pub fn system_state(&self) -> &SystemState {
        &self.system_state
    }
}

/// The shards system state at its start and end
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SystemState {
    input: ImageID,
    output: ImageID,
}

impl SystemState {
    /// Create a new instance of `SystemState`
    pub fn new(input: ImageID, output: ImageID) -> Self {
        SystemState { input, output }
    }

    /// Set the input image
    pub fn set_input(&mut self, input: ImageID) {
        self.input = input;
    }

    /// Set the output image
    pub fn set_output(&mut self, output: ImageID) {
        self.output = output;
    }

    /// Get the output image
    pub fn output(&self) -> &ImageID {
        &self.output
    }

    /// Get the input image
    pub fn input(&self) -> &ImageID {
        &self.input
    }
}

/// Represents the ID of an image (memory snapshot)
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct ImageID(String);

impl ImageID {
    /// Create a new instance of `ImageID`
    pub fn new(s: String) -> Self {
        ImageID(s)
    }

    /// Get the string representation of the `ImageID`
    pub fn as_string(&self) -> &str {
        &self.0
    }
}
