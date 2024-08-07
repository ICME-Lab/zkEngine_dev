//! Contains implementation of a `Receipt` that attests to the valid execution of a WASM file or
//! WASM shard.

use serde::{Deserialize, Serialize};
use wasmi::continuations::{ImageID, SystemState};

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
/// Contains a zkSNARK and its corresponding system state.
/// The system state is a pair of input and output memory images.
///
/// This will be used to prove shards are connected and aggregate to a valid execution of a full
/// WASM file.
pub struct Receipt {
  /// Input & output memory snapshots of the shard
  pub system_state: SystemState,
  // TODO: Add SNARK proof
}

impl Receipt {
  /// Create a new `Receipt` with the given system state.
  pub fn new(system_state: SystemState) -> Self {
    Receipt { system_state }
  }
}

impl Receipt {
  /// Get the input value for sytem state
  pub fn system_state_input(&self) -> &ImageID {
    self.system_state.input()
  }

  /// Get the output value for sytem state
  pub fn system_state_output(&self) -> &ImageID {
    self.system_state.output()
  }
}
