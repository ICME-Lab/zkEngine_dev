//! This module defines errors returned by the library.

use nova::errors::NovaError;
use thiserror::Error;

/// Errors returned by the zkWASM library
#[derive(Debug, Error)]
pub enum ZKWASMError {
  /// Nova error
  #[error("NovaError")]
  NovaError(#[from] NovaError),
  /// returned RecursiveSNARK is badly formed
  #[error("NoCircuit")]
  NoCircuit,
  /// Anyhow Error
  #[error("AnyhowError")]
  AnyhowError(#[from] anyhow::Error),
  /// Wasmi Error
  #[error("WasmiError")]
  WasmiError(wasmi::Error),
  /// Failed to load WASM module
  #[error("WasmError: {0}")]
  WASMError(String),
  /// Something went wrong when verifying the multisets
  #[error("MultisetVerificationError")]
  MultisetVerificationError,
  #[error("Input SNARK needs to be Recursive")]
  /// Returned when trying to compress or aggregate an already compressed proof
  NotRecursive,
  /// Returned when invalid [`TraceSliceValues`] are passed
  #[error("InvalidTraceSliceValues: {0}")]
  InvalidTraceSliceValues(String),
}

impl From<wasmi::Error> for ZKWASMError {
  fn from(error: wasmi::Error) -> Self {
    Self::WasmiError(error)
  }
}
