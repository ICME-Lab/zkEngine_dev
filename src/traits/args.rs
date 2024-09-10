//! Contains definitions for a zkWASM execution context, to get an execution trace
use std::{cell::RefCell, rc::Rc};
use wasmi::{etable::ETable, Func, Store, TraceSliceValues, Tracer};

/// The trait to define what you need to run a WASM module and to expose the WASM modules bytecode.
///
/// You should be able to get a WASM modules bytecode and the function to invoke and its
/// corresponding arguments.
pub trait ZKWASMArgs {
  /// Get bytecode from WASM module
  fn bytecode(&self) -> anyhow::Result<Vec<u8>>;

  /// Get the function to invoke
  fn invoke(&self) -> &str;

  /// Every function signature requires parameters that may or may not be passed (if no parametes
  /// are needed).
  ///
  /// Empty parameters are represented as an empty vector.
  fn func_args(&self) -> Vec<String>;

  /// A zkVM sometimes only proves a portion of the execution trace.
  /// This is where these values become important.
  ///
  /// These values specify the starting point and end point of the trace to prove.
  fn trace_slice_values(&self) -> TraceSliceValues;
}
