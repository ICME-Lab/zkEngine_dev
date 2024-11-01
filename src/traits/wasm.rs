//! Contains definitions for a zkWASM execution context, to get an execution trace
use std::{cell::RefCell, rc::Rc};
use wasmi::{etable::ETable, Func, FuncType, Store, TraceSliceValues, TracerV0};

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

/// This trait is used to define the wasm context that is passed to the zkWASM.
///
/// Guarantees an execution trace from the wasm bytecode.
pub trait ZKWASMContext {
  /// User provided host data owned by the [`Store`].
  type T;

  /// Returns an exclusive reference to the [`Store`] of the [`Context`].
  fn store_mut(&mut self) -> &mut Store<Self::T>;

  /// Returns a shared reference to the [`Store`] of the [`Context`].
  fn store(&self) -> &Store<Self::T>;

  /// To get a trace you need a function to invoke.
  ///
  /// Gets a function to invoke from an instantiated WASM module.
  fn func(&self, fn_name: &str) -> anyhow::Result<Func>;

  /// returns a struct that is used to build the execution trace.
  fn tracer(&self) -> anyhow::Result<Rc<RefCell<TracerV0>>>;

  /// builds and returns a struct that contains the execution trace and the invoked functions
  /// result.
  fn build_execution_trace(&mut self) -> anyhow::Result<(ETable, Box<[wasmi::Value]>)>;

  /// Get the args needed to run the WASM module.
  fn args(&self) -> &dyn ZKWASMArgs;

  /// Returns the exported named functions of the Wasm [`Module`].
  ///
  /// [`Module`]: wasmi::Module
  fn exported_funcs(&self) -> impl Iterator<Item = (&str, FuncType)>;
}
