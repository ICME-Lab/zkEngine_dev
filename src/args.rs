//! This module contains the data structures to contain the arguments needed to run arbitrary WASM.
use crate::{
  traits::args::ZKWASMArgs,
  utils::{
    display::DisplayExportedFuncs,
    wasm::{decode_func_args, prepare_func_results, read_wasm_or_wat, typecheck_args},
  },
};
use anyhow::anyhow;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{cell::RefCell, path::PathBuf, rc::Rc};
use wasmi::{
  core::UntypedValue, etable::ETable, Engine, ExternType, Func, FuncType, Linker, Module, Store,
  TraceSliceValues, Tracer,
};
use wasmi_wasi::{clocks_ctx, sched_ctx, Table, WasiCtx, WasiCtxBuilder};

/// If no WASM function to invoke attemp to fetch a function call `main`
const DEFAULT_FN_NAME: &str = "main";

#[derive(Debug, Clone, Default)]
/// Arguments needed to run arbitrary WASM.
pub struct WASMArgs {
  file_path: PathBuf,
  trace_slice_values: TraceSliceValues,
  invoke: String,
  func_args: Vec<String>,
}

/// Builder for `WASMArgs`.
#[derive(Debug, Clone, Default)]
pub struct WASMArgsBuilder {
  file_path: Option<PathBuf>,
  trace_slice_values: Option<TraceSliceValues>,
  invoke: Option<String>,
  func_args: Vec<String>,
}

impl WASMArgsBuilder {
  /// Set the file path.
  pub fn file_path(mut self, file_path: PathBuf) -> Self {
    self.file_path = Some(file_path);
    self
  }

  /// Set the trace slice values.
  pub fn trace_slice_values(mut self, trace_slice_values: TraceSliceValues) -> Self {
    self.trace_slice_values = Some(trace_slice_values);
    self
  }

  /// Set the function to invoke.
  pub fn invoke(mut self, invoke: Option<String>) -> Self {
    self.invoke = invoke;
    self
  }

  /// Set the function arguments.
  pub fn func_args(mut self, func_args: Vec<String>) -> Self {
    self.func_args = func_args;
    self
  }

  /// Build the `WASMArgs`.
  pub fn build(self) -> WASMArgs {
    WASMArgs {
      file_path: self.file_path.unwrap_or_default(),
      trace_slice_values: self.trace_slice_values.unwrap_or_default(),
      invoke: self.invoke.unwrap_or(DEFAULT_FN_NAME.to_string()),
      func_args: self.func_args,
    }
  }
}

impl ZKWASMArgs for WASMArgs {
  /// Get the bytecode from the WASM module.
  fn bytecode(&self) -> anyhow::Result<Vec<u8>> {
    read_wasm_or_wat(&self.file_path)
  }
  /// Get the function to invoke
  fn invoke(&self) -> &str {
    &self.invoke
  }

  /// Every function has a signature (params and return type) and a body.
  fn func_args(&self) -> Vec<String> {
    self.func_args.clone()
  }

  /// Get the trace slice values
  fn trace_slice_values(&self) -> TraceSliceValues {
    self.trace_slice_values
  }
}
