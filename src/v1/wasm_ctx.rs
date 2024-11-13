//! Implementation of WASM execution context for zkVM
use crate::{
  utils::wasm::{decode_func_args, prepare_func_results},
  v1::utils::tracing::unwrap_rc_refcell,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{cell::RefCell, path::PathBuf, rc::Rc};
use wasmi::{Tracer, WitnessVM};
use wasmi_wasi::{clocks_ctx, sched_ctx, Table, WasiCtx};

use crate::utils::wasm::read_wasm_or_wat;

use super::error::ZKWASMError;

/// Builder for [`WASMCtx`]. Defines the WASM execution context that will be used for proving
#[derive(Debug)]
pub struct WASMArgsBuilder {
  program: Vec<u8>,
  invoke: String,
  func_args: Vec<String>,
}

impl WASMArgsBuilder {
  /// Set the program bytecode from file
  pub fn file_path(mut self, path: PathBuf) -> Result<Self, ZKWASMError> {
    let bytecode =
      read_wasm_or_wat(&path).map_err(|err| ZKWASMError::WASMError(err.to_string()))?;
    self.program = bytecode;
    Ok(self)
  }

  /// Set the program bytecode
  pub fn bytecode(mut self, program: Vec<u8>) -> Self {
    self.program = program;
    self
  }

  /// Set the WASM function to invoke
  pub fn invoke(mut self, invoke: &str) -> Self {
    self.invoke = invoke.to_string();
    self
  }

  /// Set the function arguments
  pub fn func_args(mut self, func_args: Vec<String>) -> Self {
    self.func_args = func_args;
    self
  }

  /// Build the WASM context
  pub fn build(self) -> WASMArgs {
    WASMArgs {
      program: self.program,
      func_args: self.func_args,
      invoke: self.invoke,
    }
  }
}

/// WASM execution context: contains the WASM program and its [`WASMCtxMetaData`]
pub struct WASMArgs {
  pub(in crate::v1) program: Vec<u8>,
  pub(in crate::v1) invoke: String,
  pub(in crate::v1) func_args: Vec<String>,
}

impl Default for WASMArgsBuilder {
  fn default() -> Self {
    Self {
      program: vec![],
      invoke: "main".to_string(),
      func_args: vec![],
    }
  }
}

/// Execution trace, Initial memory trace, Initial stack trace length, Initial linear memory length
type ExecutionTrace = (Vec<WitnessVM>, Vec<(usize, u64, u64)>, usize, usize);

/// Definition for WASM execution context
pub trait ZKWASMCtx {
  /// Get the execution trace from WASM execution context
  fn execution_trace(&self) -> Result<ExecutionTrace, ZKWASMError>;
}

/// Wasm execution context
pub struct WASMCtx {
  args: WASMArgs,
}

impl WASMCtx {
  /// Create a new instance of [`WASMCtx`]
  pub fn new(args: WASMArgs) -> Self {
    Self { args }
  }
}

impl ZKWASMCtx for WASMCtx {
  fn execution_trace(&self) -> Result<ExecutionTrace, ZKWASMError> {
    // Execute WASM module and build execution trace documenting vm state at
    // each step. Also get meta-date from execution like the max height of the [`ValueStack`]
    let tracer = Rc::new(RefCell::new(Tracer::new()));
    // Setup and parse the wasm bytecode.
    let engine = wasmi::Engine::default();
    let linker = <wasmi::Linker<()>>::new(&engine);
    let module = wasmi::Module::new(&engine, &self.args.program[..])?;

    // Create a new store & add wasi through the linker
    let mut store = wasmi::Store::new(&engine, ());

    // Instantiate the module and trace WASM linear memory and global memory initializations
    let instance = linker
      .instantiate_with_trace(&mut store, &module, tracer.clone())?
      .start(&mut store)?;

    let func = instance
      .get_func(&store, &self.args.invoke)
      .ok_or_else(|| {
        ZKWASMError::WasmiError(wasmi::Error::Func(
          wasmi::errors::FuncError::ExportedFuncNotFound,
        ))
      })?;

    // Prepare i/o
    let ty = func.ty(&store);
    let func_args = decode_func_args(&ty, &self.args.func_args)?;
    let mut func_results = prepare_func_results(&ty);

    // Call the function to invoke.
    func.call_with_trace(&mut store, &func_args, &mut func_results, tracer.clone())?;
    tracing::debug!("wasm func res: {:#?}", func_results);

    let tracer = unwrap_rc_refcell(tracer);

    /*
     * Get MCC values:
     */
    let IS_stack_len = tracer.IS_stack_len();
    let IS_mem_len = tracer.IS_mem_len();
    tracing::debug!("stack len: {}", IS_stack_len);
    let IS = tracer.IS();
    tracing::debug!("IS_mem.len: {}", IS_mem_len);

    let execution_trace = tracer.into_execution_trace();
    tracing::trace!(
      "Non padded execution trace len: {:?}",
      execution_trace.len()
    );

    Ok((execution_trace, IS, IS_stack_len, IS_mem_len))
  }
}

/// Wasm execution context
pub struct WasiWASMCtx {
  args: WASMArgs,
}

impl WasiWASMCtx {
  /// Create a new instance of [`WasiWASMCtx`]
  pub fn new(args: WASMArgs) -> Self {
    Self { args }
  }
}

impl ZKWASMCtx for WasiWASMCtx {
  fn execution_trace(&self) -> Result<ExecutionTrace, ZKWASMError> {
    // Execute WASM module and build execution trace documenting vm state at
    // each step. Also get meta-date from execution like the max height of the [`ValueStack`]
    let tracer = Rc::new(RefCell::new(Tracer::new()));
    // build wasi ctx to add to linker.
    let wasi = WasiCtx::new(zkvm_random_ctx(), clocks_ctx(), sched_ctx(), Table::new());
    // Setup and parse the wasm bytecode.
    let engine = wasmi::Engine::default();
    let mut linker = <wasmi::Linker<WasiCtx>>::new(&engine);
    let module = wasmi::Module::new(&engine, &self.args.program[..])?;

    // Create a new store & add wasi through the linker
    let mut store = wasmi::Store::new(&engine, wasi);
    wasmi_wasi::add_to_linker(&mut linker, |ctx| ctx)?;

    // Instantiate the module and trace WASM linear memory and global memory initializations
    let instance = linker
      .instantiate_with_trace(&mut store, &module, tracer.clone())?
      .start(&mut store)?;

    let func = instance
      .get_func(&store, &self.args.invoke)
      .ok_or_else(|| {
        ZKWASMError::WasmiError(wasmi::Error::Func(
          wasmi::errors::FuncError::ExportedFuncNotFound,
        ))
      })?;

    // Prepare i/o
    let ty = func.ty(&store);
    let func_args = decode_func_args(&ty, &self.args.func_args)?;
    let mut func_results = prepare_func_results(&ty);

    // Call the function to invoke.
    func.call_with_trace(&mut store, &func_args, &mut func_results, tracer.clone())?;
    tracing::debug!("wasm func res: {:#?}", func_results);

    let tracer = unwrap_rc_refcell(tracer);

    /*
     * Get MCC values:
     */
    let IS_stack_len = tracer.IS_stack_len();
    let IS_mem_len = tracer.IS_mem_len();
    tracing::debug!("stack len: {}", IS_stack_len);
    let IS = tracer.IS();
    tracing::debug!("IS_mem.len: {}", IS_mem_len);

    let execution_trace = tracer.into_execution_trace();
    tracing::trace!(
      "Non padded execution trace len: {:?}",
      execution_trace.len()
    );

    Ok((execution_trace, IS, IS_stack_len, IS_mem_len))
  }
}

/// zkvm uses a seed to generate random numbers.
pub fn zkvm_random_ctx() -> Box<dyn RngCore + Send + Sync> {
  Box::new(StdRng::from_seed([0; 32]))
}
