//! Implementation of WASM execution context for zkVM
use super::error::ZKWASMError;
use crate::{
  utils::wasm::{decode_func_args, prepare_func_results, read_wasm_or_wat},
  v1::utils::tracing::unwrap_rc_refcell,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{cell::RefCell, path::PathBuf, rc::Rc};
use wasmi::{Tracer, WitnessVM};
use wasmi_wasi::{clocks_ctx, sched_ctx, Table, WasiCtx};

/// Builder for [`WASMCtx`]. Defines the WASM execution context that will be used for proving
#[derive(Debug, Clone)]
pub struct WASMArgsBuilder {
  program: Vec<u8>,
  invoke: String,
  func_args: Vec<String>,
  trace_slice_vals: Option<TraceSliceValues>,
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

  /// Set the end slice
  pub fn trace_slice(mut self, trace_slice_vals: TraceSliceValues) -> Self {
    self.trace_slice_vals = Some(trace_slice_vals);
    self
  }

  /// Build the WASM context
  pub fn build(self) -> WASMArgs {
    WASMArgs {
      program: self.program,
      func_args: self.func_args,
      invoke: self.invoke,
      trace_slice_vals: self.trace_slice_vals,
    }
  }
}

/// WASM execution context: contains the WASM program and its [`WASMCtxMetaData`]
#[derive(Debug, Clone)]
pub struct WASMArgs {
  pub(in crate::v1) program: Vec<u8>,
  pub(in crate::v1) invoke: String,
  pub(in crate::v1) func_args: Vec<String>,
  pub(in crate::v1) trace_slice_vals: Option<TraceSliceValues>,
}

impl WASMArgs {
  /// Get the start value of the trace slice
  pub fn start(&self) -> usize {
    self
      .trace_slice_vals
      .map(|val| val.start())
      .unwrap_or_default()
  }
}

impl Default for WASMArgsBuilder {
  fn default() -> Self {
    Self {
      program: vec![],
      invoke: "main".to_string(),
      func_args: vec![],
      trace_slice_vals: None,
    }
  }
}

/// Used to set start and end values to slice execution trace. Used in sharding/continuations
#[derive(Debug, Clone, Default, Copy)]
pub struct TraceSliceValues {
  /// Start opcode
  pub(crate) start: usize,
  /// End opcode
  pub(crate) end: usize,
}

impl TraceSliceValues {
  /// Build new `TraceSliceValues`
  ///
  /// # Panics
  ///
  /// panics if start is greater than or equal to end
  pub fn new(start: usize, end: usize) -> Self {
    assert!(start < end);
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

/// Execution trace, Initial memory trace, Initial stack trace length, Initial linear memory length
pub type ExecutionTrace = (Vec<WitnessVM>, Vec<(usize, u64, u64)>, usize, usize);

/// Definition for WASM execution context
pub trait ZKWASMCtx {
  /// Data type used in wasmi::Store
  type T;

  /// create store
  fn create_store(engine: &wasmi::Engine) -> wasmi::Store<Self::T>;

  /// create linker
  fn create_linker(engine: &wasmi::Engine) -> Result<wasmi::Linker<Self::T>, ZKWASMError>;

  /// Getter for WASM args
  fn args(&self) -> &WASMArgs;

  /// Get the execution trace from WASM execution context
  fn execution_trace(&self) -> Result<ExecutionTrace, ZKWASMError> {
    // Execute WASM module and build execution trace documenting vm state at
    // each step. Also get meta-date from execution like the max height of the [`ValueStack`]
    let tracer = Rc::new(RefCell::new(Tracer::new()));
    // Setup and parse the wasm bytecode.
    let engine = wasmi::Engine::default();
    let module = wasmi::Module::new(&engine, &self.args().program[..])?;

    // Create a new store and linker
    let mut store = Self::create_store(&engine);
    let linker = Self::create_linker(&engine)?;

    // Instantiate the module and trace WASM linear memory and global memory initializations
    let instance = linker
      .instantiate_with_trace(&mut store, &module, tracer.clone())?
      .start(&mut store)?;

    let func = instance
      .get_func(&store, &self.args().invoke)
      .ok_or_else(|| {
        ZKWASMError::WasmiError(wasmi::Error::Func(
          wasmi::errors::FuncError::ExportedFuncNotFound,
        ))
      })?;

    // Prepare i/o
    let ty = func.ty(&store);
    let func_args = decode_func_args(&ty, &self.args().func_args)?;
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
    let max_sp = tracer.max_sp();
    tracing::debug!("max_sp: {}", max_sp);
    tracing::debug!("stack len: {}", IS_stack_len);
    let IS = tracer.IS();
    tracing::debug!("IS_mem.len: {}", IS_mem_len);

    let execution_trace = tracer.into_execution_trace();
    tracing::debug!(
      "Non padded execution trace len: {:?}",
      execution_trace.len()
    );

    let end_slice = {
      let end_slice_val = self
        .args()
        .trace_slice_vals
        .map(|val| val.end())
        .unwrap_or(execution_trace.len());
      std::cmp::min(end_slice_val, execution_trace.len())
    };

    let execution_trace = execution_trace[..end_slice].to_vec();

    Ok((execution_trace, IS, IS_stack_len, IS_mem_len))
  }
}

#[derive(Debug, Clone)]
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
  type T = ();

  fn create_store(engine: &wasmi::Engine) -> wasmi::Store<Self::T> {
    wasmi::Store::new(engine, ())
  }

  fn create_linker(engine: &wasmi::Engine) -> Result<wasmi::Linker<Self::T>, ZKWASMError> {
    Ok(<wasmi::Linker<()>>::new(engine))
  }

  fn args(&self) -> &WASMArgs {
    &self.args
  }
}

/// Wasm execution context
#[derive(Debug, Clone)]
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
  type T = WasiCtx;

  fn args(&self) -> &WASMArgs {
    &self.args
  }

  fn create_store(engine: &wasmi::Engine) -> wasmi::Store<Self::T> {
    let wasi = WasiCtx::new(zkvm_random_ctx(), clocks_ctx(), sched_ctx(), Table::new());
    wasmi::Store::new(engine, wasi)
  }

  fn create_linker(engine: &wasmi::Engine) -> Result<wasmi::Linker<Self::T>, ZKWASMError> {
    let mut linker = <wasmi::Linker<WasiCtx>>::new(engine);
    wasmi_wasi::add_to_linker(&mut linker, |ctx| ctx)?;
    Ok(linker)
  }
}

/// zkvm uses a seed to generate random numbers.
pub fn zkvm_random_ctx() -> Box<dyn RngCore + Send + Sync> {
  Box::new(StdRng::from_seed([0; 32]))
}
