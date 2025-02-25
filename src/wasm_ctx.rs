//! Implementation of WASM execution context for zkVM
use super::error::ZKWASMError;
use crate::{
  utils::{
    tracing::{split_vector, unwrap_rc_refcell},
    wasm::{decode_func_args, prepare_func_results, read_wasm_or_wat},
  },
  wasm_snark::StepSize,
};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, cmp, num::NonZeroUsize, path::PathBuf, rc::Rc};
use wasmi::{Tracer, WitnessVM};

/// Builder for [`WASMArgs`]. Constructs the arguments needed to construct a WASM execution context
/// that will be used for proving.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

  /// Set the `start` and `end` values to slice the execution trace
  pub fn trace_slice(mut self, trace_slice_vals: TraceSliceValues) -> Self {
    self.trace_slice_vals = Some(trace_slice_vals);
    self
  }

  /// Build the [`WASMArgs`] from the builder
  pub fn build(self) -> WASMArgs {
    WASMArgs {
      program: self.program,
      func_args: self.func_args,
      invoke: self.invoke,
      trace_slice_vals: self.trace_slice_vals,
    }
  }
}

/// Arguments needed to construct a WASM execution context that will be used for proving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WASMArgs {
  pub(crate) program: Vec<u8>,
  pub(crate) invoke: String,
  pub(crate) func_args: Vec<String>,
  pub(crate) trace_slice_vals: Option<TraceSliceValues>,
}

impl WASMArgs {
  /// Get the start value of the trace slice
  pub fn start(&self) -> usize {
    self
      .trace_slice_vals
      .map(|val| val.start())
      .unwrap_or_default()
  }

  /// Check if program is being sharded
  pub fn is_sharded(&self) -> bool {
    self.start() != 0
  }

  /// Get the shard_size
  pub fn shard_size(&self) -> Option<usize> {
    self.trace_slice_vals.and_then(|val| val.shard_size())
  }

  /// Get reference to bytecode.
  pub fn bytecode(&self) -> &[u8] {
    &self.program
  }

  /// Get the end slice value after WASM execution
  pub fn end(&self, execution_trace_len: usize) -> Result<usize, ZKWASMError> {
    let end_slice_val = self.calculate_end_slice_value(execution_trace_len);
    if self.start() >= end_slice_val {
      return Err(ZKWASMError::InvalidTraceSliceValues(
        "start value cannot be greater than or equal to end value".to_string(),
      ));
    }
    Ok(end_slice_val)
  }

  /// Calculate the end slice value considering the execution trace length
  fn calculate_end_slice_value(&self, execution_trace_len: usize) -> usize {
    self.trace_slice_vals.map_or(execution_trace_len, |val| {
      cmp::min(
        val.end().map_or(execution_trace_len, |end| end.get()),
        execution_trace_len,
      )
    })
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

/// Definition for WASM execution context
pub trait ZKWASMCtx {
  /// Data type used in wasmi::Store
  type T;

  /// create store
  fn store(engine: &wasmi::Engine) -> wasmi::Store<Self::T>;

  /// create linker
  fn linker(engine: &wasmi::Engine) -> Result<wasmi::Linker<Self::T>, ZKWASMError>;

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
    let mut store = Self::store(&engine);
    let linker = Self::linker(&engine)?;

    // Instantiate the module and trace WASM linear memory and global memory initializations
    let instance = linker
      .instantiate_with_trace(&mut store, &module, tracer.clone())?
      .start(&mut store)?;

    // Get the WASM module function we are going to invoke.
    let func = instance
      .get_func(&store, &self.args().invoke)
      .ok_or_else(|| {
        ZKWASMError::WasmiError(wasmi::Error::Func(
          wasmi::errors::FuncError::ExportedFuncNotFound,
        ))
      })?;

    // Prepare i/o for the function call.
    let ty = func.ty(&store);
    let func_args = decode_func_args(&ty, &self.args().func_args)?;
    let mut func_results = prepare_func_results(&ty);

    // Call the function to invoke.
    func.call_with_trace(&mut store, &func_args, &mut func_results, tracer.clone())?;
    tracing::debug!("wasm func res: {:#?}", func_results);

    // Extract the execution trace produced from WASM execution.
    //
    // [`unwrap_rc_refcell`] is safe to use here since this parent function ensures that the [`Rc`]
    // is the sole owner of the execution trace.
    let tracer = unwrap_rc_refcell(tracer);

    // Get the MCC values used to construct the initial memory state of the zkWASM.
    let init_stack_len = tracer.IS_stack_len();
    let init_mem_len = tracer.IS_mem_len();
    let init_memory = tracer.init_memory();

    // Take ownership of the execution trace of type [`Vec<WitnessVM>`] because the zkWASM needs
    // this type to execute.
    let execution_trace = tracer.into_execution_trace();

    // If only proving a portion of the execution trace (a shard) calculate the end value to slice
    // execution trace and use it to slice the execution trace.
    //
    // # Note:
    //
    // We do not use the `start` value to slice the execution trace because we need the execution
    // trace from opcode 0 to opcode `start` to construct the initial memory state of the shard.
    let end_slice = self.args().end(execution_trace.len())?;
    let execution_trace = execution_trace[..end_slice].to_vec();

    Ok((
      execution_trace,
      InitMemData {
        init_memory,
        memory_size: ISMemSizes::new(init_stack_len, init_mem_len),
        global_ts: 0,
      },
    ))
  }
}

/// Execution trace, Initial memory trace, Initial stack trace length, Initial linear memory length
pub type ExecutionTrace = (Vec<WitnessVM>, InitMemData);

impl MemorySetupTrait for ExecutionTrace {
  fn setup_init_memory(self, args: &WASMArgs, step_size: StepSize) -> Result<Self, ZKWASMError> {
    let (init_execution_trace, init_memory_data) = self;
    let InitMemData {
      mut init_memory,
      memory_size,
      mut global_ts,
    } = init_memory_data;
    //  --- Construct IS multiset ---
    //
    // Split the execution trace at `TraceSliceValues` `start` value. Use the first split to
    // construct IS and use the second split for the actual proving of the shard
    let (init_execution_trace, execution_trace) = split_vector(init_execution_trace, args.start());
    // If we are proving a shard of a WASM program: calculate shard size & construct correct shard IS
    utils::shard_init_memory(
      &mut init_memory,
      memory_size,
      args.is_sharded(),
      args.shard_size().unwrap_or(execution_trace.len()),
      step_size,
      init_execution_trace,
      &mut global_ts,
    );
    Ok((
      execution_trace,
      InitMemData {
        init_memory,
        memory_size,
        global_ts,
      },
    ))
  }
}

pub(crate) trait MemorySetupTrait
where
  Self: Sized,
{
  fn setup_init_memory(self, args: &WASMArgs, step_size: StepSize) -> Result<Self, ZKWASMError>;
}

#[derive(Debug, Clone)]
/// A type used to construct a WASM execution context used for proving.
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

  fn store(engine: &wasmi::Engine) -> wasmi::Store<Self::T> {
    wasmi::Store::new(engine, ())
  }

  fn linker(engine: &wasmi::Engine) -> Result<wasmi::Linker<Self::T>, ZKWASMError> {
    Ok(<wasmi::Linker<()>>::new(engine))
  }

  fn args(&self) -> &WASMArgs {
    &self.args
  }
}

#[cfg(not(target_arch = "wasm32"))]
/// Implementation of WASM execution context for zkVM using wasmi-wasi
pub mod wasi {
  use crate::error::ZKWASMError;

  use super::{WASMArgs, ZKWASMCtx};
  use rand::{rngs::StdRng, RngCore, SeedableRng};
  use wasmi_wasi::{clocks_ctx, sched_ctx, Table, WasiCtx};

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

    fn store(engine: &wasmi::Engine) -> wasmi::Store<Self::T> {
      let wasi = WasiCtx::new(zkvm_random_ctx(), clocks_ctx(), sched_ctx(), Table::new());
      wasmi::Store::new(engine, wasi)
    }

    fn linker(engine: &wasmi::Engine) -> Result<wasmi::Linker<Self::T>, ZKWASMError> {
      let mut linker = <wasmi::Linker<WasiCtx>>::new(engine);
      wasmi_wasi::add_to_linker(&mut linker, |ctx| ctx)?;
      Ok(linker)
    }
  }

  /// zkvm uses a seed to generate random numbers.
  pub fn zkvm_random_ctx() -> Box<dyn RngCore + Send + Sync> {
    Box::new(StdRng::from_seed([0; 32]))
  }
}

/// Used to set start and end values to slice execution trace. Used in sharding/continuations
#[derive(Debug, Clone, Default, Copy, Serialize, Deserialize)]
pub struct TraceSliceValues {
  /// Start opcode
  pub(crate) start: usize,
  /// End opcode
  pub(crate) end: Option<NonZeroUsize>,
}

impl TraceSliceValues {
  /// Build new [`TraceSliceValues`]
  ///
  /// # Note:
  ///
  /// if end does not equal 0 start value cannot be greater than or equal to end value
  pub fn new(start: usize, end: Option<NonZeroUsize>) -> Self {
    TraceSliceValues { start, end }
  }

  /// Get start value
  pub fn start(&self) -> usize {
    self.start
  }

  /// Get end value
  pub fn end(&self) -> Option<NonZeroUsize> {
    self.end
  }

  /// Setter for start value
  pub fn set_start(&mut self, start: usize) {
    self.start = start;
  }

  /// Setter for end value
  pub fn set_end(&mut self, end: Option<NonZeroUsize>) {
    self.end = end;
  }

  /// Calculate the shard_size
  pub fn shard_size(&self) -> Option<usize> {
    self.end.and_then(|end| end.get().checked_sub(self.start))
  }
}

/// Holds the initial memory data from vm execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitMemData {
  pub(crate) init_memory: Vec<(usize, u64, u64)>,
  pub(crate) memory_size: ISMemSizes,
  pub(crate) global_ts: u64,
}

/// # Initial Set (IS) Memory Sizes.
///
/// i.e. Memory sizes for the initial state.
/// We need to know the sizes of the stack and linear
/// memory of the WASM module to initialize the initial memory state of the zkVM.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ISMemSizes {
  IS_stack_len: usize,
  IS_mem_len: usize,
}

impl ISMemSizes {
  /// Create a new instance of [`ISMemSizes`]
  pub fn new(IS_stack_len: usize, IS_mem_len: usize) -> Self {
    Self {
      IS_stack_len,
      IS_mem_len,
    }
  }

  /// Get the stack length
  pub fn stack_len(&self) -> usize {
    self.IS_stack_len
  }

  /// Get the memory length
  pub fn mem_len(&self) -> usize {
    self.IS_mem_len
  }
}

mod utils {
  use wasmi::WitnessVM;

  use crate::wasm_snark::{memory_ops_trace, StepSize};

  use super::ISMemSizes;

  /// Helper function to construct initial zkvm memory when WASM program is being sharded
  pub fn shard_init_memory(
    init_memory: &mut [(usize, u64, u64)],
    memory_sizes: ISMemSizes,
    is_sharded: bool,
    shard_size: usize,
    step_size: StepSize,
    init_execution_trace: Vec<WitnessVM>,
    global_ts: &mut u64,
  ) {
    // Calculate shard size
    let sharding_pad_len = if shard_size % step_size.execution != 0 && is_sharded {
      step_size.execution - (shard_size % step_size.execution)
    } else {
      0
    };

    init_execution_trace.iter().enumerate().for_each(|(i, vm)| {
      if i != 0 && i % shard_size == 0 {
        init_memory_ts_padding(sharding_pad_len, init_memory, global_ts, memory_sizes);
      }
      let _ = memory_ops_trace(vm, init_memory, global_ts, memory_sizes);
    });
    if !init_execution_trace.is_empty() && is_sharded {
      init_memory_ts_padding(sharding_pad_len, init_memory, global_ts, memory_sizes);
    }
  }

  // Add the timestamp padding to the IS multiset
  fn init_memory_ts_padding(
    sharding_pad_len: usize,
    init_memory: &mut [(usize, u64, u64)],
    global_ts: &mut u64,
    mem_sizes: ISMemSizes,
  ) {
    for _ in 0..sharding_pad_len {
      let _ = memory_ops_trace(&WitnessVM::default(), init_memory, global_ts, mem_sizes);
    }
  }
}
