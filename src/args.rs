//! This module contains the data structures to contain the arguments needed to run arbitrary WASM.
use std::{cell::RefCell, path::PathBuf, rc::Rc};

use crate::{
  traits::args::{ZKWASMArgs, ZKWASMContext},
  utils::{
    display::DisplayExportedFuncs,
    wasm::{
      decode_func_args, prepare_func_results, print_pretty_results, read_wasm_or_wat,
      typecheck_args,
    },
  },
};
use anyhow::anyhow;
use wasmi::{
  core::UntypedValue, etable::ETable, Engine, ExternType, Func, FuncType, Linker, Module, Store,
  TraceSliceValues, Tracer,
};
use wasmi_wasi::{WasiCtx, WasiCtxBuilder};

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

/// The WASM execution context.
///
/// Stores all the necessary data to run a WASM module.
pub struct WASMCtx<WA: ZKWASMArgs> {
  /// The used Wasm store that contains all the modules data.
  store: wasmi::Store<WasiCtx>,
  /// The Wasm module instance to operate on.
  instance: wasmi::Instance,
  /// The given WASM module
  module: wasmi::Module,
  /// The structure that containt the execution trace of the WASM module
  tracer: Rc<RefCell<Tracer>>,
  /// The arguments needed to run the WASM module.
  wasm_args: WA,
}

impl<WA: ZKWASMArgs> WASMCtx<WA> {
  /// Create a new instance of `WASMCtx`.
  ///
  /// # Arguments
  /// * `file_path` - The path to the WASM file.
  ///
  /// # Returns
  /// A new instance of `WASMCtx`.
  pub fn new_from_file(wasm_args: WA) -> anyhow::Result<Self> {
    Self::new_from_bytecode(&wasm_args.bytecode()?, wasm_args)
  }

  /// Create a new instance of `WASMCtx` from a byte code.
  pub fn new_from_bytecode(wasm_bytes: &[u8], wasm_args: WA) -> anyhow::Result<Self> {
    // Setup and parse the wasm bytecode.
    let engine = Engine::default();
    let mut linker = <Linker<WasiCtx>>::new(&engine);
    let module = Module::new(&engine, wasm_bytes)?;

    // Create a new tracer
    let tracer = Rc::new(RefCell::new(Tracer::new(wasm_args.trace_slice_values())));

    // build wasi ctx to add to linker.
    let wasi = WasiCtxBuilder::new()
      .inherit_stdio()
      .inherit_args()?
      .build();

    // Create a new store & add wasi through the linker
    let mut store = Store::new(&engine, wasi);
    wasmi_wasi::add_to_linker(&mut linker, |ctx| ctx)?;

    // Instantiate the module and trace WASM linear memory and global memory initializations
    let instance = linker
      .instantiate_with_tracer(&mut store, &module, tracer.clone())?
      .start(&mut store)?;

    // Return the new instance of `WASMCtx`
    Ok(Self {
      store,
      instance,
      module,
      tracer,
      wasm_args,
    })
  }

  /// Create a new instance of `WASMCtx`.
  ///
  /// # Arguments
  /// * `file_path` - The path to the WASM file.
  ///
  /// # Returns
  /// A new instance of `WASMCtx`.
  pub fn new_from_file_with_linking(
    wasm_args: WA,
    linking_fn: fn(&mut Linker<WasiCtx>),
  ) -> anyhow::Result<Self> {
    Self::new_from_bytecode_with_linking(&wasm_args.bytecode()?, wasm_args, linking_fn)
  }

  /// Create a new instance of `WASMCtx` from a byte code.
  pub fn new_from_bytecode_with_linking(
    wasm_bytes: &[u8],
    wasm_args: WA,
    linking_fn: fn(&mut Linker<WasiCtx>) -> (),
  ) -> anyhow::Result<Self> {
    // Setup and parse the wasm bytecode.
    let engine = Engine::default();
    let mut linker = <Linker<WasiCtx>>::new(&engine);
    let module = Module::new(&engine, wasm_bytes)?;

    // Create a new tracer
    let tracer = Rc::new(RefCell::new(Tracer::new(wasm_args.trace_slice_values())));

    // build wasi ctx to add to linker.
    let wasi = WasiCtxBuilder::new()
      .inherit_stdio()
      .inherit_args()?
      .build();

    // Create a new store & add wasi through the linker
    let mut store = Store::new(&engine, wasi);
    wasmi_wasi::add_to_linker(&mut linker, |ctx| ctx)?;

    // Add custom linking
    linking_fn(&mut linker);

    // Instantiate the module and trace WASM linear memory and global memory initializations
    let instance = linker
      .instantiate_with_tracer(&mut store, &module, tracer.clone())?
      .start(&mut store)?;

    // Return the new instance of `WASMCtx`
    Ok(Self {
      store,
      instance,
      module,
      tracer,
      wasm_args,
    })
  }

  /// Returns the exported named functions of the Wasm [`Module`].
  ///
  /// [`Module`]: wasmi::Module
  pub fn exported_funcs(&self) -> impl Iterator<Item = (&str, FuncType)> {
    self.module.exports().filter_map(|export| {
      let name = export.name();
      match export.ty() {
        ExternType::Func(func_type) => Some((name, func_type.clone())),
        _ => None,
      }
    })
  }

  /// Get the args needed to run the WASM module.
  pub fn args(&self) -> &WA {
    &self.wasm_args
  }

  /// Set the wasm_args
  pub fn set_args(&mut self, wasm_args: WA) {
    self.wasm_args = wasm_args;
  }

  /// Set the TracerSliceValues
  pub fn set_tracer_slice_values(&mut self, start: usize, end: usize) {
    self.args().trace_slice_values().set_start(start);
    self.args().trace_slice_values().set_end(end);
  }

  /// Get the linear memory of the WASM module.
  pub fn memory(&mut self, name: &str) -> anyhow::Result<wasmi::Memory> {
    self
      .instance
      .get_memory(&mut self.store, name)
      .ok_or(anyhow!(
        "failed to find memory named {name:?} in the Wasm module"
      ))
  }
}

impl<WA: ZKWASMArgs> ZKWASMContext<WasiCtx> for WASMCtx<WA> {
  /// Returns an exclusive reference to the [`Store`] of the [`Context`].
  fn store_mut(&mut self) -> &mut Store<WasiCtx> {
    &mut self.store
  }

  /// Returns a shared reference to the [`Store`] of the [`Context`].
  fn store(&self) -> &Store<WasiCtx> {
    &self.store
  }

  /// Returns the exported function named `name` if any.
  ///
  /// # Errors
  ///
  /// - If the function is not found in the WASM module.
  fn func(&self, name: &str) -> anyhow::Result<Func> {
    self
      .instance
      .get_func(&self.store, name)
      .ok_or_else(|| anyhow!("failed to find function named {name:?} in the Wasm module"))
      .map_err(|error| anyhow!("{error}\n\n{}", DisplayExportedFuncs::from(self)))
  }

  /// Retrive the tracer
  fn tracer(&self) -> anyhow::Result<Rc<RefCell<Tracer>>> {
    Ok(self.tracer.clone())
  }

  /// Get the arguments needed to run the WASM module.
  fn args(&self) -> &dyn ZKWASMArgs {
    &self.wasm_args
  }

  /// Build and retrive the execution trace
  fn build_execution_trace(&mut self) -> anyhow::Result<ETable> {
    // WASM function name to invoke
    let fn_name = self.args().invoke();

    // WASM Func to invoke
    // You need a function to invoke to get an execution trace
    let func = self.func(fn_name)?;

    // Prepare inputs for function invokation
    let ty = func.ty(self.store());

    // Prepare func args for getting memory trace
    let func_args = decode_func_args(&ty, &self.args().func_args())?;
    {
      let mut tracer = self.tracer.borrow_mut();
      let untyped_val_args: Vec<UntypedValue> = func_args
        .iter()
        .map(|v| UntypedValue::from(v.clone()))
        .collect();
      tracer.set_inputs(untyped_val_args);
    }

    // Validate args
    typecheck_args(fn_name, &ty, &func_args)?;

    // Prepare function outputs
    let mut func_results = prepare_func_results(&ty);

    // Get struct that builds the execution trace
    let tracer = self.tracer.clone();

    // Call the function to invoke.
    // Gets the execution trace.
    func.call_with_trace(
      self.store_mut(),
      &func_args,
      &mut func_results,
      tracer.clone(),
    )?;
    print_pretty_results(&func_results);

    // Return the execution trace
    let etable = tracer.borrow().etable();

    // Validate end opcode
    let end_opcode = {
      // Get values from trace_slice_values
      let mut end = self.args().trace_slice_values().end();

      // Default is 0, so if end == 0 make the end_opcode the last opcode in the trace
      if end == 0 {
        // Execution trace length = last_opcode
        end = etable.entries().len()
      }
      end
    };

    // Slice etable if necessary
    let etable =
      ETable::new(etable.entries()[self.args().trace_slice_values().start()..end_opcode].to_vec());
    tracing::trace!("Execution trace: {:#?}", etable);

    // Execution trace
    Ok(etable)
  }
}
