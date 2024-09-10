//! Data structures used to build wasm context for zkWASM execution.

use anyhow::anyhow;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{cell::RefCell, rc::Rc};
use wasmi::{
  core::UntypedValue, etable::ETable, Engine, ExternType, Func, FuncType, Linker, Module, Store,
  Tracer,
};
use wasmi_wasi::{clocks_ctx, sched_ctx, Table, WasiCtx, WasiCtxBuilder};

use crate::{
  traits::args::ZKWASMArgs,
  utils::{
    display::DisplayExportedFuncs,
    wasm::{decode_func_args, prepare_func_results, typecheck_args},
  },
};

/// This trait is used to define the wasm context that is passed to the zkWASM.
///
/// Guarantees an execution trace from the wasm bytecode.
pub trait ZKWASMContext<T> {
  /// Returns an exclusive reference to the [`Store`] of the [`Context`].
  fn store_mut(&mut self) -> &mut Store<T>;

  /// Returns a shared reference to the [`Store`] of the [`Context`].
  fn store(&self) -> &Store<T>;

  /// To get a trace you need a function to invoke.
  ///
  /// Gets a function to invoke from an instantiated WASM module.
  fn func(&self, fn_name: &str) -> anyhow::Result<Func>;

  /// returns a struct that is used to build the execution trace.
  fn tracer(&self) -> anyhow::Result<Rc<RefCell<Tracer>>>;

  /// builds and returns a struct that contains the execution trace.
  fn build_execution_trace(&mut self) -> anyhow::Result<(ETable, Box<[wasmi::Value]>)>;

  /// Get the args needed to run the WASM module.
  fn args(&self) -> &dyn ZKWASMArgs;
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

impl<WA: ZKWASMArgs + Clone> WASMCtx<WA> {
  /// Create a new instance of `WASMCtx`.
  ///
  /// # Returns
  /// A new instance of `WASMCtx`.
  pub fn new_from_file(wasm_args: &WA) -> anyhow::Result<Self> {
    Self::new_from_bytecode(&wasm_args.bytecode()?, wasm_args)
  }

  /// Create a new instance of `WASMCtx` from a byte code.
  pub fn new_from_bytecode(wasm_bytes: &[u8], wasm_args: &WA) -> anyhow::Result<Self> {
    // Setup and parse the wasm bytecode.
    let engine = Engine::default();
    let mut linker = <Linker<WasiCtx>>::new(&engine);
    let module = Module::new(&engine, wasm_bytes)?;

    // Create a new tracer
    let tracer = Rc::new(RefCell::new(Tracer::new(wasm_args.trace_slice_values())));

    // build wasi ctx to add to linker.
    let wasi = WasiCtx::new(zkvm_random_ctx(), clocks_ctx(), sched_ctx(), Table::new());

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
      wasm_args: wasm_args.clone(),
    })
  }

  /// Create a new instance of `WASMCtx`.
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

impl<WA: ZKWASMArgs + Clone> ZKWASMContext<WasiCtx> for WASMCtx<WA> {
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
  fn build_execution_trace(&mut self) -> anyhow::Result<(ETable, Box<[wasmi::Value]>)> {
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
    let start_opcode = self.args().trace_slice_values().start();
    let etable = ETable::new(etable.entries()[start_opcode..end_opcode].to_vec());
    tracing::trace!("Execution trace: {:#?}", etable);

    // Execution trace
    Ok((etable, func_results))
  }
}

/// zkvm uses a seed to generate random numbers.
pub fn zkvm_random_ctx() -> Box<dyn RngCore + Send + Sync> {
  Box::new(StdRng::from_seed([0; 32]))
}
