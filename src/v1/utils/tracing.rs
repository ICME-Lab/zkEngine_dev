use crate::{
  utils::wasm::{decode_func_args, prepare_func_results},
  v1::{error::ZKWASMError, wasm_ctx::WASMCtx},
};
use std::{cell::RefCell, rc::Rc, time::Instant};
use wasmi::Tracer;

use super::macros::{start_timer, stop_timer};

/// Get inner value of [`Rc<RefCell<T>>`]
pub fn unwrap_rc_refcell<T>(last_elem: Rc<RefCell<T>>) -> T {
  let inner: RefCell<T> = Rc::try_unwrap(last_elem)
    .unwrap_or_else(|_| panic!("The last_elem was shared, failed to unwrap"));
  inner.into_inner()
}

// TODO: refactor this
/// Execute a WASM module & extract the execution trace
pub fn execute_wasm(wasm_ctx: &WASMCtx, tracer: Rc<RefCell<Tracer>>) -> Result<(), ZKWASMError> {
  // Setup and parse the wasm bytecode.
  let engine = wasmi::Engine::default();
  let linker = <wasmi::Linker<()>>::new(&engine);
  let module = wasmi::Module::new(&engine, &wasm_ctx.program[..])?;

  // Create a new store & add wasi through the linker
  let mut store = wasmi::Store::new(&engine, ());

  // Instantiate the module and trace WASM linear memory and global memory initializations
  let instance = linker
    .instantiate_with_trace(&mut store, &module, tracer.clone())?
    .start(&mut store)?;

  let func = instance
    .get_func(&store, &wasm_ctx.meta_data.invoke)
    .ok_or_else(|| {
      ZKWASMError::WasmiError(wasmi::Error::Func(
        wasmi::errors::FuncError::ExportedFuncNotFound,
      ))
    })?;

  // Prepare i/o
  let ty = func.ty(&store);
  let func_args = decode_func_args(&ty, &wasm_ctx.meta_data.func_args)?;
  let mut func_results = prepare_func_results(&ty);

  // Call the function to invoke.
  func.call_with_trace(&mut store, &func_args, &mut func_results, tracer.clone())?;
  tracing::debug!("wasm func res: {:#?}", func_results);
  Ok(())
}

/// Get estimations of the WASM execution trace size
pub fn estimate_wasm(program: &WASMCtx) -> Result<(), ZKWASMError> {
  let tracer = Rc::new(RefCell::new(Tracer::new()));

  let execution_timer = start_timer!("Running WASM");
  execute_wasm(program, tracer.clone())?;
  stop_timer!(execution_timer);

  let tracer = unwrap_rc_refcell(tracer);

  let IS_stack_len = tracer.IS_stack_len();
  let IS_mem_len = tracer.IS_mem_len();
  tracing::info!("stack len: {}", IS_stack_len);
  tracing::info!("IS_mem.len: {}", IS_mem_len);

  let execution_trace = tracer.into_execution_trace();
  tracing::info!("Execution trace len: {:?}", execution_trace.len());
  Ok(())
}
