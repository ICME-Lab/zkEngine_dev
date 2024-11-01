use std::{cell::RefCell, path::PathBuf, rc::Rc};

use wasmi::Tracer;

use crate::{
  traits::wasm::ZKWASMArgs,
  utils::wasm::{decode_func_args, prepare_func_results},
  wasm::args::WASMArgsBuilder,
};

use super::error::ZKWASMError;

#[test]
fn test_tracing() -> Result<(), ZKWASMError> {
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/ams_isa.wat"))
    .build();

  let wasm = args.bytecode().map_err(ZKWASMError::AnyhowError)?;

  // Setup and parse the wasm bytecode.
  let engine = wasmi::Engine::default();
  let linker = <wasmi::Linker<()>>::new(&engine);
  let module = wasmi::Module::new(&engine, &wasm[..])?;
  let tracer = Rc::new(RefCell::new(Tracer::new()));

  // build wasi ctx to add to linker.

  // Create a new store & add wasi through the linker
  let mut store = wasmi::Store::new(&engine, ());

  // Instantiate the module and trace WASM linear memory and global memory initializations
  let instance = linker.instantiate(&mut store, &module)?.start(&mut store)?;

  let func = instance.get_func(&store, args.invoke()).ok_or_else(|| {
    ZKWASMError::WasmiError(wasmi::Error::Func(
      wasmi::errors::FuncError::ExportedFuncNotFound,
    ))
  })?;

  // Prepare i/o
  let ty = func.ty(&store);
  let func_args = decode_func_args(&ty, &args.func_args())?;
  let mut func_results = prepare_func_results(&ty);

  // Call the function to invoke.
  func.call_with_trace(&mut store, &func_args, &mut func_results, tracer.clone())?;

  println!("{:?}", func_results);
  Ok(())
}
