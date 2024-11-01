use std::{cell::RefCell, path::PathBuf, rc::Rc};

use wasmi::Tracer;

use crate::{
  traits::wasm::ZKWASMArgs,
  utils::wasm::{decode_func_args, prepare_func_results},
  v1::utils::tracing::{execute_wasm, unwrap_rc_refcell},
  wasm::args::WASMArgsBuilder,
};

use super::error::ZKWASMError;

#[test]
fn test_tracing() -> Result<(), ZKWASMError> {
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/ams_isa.wat"))
    .build();

  let tracer = Rc::new(RefCell::new(Tracer::new()));
  execute_wasm(&args, tracer.clone())?;

  let tracer = unwrap_rc_refcell(tracer);
  println!("max sp: {:#?}", tracer.max_sp());
  let execution_trace = tracer.into_execution_trace();

  println!("{:#?}", execution_trace);
  Ok(())
}
