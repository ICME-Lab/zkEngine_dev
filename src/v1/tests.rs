use std::{cell::RefCell, path::PathBuf, rc::Rc};

use nova::provider::Bn256EngineIPA;
use wasmi::Tracer;

use crate::{
  v1::utils::tracing::{execute_wasm, unwrap_rc_refcell},
  wasm::args::WASMArgsBuilder,
};

use super::{error::ZKWASMError, wasm_snark::WasmSNARK};

/// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

#[test]
fn test_wasm_snark() -> Result<(), ZKWASMError> {
  let program = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/ams_isa.wat"))
    .build();

  let pp = WasmSNARK::<E>::setup();

  let _snark = WasmSNARK::<E>::prove(&pp, &program)?;
  Ok(())
}

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
