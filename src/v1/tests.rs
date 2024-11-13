use std::{path::PathBuf, time::Instant};

use nova::provider::Bn256EngineIPA;

use crate::utils::{logging::init_logger, wasm::wat2wasm};

use super::{
  error::ZKWASMError,
  wasm_ctx::{WASMCtx, WASMCtxBuilder},
  wasm_snark::WasmSNARK,
};

/// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

fn test_wasm_snark_with(wasm_ctx: WASMCtx, step_size: usize) -> Result<(), ZKWASMError> {
  let pp = WasmSNARK::<E>::setup(step_size);

  let (snark, U) = WasmSNARK::<E>::prove(&pp, &wasm_ctx, step_size)?;
  let time = Instant::now();
  snark.verify(&pp, &U).unwrap();
  tracing::info!("Verification time: {:?}", time.elapsed());
  Ok(())
}

#[test]
fn test_bit_check() -> Result<(), ZKWASMError> {
  let step_size = 16;
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/bit_check.wat"))
    .unwrap()
    .invoke("bit_check")
    .func_args(vec!["255".to_string(), "255".to_string()])
    .build();

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_int_opcodes() -> Result<(), ZKWASMError> {
  let step_size = 100;
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/int_opcodes.wat"))
    .unwrap()
    .build();

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_omit_rel_ops() -> Result<(), ZKWASMError> {
  let step_size = 50;
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/omit_rel_ops.wat"))
    .unwrap()
    .build();

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_eq_func() -> Result<(), ZKWASMError> {
  let step_size = 500;
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/eq_func.wat"))
    .unwrap()
    .invoke("eq_func")
    .func_args(vec!["255".to_string(), "255".to_string()])
    .build();

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_complete_int_opcodes() -> Result<(), ZKWASMError> {
  let step_size = 1000;
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/complete_int_opcodes.wat"))
    .unwrap()
    .build();

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_kth_factor() -> Result<(), ZKWASMError> {
  let step_size = 1000;
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/kth_factor.wat"))
    .unwrap()
    .invoke("kth_factor")
    .func_args(vec!["10".to_string(), "3".to_string()])
    .build();

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_regression_model() {
  let step_size = 1_000;
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/regression_model.wasm"))
    .unwrap()
    .func_args(vec!["10".to_string()])
    .invoke("regression")
    .build();

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_integer_hash() {
  let step_size = 100;
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/integer_hash.wasm"))
    .unwrap()
    .func_args(vec!["10".to_string()])
    .invoke("integer_hash")
    .build();

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_bls() {
  let step_size = 1_000_000;
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/bls.wasm"))
    .unwrap()
    .invoke("main")
    .build();

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}
