use std::{path::PathBuf, time::Instant};

use nova::provider::Bn256EngineIPA;

use crate::{
  utils::logging::init_logger,
  v1::utils::macros::{start_timer, stop_timer},
};

use super::{
  error::ZKWASMError,
  wasm_ctx::{WASMArgsBuilder, WASMCtx, ZKWASMCtx},
  wasm_snark::WasmSNARK,
};

/// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

fn test_wasm_snark_with(wasm_ctx: impl ZKWASMCtx, step_size: usize) -> Result<(), ZKWASMError> {
  let pp_timer = start_timer!("Producing Public Parameters");
  let pp = WasmSNARK::<E>::setup(step_size);
  stop_timer!(pp_timer);

  let proving_timer = start_timer!("Producing WasmSNARK");
  let (snark, U) = WasmSNARK::<E>::prove(&pp, wasm_ctx, step_size)?;
  stop_timer!(proving_timer);

  let verification_timer = start_timer!("Verifying WasmSNARK");
  snark.verify(&pp, &U).unwrap();
  stop_timer!(verification_timer);

  Ok(())
}

#[test]
fn test_bit_check() -> Result<(), ZKWASMError> {
  let step_size = 16;
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/bit_check.wat"))
    .unwrap()
    .invoke("bit_check")
    .func_args(vec!["255".to_string(), "255".to_string()])
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_int_opcodes() -> Result<(), ZKWASMError> {
  let step_size = 100;
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/int_opcodes.wat"))
    .unwrap()
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_eq_func() -> Result<(), ZKWASMError> {
  let step_size = 500;
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/eq_func.wat"))
    .unwrap()
    .invoke("eq_func")
    .func_args(vec!["255".to_string(), "255".to_string()])
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_complete_int_opcodes() -> Result<(), ZKWASMError> {
  let step_size = 1000;
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/complete_int_opcodes.wat"))
    .unwrap()
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_integer_hash() {
  let step_size = 10_000;
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/integer_hash.wasm"))
    .unwrap()
    .func_args(vec!["10".to_string()])
    .invoke("integer_hash")
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_zk_ads() {
  init_logger();
  let step_size = 1_000;
  let input_x = "200.05";
  let input_y = "-30.0";
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/zk_ads.wasm"))
    .unwrap()
    .func_args(vec![
      String::from("0"),
      String::from(input_x),
      String::from(input_y),
    ])
    .invoke("is_user_close_enough")
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}
