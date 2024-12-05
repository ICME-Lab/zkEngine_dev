use super::{
  error::ZKWASMError,
  wasm_ctx::{TraceSliceValues, WASMArgsBuilder, WASMCtx, WasiWASMCtx, ZKWASMCtx},
  wasm_snark::{StepSize, WasmSNARK},
};
use crate::{
  utils::logging::init_logger,
  v1::utils::macros::{start_timer, stop_timer},
};
use nova::provider::Bn256EngineIPA;
use std::{path::PathBuf, time::Instant};

/// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

fn test_wasm_snark_with(wasm_ctx: impl ZKWASMCtx, step_size: StepSize) -> Result<(), ZKWASMError> {
  let pp_timer = start_timer!("Producing Public Parameters");
  let pp = WasmSNARK::<E>::setup(step_size);
  stop_timer!(pp_timer);

  let proving_timer = start_timer!("Producing WasmSNARK");
  let (snark, U) = WasmSNARK::<E>::prove(&pp, &wasm_ctx, step_size)?;
  stop_timer!(proving_timer);

  let verification_timer = start_timer!("Verifying WasmSNARK");
  snark.verify(&pp, &U).unwrap();
  stop_timer!(verification_timer);

  Ok(())
}

#[test]
fn test_bit_check() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(16);
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
  let step_size = StepSize::new(100);
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
  let step_size = StepSize::new(500);
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
  let step_size = StepSize::new(1000);
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
fn test_zk_ads() {
  init_logger();
  let step_size = StepSize::new(500).set_memory_step_size(50_000);
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

  let wasm_ctx = WasiWASMCtx::new(wasm_args);
  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_bulk_ops() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(1000).set_memory_step_size(10_000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/bulk-ops.wat"))?
    .func_args(vec!["200".to_string()])
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_kth_factor() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(1000).set_memory_step_size(50_000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/kth_factor.wat"))?
    .func_args(vec!["250".to_string(), "15".to_string()])
    .invoke("kth_factor")
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size)?;
  Ok(())
}

#[test]
fn test_integer_hash() {
  let step_size = StepSize::new(2_500).set_memory_step_size(50_000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/integer_hash.wasm"))
    .unwrap()
    .func_args(vec!["100".to_string()])
    .invoke("integer_hash")
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_gradient_boosting() {
  let step_size = StepSize::new(5_000).set_memory_step_size(50_000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
    .unwrap()
    .invoke("_start")
    .build();

  let wasm_ctx = WasiWASMCtx::new(wasm_args);
  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_uni_poly_eval() {
  let x = "1";
  let size = "10";

  let step_size = StepSize::new(2_500).set_memory_step_size(50_000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/uni-poly-eval.wasm"))
    .unwrap()
    .invoke("eval")
    .func_args(vec![String::from(x), String::from(size)])
    .build();

  let wasm_ctx = WasiWASMCtx::new(wasm_args);
  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_bls() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(1_000).set_memory_step_size(50_000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/bls.wasm"))
    .unwrap()
    .trace_slice(TraceSliceValues::new(10_000, 20_000))
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);
  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_fib_large() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(1_000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))?
    .invoke("fib")
    .func_args(vec![String::from("1000")])
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);
  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}

#[test]
fn test_fib_small() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(10);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))?
    .invoke("fib")
    .func_args(vec![String::from("16")])
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);
  test_wasm_snark_with(wasm_ctx, step_size)?;

  Ok(())
}
