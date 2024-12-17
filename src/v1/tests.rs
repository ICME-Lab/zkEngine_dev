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

#[test]
fn test_defi_transaction() {
  init_logger();
  let step_size = StepSize::new(500).set_memory_step_size(50_000);
  // Simulated user and pool balances
  let user_input_balance = "1000"; // User's balance of token A
  let pool_input_reserve = "10000"; // Pool's reserve of token A
  let pool_output_reserve = "10000"; // Pool's reserve of token B
  let swap_amount = "500"; // Amount of token A to swap for token B
  let price = "100"; // Price of token A in terms of token B

  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/use_cases/defi_transaction.wasm"))
    .unwrap()
    .func_args(vec![
      user_input_balance.to_string(),
      pool_input_reserve.to_string(),
      pool_output_reserve.to_string(),
      swap_amount.to_string(),
      price.to_string(),
    ])
    .invoke("main")
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_energy_consumption() {
  init_logger();
  let step_size = StepSize::new(200).set_memory_step_size(50_000);

  let total_produced = "5000"; // Total energy produced by the microgrid in some time frame (e.g., in watt-hours).
  let total_consumed = "4900"; // Total energy consumed by all devices in the microgrid for the same period.
  let device_count = "100"; // Number of IoT devices or meters in the network.
  let baseline_price = "100"; // A baseline price or factor used for further calculations (e.g., cost per watt-hour or an
                              // index).

  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/use_cases/energy_usage.wasm"))
    .unwrap()
    .func_args(vec![
      total_produced.to_string(),
      total_consumed.to_string(),
      device_count.to_string(),
      baseline_price.to_string(),
    ])
    .invoke("main")
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_toy_rsa() {
  init_logger();
  let step_size = StepSize::new(1000).set_memory_step_size(50_000);

  let p_candidate = "1009"; // A candidate prime number p.
  let q_candidate = "1013"; // A candidate prime number q.
  let e = "17"; // A public exponent e.
  let message = "65"; // A message to encrypt.
  let use_crt = "1"; // A flag to use the Chinese Remainder Theorem (CRT) optimization.

  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/use_cases/toy_rsa.wasm"))
    .unwrap()
    .func_args(vec![
      p_candidate.to_string(),
      q_candidate.to_string(),
      e.to_string(),
      message.to_string(),
      use_crt.to_string(),
    ])
    .invoke("main")
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}

#[test]
fn test_financial_protocol() {
  init_logger();
  let step_size = StepSize::new(1000).set_memory_step_size(50_000);
  //  Moderately healthy loan, moderate staking, moderate interest
  let collateral_amount = "2000";
  let borrowed_amount = "1000";
  let stake_ratio = "50";
  let annual_interest_bps = "600"; // 6% annual interest

  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/use_cases/financial_protocol.wasm"))
    .unwrap()
    .func_args(vec![
      collateral_amount.to_string(),
      borrowed_amount.to_string(),
      stake_ratio.to_string(),
      annual_interest_bps.to_string(),
    ])
    .invoke("main")
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);

  test_wasm_snark_with(wasm_ctx, step_size).unwrap();
}
