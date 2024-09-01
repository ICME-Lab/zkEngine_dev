use std::path::PathBuf;

use crate::{
  args::{WASMArgsBuilder, WASMCtx},
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
  BatchedZKEngine,
};

#[test]
fn test_gradient_boosting() -> anyhow::Result<()> {
  init_logger();

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
    .invoke(Some(String::from("_start")))
    .build();

  // Create a WASM execution context for proving.
  let pp = BatchedZKEngine::setup(&mut WASMCtx::new_from_file(&args)?)?;

  let mut wasm_ctx = WASMCtx::new_from_file(&args)?;

  let (proof, public_values, _) = BatchedZKEngine::prove_wasm(&mut wasm_ctx, &pp)?;

  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}

#[test]
fn test_zk_ads() -> anyhow::Result<()> {
  init_logger();

  let input_x = "200.05";
  let input_y = "-30.0";

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/zk_ads.wasm"))
    .invoke(Some(String::from("is_user_close_enough")))
    .func_args(vec![
      String::from("0"),
      String::from(input_x),
      String::from(input_y),
    ])
    .build();

  let pp = BatchedZKEngine::setup(&mut WASMCtx::new_from_file(&args)?)?;

  let mut wasm_ctx = WASMCtx::new_from_file(&args)?;

  let (proof, public_values, _) = BatchedZKEngine::prove_wasm(&mut wasm_ctx, &pp)?;

  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}

#[test]
fn test_uni_poly_eval() -> anyhow::Result<()> {
  init_logger();
  let x = "1";
  let size = "10";

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/uni-poly-eval.wasm"))
    .invoke(Some(String::from("eval")))
    .func_args(vec![String::from(x), String::from(size)])
    .build();

  let pp = BatchedZKEngine::setup(&mut WASMCtx::new_from_file(&args)?)?;

  let mut wasm_ctx = WASMCtx::new_from_file(&args)?;

  let (proof, public_values, _) = BatchedZKEngine::prove_wasm(&mut wasm_ctx, &pp)?;

  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}
