use std::path::PathBuf;
use zk_engine::{
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
  wasm::{args::WASMArgsBuilder, ctx::wasi::WasiWASMCtx},
  BatchedZKEngine,
};

fn main() -> anyhow::Result<()> {
  init_logger();

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
    .invoke(Some(String::from("_start")))
    .build();

  // Create a WASM execution context for proving.
  let pp = BatchedZKEngine::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  let mut wasm_ctx = WasiWASMCtx::new_from_file(&args)?;

  let (proof, public_values, _) = BatchedZKEngine::prove_wasm(&mut wasm_ctx, &pp)?;

  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}
