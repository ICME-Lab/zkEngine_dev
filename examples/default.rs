use std::path::PathBuf;
use zk_engine::{
  args::{WASMArgsBuilder, WASMCtx},
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
  BatchedZKEngine,
};

fn main() -> anyhow::Result<()> {
  init_logger();

  // Configure the arguments needed for WASM execution
  //
  // Here we are configuring the path to the WASM file
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();

  // Run setup step for ZKVM
  let pp = BatchedZKEngine::setup(&mut WASMCtx::new_from_file(&args)?)?;

  // Prove execution and run memory consistency checks
  //
  // Get proof for verification and corresponding public values
  //
  // Above type alias's (for the backend config) get used here
  let (proof, public_values, _) =
    BatchedZKEngine::prove_wasm(&mut WASMCtx::new_from_file(&args)?, &pp)?;

  // // Verify proof
  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}
