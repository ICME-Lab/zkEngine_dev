use std::path::PathBuf;
use zk_engine::{
  nova::provider::Bn256EngineIPA,
  utils::logging::init_logger,
  v1::{
    error::ZKWASMError,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK},
  },
};

// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

fn main() -> Result<(), ZKWASMError> {
  init_logger();

  // Here we chose execution step size of 1000 since the WASM execution is 7601 opcodes.
  //
  // However the memory size is 147456 address spaces, so we set memory step size to 50_000.
  // Resulting in 3 steps for MCC
  let step_size = StepSize::new(1000).set_memory_step_size(50_000);

  // Produce setup material
  let pp = WasmSNARK::<E>::setup(step_size);

  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/kth_factor.wat"))?
    .func_args(vec!["250".to_string(), "15".to_string()])
    .invoke("kth_factor")
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);

  let (snark, instance) = WasmSNARK::<E>::prove(&pp, &wasm_ctx, step_size)?;

  // Verify the proof
  snark.verify(&pp, &instance)?;

  Ok(())
}
