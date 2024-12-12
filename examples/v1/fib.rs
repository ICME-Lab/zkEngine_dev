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

  // Specify step size.
  //
  // Here we choose `10` as the step size because the wasm execution of fib(16) is 253 opcodes.
  // meaning zkWASM will run for 26 steps (rounds up).
  let step_size = StepSize::new(10);

  // Produce setup material
  let pp = WasmSNARK::<E>::setup(step_size);

  // Specify arguments to the WASM and use it to build a `WASMCtx`
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .unwrap()
    .invoke("fib")
    .func_args(vec![String::from("16")])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);

  // Prove wasm execution of fib.wat::fib(16)
  let (snark, instance) = WasmSNARK::<E>::prove(&pp, &wasm_ctx, step_size)?;

  // Verify the proof
  snark.verify(&pp, &instance)?;

  Ok(())
}