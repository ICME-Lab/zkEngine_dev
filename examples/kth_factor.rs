use std::path::PathBuf;
use zk_engine::{
  error::ZKWASMError,
  nova::{
    provider::ipa_pc,
    provider::{hyperkzg, Bn256EngineKZG, GrumpkinEngine},
    spartan::ppsnark::RelaxedR1CSSNARK,
  },
  utils::logging::init_logger,
  wasm_ctx::{WASMArgsBuilder, WASMCtx},
  wasm_snark::{StepSize, WasmSNARK},
};

// Curve Cycle to prove/verify on
type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = hyperkzg::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<E2, EE2>;

fn main() -> Result<(), ZKWASMError> {
  init_logger();

  // Here we chose execution step size of 1000 since the WASM execution is 7601 opcodes.
  //
  // However the memory size is 147456 address spaces, so we set memory step size to 50_000.
  // Resulting in 3 steps for MCC
  let step_size = StepSize::new(1000).set_memory_step_size(50_000);

  // Produce setup material
  let pp = WasmSNARK::<E1, E2, S1, S2>::setup(step_size).unwrap();

  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/kth_factor.wat"))?
    .func_args(vec!["250".to_string(), "15".to_string()])
    .invoke("kth_factor")
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);

  let (snark, instance) = WasmSNARK::<E1, E2, S1, S2>::prove(&pp, &wasm_ctx, step_size)?;

  // Verify the proof
  snark.verify(&pp, &instance)?;

  Ok(())
}
