use std::path::PathBuf;
use zk_engine::{
  nova::{
    provider::{ipa_pc, Bn256EngineIPA},
    spartan,
    traits::Dual,
  },
  utils::logging::init_logger,
  {
    error::ZKWASMError,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK},
  },
};

// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;
pub type EE1 = ipa_pc::EvaluationEngine<E>;
pub type EE2 = ipa_pc::EvaluationEngine<Dual<E>>;
pub type S1 = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1>;
pub type S2 = spartan::batched::BatchedRelaxedR1CSSNARK<Dual<E>, EE2>;

fn main() -> Result<(), ZKWASMError> {
  init_logger();

  let step_size = StepSize::new(10);
  let pp = WasmSNARK::<E, S1, S2>::setup(step_size);

  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/use_cases/tic_tac_toe.wasm"))
    .unwrap()
    .invoke("start")
    .func_args(vec![])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);

  let (snark, instance) = WasmSNARK::<E, S1, S2>::prove(&pp, &wasm_ctx, step_size)?;

  snark.verify(&pp, &instance)?;

  Ok(())
}
