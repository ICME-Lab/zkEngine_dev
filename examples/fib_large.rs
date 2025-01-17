use std::path::PathBuf;
use zk_engine::{
  nova::{
    provider::{ipa_pc, Bn256EngineIPA},
    spartan,
    traits::Dual,
  },
  v1::{
    error::ZKWASMError,
    utils::logging::init_logger,
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

  // Specify step size.
  //
  // Here we choose `1_000` as the step size because the wasm execution of fib(1000) is 16,981
  // opcodes. meaning zkWASM will run for 17 steps (rounds up).
  let step_size = StepSize::new(1_000);

  // Produce setup material
  let pp = WasmSNARK::<E, S1, S2>::setup(step_size);

  // Specify arguments to the WASM and use it to build a `WASMCtx`
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .unwrap()
    .invoke("fib")
    .func_args(vec![String::from("1000")])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);

  // Prove wasm execution of fib.wat::fib(1000)
  let (snark, instance) = WasmSNARK::<E, S1, S2>::prove(&pp, &wasm_ctx, step_size)?;

  // Verify the proof
  snark.verify(&pp, &instance)?;

  Ok(())
}
