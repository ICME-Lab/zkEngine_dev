use nova::nova::nebula::api::NebulaInstance;
use std::path::PathBuf;
use zk_engine::{
  nova::{
    provider::ipa_pc,
    provider::{hyperkzg, Bn256EngineKZG, GrumpkinEngine},
    spartan::ppsnark::RelaxedR1CSSNARK,
  },
  {
    error::ZKWASMError,
    utils::logging::init_logger,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK},
  },
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

  // Specify step size.
  //
  // Here we choose `10` as the step size because the wasm execution of fib(16) is 253 opcodes.
  // meaning zkWASM will run for 26 steps (rounds up).
  let step_size = StepSize::new(10);

  // Produce setup material
  let pp = WasmSNARK::<E1, E2, S1, S2>::setup(step_size).unwrap();

  // Specify arguments to the WASM and use it to build a `WASMCtx`
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .unwrap()
    .invoke("fib")
    .func_args(vec![String::from("16")])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);

  // Prove wasm execution of fib.wat::fib(16)
  let (snark, instance) = WasmSNARK::<E1, E2, S1, S2>::prove(&pp, &wasm_ctx, step_size)?;

  let str_instance = serde_json::to_string(&instance).unwrap();
  let str_snark = serde_json::to_string(&snark).unwrap();

  let snark: WasmSNARK<E1, E2, S1, S2> = serde_json::from_str(&str_snark).unwrap();
  let instance: NebulaInstance<E1> = serde_json::from_str(&str_instance).unwrap();

  // Verify the proof
  snark.verify(&pp, &instance)?;

  Ok(())
}
