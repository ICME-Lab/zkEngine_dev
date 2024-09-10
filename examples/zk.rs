use nova::provider::ZKPallasEngine;
use std::path::PathBuf;
use zk_engine::{
  // Backend imports for ZK
  nova::{
    provider::ipa_pc,
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::Dual,
  },
  run::batched::BatchedZKEProof,
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
  wasm::{args::WASMArgsBuilder, ctx::wasi::WasiWASMCtx},
};

// Configs to enable ZK
type E1 = ZKPallasEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;
type BS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

type ZKEngine = BatchedZKEProof<E1, BS1, S1, S2>;

fn main() -> anyhow::Result<()> {
  init_logger();

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .invoke(Some(String::from("fib")))
    .func_args(vec![String::from("1000")]) // This will generate 16,000 + opcodes
    .build();

  let pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  // ZKPallasEngine get's used here
  let (proof, public_values, _) =
    ZKEngine::prove_wasm(&mut WasiWASMCtx::new_from_file(&args)?, &pp)?;

  // Verify proof
  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}
