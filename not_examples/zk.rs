use std::path::PathBuf;
// Backend imports for ZK
use zk_engine::{
  args::{WASMArgsBuilder, WASMCtx},
  nova::{
    provider::{ipa_pc, ZKPallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::Dual,
  },
  run::batched::BatchedZKEProof,
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
};

// Configs to enable ZK
type E1 = ZKPallasEngine;
type EE1<E> = ipa_pc::EvaluationEngine<E>;
type EE2<E> = ipa_pc::EvaluationEngine<Dual<E>>;
type BS1<E> = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1<E>>;
type S1<E> = RelaxedR1CSSNARK<E, EE1<E>>;
type S2<E> = RelaxedR1CSSNARK<Dual<E>, EE2<E>>;

fn main() -> anyhow::Result<()> {
  init_logger();

  // WASM Arguments
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .invoke(Some(String::from("fib")))
    .func_args(vec![String::from("1000")])
    .build();
  let mut wasm_ctx = WASMCtx::new_from_file(args)?;

  // ZKPallasEngine get's used here
  let (proof, public_values, _) =
    BatchedZKEProof::<E1, BS1<E1>, S1<E1>, S2<E1>>::prove_wasm(&mut wasm_ctx)?;

  let result = proof.verify(public_values)?;
  Ok(assert!(result))
}
