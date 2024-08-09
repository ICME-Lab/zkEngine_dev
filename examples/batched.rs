
use std::path::PathBuf;
// Backend imports
use zk_engine::{
  args::{WASMArgsBuilder, WASMCtx},
  nova::{
    provider::{ipa_pc, PallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::{
      snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
      CurveCycleEquipped, Dual, Engine,
    },
  },
  run::batched::BatchedZKEProof,
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
};

// Backend configs
type E1 = PallasEngine;
type EE1<E> = ipa_pc::EvaluationEngine<E>;
type EE2<E> = ipa_pc::EvaluationEngine<Dual<E>>;
type BS1<E> = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1<E>>;
type S1<E> = RelaxedR1CSSNARK<E, EE1<E>>;
type S2<E> = RelaxedR1CSSNARK<Dual<E>, EE2<E>>;

fn main() -> anyhow::Result<()> {
  init_logger();

  // Some WASM' modules require the function to invoke and it's functions arguments.
  // The below code is an example of how to configure the WASM arguments for such cases.
  //
  // This WASM module (fib.wat) has a fib fn which will
  // produce the n'th number in the fibonacci sequence.
  // The function we want to invoke has the following signature:
  //
  // fib(n: i32) -> i32;
  //
  // This means the higher the user input is for `n` the more opcodes will need to be proven
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .invoke(Some(String::from("fib")))
    .func_args(vec![String::from("1000")]) // This will generate 16,000 + opcodes
    .build();
  let mut wasm_ctx = WASMCtx::new_from_file(args)?;

  // Use `BatchedZKEProof` for batched proving
  let (proof, public_values) =
    BatchedZKEProof::<E1, BS1<E1>, S1<E1>, S2<E1>>::prove_wasm(&mut wasm_ctx)?;
  let result = proof.verify(public_values)?;
  Ok(assert!(result))
}
