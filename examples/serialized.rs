use std::path::PathBuf;
use zk_engine::{
  args::{WASMArgsBuilder, WASMCtx},
  nova::{
    provider::{ipa_pc, PallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::Dual,
  },
  run::default::{public_values::PublicValues, ZKEProof},
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
};

// Backend configs
type E1 = PallasEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;
type BS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

type ZKEngine = ZKEProof<E1, BS1, S1, S2>;

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
    .func_args(vec![String::from("10")]) // This will generate 152 opcodes
    .build();
  let mut wasm_ctx = WASMCtx::new_from_file(args)?;

  let (proof, public_values, _) = ZKEngine::prove_wasm(&mut wasm_ctx)?;

  // Serialize the proof and public values
  let proof_str = serde_json::to_string(&proof)?;
  let public_values_str = serde_json::to_string(&public_values)?;

  // Deserialize the proof and public values
  let proof: ZKEProof<E1, BS1, S1, S2> = serde_json::from_str(&proof_str)?;
  let public_values: PublicValues<E1, BS1, S1, S2> = serde_json::from_str(&public_values_str)?;

  // Verify the proof
  let result = proof.verify(public_values)?;
  Ok(assert!(result))
}
