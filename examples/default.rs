use std::path::PathBuf;
use zk_engine::{
  args::{WASMArgsBuilder, WASMCtx},
  // Backend imports
  nova::{
    provider::{ipa_pc, PallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::Dual,
  },
  run::default::ZKEProof,
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
};

// Curve cycle to use for proving
type E1 = PallasEngine;
// PCS used for final SNARK at the end of (N)IVC
type EE1 = ipa_pc::EvaluationEngine<E1>;
// PCS on secondary curve
type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;

// Spartan SNARKS used for compressing at then end of (N)IVC
type BS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

type ZKEngine = ZKEProof<E1, BS1, S1, S2>;

fn main() -> anyhow::Result<()> {
  init_logger();

  // Configure the arguments needed for WASM execution
  //
  // Here we are configuring the path to the WASM file
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();

  let pp = ZKEngine::setup(&mut WASMCtx::new_from_file(args.clone())?)?;

  // Prove execution and run memory consistency checks
  //
  // Get proof for verification and corresponding public values
  //
  // Above type alias's (for the backend config) get used here
  let (proof, public_values, _) =
    ZKEngine::prove_wasm(&mut WASMCtx::new_from_file(args.clone())?, &pp)?;

  // // Verify proof
  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}
