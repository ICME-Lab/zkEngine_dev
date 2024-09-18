use std::path::PathBuf;

use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan::{
    self,
    snark::RelaxedR1CSSNARK,
    verify_circuit::{
      self,
      aggregator::{self, AggregatedSNARK, AggregatorSNARKData},
    },
  },
  traits::{snark::default_ck_hint, Dual},
};

use crate::{
  run::default::ZKEProof,
  traits::{public_values::ZKVMPublicParams, zkvm::ZKVM},
  utils::logging::init_logger,
  wasm::{args::WASMArgsBuilder, ctx::wasi::WasiWASMCtx},
};

#[test]
fn test_aggregator() -> anyhow::Result<()> {
  type E1 = PallasEngine;
  type BS1 = spartan::verify_circuit::ipa_prover_poseidon::batched::BatchedRelaxedR1CSSNARK<E1>;
  type EE1 = ipa_pc::EvaluationEngine<E1>;
  type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;
  type S1 = RelaxedR1CSSNARK<E1, EE1>;
  type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

  pub type ZKEngine = ZKEProof<E1, BS1, S1, S2>;

  type AS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
  type AS2 = spartan::batched::BatchedRelaxedR1CSSNARK<Dual<E1>, EE2>;
  init_logger();

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();

  let pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  let (proof, public_values, _) =
    ZKEngine::prove_wasm(&mut WasiWASMCtx::new_from_file(&args)?, &pp)?;

  let (s1, U) = proof.execution_proof.agg_snark_data();
  // TODO: check if we can use the same vk
  let vk = pp.execution().vk().primary().clone();
  let agg_snark_data = AggregatorSNARKData::new(s1, vk, U);
  let snarks_data = vec![agg_snark_data];

  let agg_pp =
    aggregator::PublicParams::setup(&snarks_data, &default_ck_hint(), &default_ck_hint())?;

  let (agg_pk, agg_vk) = AggregatedSNARK::<E1, AS1, AS2>::setup(&agg_pp)?;
  let snark = AggregatedSNARK::prove(&agg_pp, &agg_pk, &snarks_data)?;

  snark.verify(&agg_vk)?;

  Ok(())
}
