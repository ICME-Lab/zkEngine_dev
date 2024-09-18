use std::marker::PhantomData;

use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan::{
    self,
    snark::RelaxedR1CSSNARK,
    verify_circuit::aggregator::{self, AggregatedSNARK, AggregatorSNARKData},
  },
  traits::{snark::default_ck_hint, CurveCycleEquipped, Dual},
};

use crate::{
  run::batched::BatchedZKEProof,
  traits::{public_values::ZKVMPublicParams, zkvm::ZKVM},
  wasm::{args::WASMArgs, ctx::wasi::WasiWASMCtx},
};

#[cfg(test)]
mod tests;
//TODO: make ZKWasmSNARK a generic here

type E1 = PallasEngine;
type BS1 = spartan::verify_circuit::ipa_prover_poseidon::batched::BatchedRelaxedR1CSSNARK<E1>;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

pub type ZKEngine = BatchedZKEProof<E1, BS1, S1, S2>;

type AS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
type AS2 = spartan::batched::BatchedRelaxedR1CSSNARK<Dual<E1>, EE2>;

struct Aggregator {}

impl Aggregator {
  // TODO: use custom error
  fn setup(
    wasm_args: &WASMArgs,
    snarks: &[ZKEngine],
  ) -> anyhow::Result<(
    aggregator::PublicParams<E1>,
    aggregator::ProverKey<E1, AS1, AS2>,
    aggregator::VerifierKey<E1, AS1, AS2>,
    Vec<AggregatorSNARKData<E1>>,
  )> {
    let mut snarks_data = Vec::with_capacity(snarks.len());
    let pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;

    for snark in snarks.iter() {
      let (s1, U) = snark.execution_proof.agg_snark_data();

      let vk = pp.execution().vk().primary().clone();
      let agg_snark_data = AggregatorSNARKData::new(s1, vk, U);
      snarks_data.push(agg_snark_data);
    }

    let agg_pp =
      aggregator::PublicParams::setup(&snarks_data, &default_ck_hint(), &default_ck_hint())?;

    let (agg_pk, agg_vk) = AggregatedSNARK::<E1, AS1, AS2>::setup(&agg_pp)?;

    Ok((agg_pp, agg_pk, agg_vk, snarks_data))
  }

  fn prove(
    pp: &aggregator::PublicParams<E1>,
    pk: &aggregator::ProverKey<E1, AS1, AS2>,
    snarks_data: &[AggregatorSNARKData<E1>],
  ) -> anyhow::Result<AggregatedSNARK<E1, AS1, AS2>> {
    let snark = AggregatedSNARK::prove(pp, pk, snarks_data)?;
    Ok(snark)
  }
}
