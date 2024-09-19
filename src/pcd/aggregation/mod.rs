//! This module contains the `Aggregator` data structure used for "Aggregation"
//!
//! Aggregation is the term used to describe the process of aggregating many SNARKS into one SNARK.
//! This is done by turning their verify algorithm into a circuit and running the circuit and using
//! the SNARK as a witness
//!
//!
//! # Note
//!
//! These SNARKS that are meant to be aggregated have to prove the same WASM computation

use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan::{
    self,
    snark::RelaxedR1CSSNARK,
    verify_circuit::aggregator::{self, AggregatedSNARK, AggregatorSNARKData},
  },
  traits::{snark::default_ck_hint, Dual},
};

use crate::{
  run::batched::{BatchedZKEProof, BatchedZKEPublicParams},
  traits::public_values::ZKVMPublicParams,
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

type ZKEngine = BatchedZKEProof<E1, BS1, S1, S2>;

type AS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
type AS2 = spartan::batched::BatchedRelaxedR1CSSNARK<Dual<E1>, EE2>;

// TODO: use custom error

type SetupOutput<'a> = (
  aggregator::PublicParams<E1>,
  aggregator::ProverKey<E1, AS1, AS2>,
  aggregator::VerifierKey<E1, AS1, AS2>,
  Vec<AggregatorSNARKData<'a, E1>>,
);

/// Implements methods to convert many SNARKS (of the same computation) into one [`AggregatedSNARK`]
pub struct Aggregator;

impl Aggregator {
  /// Runs setup algorithm for aggregation
  ///
  /// 1. Convert SNARKS into data-structure ammenable to aggregation.
  /// 2. Get public params of verify circuit
  /// 3. Get pk  vk for verify circuit
  ///
  /// # Arguments
  /// * `wasm_args` - configurations needed to run the WASM module. Corresponds to the WASM the
  ///   SNARKS are proving
  /// * `snarks` - the SNARKS to be aggregated
  ///
  /// # Returns
  ///
  /// Returns a tuple containing the following:
  /// * `PublicParams` - the public parameters for the aggregation computation
  /// * `ProverKey` - Key needed in proving algorithm to produce final [`AggregatedSNARK`]
  /// * `VerifierKey` - Key needed in verifying algorithm to verify the final [`AggregatedSNARK`]
  /// * `Vec<AggregatorSNARKData>` - data made from converting input SNARKS into their data needed
  ///   for Aggregating
  pub fn setup<'a>(
    pp: &'a BatchedZKEPublicParams<E1, BS1, S1, S2>,
    snarks: &[ZKEngine],
  ) -> anyhow::Result<SetupOutput<'a>> {
    let mut snarks_data = Vec::with_capacity(snarks.len());
    let vk = pp.execution().vk().primary();

    for snark in snarks.iter() {
      let (s1, U) = snark.execution_proof.agg_snark_data();

      let agg_snark_data = AggregatorSNARKData::new(s1, vk, U);
      snarks_data.push(agg_snark_data);
    }

    let agg_pp =
      aggregator::PublicParams::setup(&snarks_data, &default_ck_hint(), &default_ck_hint())?;

    let (agg_pk, agg_vk) = AggregatedSNARK::<E1, AS1, AS2>::setup(&agg_pp)?;

    Ok((agg_pp, agg_pk, agg_vk, snarks_data))
  }

  /// Run SNARK's through verify circuit and produce final [`AggregatedSNARK`] on the R1CS of the
  /// verify circuit algorithm
  pub fn prove(
    pp: &aggregator::PublicParams<E1>,
    pk: &aggregator::ProverKey<E1, AS1, AS2>,
    snarks_data: &[AggregatorSNARKData<E1>],
  ) -> anyhow::Result<AggregatedSNARK<E1, AS1, AS2>> {
    let snark = AggregatedSNARK::prove(pp, pk, snarks_data)?;
    Ok(snark)
  }
}
