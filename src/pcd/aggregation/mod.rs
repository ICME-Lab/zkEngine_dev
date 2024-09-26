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

use crate::traits::{be_engine::BackendEngine, public_values::ZKVMPublicParams};
use nova::{
  errors::NovaError,
  provider::PallasEngine,
  spartan::verify_circuit::aggregator::{
    build_verify_circuits, AggregatedVerifierKey, AggregatorPublicParams, AggregatorSNARKData,
    CompressedAggregatedSNARK, FFACircuit, IOPCircuit, RecursiveAggregatedSNARK,
  },
  traits::snark::RelaxedR1CSSNARKTrait,
};

use crate::{
  provider::{AggregationEngine, E},
  run::batched::{PublicParams, WasmSNARK},
  //   traits::{be_engine::BackendEngine, public_values::ZKVMPublicParams},
};

#[cfg(test)]
mod tests;

type CompressedOutput = (
  CompressedAggregatedSNARK<
    <E as BackendEngine>::E1,
    <E as BackendEngine>::S1,
    <E as BackendEngine>::S2,
  >,
  AggregatedVerifierKey<
    <E as BackendEngine>::E1,
    <E as BackendEngine>::S1,
    <E as BackendEngine>::S2,
  >,
);

/// Implements methods to convert many SNARKS (of the same computation) into one SNARK
pub struct Aggregator;

impl Aggregator {
  /// Prepare input SNARK's for aggregation
  pub fn prepare_snarks<'a>(
    pp: &'a PublicParams<AggregationEngine>,
    snarks: &[WasmSNARK<AggregationEngine>],
  ) -> anyhow::Result<Vec<AggregatorSNARKData<'a, PallasEngine>>> {
    // Get verifiers key which will be passed in the verify circuit
    //
    // The verifier key for each proof to be aggregated is the same
    let vk = pp.execution().vk().primary();

    // Convert SNARKS into data-structure ammenable to aggregation.
    let mut snarks_data = Vec::with_capacity(snarks.len());
    for snark in snarks.iter() {
      let (s1, U) = snark.execution_proof.agg_snark_data();

      let agg_snark_data = AggregatorSNARKData::new(s1, vk, U);
      snarks_data.push(agg_snark_data);
    }

    Ok(snarks_data)
  }

  /// Build the verify circuits
  pub fn build_verify_circuits<'a>(
    snarks_data: &'a [AggregatorSNARKData<PallasEngine>],
  ) -> anyhow::Result<Vec<(IOPCircuit<'a, PallasEngine>, FFACircuit<'a, PallasEngine>)>> {
    // Get the public parameters of the verify circuit
    Ok(build_verify_circuits(snarks_data)?)
  }

  /// Create the public parameters of the verify circuit
  pub fn public_params(
    circuit_iop: &IOPCircuit<PallasEngine>,
    circuit_ffa: &FFACircuit<PallasEngine>,
  ) -> anyhow::Result<AggregatorPublicParams<PallasEngine>> {
    // Get the public parameters of the verify circuit
    Ok(AggregatorPublicParams::setup(
      circuit_iop,
      circuit_ffa,
      &*<E as BackendEngine>::S1::ck_floor(),
      &*<E as BackendEngine>::S2::ck_floor(),
    )?)
  }

  /// Prove Aggregation computation
  ///
  /// Runs verify circuit for each SNARK and aggregates them into one SNARK
  ///
  /// Inputs a RecursiveAggregatedSNARK that is used to keep aggregation process "open" if need be
  pub fn prove(
    pp: &AggregatorPublicParams<PallasEngine>,
    circuits: &[(IOPCircuit<'_, PallasEngine>, FFACircuit<'_, PallasEngine>)],
    mut rs_option: Option<RecursiveAggregatedSNARK<PallasEngine>>,
  ) -> anyhow::Result<RecursiveAggregatedSNARK<PallasEngine>> {
    for (iop_circuit, ffa_circuit) in circuits.iter() {
      let mut rs = rs_option
        .unwrap_or_else(|| RecursiveAggregatedSNARK::new(pp, iop_circuit, ffa_circuit).unwrap());

      rs.prove_step(pp, iop_circuit, ffa_circuit)?;
      rs_option = Some(rs)
    }

    debug_assert!(rs_option.is_some());
    let rs = rs_option.ok_or(NovaError::UnSat)?;
    let num_steps = rs.num_steps();
    rs.verify(pp, num_steps)?;

    Ok(rs)
  }

  /// Compress the recursive Aggregated SNARK (this is the SNARK that will be sent to the client if
  /// they want an intermediate SNARK for the aggregation or at the end of the aggregation)
  pub fn compress(
    pp: &AggregatorPublicParams<PallasEngine>,
    rs: &RecursiveAggregatedSNARK<PallasEngine>,
  ) -> anyhow::Result<CompressedOutput> {
    let (pk, vk) = CompressedAggregatedSNARK::<
      <E as BackendEngine>::E1,
      <E as BackendEngine>::S1,
      <E as BackendEngine>::S2,
    >::setup(pp)?;
    let snark = CompressedAggregatedSNARK::<
      <E as BackendEngine>::E1,
      <E as BackendEngine>::S1,
      <E as BackendEngine>::S2,
    >::prove(pp, &pk, rs)?;

    Ok((snark, vk))
  }
}
