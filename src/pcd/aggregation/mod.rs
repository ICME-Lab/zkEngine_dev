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
  spartan::verify_circuit::aggregator::{self, AggregatedSNARK, AggregatorSNARKData},
  traits::snark::default_ck_hint,
};

use crate::{
  provider::{AggregationEngine, E},
  run::batched::{PublicParams, WasmSNARK},
  traits::{be_engine::BackendEngine, public_values::ZKVMPublicParams},
};

#[cfg(test)]
mod tests;

// TODO: make more generic, in turn more readable

/// Output of the aggregation setup algorithm
type SetupOutput<'a> = (
  aggregator::PublicParams<<E as BackendEngine>::E1>, // Public Params
  aggregator::ProverKey<
    <E as BackendEngine>::E1,
    <E as BackendEngine>::BS1,
    <E as BackendEngine>::BS2,
  >, // Prover Key
  aggregator::VerifierKey<
    <E as BackendEngine>::E1,
    <E as BackendEngine>::BS1,
    <E as BackendEngine>::BS2,
  >, // Verifier Key
  Vec<AggregatorSNARKData<'a, <E as BackendEngine>::E1>>, // SNARK Data
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
    pp: &'a PublicParams<AggregationEngine>,
    snarks: &[WasmSNARK<AggregationEngine>],
  ) -> anyhow::Result<SetupOutput<'a>> {
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

    // Get the public parameters of the verify circuit
    tracing::info!("Producing Aggregator public params...");
    let agg_pp =
      aggregator::PublicParams::setup(&snarks_data, &default_ck_hint(), &default_ck_hint())?;

    // Get the prover and verifier keys for the proving/verifying of the verify circuit
    tracing::info!("Setting up Aggregator prover and verifier keys...");
    let (agg_pk, agg_vk) = AggregatedSNARK::<
      <E as BackendEngine>::E1,
      <E as BackendEngine>::BS1,
      <E as BackendEngine>::BS2,
    >::setup(&agg_pp)?;

    Ok((agg_pp, agg_pk, agg_vk, snarks_data))
  }

  /// Run SNARK's through verify circuit and produce final [`AggregatedSNARK`] on the R1CS of the
  /// verify circuit algorithm
  ///
  /// # Arguments
  /// * `pp` - the public parameters for the aggregation computation (corresponding to the verify
  ///   circuit)
  /// * `pk` - the prover key for the aggregation (needed for final Aggregated SNARK)
  /// * `snarks_data` - the data produced from converting the input SNARKS into data structure
  ///   ammenable to aggregation
  ///
  /// # Returns
  ///
  /// Returns the final [`AggregatedSNARK`] which has a verify method
  pub fn prove(
    pp: &aggregator::PublicParams<<E as BackendEngine>::E1>,
    pk: &aggregator::ProverKey<
      <E as BackendEngine>::E1,
      <E as BackendEngine>::BS1,
      <E as BackendEngine>::BS2,
    >,
    snarks_data: &[AggregatorSNARKData<<E as BackendEngine>::E1>],
  ) -> anyhow::Result<
    AggregatedSNARK<<E as BackendEngine>::E1, <E as BackendEngine>::BS1, <E as BackendEngine>::BS2>,
  > {
    // Run verify circuit on SNARK's and produce final Aggregated SNARK
    tracing::info!("Proving Aggregated SNARK...");
    let snark = AggregatedSNARK::prove(pp, pk, snarks_data)?;
    Ok(snark)
  }
}
