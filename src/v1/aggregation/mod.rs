//! This module implements aggregation logic for the zkWASM.
use super::{
  error::ZKWASMError,
  wasm_snark::{WASMPublicParams, WasmSNARK, ZKWASMInstance},
};
use itertools::Itertools;
use nova::{
  nebula::l2::{AggregationPublicParams, AggregationRecursiveSNARK},
  traits::CurveCycleEquipped,
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Get aggregation public parameters
pub fn gen_aggregation_pp<E>(wasm_pp: WASMPublicParams<E>) -> AggregationPublicParams<E>
where
  E: CurveCycleEquipped,
{
  AggregationPublicParams::setup(wasm_pp)
}

/// Aggregation SNARK used to aggregate [`WasmSNARK`]'s
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AggregationSNARK<E>
where
  E: CurveCycleEquipped,
{
  rs: AggregationRecursiveSNARK<E>,
}

impl<E> AggregationSNARK<E>
where
  E: CurveCycleEquipped,
{
  /// Create a new instance of [`AggregationSNARK`]
  pub fn new(
    pp: &AggregationPublicParams<E>,
    wasm_snark: &WasmSNARK<E>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    let rs = AggregationRecursiveSNARK::new(pp, wasm_snark, U)?;
    Ok(Self { rs })
  }

  /// Aggregate the [`WasmSNARK`]s
  ///
  /// # Panics
  ///
  /// Panics if the number of [`WasmSNARK`]'s and U's ([`ZKWASMInstance`]'s) are not equal
  pub fn aggregate(
    &mut self,
    pp: &AggregationPublicParams<E>,
    wasm_snarks: &[WasmSNARK<E>],
    U: &[ZKWASMInstance<E>],
  ) -> Result<(), ZKWASMError> {
    for (snark, U) in wasm_snarks.iter().zip_eq(U.iter()) {
      self.rs.prove_step(pp, snark, U)?;
    }

    Ok(())
  }

  /// Verify the [`AggregationSNARK`]
  pub fn verify(&self, pp: &AggregationPublicParams<E>) -> Result<(), ZKWASMError> {
    self.rs.verify(pp)?;
    Ok(())
  }
}
