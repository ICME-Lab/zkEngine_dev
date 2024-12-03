//! This module implements aggregation logic for the zkWASM.
use nova::{
  nebula::l2::{AggregationPublicParams, AggregationRecursiveSNARK},
  traits::CurveCycleEquipped,
};

use super::{
  error::ZKWASMError,
  wasm_snark::{WASMPublicParams, WasmSNARK},
};

/// Get aggregation public parameters
pub fn gen_aggregation_pp<E>(wasm_pp: WASMPublicParams<E>) -> AggregationPublicParams<E>
where
  E: CurveCycleEquipped,
{
  AggregationPublicParams::setup(wasm_pp)
}

/// Aggregation SNARK used to aggregate [`WasmSNARK`]'s
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
  ) -> Result<Self, ZKWASMError> {
    let rs = AggregationRecursiveSNARK::new(pp, wasm_snark)?;
    Ok(Self { rs })
  }

  /// Aggregate the [`WasmSNARK`]s
  pub fn aggregate(
    &mut self,
    pp: &AggregationPublicParams<E>,
    wasm_snarks: &[WasmSNARK<E>],
  ) -> Result<(), ZKWASMError> {
    for snark in wasm_snarks {
      self.rs.prove_step(pp, snark)?;
    }

    Ok(())
  }

  /// Verify the [`AggregationSNARK`]
  pub fn verify(&self, pp: &AggregationPublicParams<E>) -> Result<(), ZKWASMError> {
    self.rs.verify(pp)?;
    Ok(())
  }
}
