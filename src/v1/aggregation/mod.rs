//! This module implements aggregation logic for the zkWASM.
use std::marker::PhantomData;

use super::{
  error::ZKWASMError,
  wasm_snark::{WASMPublicParams, WasmSNARK, ZKWASMInstance},
};
use itertools::Itertools;
use nova::{
  nebula::layer_2::aggregation::{AggregationPublicParams, AggregationRecursiveSNARK},
  traits::{snark::BatchedRelaxedR1CSSNARKTrait, CurveCycleEquipped, Dual},
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Get aggregation public parameters
pub fn gen_aggregation_pp<E, S1, S2>(
  wasm_pp: WASMPublicParams<E, S1, S2>,
) -> AggregationPublicParams<E>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: BatchedRelaxedR1CSSNARKTrait<Dual<E>>,
{
  AggregationPublicParams::setup(wasm_pp)
}

/// Aggregation SNARK used to aggregate [`WasmSNARK`]'s
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AggregationSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: BatchedRelaxedR1CSSNARKTrait<Dual<E>>,
{
  rs: AggregationRecursiveSNARK<E>,
  _s1: PhantomData<S1>,
  _s2: PhantomData<S2>,
}

impl<E, S1, S2> AggregationSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: BatchedRelaxedR1CSSNARKTrait<Dual<E>>,
{
  /// Create a new instance of [`AggregationSNARK`]
  pub fn new(
    pp: &AggregationPublicParams<E>,
    wasm_snark: &WasmSNARK<E, S1, S2>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    match wasm_snark {
      WasmSNARK::Recursive(wasm_snark) => {
        let rs = AggregationRecursiveSNARK::new(pp, wasm_snark, U)?;
        Ok(Self {
          rs,
          _s1: PhantomData,
          _s2: PhantomData,
        })
      }
      WasmSNARK::Compressed(_) => Err(ZKWASMError::NotRecursive),
    }
  }

  /// Aggregate the [`WasmSNARK`]s
  ///
  /// # Panics
  ///
  /// Panics if the number of [`WasmSNARK`]'s and U's ([`ZKWASMInstance`]'s) are not equal
  pub fn aggregate(
    &mut self,
    pp: &AggregationPublicParams<E>,
    wasm_snarks: &[WasmSNARK<E, S1, S2>],
    U: &[ZKWASMInstance<E>],
  ) -> Result<(), ZKWASMError> {
    for (snark, U) in wasm_snarks.iter().zip_eq(U.iter()) {
      match snark {
        WasmSNARK::Recursive(wasm_snark) => {
          self.rs.prove_step(pp, wasm_snark, U)?;
        }
        WasmSNARK::Compressed(_) => return Err(ZKWASMError::NotRecursive),
      }
    }

    Ok(())
  }

  /// Verify the [`AggregationSNARK`]
  pub fn verify(&self, pp: &AggregationPublicParams<E>) -> Result<(), ZKWASMError> {
    self.rs.verify(pp)?;
    Ok(())
  }
}
