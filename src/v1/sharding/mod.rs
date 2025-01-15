//! This module implements the sharding logic for the zkWASM.
//!
//! i.e. continuations

use std::marker::PhantomData;

use super::{
  error::ZKWASMError,
  wasm_snark::{WASMPublicParams, WasmSNARK, ZKWASMInstance},
};
use itertools::Itertools;
use nova::{
  nebula::layer_2::sharding::{ShardingPublicParams, ShardingRecursiveSNARK},
  traits::{snark::BatchedRelaxedR1CSSNARKTrait, CurveCycleEquipped, Dual},
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod tests;

/// Generate sharding public parameters
pub fn gen_sharding_pp<E, S1, S2>(wasm_pp: WASMPublicParams<E, S1, S2>) -> ShardingPublicParams<E>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: BatchedRelaxedR1CSSNARKTrait<Dual<E>>,
{
  ShardingPublicParams::setup(wasm_pp)
}

/// Sharding SNARK used to aggregate [`WasmSNARK`]'s
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ShardingSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: BatchedRelaxedR1CSSNARKTrait<Dual<E>>,
{
  rs: ShardingRecursiveSNARK<E>,
  _s1: PhantomData<S1>,
  _s2: PhantomData<S2>,
}

impl<E, S1, S2> ShardingSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: BatchedRelaxedR1CSSNARKTrait<Dual<E>>,
{
  /// Create a new instance of [`ShardingSNARK`]
  ///
  /// # Note
  ///
  /// Input first shard here
  pub fn new(
    pp: &ShardingPublicParams<E>,
    wasm_snark: &WasmSNARK<E, S1, S2>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    match wasm_snark {
      WasmSNARK::Recursive(wasm_snark) => {
        let rs = ShardingRecursiveSNARK::new(pp, wasm_snark, U)?;
        Ok(Self {
          rs,
          _s1: PhantomData,
          _s2: PhantomData,
        })
      }
      WasmSNARK::Compressed(_) => Err(ZKWASMError::NotRecursive),
    }
  }

  /// Combine the shards [`WasmSNARK`]s
  ///
  /// # Panics
  ///
  /// Panics if the number of [`WasmSNARK`]'s  and U's ([`ZKWASMInstance`]'s) are not equal
  ///
  /// # Note
  ///
  /// Order of shards inputted here matter.
  pub fn prove_sharding(
    &mut self,
    pp: &ShardingPublicParams<E>,
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

  /// Verify the [`ShardingSNARK`]
  pub fn verify(&self, pp: &ShardingPublicParams<E>) -> Result<(), ZKWASMError> {
    self.rs.verify(pp)?;
    Ok(())
  }
}
