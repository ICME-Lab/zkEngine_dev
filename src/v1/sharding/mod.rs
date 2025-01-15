//! This module implements the sharding logic for the zkWASM.
//!
//! i.e. continuations

use super::{
  error::ZKWASMError,
  wasm_snark::{WASMPublicParams, WasmSNARK, ZKWASMInstance},
};
use itertools::Itertools;
use nova::{
  nebula::layer_2::sharding::{ShardingPublicParams, ShardingRecursiveSNARK},
  traits::CurveCycleEquipped,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod tests;

/// Generate sharding public parameters
pub fn gen_sharding_pp<E>(wasm_pp: WASMPublicParams<E>) -> ShardingPublicParams<E>
where
  E: CurveCycleEquipped,
{
  ShardingPublicParams::setup(wasm_pp)
}

/// Sharding SNARK used to aggregate [`WasmSNARK`]'s
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ShardingSNARK<E>
where
  E: CurveCycleEquipped,
{
  rs: ShardingRecursiveSNARK<E>,
}

impl<E> ShardingSNARK<E>
where
  E: CurveCycleEquipped,
{
  /// Create a new instance of [`ShardingSNARK`]
  ///
  /// # Note
  ///
  /// Input first shard here
  pub fn new(
    pp: &ShardingPublicParams<E>,
    wasm_snark: &WasmSNARK<E>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    let rs = ShardingRecursiveSNARK::new(pp, wasm_snark, U)?;
    Ok(Self { rs })
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
    wasm_snarks: &[WasmSNARK<E>],
    U: &[ZKWASMInstance<E>],
  ) -> Result<(), ZKWASMError> {
    for (snark, U) in wasm_snarks.iter().zip_eq(U.iter()) {
      self.rs.prove_step(pp, snark, U)?;
    }

    Ok(())
  }

  /// Verify the [`ShardingSNARK`]
  pub fn verify(&self, pp: &ShardingPublicParams<E>) -> Result<(), ZKWASMError> {
    self.rs.verify(pp)?;
    Ok(())
  }
}
