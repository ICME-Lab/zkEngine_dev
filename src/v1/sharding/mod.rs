//! This module implements the sharding logic for the zkWASM.
//!
//! i.e. continuations

use nova::{
  nebula::l2::sharding::{ShardingPublicParams, ShardingRecursiveSNARK},
  traits::CurveCycleEquipped,
};

use super::{
  error::ZKWASMError,
  wasm_snark::{WASMPublicParams, WasmSNARK, ZKWASMInstance},
};

/// Generate sharding public parameters
pub fn gen_sharding_pp<E>(wasm_pp: WASMPublicParams<E>) -> ShardingPublicParams<E>
where
  E: CurveCycleEquipped,
{
  ShardingPublicParams::setup(wasm_pp)
}

/// Sharding SNARK used to aggregate [`WasmSNARK`]'s
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
  pub fn new(
    pp: &ShardingPublicParams<E>,
    wasm_snark: &WasmSNARK<E>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    let rs = ShardingRecursiveSNARK::new(pp, wasm_snark, U)?;
    Ok(Self { rs })
  }

  /// Combine the shards [`WasmSNARK`]s
  pub fn sharding(
    &mut self,
    pp: &ShardingPublicParams<E>,
    wasm_snarks: &[WasmSNARK<E>],
    U: &ZKWASMInstance<E>,
  ) -> Result<(), ZKWASMError> {
    for snark in wasm_snarks {
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
