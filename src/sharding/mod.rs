//! This module implements the sharding logic for the zkWASM.
//!
//! i.e. continuations

use std::{cell::OnceCell, marker::PhantomData};

use super::{
  error::ZKWASMError,
  wasm_snark::{WASMPublicParams, WasmSNARK, ZKWASMInstance},
};
use itertools::Itertools;
use nova::{
  nebula::layer_2::sharding::{
    compression::{CompressedSNARK, ProverKey, VerifierKey},
    ShardingPublicParams as NovaShardingPublicParams, ShardingRecursiveSNARK,
  },
  traits::{
    snark::{default_ck_hint, BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
    CurveCycleEquipped, Dual,
  },
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod tests;

/// Sharding public parameters
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ShardingPublicParams<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  pp: NovaShardingPublicParams<E>,
  /// Prover and verifier key for final proof compression
  #[serde(skip)]
  pk_and_vk: OnceCell<(ProverKey<E, S1, S2>, VerifierKey<E, S1, S2>)>,
}

impl<E, S1, S2> ShardingPublicParams<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  /// provides a reference to a ProverKey suitable for producing a CompressedProof
  pub async fn pk(&self) -> &ProverKey<E, S1, S2> {
    let m = self
      .pk_and_vk
      .get();

    match m {
      Some(m) => &m.0,
      None => {
        let (pk, vk) = CompressedSNARK::<E, S1, S2>::setup(&self.pp).await.unwrap();
        self.pk_and_vk.set((pk, vk));
        &self.pk_and_vk.get().unwrap().0
      }
    }
  }

  /// provides a reference to a VerifierKey suitable for verifying a CompressedProof
  pub async fn vk(&self) -> &VerifierKey<E, S1, S2> {
    let m = self
    .pk_and_vk
    .get();

  match m {
    Some(m) => &m.1,
    None => {
        let (pk, vk) = CompressedSNARK::<E, S1, S2>::setup(&self.pp).await.unwrap();
        self.pk_and_vk.set((pk, vk));
        &self.pk_and_vk.get().unwrap().1
      }
    }
  }

  /// Get the inner public parameters
  pub fn inner(&self) -> &NovaShardingPublicParams<E> {
    &self.pp
  }
}

/// Sharding SNARK used to aggregate [`WasmSNARK`]'s
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ShardingSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  rs: ShardingRecursiveSNARK<E>,
  _s1: PhantomData<S1>,
  _s2: PhantomData<S2>,
}

impl<E, S1, S2> ShardingSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  /// Get the [`ShardingPublicParams`]
  pub fn setup(wasm_pp: WASMPublicParams<E, S1, S2>) -> ShardingPublicParams<E, S1, S2> {
    let pp =
      NovaShardingPublicParams::<E>::setup(wasm_pp, &*default_ck_hint(), &*default_ck_hint());
    ShardingPublicParams {
      pp,
      pk_and_vk: OnceCell::new(),
    }
  }

  /// Create a new instance of [`ShardingSNARK`]
  ///
  /// # Note
  ///
  /// Input first shard here
  pub async fn new(
    pp: &ShardingPublicParams<E, S1, S2>,
    wasm_snark: &WasmSNARK<E, S1, S2>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    match wasm_snark {
      WasmSNARK::Recursive(wasm_snark) => {
        let rs = ShardingRecursiveSNARK::new(pp.inner(), wasm_snark.as_ref(), U).await?;
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
  pub async fn prove_sharding(
    &mut self,
    pp: &ShardingPublicParams<E, S1, S2>,
    wasm_snarks: &[WasmSNARK<E, S1, S2>],
    U: &[ZKWASMInstance<E>],
  ) -> Result<(), ZKWASMError> {
    for (snark, U) in wasm_snarks.iter().zip_eq(U.iter()) {
      match snark {
        WasmSNARK::Recursive(wasm_snark) => {
          self.rs.prove_step(pp.inner(), wasm_snark.as_ref(), U).await?;
        }
        WasmSNARK::Compressed(_) => return Err(ZKWASMError::NotRecursive),
      }
    }

    Ok(())
  }

  /// Verify the [`ShardingSNARK`]
  pub async fn verify(&self, pp: &ShardingPublicParams<E, S1, S2>) -> Result<(), ZKWASMError> {
    self.rs.verify(pp.inner()).await?;
    Ok(())
  }

  /// Apply Spartan on top of the[`ShardingSNARK`]
  pub async fn compress(
    &self,
    pp: &ShardingPublicParams<E, S1, S2>,
  ) -> Result<CompressedSNARK<E, S1, S2>, ZKWASMError> {
    let pk = pp.pk().await;
    let snark = CompressedSNARK::prove(pp.inner(), pk, &self.rs).await?;
    Ok(snark)
  }
}
