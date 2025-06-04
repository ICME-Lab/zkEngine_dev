//! This module implements aggregation logic for the zkWASM.
use std::{cell::OnceCell, marker::PhantomData};

use super::{
  error::ZKWASMError,
  wasm_snark::{WASMPublicParams, WasmSNARK, ZKWASMInstance},
};
use itertools::Itertools;
use nova::{
  nebula::layer_2::aggregation::{
    compression::{CompressedSNARK, ProverKey, VerifierKey},
    AggregationPublicParams as NovaAggregationPublicParams, AggregationRecursiveSNARK,
  },
  traits::{
    snark::{default_ck_hint, BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
    CurveCycleEquipped, Dual,
  },
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Aggregation public parameters
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AggregationPublicParams<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  pp: NovaAggregationPublicParams<E>,
  /// Prover and verifier key for final proof compression
  #[serde(skip)]
  pk_and_vk: OnceCell<(ProverKey<E, S1, S2>, VerifierKey<E, S1, S2>)>,
}

impl<E, S1, S2> AggregationPublicParams<E, S1, S2>
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
  pub fn inner(&self) -> &NovaAggregationPublicParams<E> {
    &self.pp
  }
}

/// Aggregation SNARK used to aggregate [`WasmSNARK`]'s
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AggregationSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  rs: AggregationRecursiveSNARK<E>,
  _s1: PhantomData<S1>,
  _s2: PhantomData<S2>,
}

impl<E, S1, S2> AggregationSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  /// Get the [`AggregationPublicParams`]
  pub fn setup(wasm_pp: WASMPublicParams<E, S1, S2>) -> AggregationPublicParams<E, S1, S2> {
    let pp =
      NovaAggregationPublicParams::<E>::setup(wasm_pp, &*default_ck_hint(), &*default_ck_hint());
    AggregationPublicParams {
      pp,
      pk_and_vk: OnceCell::new(),
    }
  }
  /// Create a new instance of [`AggregationSNARK`]
  pub async fn new(
    pp: &AggregationPublicParams<E, S1, S2>,
    wasm_snark: &WasmSNARK<E, S1, S2>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    match wasm_snark {
      WasmSNARK::Recursive(wasm_snark) => {
        let rs = AggregationRecursiveSNARK::new(pp.inner(), wasm_snark.as_ref(), U).await?;
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
  pub async fn aggregate(
    &mut self,
    pp: &AggregationPublicParams<E, S1, S2>,
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

  /// Verify the [`AggregationSNARK`]
  pub async fn verify(&self, pp: &AggregationPublicParams<E, S1, S2>) -> Result<(), ZKWASMError> {
    self.rs.verify(pp.inner()).await?;
    Ok(())
  }

  /// Apply Spartan on top of the [`AggregationSNARK`]
  pub async fn compress(
    &self,
    pp: &AggregationPublicParams<E, S1, S2>,
  ) -> Result<CompressedSNARK<E, S1, S2>, ZKWASMError> {
    let pk = pp.pk().await;
    let snark = CompressedSNARK::prove(pp.inner(), pk, &self.rs).await?;
    Ok(snark)
  }
}
