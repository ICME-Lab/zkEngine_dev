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
    snark::{default_ck_hint, BatchedRelaxedR1CSSNARKTrait},
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
  S2: BatchedRelaxedR1CSSNARKTrait<Dual<E>>,
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
  S2: BatchedRelaxedR1CSSNARKTrait<Dual<E>>,
{
  /// provides a reference to a ProverKey suitable for producing a CompressedProof
  pub fn pk(&self) -> &ProverKey<E, S1, S2> {
    let (pk, _vk) = self
      .pk_and_vk
      .get_or_init(|| CompressedSNARK::<E, S1, S2>::setup(&self.pp).unwrap());
    pk
  }

  /// provides a reference to a VerifierKey suitable for verifying a CompressedProof
  pub fn vk(&self) -> &VerifierKey<E, S1, S2> {
    let (_pk, vk) = self
      .pk_and_vk
      .get_or_init(|| CompressedSNARK::<E, S1, S2>::setup(&self.pp).unwrap());
    vk
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
  pub fn new(
    pp: &AggregationPublicParams<E, S1, S2>,
    wasm_snark: &WasmSNARK<E, S1, S2>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    match wasm_snark {
      WasmSNARK::Recursive(wasm_snark) => {
        let rs = AggregationRecursiveSNARK::new(pp.inner(), wasm_snark.as_ref(), U)?;
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
    pp: &AggregationPublicParams<E, S1, S2>,
    wasm_snarks: &[WasmSNARK<E, S1, S2>],
    U: &[ZKWASMInstance<E>],
  ) -> Result<(), ZKWASMError> {
    for (snark, U) in wasm_snarks.iter().zip_eq(U.iter()) {
      match snark {
        WasmSNARK::Recursive(wasm_snark) => {
          self.rs.prove_step(pp.inner(), wasm_snark.as_ref(), U)?;
        }
        WasmSNARK::Compressed(_) => return Err(ZKWASMError::NotRecursive),
      }
    }

    Ok(())
  }

  /// Verify the [`AggregationSNARK`]
  pub fn verify(&self, pp: &AggregationPublicParams<E, S1, S2>) -> Result<(), ZKWASMError> {
    self.rs.verify(pp.inner())?;
    Ok(())
  }

  /// Apply Spartan on top of the [`AggregationSNARK`]
  pub fn compress(
    &self,
    pp: &AggregationPublicParams<E, S1, S2>,
  ) -> Result<CompressedSNARK<E, S1, S2>, ZKWASMError> {
    let snark = CompressedSNARK::prove(pp.inner(), pp.pk(), &self.rs)?;
    Ok(snark)
  }
}
