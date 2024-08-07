use std::borrow::Cow;

use ff::Field;
use nova::traits::{CurveCycleEquipped, Dual, Engine};

use crate::errors::ProofError;

pub trait RecursiveSNARKTrait<E1: CurveCycleEquipped, C>
where
  Self: Sized + Clone,
{
  /// Associated type for public parameters
  type PublicParams;

  /// Type for the base recursive SNARK that can be used as a starting point
  /// in `Self::prove_recursively`
  type BaseRecursiveSNARK;

  /// Type for error potentially thrown during verification
  type ErrorType;

  /// Generate the recursive SNARK
  fn prove_recursively(
    pp: &Self::PublicParams,
    z0: &[E1::Scalar],
    init: Option<Self::BaseRecursiveSNARK>,
    steps: C,
  ) -> Result<Self, ProofError>;

  /// Compress a proof
  fn compress(&self, pp: &Self::PublicParams) -> Result<Cow<'_, Self>, ProofError>;

  /// Verify the proof given the public parameters, the input and output values
  fn verify(
    &self,
    pp: &Self::PublicParams,
    z0: &[E1::Scalar],
    zi: &[E1::Scalar],
  ) -> Result<bool, Self::ErrorType>;

  /// Return the `z0_secondary`
  #[inline]
  fn z0_secondary() -> Vec<<Dual<E1> as Engine>::Scalar> {
    vec![<Dual<E1> as Engine>::Scalar::ZERO]
  }

  fn zi_primary(&self) -> anyhow::Result<&[E1::Scalar]>;
}
