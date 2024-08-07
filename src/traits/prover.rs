use nova::traits::CurveCycleEquipped;

use crate::errors::ProofError;

use super::snark::RecursiveSNARKTrait;

pub trait Prover<E1: CurveCycleEquipped> {
  type Frames: Send;
  type PublicParams;

  /// Associated proof type, which must implement `RecursiveSNARKTrait`
  type RecursiveSNARK: RecursiveSNARKTrait<E1, Self::Frames, PublicParams = Self::PublicParams>;

  /// Generates a recursive proof from a vector of `M`
  fn prove(
    pp: &Self::PublicParams,
    z0: Vec<E1::Scalar>,
    steps: Self::Frames,
    init: Option<
      <Self::RecursiveSNARK as RecursiveSNARKTrait<E1, Self::Frames>>::BaseRecursiveSNARK,
    >,
  ) -> Result<(Self::RecursiveSNARK, Vec<E1::Scalar>), ProofError> {
    let prove_output = Self::RecursiveSNARK::prove_recursively(pp, &z0, init, steps)?;

    Ok((prove_output, z0))
  }
}
