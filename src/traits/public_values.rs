//! Contains the required methods needed from the public values for the ZKVM proving with
//! (Super)Nova.
use nova::traits::CurveCycleEquipped;

/// Define public values for a (Super)Nova proving system.
pub trait PublicValuesTrait<E1: CurveCycleEquipped> {
  /// (Super)Nova public parameters
  type PublicParams;

  /// Getter for the public parameters
  fn public_params(&self) -> &Self::PublicParams;

  /// Getter for the public inputs of the proving system (z0)
  fn public_inputs(&self) -> &[E1::Scalar];

  /// Getter for the public outputs of the proving system (zi)
  fn public_outputs(&self) -> &[E1::Scalar];
}

/// Define public values for a ZKVM proving system.
pub trait ZKVMPublicValues<E1: CurveCycleEquipped> {
  /// Nova type public parameters for MCC
  type MCCPublicParams;

  /// SuperNova type public parameters for execution proving
  type ExecutionPublicParams;

  /// Public values for MCC
  type MCCPublicValues: PublicValuesTrait<E1, PublicParams = Self::MCCPublicParams>;

  /// Public values for execution proving
  type ExecutionPublicValues: PublicValuesTrait<E1, PublicParams = Self::ExecutionPublicParams>;

  /// Getter for the public values of MCC
  fn mcc(&self) -> &Self::MCCPublicValues;

  /// Getter for the public values of execution proving
  fn execution(&self) -> &Self::ExecutionPublicValues;
}
