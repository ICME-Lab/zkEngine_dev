//! This module holds the data structures of the public values produced by the batched zkEngine.
use nova::traits::CurveCycleEquipped;
use serde::{Deserialize, Serialize};

use crate::traits::public_values::{PublicValuesTrait, ZKVMPublicValues};

/// Public values used for proving batched MCC
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct MCCPublicValues<E1>
where
  E1: CurveCycleEquipped,
{
  public_inputs: Vec<E1::Scalar>,
  public_outputs: Vec<E1::Scalar>,
}

impl<E1> MCCPublicValues<E1>
where
  E1: CurveCycleEquipped,
{
  /// Create a new instance of MCCPublicValues
  pub fn new(public_inputs: &[E1::Scalar], public_outputs: &[E1::Scalar]) -> Self {
    Self {
      public_inputs: public_inputs.to_vec(),
      public_outputs: public_outputs.to_vec(),
    }
  }
}

impl<E1> PublicValuesTrait<E1> for MCCPublicValues<E1>
where
  E1: CurveCycleEquipped,
{
  fn public_inputs(&self) -> &[E1::Scalar] {
    &self.public_inputs
  }

  fn public_outputs(&self) -> &[E1::Scalar] {
    &self.public_outputs
  }
}

/// Public values used for batched execution proving
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct ExecutionPublicValues<E1>
where
  E1: CurveCycleEquipped,
{
  public_inputs: Vec<E1::Scalar>,
  public_outputs: Vec<E1::Scalar>,
}

impl<E1> ExecutionPublicValues<E1>
where
  E1: CurveCycleEquipped,
{
  /// Create a new instance of `ExecutionPublicValues`
  pub fn new(public_inputs: &[E1::Scalar], public_outputs: &[E1::Scalar]) -> Self {
    Self {
      public_inputs: public_inputs.to_vec(),
      public_outputs: public_outputs.to_vec(),
    }
  }
}

impl<E1> PublicValuesTrait<E1> for ExecutionPublicValues<E1>
where
  E1: CurveCycleEquipped,
{
  fn public_inputs(&self) -> &[E1::Scalar] {
    &self.public_inputs
  }

  fn public_outputs(&self) -> &[E1::Scalar] {
    &self.public_outputs
  }
}

/// Public values for the batched zkEngine
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct BatchedPublicValues<E1>
where
  E1: CurveCycleEquipped,
{
  execution: ExecutionPublicValues<E1>,
  mcc: MCCPublicValues<E1>,
}

impl<E1> BatchedPublicValues<E1>
where
  E1: CurveCycleEquipped,
{
  /// Create a new instance of `BatchedPublicValues`
  pub fn new(execution: ExecutionPublicValues<E1>, mcc: MCCPublicValues<E1>) -> Self {
    Self { execution, mcc }
  }
}

impl<E1> ZKVMPublicValues<E1> for BatchedPublicValues<E1>
where
  E1: CurveCycleEquipped,
{
  type ExecutionPublicValues = ExecutionPublicValues<E1>;
  type MCCPublicValues = MCCPublicValues<E1>;

  fn mcc(&self) -> &Self::MCCPublicValues {
    &self.mcc
  }

  fn execution(&self) -> &Self::ExecutionPublicValues {
    &self.execution
  }
}
