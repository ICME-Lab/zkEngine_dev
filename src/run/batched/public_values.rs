//! This module holds the data structures of the public values produced by the batched zkEngine.
use nova::traits::{
  snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
  CurveCycleEquipped, Dual,
};
use serde::{Deserialize, Serialize};

use crate::{
  circuits::{
    execution::batched::BatchedExecutionPublicParams, mcc::batched::BatchedMCCPublicParams,
  },
  traits::public_values::{PublicValuesTrait, ZKVMPublicValues},
};

/// Public values used for proving batched MCC
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MCCPublicValues<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  mcc_pp: BatchedMCCPublicParams<E1, S1, S2>,
  public_inputs: Vec<E1::Scalar>,
  public_outputs: Vec<E1::Scalar>,
}

impl<E1, S1, S2> MCCPublicValues<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  /// Create a new instance of MCCPublicValues
  pub fn new(
    mcc_pp: BatchedMCCPublicParams<E1, S1, S2>,
    public_inputs: &[E1::Scalar],
    public_outputs: &[E1::Scalar],
  ) -> Self {
    Self {
      mcc_pp,
      public_inputs: public_inputs.to_vec(),
      public_outputs: public_outputs.to_vec(),
    }
  }
}

impl<E1, S1, S2> PublicValuesTrait<E1> for MCCPublicValues<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  type PublicParams = BatchedMCCPublicParams<E1, S1, S2>;

  fn public_params(&self) -> &Self::PublicParams {
    &self.mcc_pp
  }

  fn public_inputs(&self) -> &[E1::Scalar] {
    &self.public_inputs
  }

  fn public_outputs(&self) -> &[E1::Scalar] {
    &self.public_outputs
  }
}

/// Public values used for batched execution proving
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ExecutionPublicValues<E1, BS1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  execution_pp: BatchedExecutionPublicParams<E1, BS1, S2>,
  public_inputs: Vec<E1::Scalar>,
  public_outputs: Vec<E1::Scalar>,
}

impl<E1, BS1, S2> ExecutionPublicValues<E1, BS1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  /// Create a new instance of `ExecutionPublicValues`
  pub fn new(
    execution_pp: BatchedExecutionPublicParams<E1, BS1, S2>,
    public_inputs: &[E1::Scalar],
    public_outputs: &[E1::Scalar],
  ) -> Self {
    Self {
      execution_pp,
      public_inputs: public_inputs.to_vec(),
      public_outputs: public_outputs.to_vec(),
    }
  }
}

impl<E1, BS1, S2> PublicValuesTrait<E1> for ExecutionPublicValues<E1, BS1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  type PublicParams = BatchedExecutionPublicParams<E1, BS1, S2>;

  fn public_params(&self) -> &Self::PublicParams {
    &self.execution_pp
  }

  fn public_inputs(&self) -> &[E1::Scalar] {
    &self.public_inputs
  }

  fn public_outputs(&self) -> &[E1::Scalar] {
    &self.public_outputs
  }
}

/// Public values for the batched zkEngine
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BatchedPublicValues<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  execution: ExecutionPublicValues<E1, BS1, S2>,
  mcc: MCCPublicValues<E1, S1, S2>,
}

impl<E1, BS1, S1, S2> BatchedPublicValues<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  /// Create a new instance of `BatchedPublicValues`
  pub fn new(
    execution: ExecutionPublicValues<E1, BS1, S2>,
    mcc: MCCPublicValues<E1, S1, S2>,
  ) -> Self {
    Self { execution, mcc }
  }

  /// Get the hash of Public Parameters for execution proving
  pub fn digest(&self) -> E1::Scalar {
    self.execution.execution_pp.digest()
  }
}

impl<E1, BS1, S1, S2> ZKVMPublicValues<E1> for BatchedPublicValues<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  type ExecutionPublicParams = BatchedExecutionPublicParams<E1, BS1, S2>;
  type ExecutionPublicValues = ExecutionPublicValues<E1, BS1, S2>;
  type MCCPublicParams = BatchedMCCPublicParams<E1, S1, S2>;
  type MCCPublicValues = MCCPublicValues<E1, S1, S2>;

  fn mcc(&self) -> &Self::MCCPublicValues {
    &self.mcc
  }

  fn execution(&self) -> &Self::ExecutionPublicValues {
    &self.execution
  }
}
