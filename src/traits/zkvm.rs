//! A module that defines the ZKVM trait and its builder.

use nova::traits::CurveCycleEquipped;

use super::{prover::Prover, public_values::ZKVMPublicParams, wasm::ZKWASMContext};

/// A trait that defines the behavior of a zkVM (zkWASM in our case).
pub trait ZKVM<E1: CurveCycleEquipped>
where
  Self: Sized,
{
  /// A type that represents the Public Parameters for the zkVM.
  type PublicParams;

  /// Contains the public i/o of proving system
  type PublicValues;

  /// Setup the public parameters for prover and verifier.
  fn setup(ctx: &mut impl ZKWASMContext) -> anyhow::Result<Self::PublicParams>;

  /// A method that produces a zkSNARK for the WASM, with some public values.
  ///
  /// Returns the proof, the public i/o values and the result of the invoked WASM function.
  fn prove_wasm(
    ctx: &mut impl ZKWASMContext,
    pp: &Self::PublicParams,
  ) -> anyhow::Result<(Self, Self::PublicValues, Box<[wasmi::Value]>)>;

  /// A method that verifies the zkSNARK for the WASM, with some public values.
  fn verify(
    self,
    public_values: Self::PublicValues,
    pp: &Self::PublicParams,
  ) -> anyhow::Result<bool>;
}

/// A trait to constrain the steps needed to build a zkVM proof.
pub trait ZKVMBuilder<E1>
where
  Self: Sized,
  E1: CurveCycleEquipped,
{
  /// A type that contains the public parameters for the zkVM.
  ///
  /// This is the same type as the one defined in the zkVM trait.
  type PublicParams: ZKVMPublicParams<E1>;

  /// Contains the public i/o of proving system
  type PublicValues;

  /// A type that contains the prover for the execution proof.
  type ExecutionProver: Prover<E1>;
  /// A type that contains the prover for the MCC proof.
  type MCCProver: Prover<E1>;
  /// A type that contains the zkVM proof and the public values.
  type ZKVM: ZKVM<E1, PublicParams = Self::PublicParams, PublicValues = Self::PublicValues>;

  /// A method that gets the execution trace of the WASM.
  fn get_trace(ctx: &mut impl ZKWASMContext) -> anyhow::Result<Self>;

  /// A method that proves the execution of the WASM.
  fn prove_execution(
    self,
    pp: &<Self::PublicParams as ZKVMPublicParams<E1>>::ExecutionPublicParams,
  ) -> anyhow::Result<Self>;

  /// A method that proves the MCC for the WASM.
  fn mcc(
    self,
    pp: &<Self::PublicParams as ZKVMPublicParams<E1>>::MCCPublicParams,
  ) -> anyhow::Result<Self>;

  /// A method that builds the zkVM proof.
  fn build(self) -> anyhow::Result<(Self::ZKVM, Self::PublicValues, Box<[wasmi::Value]>)>;
}
