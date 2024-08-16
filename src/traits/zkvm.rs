//! A module that defines the ZKVM trait and its builder.

use nova::traits::CurveCycleEquipped;
use wasmi_wasi::WasiCtx;

use super::{args::ZKWASMContext, prover::Prover, public_values::ZKVMPublicValues};

/// A trait that defines the behavior of a zkVM (zkWASM in our case).
pub trait ZKVM<E1: CurveCycleEquipped, PV: ZKVMPublicValues<E1>>
where
  Self: Sized,
{
  /// Setup the public parameters for prover and verifier.
  fn setup(ctx: &mut impl ZKWASMContext<WasiCtx>) -> anyhow::Result<()>;

  /// A method that produces a zkSNARK for the WASM, with some public values.
  fn prove_wasm(
    ctx: &mut impl ZKWASMContext<WasiCtx>,
  ) -> anyhow::Result<(Self, PV, Box<[wasmi::Value]>)>;

  /// A method that verifies the zkSNARK for the WASM, with some public values.
  fn verify(self, public_values: PV) -> anyhow::Result<bool>;
}

/// A trait to constrain the steps needed to build a zkVM proof.
pub trait ZKVMBuilder<E1, PV>
where
  Self: Sized,
  E1: CurveCycleEquipped,
  PV: ZKVMPublicValues<E1>,
{
  /// A type that contains the prover for the execution proof.
  type ExecutionProver: Prover<E1>;
  /// A type that contains the prover for the MCC proof.
  type MCCProver: Prover<E1>;
  /// A type that contains the zkVM proof and the public values.
  type ZKVM: ZKVM<E1, PV>;

  /// A method that gets the execution trace of the WASM.
  fn get_trace(ctx: &mut impl ZKWASMContext<WasiCtx>) -> anyhow::Result<Self>;

  /// A method that proves the execution of the WASM.
  fn prove_execution(self) -> anyhow::Result<Self>;

  /// A method that proves the MCC for the WASM.
  fn mcc(self) -> anyhow::Result<Self>;

  /// A method that builds the zkVM proof.
  fn build(self) -> anyhow::Result<(Self::ZKVM, PV, Box<[wasmi::Value]>)>;
}
