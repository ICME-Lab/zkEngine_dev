//! This module contains the implementation of the zkVM engine for batched execution.
//!
//! Batched execution is a technique that allows the zkVM to execute multiple instructions in a
//! single step.
pub mod public_values;
use std::{cell::RefCell, rc::Rc};

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

use crate::{
  circuits::{
    execution::batched::{
      super_nova_public_params, BatchedExecutionProof, BatchedExecutionProver,
      BatchedExecutionPublicParams,
    },
    mcc::batched::{public_params, BatchedMCCProof, BatchedMCCProver, BatchedMCCPublicParams},
    supernova::batched_rom::BatchedROM,
  },
  traits::{
    be_engine::BackendEngine,
    prover::Prover,
    public_values::{PublicValuesTrait, ZKVMPublicParams, ZKVMPublicValues},
    snark::RecursiveSNARKTrait,
    wasm::ZKWASMContext,
    zkvm::{WasmSNARKTrait, ZKVMBuilder},
  },
  utils::{nivc::batch_execution_trace, wasm::print_pretty_results},
};
use anyhow::anyhow;
use ff::Field;
use nova::traits::{circuit::TrivialCircuit, Engine};
use public_values::{BatchedPublicValues, ExecutionPublicValues, MCCPublicValues};
use serde::{Deserialize, Serialize};
use wasmi::{etable::ETable, Tracer};

/// A proof that testifies the correctness of the WASM execution.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "")]
pub struct WasmSNARK<E>
where
  E: BackendEngine,
{
  pub(crate) execution_proof: BatchedExecutionProof<E::E1, E::BS1, E::S2>,
  pub(crate) mcc_proof: BatchedMCCProof<E::E1, E::S1, E::S2>,
}

impl<E> WasmSNARK<E>
where
  E: BackendEngine,
{
  fn new(
    execution_proof: BatchedExecutionProof<E::E1, E::BS1, E::S2>,
    mcc_proof: BatchedMCCProof<E::E1, E::S1, E::S2>,
  ) -> Self {
    Self {
      execution_proof,
      mcc_proof,
    }
  }
}

impl<E> WasmSNARKTrait for WasmSNARK<E>
where
  E: BackendEngine,
  <E::E1 as Engine>::Scalar: PartialOrd + Ord,
{
  type PublicParams = PublicParams<E>;
  type PublicValues = BatchedPublicValues<E::E1>;
  fn setup(ctx: &mut impl ZKWASMContext) -> anyhow::Result<Self::PublicParams> {
    // Get execution trace (execution table)
    let (etable, _) = ctx.build_execution_trace()?;
    let tracer = ctx.tracer()?;

    // Batch execution trace in batched
    let (execution_trace, rom) = batch_execution_trace(&etable)?;

    // Build large step circuits
    let batched_rom = BatchedROM::<E::E1>::new(rom, execution_trace.to_vec());

    // Get SuperNova public params and prove execution
    tracing::info!("Producing public params for execution proving...");
    let execution_pp = super_nova_public_params(&batched_rom)?;

    //Setup MCC
    tracing::info!("Setting up MCC...");
    let tracer = tracer.borrow();
    let imtable = tracer.imtable();
    let mtable = etable.mtable(imtable);

    let primary_circuits = BatchedMCCProver::<E::E1, E::S1, E::S2>::mcc_inputs(mtable)?;

    // Get public params
    tracing::info!("Producing public params for MCC...");
    let mcc_pp = public_params(primary_circuits[0].clone(), TrivialCircuit::default())?;

    Ok(PublicParams {
      execution_pp,
      mcc_pp,
    })
  }

  fn prove_wasm(
    ctx: &mut impl ZKWASMContext,
    pp: &Self::PublicParams,
  ) -> anyhow::Result<(Self, Self::PublicValues, Box<[wasmi::Value]>)> {
    WasmSNARKBuilder::get_trace(ctx)?
      .prove_execution(pp.execution())?
      .mcc(pp.mcc())?
      .build()
  }

  fn verify(
    self,
    public_values: Self::PublicValues,
    pp: &Self::PublicParams,
  ) -> anyhow::Result<bool> {
    tracing::info!("Verifying proof...");
    // Get execution and MCC proofs
    let execution_proof = self.execution_proof;
    let mcc_proof = self.mcc_proof;

    // Get execution proofs public values,
    let execution_public_values = public_values.execution();

    // Get MCC proofs public values
    let mcc_public_values = public_values.mcc();

    // Verify execution proof
    let execution_verified = execution_proof.verify(
      &pp.execution_pp,
      execution_public_values.public_inputs(),
      execution_public_values.public_outputs(),
    )?;

    // Verify MCC proof
    let mcc_verified = mcc_proof.verify(
      &pp.mcc_pp,
      mcc_public_values.public_inputs(),
      mcc_public_values.public_outputs(),
    )?;

    Ok(mcc_verified && execution_verified)
  }
}

/// Contains the public parameters needed for proving/verifying
///
/// Contains public parameters for both the execution and MCC proofs
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PublicParams<E>
where
  E: BackendEngine,
{
  pub(crate) execution_pp: BatchedExecutionPublicParams<E::E1, E::BS1, E::S2>,
  mcc_pp: BatchedMCCPublicParams<E::E1, E::S1, E::S2>,
}

impl<E> ZKVMPublicParams<E::E1> for PublicParams<E>
where
  E: BackendEngine,
{
  type ExecutionPublicParams = BatchedExecutionPublicParams<E::E1, E::BS1, E::S2>;
  type MCCPublicParams = BatchedMCCPublicParams<E::E1, E::S1, E::S2>;

  fn execution(&self) -> &BatchedExecutionPublicParams<E::E1, E::BS1, E::S2> {
    &self.execution_pp
  }

  fn mcc(&self) -> &BatchedMCCPublicParams<E::E1, E::S1, E::S2> {
    &self.mcc_pp
  }
}

/// A helper struct to construct a valid zkVM proof, which has a execution proof and a MCC proof.
pub struct WasmSNARKBuilder<E>
where
  E: BackendEngine,
{
  etable: ETable,
  tracer: Rc<RefCell<Tracer>>,
  wasm_func_results: Box<[wasmi::Value]>,
  execution_proof: Option<BatchedExecutionProof<E::E1, E::BS1, E::S2>>,
  execution_public_values: Option<ExecutionPublicValues<E::E1>>,
  mcc_proof: Option<BatchedMCCProof<E::E1, E::S1, E::S2>>,
  mcc_public_values: Option<MCCPublicValues<E::E1>>,
}

impl<E> WasmSNARKBuilder<E>
where
  E: BackendEngine,
{
  pub(crate) fn etable(&self) -> &ETable {
    &self.etable
  }
}

impl<E> ZKVMBuilder<E::E1> for WasmSNARKBuilder<E>
where
  E: BackendEngine,
  <E::E1 as Engine>::Scalar: PartialOrd + Ord,
{
  type ExecutionProver = BatchedExecutionProver<E::E1, E::BS1, E::S2>;
  type MCCProver = BatchedMCCProver<E::E1, E::S1, E::S2>;
  type ZKVM = WasmSNARK<E>;
  type PublicParams = PublicParams<E>;
  type PublicValues = BatchedPublicValues<E::E1>;

  fn get_trace(ctx: &mut impl ZKWASMContext) -> anyhow::Result<Self> {
    let (etable, wasm_func_results) = ctx.build_execution_trace()?;
    print_pretty_results(&wasm_func_results);
    Ok(Self {
      etable,
      tracer: ctx.tracer()?,
      execution_proof: None,
      execution_public_values: None,
      mcc_proof: None,
      mcc_public_values: None,
      wasm_func_results,
    })
  }

  fn prove_execution(
    mut self,
    pp: &BatchedExecutionPublicParams<E::E1, E::BS1, E::S2>,
  ) -> anyhow::Result<Self> {
    // Get execution trace (execution table)
    let etable = self.etable();

    tracing::debug!("etable.len {}", etable.entries().len());
    // Batch execution trace in batched
    let (execution_trace, rom) = batch_execution_trace(etable)?;

    // Build large step circuits
    let batched_rom = BatchedROM::<E::E1>::new(rom, execution_trace.to_vec());

    // Get init z for SuperNova F
    // Build z0
    let mut z0_primary = vec![<E::E1 as Engine>::Scalar::ONE];
    z0_primary.push(<E::E1 as Engine>::Scalar::ZERO); // rom_index = 0
    z0_primary.extend(
      batched_rom
        .rom
        .iter()
        .map(|opcode| <E::E1 as Engine>::Scalar::from(*opcode as u64)),
    );

    // Prove execution
    let (nivc_proof, z0_primary) =
      <Self::ExecutionProver as Prover<E::E1>>::prove(pp, z0_primary, batched_rom, None)?;

    // Get public output
    let zi = nivc_proof.zi_primary()?;

    // Compress NIVC Proof into a zkSNARK
    #[cfg(not(target_arch = "wasm32"))]
    let time = Instant::now();

    let compressed_proof = nivc_proof.compress(pp)?;

    #[cfg(not(target_arch = "wasm32"))]
    tracing::info!("compressing took: {:?}", time.elapsed());

    // Set public values
    let execution_public_values = ExecutionPublicValues::new(&z0_primary, zi);
    self.execution_public_values = Some(execution_public_values);

    self.execution_proof = Some(compressed_proof.into_owned());
    Ok(self)
  }

  fn mcc(mut self, pp: &BatchedMCCPublicParams<E::E1, E::S1, E::S2>) -> anyhow::Result<Self> {
    tracing::info!("Proving MCC...");

    // Get memory trace (memory table)
    let tracer_binding = self.tracer.clone();
    let tracer = tracer_binding.borrow();
    let imtable = tracer.imtable();
    let mtable = self.etable().mtable(imtable);
    tracing::info!("memory trace length {}", mtable.entries().len());

    //Setup MCC
    tracing::info!("Building lookup table for MCC...");
    let primary_circuits = Self::MCCProver::mcc_inputs(mtable)?;

    // Prove MCC
    let (ivc_proof, z0_primary) =
      <Self::MCCProver as Prover<E::E1>>::prove(pp, vec![], primary_circuits, None)?;

    // Get public output
    let zi = ivc_proof.zi_primary()?;

    // Compress IVC Proof into a zkSNARK
    #[cfg(not(target_arch = "wasm32"))]
    let time = Instant::now();

    let compressed_proof = ivc_proof.compress(pp)?;

    #[cfg(not(target_arch = "wasm32"))]
    tracing::info!("compressing took: {:?}", time.elapsed());

    // Set public values
    let mcc_public_values = MCCPublicValues::new(&z0_primary, zi);
    self.mcc_public_values = Some(mcc_public_values);

    self.mcc_proof = Some(compressed_proof.into_owned());
    Ok(self)
  }

  fn build(self) -> anyhow::Result<(WasmSNARK<E>, Self::PublicValues, Box<[wasmi::Value]>)> {
    // Validate that all proofs and public values are present
    let execution_proof = self
      .execution_proof
      .ok_or(anyhow!("Execution proof not found"))?;

    let mcc_proof = self.mcc_proof.ok_or(anyhow!("MCC proof not found"))?;

    let mcc_public_values = self
      .mcc_public_values
      .ok_or(anyhow!("MCC public values not found"))?;

    let execution_public_values = self
      .execution_public_values
      .ok_or(anyhow!("Execution public values not found"))?;

    // Return proof and public values
    let public_values = BatchedPublicValues::new(execution_public_values, mcc_public_values);
    let proof = WasmSNARK::new(execution_proof, mcc_proof);

    Ok((proof, public_values, self.wasm_func_results))
  }
}

/// Execution proof output
type ExecutionProofOutput<E> = (
  WasmExecutionSNARK<E>,
  ExecutionPublicValues<<E as BackendEngine>::E1>,
);

impl<E> WasmSNARKBuilder<E>
where
  E: BackendEngine,
{
  fn build_execution_proof(self) -> anyhow::Result<ExecutionProofOutput<E>> {
    // Validate that all proofs and public values are present
    let execution_proof = self
      .execution_proof
      .ok_or(anyhow!("Execution proof not found"))?;

    let execution_public_values = self
      .execution_public_values
      .ok_or(anyhow!("Execution public values not found"))?;

    // Return proof and public values
    let proof = WasmExecutionSNARK::new(execution_proof);

    Ok((proof, execution_public_values))
  }
}
/// A proof that testifies the correct execution of a WASM program
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "")]
pub struct WasmExecutionSNARK<E>
where
  E: BackendEngine,
{
  execution_proof: BatchedExecutionProof<E::E1, E::BS1, E::S2>,
}

impl<E> WasmExecutionSNARK<E>
where
  E: BackendEngine,
{
  fn new(execution_proof: BatchedExecutionProof<E::E1, E::BS1, E::S2>) -> Self {
    Self { execution_proof }
  }
}

impl<E> WasmExecutionSNARK<E>
where
  E: BackendEngine,
  <E::E1 as Engine>::Scalar: PartialOrd + Ord,
{
  /// Produce the Public Parameters for execution proving
  pub fn setup(
    ctx: &mut impl ZKWASMContext,
  ) -> anyhow::Result<BatchedExecutionPublicParams<E::E1, E::BS1, E::S2>> {
    // Get execution trace (execution table)
    let (etable, _) = ctx.build_execution_trace()?;

    // Batch execution trace in batched
    let (execution_trace, rom) = batch_execution_trace(&etable)?;

    // Build large step circuits
    let batched_rom = BatchedROM::<E::E1>::new(rom, execution_trace.to_vec());

    // Get SuperNova public params and prove execution
    tracing::info!("Producing public params for execution proving...");
    super_nova_public_params(&batched_rom)
  }
  /// Proves only the execution of a WASM program
  pub fn prove_wasm_execution(
    ctx: &mut impl ZKWASMContext,
    pp: &BatchedExecutionPublicParams<E::E1, E::BS1, E::S2>,
  ) -> anyhow::Result<(Self, ExecutionPublicValues<E::E1>)> {
    WasmSNARKBuilder::get_trace(ctx)?
      .prove_execution(pp)?
      .build_execution_proof()
  }

  /// Verifies only the execution proof from proving WASM execution
  ///
  /// Does not run memory consistency checks
  pub fn verify_wasm_execution(
    self,
    execution_public_values: ExecutionPublicValues<E::E1>,
    execution_pp: &BatchedExecutionPublicParams<E::E1, E::BS1, E::S2>,
  ) -> anyhow::Result<bool> {
    tracing::info!("Verifying proof...");

    // Get execution and MCC proofs
    let execution_proof = self.execution_proof;

    // Verify execution proof
    let execution_verified = execution_proof.verify(
      execution_pp,
      execution_public_values.public_inputs(),
      execution_public_values.public_outputs(),
    )?;

    Ok(execution_verified)
  }
}

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use nova::traits::Engine;

  use crate::{
    provider::E,
    run::batched::WasmSNARK,
    traits::{be_engine::BackendEngine, zkvm::WasmSNARKTrait},
    utils::logging::init_logger,
    wasm::{args::WASMArgsBuilder, ctx::wasi::WasiWASMCtx},
  };

  fn test_zk_engine_with<E>() -> anyhow::Result<()>
  where
    E: BackendEngine,
    <E::E1 as Engine>::Scalar: PartialOrd + Ord,
  {
    init_logger();

    let args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/misc/fib.wat"))
      .invoke(Some(String::from("fib")))
      .func_args(vec![String::from("1000")])
      .build();

    let pp = WasmSNARK::<E>::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

    let mut wasm_ctx = WasiWASMCtx::new_from_file(&args)?;

    let (proof, public_values, _) = WasmSNARK::<E>::prove_wasm(&mut wasm_ctx, &pp)?;

    let result = proof.verify(public_values, &pp)?;
    Ok(assert!(result))
  }

  #[test]
  fn test_zk_engine() -> anyhow::Result<()> {
    init_logger();
    tracing::debug!("Pasta Curve Cycle");
    test_zk_engine_with::<E>()?;
    Ok(())
  }
}
