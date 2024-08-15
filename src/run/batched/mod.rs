//! This module contains the implementation of the zkVM engine for batched execution.
//!
//! Batched execution is a technique that allows the zkVM to execute multiple instructions in a
//! single step.
pub mod public_values;
use std::{cell::RefCell, marker::PhantomData, rc::Rc, time::Instant};

use public_values::ExecutionPublicValues;
use serde::{Deserialize, Serialize};

use crate::{
  circuits::{
    execution::batched::{super_nova_public_params, BatchedExecutionProof, BatchedExecutionProver},
    mcc::batched::{public_params, BatchedMCCProof, BatchedMCCProver},
    supernova::batched_rom::BatchedROM,
  },
  traits::{
    args::ZKWASMContext,
    prover::Prover,
    public_values::{PublicValuesTrait, ZKVMPublicValues},
    snark::RecursiveSNARKTrait,
    zkvm::{ZKVMBuilder, ZKVM},
  },
  utils::nivc::batch_execution_trace,
};
use anyhow::anyhow;
use ff::Field;
use nova::traits::{
  circuit::TrivialCircuit,
  snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
  CurveCycleEquipped, Dual, Engine,
};
use public_values::{BatchedPublicValues, MCCPublicValues};
use wasmi::{etable::ETable, Tracer};
use wasmi_wasi::WasiCtx;

/// Type alias for public values produced by the proving system
type PV<E1, BS1, S1, S2> = BatchedPublicValues<E1, BS1, S1, S2>;

/// Execution proof output
type ExecutionProofOutput<E1, BS1, S1, S2> = (
  BatchedZKEExecutionProof<E1, BS1, S1, S2>,
  ExecutionPublicValues<E1, BS1, S2>,
);

/// A helper struct to construct a valid zkVM proof, which has a execution proof and a MCC proof.
pub struct BatchedZKEProofBuilder<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  etable: ETable,
  tracer: Rc<RefCell<Tracer>>,
  execution_proof: Option<BatchedExecutionProof<E1, BS1, S2>>,
  execution_public_values: Option<ExecutionPublicValues<E1, BS1, S2>>,
  mcc_proof: Option<BatchedMCCProof<E1, S1, S2>>,
  mcc_public_values: Option<MCCPublicValues<E1, S1, S2>>,
  wasm_func_results: Box<[wasmi::Value]>,
}

impl<E1, BS1, S1, S2> BatchedZKEProofBuilder<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  pub(crate) fn etable(&self) -> &ETable {
    &self.etable
  }
}

impl<E1, BS1, S1, S2> ZKVMBuilder<E1, PV<E1, BS1, S1, S2>>
  for BatchedZKEProofBuilder<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd + Ord,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1> + Clone,
  S1: RelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  type ExecutionProver = BatchedExecutionProver<E1, BS1, S2>;
  type MCCProver = BatchedMCCProver<E1, S1, S2>;
  type ZKVM = BatchedZKEProof<E1, BS1, S1, S2>;

  fn get_trace(ctx: &mut impl ZKWASMContext<WasiCtx>) -> anyhow::Result<Self> {
    let (etable, func_res) = ctx.build_execution_trace()?;
    Ok(Self {
      etable,
      tracer: ctx.tracer()?,
      execution_proof: None,
      execution_public_values: None,
      mcc_proof: None,
      mcc_public_values: None,
      wasm_func_results: func_res,
    })
  }

  fn prove_execution(mut self) -> anyhow::Result<Self> {
    // Get execution trace (execution table)
    let etable = self.etable();

    tracing::debug!("etable.len {}", etable.entries().len());
    // Batch execution trace in batched
    let (execution_trace, rom) = batch_execution_trace(etable)?;

    // Build large step circuits
    let batched_rom = BatchedROM::<E1>::new(rom, execution_trace.to_vec());

    // Get SuperNova public params and prove execution
    let pp = super_nova_public_params(&batched_rom)?;

    // Get init z for SuperNova F
    // Build z0
    let mut z0_primary = vec![<E1 as Engine>::Scalar::ONE];
    z0_primary.push(<E1 as Engine>::Scalar::ZERO); // rom_index = 0
    z0_primary.extend(
      batched_rom
        .rom
        .iter()
        .map(|opcode| <E1 as Engine>::Scalar::from(*opcode as u64)),
    );

    // Prove execution
    let (nivc_proof, z0_primary) =
      <Self::ExecutionProver as Prover<E1>>::prove(&pp, z0_primary, batched_rom, None)?;

    // Get public output
    let zi = nivc_proof.zi_primary()?;

    // Compress NIVC Proof into a zkSNARK
    let time = Instant::now();
    let compressed_proof = nivc_proof.compress(&pp)?;
    tracing::info!("compressing took: {:?}", time.elapsed());

    // Set public values
    let execution_public_values = ExecutionPublicValues::new(pp, &z0_primary, zi);
    self.execution_public_values = Some(execution_public_values);

    self.execution_proof = Some(compressed_proof.into_owned());
    Ok(self)
  }

  fn mcc(mut self) -> anyhow::Result<Self> {
    tracing::info!("Proving MCC...");

    // Get memory trace (memory table)
    let tracer_binding = self.tracer.clone();
    let tracer = tracer_binding.borrow();
    let imtable = tracer.imtable();
    let mtable = self.etable().mtable(imtable);
    tracing::info!("memory trace length {}", mtable.entries().len());

    //Setup MCC
    tracing::info!("Building lookup table for MCC...");
    let (circuit_primaries, _, _) = Self::MCCProver::mcc_inputs(mtable)?;

    // Get public params
    let pp = public_params(circuit_primaries[0].clone(), TrivialCircuit::default())?;

    // Prove MCC
    let (ivc_proof, z0_primary) =
      <Self::MCCProver as Prover<E1>>::prove(&pp, vec![], circuit_primaries, None)?;

    // Get public output
    let zi = ivc_proof.zi_primary()?;

    // Compress IVC Proof into a zkSNARK
    let time = Instant::now();
    let compressed_proof = ivc_proof.compress(&pp)?;
    tracing::info!("compressing took: {:?}", time.elapsed());

    // Set public values
    let mcc_public_values = MCCPublicValues::new(pp, &z0_primary, zi);
    self.mcc_public_values = Some(mcc_public_values);

    self.mcc_proof = Some(compressed_proof.into_owned());
    Ok(self)
  }

  fn build(
    self,
  ) -> anyhow::Result<(
    BatchedZKEProof<E1, BS1, S1, S2>,
    PV<E1, BS1, S1, S2>,
    Box<[wasmi::Value]>,
  )> {
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
    let proof = BatchedZKEProof::new(execution_proof, mcc_proof);

    Ok((proof, public_values, self.wasm_func_results))
  }
}

/// A proof that testifies the correctness of the WASM execution.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "")]
pub struct BatchedZKEProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  execution_proof: BatchedExecutionProof<E1, BS1, S2>,
  mcc_proof: BatchedMCCProof<E1, S1, S2>,
}

impl<E1, BS1, S1, S2> BatchedZKEProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  fn new(
    execution_proof: BatchedExecutionProof<E1, BS1, S2>,
    mcc_proof: BatchedMCCProof<E1, S1, S2>,
  ) -> Self {
    Self {
      execution_proof,
      mcc_proof,
    }
  }
}

impl<E1, BS1, S1, S2> ZKVM<E1, PV<E1, BS1, S1, S2>> for BatchedZKEProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd + Ord,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1> + Clone,
  S1: RelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  fn prove_wasm(
    ctx: &mut impl ZKWASMContext<WasiCtx>,
  ) -> anyhow::Result<(Self, PV<E1, BS1, S1, S2>, Box<[wasmi::Value]>)> {
    BatchedZKEProofBuilder::get_trace(ctx)?
      .prove_execution()?
      .mcc()?
      .build()
  }

  fn verify(self, public_values: PV<E1, BS1, S1, S2>) -> anyhow::Result<bool> {
    tracing::info!("Verifying proof...");
    // Get execution and MCC proofs
    let execution_proof = self.execution_proof;
    let mcc_proof = self.mcc_proof;

    // Get execution proofs public values,
    let execution_public_values = public_values.execution();
    let execution_pp = execution_public_values.public_params();

    // Get MCC proofs public values
    let mcc_public_values = public_values.mcc();
    let mcc_pp = mcc_public_values.public_params();

    // Verify execution proof
    let execution_verified = execution_proof.verify(
      execution_pp,
      execution_public_values.public_inputs(),
      execution_public_values.public_outputs(),
    )?;

    // Verify MCC proof
    let mcc_verified = mcc_proof.verify(
      mcc_pp,
      mcc_public_values.public_inputs(),
      mcc_public_values.public_outputs(),
    )?;

    Ok(mcc_verified && execution_verified)
  }
}

impl<E1, BS1, S1, S2> BatchedZKEProofBuilder<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  fn build_execution_proof(self) -> anyhow::Result<ExecutionProofOutput<E1, BS1, S1, S2>> {
    // Validate that all proofs and public values are present
    let execution_proof = self
      .execution_proof
      .ok_or(anyhow!("Execution proof not found"))?;

    let execution_public_values = self
      .execution_public_values
      .ok_or(anyhow!("Execution public values not found"))?;

    // Return proof and public values
    let proof = BatchedZKEExecutionProof::new(execution_proof);

    Ok((proof, execution_public_values))
  }
}
/// A proof that testifies the correct execution of a WASM program
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "")]
pub struct BatchedZKEExecutionProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  execution_proof: BatchedExecutionProof<E1, BS1, S2>,
  _s1: PhantomData<S1>,
}

impl<E1, BS1, S1, S2> BatchedZKEExecutionProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  fn new(execution_proof: BatchedExecutionProof<E1, BS1, S2>) -> Self {
    Self {
      execution_proof,
      _s1: PhantomData,
    }
  }
}

impl<E1, BS1, S1, S2> BatchedZKEExecutionProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd + Ord,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1> + Clone,
  S1: RelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  /// Proves only the execution of a WASM program
  pub fn prove_wasm_execution(
    ctx: &mut impl ZKWASMContext<WasiCtx>,
  ) -> anyhow::Result<(Self, ExecutionPublicValues<E1, BS1, S2>)> {
    BatchedZKEProofBuilder::get_trace(ctx)?
      .prove_execution()?
      .build_execution_proof()
  }

  /// Verifies only the execution proof from proving WASM execution
  ///
  /// Does not run memory consistency checks
  pub fn verify_wasm_execution(
    self,
    execution_public_values: ExecutionPublicValues<E1, BS1, S2>,
  ) -> anyhow::Result<bool> {
    tracing::info!("Verifying proof...");

    // Get execution and MCC proofs
    let execution_proof = self.execution_proof;

    // Get execution proofs public values,
    let execution_pp = execution_public_values.public_params();

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

  use nova::{
    provider::{ipa_pc, PallasEngine, ZKPallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::{
      snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
      CurveCycleEquipped, Dual, Engine,
    },
  };

  use crate::{
    args::{WASMArgsBuilder, WASMCtx},
    run::batched::BatchedZKEProof,
    traits::zkvm::ZKVM,
    utils::logging::init_logger,
  };

  type EE1<E> = ipa_pc::EvaluationEngine<E>;
  type EE2<E> = ipa_pc::EvaluationEngine<Dual<E>>;

  type BS1<E> = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1<E>>;
  type S1<E> = RelaxedR1CSSNARK<E, EE1<E>>;
  type S2<E> = RelaxedR1CSSNARK<Dual<E>, EE2<E>>;

  fn test_zk_engine_with<E1, BS1, S1, S2>() -> anyhow::Result<()>
  where
    E1: CurveCycleEquipped,
    <E1 as Engine>::Scalar: PartialOrd + Ord,
    BS1: BatchedRelaxedR1CSSNARKTrait<E1> + Clone,
    S1: RelaxedR1CSSNARKTrait<E1> + Clone,
    S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
  {
    init_logger();

    let args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/misc/fib.wat"))
      .invoke(Some(String::from("fib")))
      .func_args(vec![String::from("1000")])
      .build();

    let mut wasm_ctx = WASMCtx::new_from_file(args)?;

    let (proof, public_values, _) = BatchedZKEProof::<E1, BS1, S1, S2>::prove_wasm(&mut wasm_ctx)?;
    let result = proof.verify(public_values)?;
    assert!(result);
    Ok(())
  }

  #[test]
  fn test_zk_engine() -> anyhow::Result<()> {
    init_logger();
    tracing::trace!("PallasEngine Curve Cycle");
    test_zk_engine_with::<PallasEngine, BS1<_>, S1<_>, S2<PallasEngine>>()?;
    tracing::trace!("ZKPallasEngine Curve Cycle");
    test_zk_engine_with::<ZKPallasEngine, BS1<_>, S1<_>, S2<ZKPallasEngine>>()?;
    Ok(())
  }
}
