//! Default implementation of ZKVM for SuperNova and MCC circuits
//!
//! This run method runs one opcode per step in the zkVM.
pub mod public_values;
use std::{cell::RefCell, marker::PhantomData, rc::Rc, time::Instant};

use crate::{
  circuits::{
    execution::default::{
      super_nova_public_params, ExecutionProof, ExecutionProver, ExecutionPublicParams,
    },
    mcc::default::{public_params, MCCProof, MCCProver, MCCPublicParams},
    supernova::etable_rom::EtableROM,
  },
  traits::{
    prover::Prover,
    public_values::{PublicValuesTrait, ZKVMPublicParams, ZKVMPublicValues},
    snark::RecursiveSNARKTrait,
    wasm::ZKWASMContext,
    zkvm::{ZKVMBuilder, ZKVM},
  },
  utils::{nivc::build_rom, wasm::print_pretty_results},
};
use anyhow::anyhow;
use ff::Field;
use nova::traits::{
  circuit::TrivialCircuit,
  snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
  CurveCycleEquipped, Dual, Engine,
};
use public_values::{ExecutionPublicValues, MCCPublicValues, PublicValues};
use serde::{Deserialize, Serialize};
use wasmi::{etable::ETable, Tracer};

type PV<E1> = PublicValues<E1>;

/// A proof that testifies the correct execution of a WASM program
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "")]
pub struct ZKEProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  execution_proof: ExecutionProof<E1, BS1, S2>,
  mcc_proof: MCCProof<E1, S1, S2>,
}

impl<E1, BS1, S1, S2> ZKEProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  fn new(execution_proof: ExecutionProof<E1, BS1, S2>, mcc_proof: MCCProof<E1, S1, S2>) -> Self {
    Self {
      execution_proof,
      mcc_proof,
    }
  }
}

impl<E1, BS1, S1, S2> ZKVM<E1, PV<E1>> for ZKEProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd + Ord,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1> + Clone,
  S1: RelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  type PublicParams = ZKEPublicParams<E1, BS1, S1, S2>;

  fn setup(ctx: &mut impl ZKWASMContext) -> anyhow::Result<Self::PublicParams> {
    let (etable, _) = ctx.build_execution_trace()?;
    let tracer = ctx.tracer()?;

    // Build ROM and corresponding tracer values
    let (rom, tracer_values) = build_rom(&etable.plain_execution_trace());

    // Build SuperNova non-uniform circuit for WASM opcodes
    let etable_rom = EtableROM::<E1>::new(rom, tracer_values.to_vec());

    // Get SuperNova public params and prove execution
    tracing::info!("Producing public params for execution proving...");
    let execution_pp = super_nova_public_params::<_, BS1, S2>(&etable_rom)?;

    // Get memory trace (memory table)
    // Setup  MCC
    tracing::info!("Setting up MCC...");
    let tracer = tracer.borrow();
    let imtable = tracer.imtable();
    let mtable = etable.mtable(imtable);
    let primary_circuits = MCCProver::<E1, S1, S2>::mcc_inputs(mtable);

    // Get public params
    tracing::info!("Producing public params for MCC...");
    let mcc_pp =
      public_params::<_, S1, S2>(primary_circuits[0].clone(), TrivialCircuit::default())?;

    Ok(ZKEPublicParams {
      execution_pp,
      mcc_pp,
    })
  }

  fn prove_wasm(
    ctx: &mut impl ZKWASMContext,
    pp: &Self::PublicParams,
  ) -> anyhow::Result<(Self, PV<E1>, Box<[wasmi::Value]>)> {
    ZKEProofBuilder::get_trace(ctx)?
      .prove_execution(pp.execution())?
      .mcc(pp.mcc())?
      .build()
  }

  fn verify(self, public_values: PV<E1>, pp: &Self::PublicParams) -> anyhow::Result<bool> {
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
pub struct ZKEPublicParams<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  execution_pp: ExecutionPublicParams<E1, BS1, S2>,
  mcc_pp: MCCPublicParams<E1, S1, S2>,
}

impl<E1, BS1, S1, S2> ZKVMPublicParams<E1> for ZKEPublicParams<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  type ExecutionPublicParams = ExecutionPublicParams<E1, BS1, S2>;
  type MCCPublicParams = MCCPublicParams<E1, S1, S2>;

  fn execution(&self) -> &ExecutionPublicParams<E1, BS1, S2> {
    &self.execution_pp
  }

  fn mcc(&self) -> &MCCPublicParams<E1, S1, S2> {
    &self.mcc_pp
  }
}

/// A helper struct to construct a valid zkVM proof, which has a execution proof and a MCC proof.
pub struct ZKEProofBuilder<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  etable: ETable,
  tracer: Rc<RefCell<Tracer>>,
  wasm_func_res: Box<[wasmi::Value]>,
  execution_proof: Option<ExecutionProof<E1, BS1, S2>>,
  execution_public_values: Option<ExecutionPublicValues<E1>>,
  mcc_proof: Option<MCCProof<E1, S1, S2>>,
  mcc_public_values: Option<MCCPublicValues<E1>>,
}

impl<E1, BS1, S1, S2> ZKEProofBuilder<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  fn etable(&self) -> &ETable {
    &self.etable
  }
}

impl<E1, BS1, S1, S2> ZKVMBuilder<E1, PV<E1>> for ZKEProofBuilder<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd + Ord,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1> + Clone,
  S1: RelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  type ExecutionProver = ExecutionProver<E1, BS1, S2>;
  type MCCProver = MCCProver<E1, S1, S2>;
  type ZKVM = ZKEProof<E1, BS1, S1, S2>;
  type PublicParams = ZKEPublicParams<E1, BS1, S1, S2>;

  fn get_trace(ctx: &mut impl ZKWASMContext) -> anyhow::Result<Self> {
    let (etable, wasm_func_res) = ctx.build_execution_trace()?;
    print_pretty_results(&wasm_func_res);

    let tracer = ctx.tracer()?;

    Ok(Self {
      etable,
      tracer,
      execution_proof: None,
      execution_public_values: None,
      mcc_proof: None,
      mcc_public_values: None,
      wasm_func_res,
    })
  }

  fn prove_execution(mut self, pp: &ExecutionPublicParams<E1, BS1, S2>) -> anyhow::Result<Self> {
    // Get execution trace (execution table)
    let etable = self.etable();

    tracing::debug!("etable.len {}", etable.entries().len());
    // Build ROM and corresponding tracer values
    let (rom, tracer_values) = build_rom(&etable.plain_execution_trace());

    // Build SuperNova non-uniform circuit for WASM opcodes
    let etable_rom = EtableROM::<E1>::new(rom, tracer_values.to_vec());

    // Get init z for SuperNova F
    let mut z0_primary = vec![<E1 as Engine>::Scalar::ONE];
    z0_primary.push(<E1 as Engine>::Scalar::ZERO); // rom_index = 0

    // Prove execution
    let (nivc_proof, z0_primary) =
      <Self::ExecutionProver as Prover<E1>>::prove(pp, z0_primary, etable_rom, None)?;

    // Get public output
    let zi = nivc_proof.zi_primary()?;

    // Compress NIVC Proof into a zkSNARK
    let time = Instant::now();
    let compressed_proof = nivc_proof.compress(pp)?;
    tracing::info!("compressing took: {:?}", time.elapsed());

    // Set public values
    let execution_public_values = ExecutionPublicValues::new(&z0_primary, zi);
    self.execution_public_values = Some(execution_public_values);

    self.execution_proof = Some(compressed_proof.into_owned());

    Ok(self)
  }

  fn mcc(mut self, pp: &MCCPublicParams<E1, S1, S2>) -> anyhow::Result<Self> {
    tracing::info!("Proving MCC...");

    // Get memory trace (memory table)
    let tracer_binding = self.tracer.clone();
    let tracer = tracer_binding.borrow();
    let imtable = tracer.imtable();
    let mtable = self.etable().mtable(imtable);
    tracing::info!("memory trace length {}", mtable.entries().len());

    tracing::info!("Building lookup table for MCC...");
    // Setup  MCC
    let primary_circuits = Self::MCCProver::mcc_inputs(mtable);

    // Get init z for F
    let z0 = vec![];

    // Prove MCC
    let (ivc_proof, z0_primary) =
      <Self::MCCProver as Prover<E1>>::prove(pp, z0, primary_circuits, None)?;

    // Get public output
    let zi = ivc_proof.zi_primary()?;

    // Compress IVC Proof into a zkSNARK
    let time = Instant::now();
    let compressed_proof = ivc_proof.compress(pp)?;
    tracing::info!("compressing took: {:?}", time.elapsed());

    // Set public values
    let mcc_public_values = MCCPublicValues::new(&z0_primary, zi);
    self.mcc_public_values = Some(mcc_public_values);

    self.mcc_proof = Some(compressed_proof.into_owned());
    Ok(self)
  }

  fn build(self) -> anyhow::Result<(ZKEProof<E1, BS1, S1, S2>, PV<E1>, Box<[wasmi::Value]>)> {
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
    let public_values = PublicValues::new(execution_public_values, mcc_public_values);
    let proof = ZKEProof::new(execution_proof, mcc_proof);

    Ok((proof, public_values, self.wasm_func_res))
  }
}

/// Output of execution proof
type ExecutionProofOutput<E1, BS1, S1, S2> = (
  ZKEExecutionProof<E1, BS1, S1, S2>,
  ExecutionPublicValues<E1>,
);

impl<E1, BS1, S1, S2> ZKEProofBuilder<E1, BS1, S1, S2>
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
    let proof = ZKEExecutionProof::new(execution_proof);

    Ok((proof, execution_public_values))
  }
}

/// A proof that testifies the correct execution of a WASM program
pub struct ZKEExecutionProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  execution_proof: ExecutionProof<E1, BS1, S2>,
  _s1: PhantomData<S1>,
}

impl<E1, BS1, S1, S2> ZKEExecutionProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  fn new(execution_proof: ExecutionProof<E1, BS1, S2>) -> Self {
    Self {
      execution_proof,
      _s1: PhantomData,
    }
  }
}

impl<E1, BS1, S1, S2> ZKEExecutionProof<E1, BS1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd + Ord,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1> + Clone,
  S1: RelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  /// Produce public params for execution proving
  pub fn setup(ctx: &mut impl ZKWASMContext) -> anyhow::Result<ExecutionPublicParams<E1, BS1, S2>> {
    let (etable, _) = ctx.build_execution_trace()?;

    // Build ROM and corresponding tracer values
    let (rom, tracer_values) = build_rom(&etable.plain_execution_trace());

    // Build SuperNova non-uniform circuit for WASM opcodes
    let etable_rom = EtableROM::<E1>::new(rom, tracer_values.to_vec());

    // Get SuperNova public params and prove execution
    tracing::info!("Producing public params for execution proving...");
    super_nova_public_params::<_, BS1, S2>(&etable_rom)
  }

  /// Proves only the execution of a WASM program
  pub fn prove_wasm_execution(
    ctx: &mut impl ZKWASMContext,
    pp: &ExecutionPublicParams<E1, BS1, S2>,
  ) -> anyhow::Result<(Self, ExecutionPublicValues<E1>)> {
    ZKEProofBuilder::get_trace(ctx)?
      .prove_execution(pp)?
      .build_execution_proof()
  }

  /// Verifies only the execution proof from proving WASM execution
  ///
  /// Does not run memory consistency checks
  pub fn verify_wasm_execution(
    self,
    execution_public_values: ExecutionPublicValues<E1>,
    pp: &ExecutionPublicParams<E1, BS1, S2>,
  ) -> anyhow::Result<bool> {
    tracing::info!("Verifying proof...");

    // Get execution proof
    let execution_proof = self.execution_proof;

    // Verify execution proof
    let execution_verified = execution_proof.verify(
      pp,
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
    run::default::ZKEProof,
    traits::zkvm::ZKVM,
    utils::logging::init_logger,
    wasm::{args::WASMArgsBuilder, ctx::wasi::WasiWASMCtx},
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
      .file_path(PathBuf::from("wasm/example.wasm"))
      .build();
    let pp = ZKEProof::<E1, BS1, S1, S2>::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

    let mut wasm_ctx = WasiWASMCtx::new_from_file(&args)?;

    let (proof, public_values, _) = ZKEProof::<E1, BS1, S1, S2>::prove_wasm(&mut wasm_ctx, &pp)?;

    let result = proof.verify(public_values, &pp)?;
    Ok(assert!(result))
  }

  #[test]
  fn test_zk_engine() -> anyhow::Result<()> {
    init_logger();
    tracing::debug!("PallasEngine Curve Cycle");
    test_zk_engine_with::<PallasEngine, BS1<_>, S1<_>, S2<PallasEngine>>()?;
    tracing::debug!("ZKPallasEngine Curve Cycle");
    test_zk_engine_with::<ZKPallasEngine, BS1<_>, S1<_>, S2<ZKPallasEngine>>()?;
    Ok(())
  }
}
