#![allow(clippy::upper_case_acronyms)]
//! Implements a "lite prover"
use std::sync::Arc;

use crate::{
  circuits::supernova::batched_rom::BatchedROM, traits::wasm::ZKWASMContext,
  utils::nivc::batch_execution_trace,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem};
use ff::Field;
use itertools::Itertools;
use nova::{
  bellpepper::{
    r1cs::{NovaShape, NovaWitness},
    shape_cs::ShapeCS,
    solver::SatisfyingAssignment,
  },
  provider::{pedersen::CommitmentKey, PallasEngine},
  r1cs::{
    commitment_key_size, CommitmentKeyHint, R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness,
  },
  spartan::{
    self,
    tiny_batched_ppsnark::{ProverKey, VerifierKey},
  },
  supernova::{NonUniformCircuit, StepCircuit},
  traits::{commitment::CommitmentEngineTrait, snark::BatchedRelaxedR1CSSNARKTrait, Engine},
};
use serde::{Deserialize, Serialize};

type E = PallasEngine;
type SNARK = spartan::tiny_batched_ppsnark::BatchedRelaxedR1CSSNARK<E>;

/// Verifier key for the non-uniform circuits
pub struct VK {
  vk: VerifierKey<E>,
}

type PublicValues = (
  ProverKey<E>, // pk
  VK,           // vk
  PublicParams, // pp
);

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A lite prover for non-uniform circuits
pub struct LiteProver {
  snark: NonUniformSNARK,
}

impl LiteProver {
  /// Setup the non-uniform circuits
  pub fn setup(ctx: &mut impl ZKWASMContext) -> anyhow::Result<PublicValues> {
    // Get execution trace (execution table)
    let (etable, _) = ctx.build_execution_trace()?;

    // Batch execution trace in batched
    let (execution_trace, rom) = batch_execution_trace(&etable)?;

    // Build large step circuits
    let batched_rom = BatchedROM::<E>::new(rom, execution_trace.to_vec());
    NonUniformSNARK::setup(batched_rom)
  }

  /// Prove the non-uniform circuits
  pub fn prove(
    ctx: &mut impl ZKWASMContext,
    pp: &PublicParams,
    pk: &ProverKey<E>,
  ) -> anyhow::Result<Self> {
    // Get execution trace (execution table)
    let (etable, _) = ctx.build_execution_trace()?;

    // Batch execution trace in batched
    let (execution_trace, rom) = batch_execution_trace(&etable)?;

    // Build large step circuits
    let batched_rom = BatchedROM::<E>::new(rom, execution_trace.to_vec());
    let snark = NonUniformSNARK::prove(pk, pp, batched_rom)?;

    Ok(Self { snark })
  }

  /// Verify the correct execution of the non-uniform circuits used in WASM proving
  pub fn verify(&self, vk: &VK) -> anyhow::Result<()> {
    self.snark.verify(&vk.vk)
  }
}

/// Public parameters for the non-uniform circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicParams {
  ck: CommitmentKey<E>,
  r1cs_shapes: Vec<R1CSShape<E>>,
}

/// Non-uniform SNARK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonUniformSNARK {
  inner_snark: SNARK,
  instance: Vec<RelaxedR1CSInstance<E>>,
}

impl NonUniformSNARK {
  fn setup(batched_rom: BatchedROM<E>) -> anyhow::Result<PublicValues> {
    let circuit_shapes: Vec<R1CSShape<E>> = (0..batched_rom.num_circuits())
      .map(|circuit_index| {
        let mut cs: ShapeCS<E> = ShapeCS::new();
        let one =
          AllocatedNum::alloc_infallible(cs.namespace(|| "one"), || <E as Engine>::Scalar::ONE);
        let _ = batched_rom
          .primary_circuit(circuit_index)
          .synthesize(
            &mut cs,
            Some(&one.clone()),
            &vec![one.clone(); batched_rom.num_circuits()],
          )
          .expect("failed to synthesize");

        cs.r1cs_shape()
      })
      .collect();

    let ck = compute_ck_primary(&circuit_shapes, &*SNARK::ck_floor());

    let (pk, vk) = SNARK::setup(Arc::new(ck.clone()), circuit_shapes.iter().collect())
      .expect("failed to setup PP SNARK");

    let pp = PublicParams {
      ck,
      r1cs_shapes: circuit_shapes,
    };

    let vk = VK { vk };
    Ok((pk, vk, pp))
  }

  fn prove(
    pk: &ProverKey<E>,
    pp: &PublicParams,
    batched_rom: BatchedROM<E>,
  ) -> anyhow::Result<Self> {
    // Get circuit instance's and witnesses
    let mut U: Vec<RelaxedR1CSInstance<E>> = Vec::new();
    let mut W: Vec<RelaxedR1CSWitness<E>> = Vec::new();
    for (circuit_index, shape) in (0..batched_rom.num_circuits()).zip_eq(pp.r1cs_shapes.iter()) {
      let mut cs = SatisfyingAssignment::<E>::new();

      let one =
        AllocatedNum::alloc_infallible(cs.namespace(|| "zero"), || <E as Engine>::Scalar::ONE);
      let _ = batched_rom
        .primary_circuit(circuit_index)
        .synthesize(
          &mut cs,
          Some(&one.clone()),
          &vec![one.clone(); batched_rom.num_circuits()],
        )
        .expect("failed to synthesize");

      let (U_i, W_i) = cs
        .r1cs_instance_and_witness(shape, &pp.ck)
        .expect("failed to synthesize circuit");

      U.push(RelaxedR1CSInstance::from_r1cs_instance(&pp.ck, shape, U_i));
      W.push(RelaxedR1CSWitness::from_r1cs_witness(shape, W_i));
    }

    let S = pp.r1cs_shapes.iter().collect();
    let proof = SNARK::prove(&pp.ck, pk, S, &U, &W)?;
    Ok(Self {
      inner_snark: proof,
      instance: U,
    })
  }

  /// verify the SNARK
  pub fn verify(&self, vk: &VerifierKey<E>) -> anyhow::Result<()> {
    self.inner_snark.verify(vk, &self.instance)?;
    Ok(())
  }
}

/// Compute primary and secondary commitment keys sized to handle the largest of the circuits in the
/// provided `R1CSWithArity`.
fn compute_ck_primary(
  circuit_shapes: &[R1CSShape<E>],
  ck_hint1: &CommitmentKeyHint<E>,
) -> CommitmentKey<E> {
  let size_primary = circuit_shapes
    .iter()
    .map(|shape| commitment_key_size(shape, ck_hint1))
    .max()
    .unwrap();

  <E as Engine>::CE::setup(b"ck", size_primary)
}

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use crate::{
    utils::{logging::init_logger, save::save_string},
    wasm::{args::WASMArgsBuilder, ctx::wasi::WasiWASMCtx},
  };

  use super::LiteProver;

  #[test]
  fn test_lite_prover() -> anyhow::Result<()> {
    init_logger();
    let x = "1";
    let size = "10";

    let args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/misc/uni-poly-eval.wasm"))
      .invoke(Some(String::from("eval")))
      .func_args(vec![String::from(x), String::from(size)])
      .build();

    tracing::info!("running setup");
    let (pk, vk, pp) = LiteProver::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

    let mut wasm_ctx = WasiWASMCtx::new_from_file(&args)?;

    tracing::info!("running prover");
    let proof = LiteProver::prove(&mut wasm_ctx, &pp, &pk)?;

    tracing::info!("running verifier");
    proof.verify(&vk)?;
    Ok(())
  }

  #[test]
  fn test_lite_prover_serde() -> anyhow::Result<()> {
    init_logger();
    let x = "1";
    let size = "10";

    let args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/misc/uni-poly-eval.wasm"))
      .invoke(Some(String::from("eval")))
      .func_args(vec![String::from(x), String::from(size)])
      .build();

    tracing::info!("running setup");
    let (pk, vk, pp) = LiteProver::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

    let mut wasm_ctx = WasiWASMCtx::new_from_file(&args)?;

    tracing::info!("running prover");
    let proof = LiteProver::prove(&mut wasm_ctx, &pp, &pk)?;

    let vk_str = serde_json::to_string(&vk)?;
    save_string(vk_str.clone(), "vk.json")?;
    let vk: super::VK = serde_json::from_str(&vk_str)?;

    tracing::info!("running verifier");
    proof.verify(&vk)?;
    Ok(())
  }
}
