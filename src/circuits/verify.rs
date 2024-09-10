//! This module contains the circuit to verify proofs/receipts

use std::{marker::PhantomData};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField};

use nova::{
  provider, spartan,
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::RelaxedR1CSSNARKTrait,
    Dual, Engine,
  },
  CompressedSNARK, PublicParams, RecursiveSNARK,
};

use crate::pcd::receipt::Receipt;

use super::supernova::helpers::string_to_u128;

// TODO: Implement SuperNova verifier circuit
type EE<E> = provider::ipa_pc::EvaluationEngine<E>;
type S<E, EE> = spartan::snark::RelaxedR1CSSNARK<E, EE>;

type E1 = provider::PallasEngine;
type E2 = Dual<E1>;
type EE1 = EE<E1>;
type EE2 = EE<E2>;
type S1 = S<E1, EE1>;
type S2 = S<E2, EE2>;

/// Circuit to verify receipts for valid execution (proofs)
///
/// Circuit enforces that the system state input of the current receipt is equal to the system state
/// output of the previous receipt.
#[derive(Clone)]
struct ReceiptVerifyCircuit<F: PrimeField> {
  receipts: Vec<Receipt>,
  _p: PhantomData<F>,
}

impl<F: PrimeField> ReceiptVerifyCircuit<F> {
  pub fn new(receipts: &[Receipt]) -> Self {
    Self {
      receipts: receipts.to_owned(),
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for ReceiptVerifyCircuit<F> {
  fn get_counter_type(&self) -> nova::StepCounterType {
    nova::StepCounterType::Incremental
  }

  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    // enforce that the system state input of the current receipt is equal to the system state
    // output
    for i in 1..self.receipts.len() {
      // Allocate the system state input and output of the current and previous receipts
      let curr_input =
        AllocatedNum::alloc(cs.namespace(|| format!("{} input imageID", i)), || {
          let str_curr_input = self.receipts[i].system_state_input().as_string();

          // Truncating ImageID to 128 bits should be okay for collision resistance
          let curr_input = string_to_u128(str_curr_input);
          Ok(F::from_u128(curr_input))
        })?;

      let prev_output =
        AllocatedNum::alloc(cs.namespace(|| format!("{} -1 output imageID", i)), || {
          let str_prev_output = self.receipts[i - 1].system_state_output().as_string();

          // Truncating ImageID to 128 bits should be okay for collision resistance
          let prev_output = string_to_u128(str_prev_output);
          Ok(F::from_u128(prev_output))
        })?;

      cs.enforce(
        || "curr_input == prev_output",
        |lc| lc + curr_input.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + prev_output.get_variable(),
      );
    }
    Ok(z.to_owned())
  }
}

/// Produces a compressed SNARK that proves receipts are valid
pub fn verify_receipts(receipts: &[Receipt]) -> anyhow::Result<String> {
  let circuit_steps = 1;
  let circuit_primary = ReceiptVerifyCircuit::<<E1 as Engine>::Scalar>::new(receipts);
  let circuit_secondary = TrivialCircuit::default();

  // produce public parameters
  //let start = Instant::now();
  tracing::info!("Producing public parameters...");
  let pp = PublicParams::<E1>::setup(
    &circuit_primary,
    &circuit_secondary,
    &*S1::ck_floor(),
    &*S2::ck_floor(),
  )?;
  //tracing::info!("PublicParams::setup, took {:?} ", start.elapsed());

  // Prove sole circuit-step
  let mut recursive_snark: RecursiveSNARK<E1> = RecursiveSNARK::<E1>::new(
    &pp,
    &circuit_primary,
    &circuit_secondary,
    &[<E1 as Engine>::Scalar::zero()],
    &[<E2 as Engine>::Scalar::zero()],
  )?;
  recursive_snark.prove_step(&pp, &circuit_primary, &circuit_secondary)?;

  // verify the recursive SNARK
  tracing::info!("Verifying a RecursiveSNARK...");
  let res = recursive_snark.verify(
    &pp,
    circuit_steps,
    &[<E1 as Engine>::Scalar::ZERO],
    &[<E2 as Engine>::Scalar::ZERO],
  )?;

  // produce a compressed SNARK
  tracing::info!("Generating a CompressedSNARK");
  let (pk, vk) = CompressedSNARK::<_, S1, S2>::setup(&pp)?;

  //let start = Instant::now();

  let compressed_snark = CompressedSNARK::<_, S1, S2>::prove(&pp, &pk, &recursive_snark)?;
  //tracing::info!("CompressedSNARK::prove took {:?}", start.elapsed());

  // verify the compressed SNARK
  compressed_snark.verify(&vk, circuit_steps, &res.0, &res.1)?;

  Ok(serde_json::to_string(&compressed_snark)?) // return the compressed SNARK
}
