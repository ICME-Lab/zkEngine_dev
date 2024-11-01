//! Implements SNARK proving the WASM module computation
use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField};
use gadgets::wasm::{alu, imm_const_opc, parse_J};
use itertools::Itertools;
use mcc::{
  multiset_ops::{avt_tuple_to_scalar_vec, step_RS_WS},
  OpsCircuit, ScanCircuit,
};
use nova::{
  nebula::rs::{PublicParams, RecursiveSNARK, StepCircuit},
  traits::{snark::default_ck_hint, CurveCycleEquipped, TranscriptEngineTrait},
};
use wasmi::{Instruction, Tracer, WitnessVM};

use crate::{
  v1::utils::tracing::{execute_wasm, unwrap_rc_refcell},
  wasm::args::WASMArgs,
};

use super::error::ZKWASMError;

mod gadgets;
mod mcc;

/// A SNARK that proves the correct execution of a WASM modules execution
pub struct WasmSNARK<E>
where
  E: CurveCycleEquipped,
{
  _p: PhantomData<E>,
}

impl<E> WasmSNARK<E>
where
  E: CurveCycleEquipped,
{
  /// Fn used to obtain setup material for producing succinct arguments for
  /// WASM program executions
  pub fn setup() -> PublicParams<E> {
    PublicParams::<E>::setup(
      &WASMTransitionCircuit::default(),
      &*default_ck_hint(),
      &*default_ck_hint(),
    )
  }

  /// Produce a SNARK for WASM program input
  pub fn prove(pp: &PublicParams<E>, program: &WASMArgs) -> Result<RecursiveSNARK<E>, ZKWASMError> {
    // Execute WASM module and build execution trace documenting vm state at
    // each step
    let tracer = Rc::new(RefCell::new(Tracer::new()));
    let _ = execute_wasm(program, tracer.clone())?;
    let tracer = unwrap_rc_refcell(tracer);
    let max_sp = tracer.max_sp();
    let execution_trace = tracer.into_execution_trace();

    /*
     * Get MCC values:
     */

    // We maintain a timestamp counter `globa_ts` that is initialized to
    // the highest timestamp value in IS.
    let mut global_ts = 0;

    // Compute multisets to perform grand product checks (uses global_ts)
    let IS = vec![(0, 0); max_sp];
    let mut RS: Vec<(usize, u64, u64)> = Vec::new();
    let mut WS: Vec<(usize, u64, u64)> = Vec::new();
    let mut FS = vec![(0, 0); max_sp];

    // Build the WASMTransitionCircuit from each traced execution frame.
    let circuits: Vec<WASMTransitionCircuit> = execution_trace
      .into_iter()
      .map(|vm| {
        let (step_rs, step_ws) = step_RS_WS(&vm, &mut FS, &mut global_ts);
        RS.extend(step_rs.clone());
        WS.extend(step_ws.clone());

        WASMTransitionCircuit {
          vm,
          RS: step_rs,
          WS: step_ws,
        }
      })
      .collect();

    // Inputs to CC-IVC for F
    let mut rs_option: Option<RecursiveSNARK<E>> = None;
    let z0 = vec![E::Scalar::ZERO];
    let mut IC_i = E::Scalar::ZERO;

    // F represents the transition function of the WASM (stack-based) VM.
    // commitment-carrying IVC to prove the repeated execution of F
    for circuit in circuits.iter() {
      let mut rs = rs_option.unwrap_or_else(|| {
        RecursiveSNARK::new(pp, circuit, &z0).expect("failed to construct initial recursive SNARK")
      });

      rs.prove_step(pp, circuit, IC_i)?;
      IC_i = rs.increment_commitment(pp, circuit);

      rs_option = Some(rs)
    }

    // Do an internal check on the final recursive SNARK
    debug_assert!(rs_option.is_some());
    let rs = rs_option.ok_or(ZKWASMError::MalformedRS)?;
    let num_steps = rs.num_steps();
    rs.verify(pp, num_steps, &z0, IC_i)?;

    /*
     * Prove grand products for MCC
     */

    // Build circuits
    let ops_circuit = OpsCircuit::new(RS, WS);
    let scan_circuit = ScanCircuit::new(IS, FS);

    // Compute commitment to IS & FS
    let IC_pprime = scan_circuit.commit_w::<E>(pp.ck());

    // Get alpha and gamma
    let mut keccak = E::TE::new(b"compute MCC challenges");
    keccak.absorb(b"C_n", &IC_i);
    keccak.absorb(b"C_pprime", &IC_pprime);
    let gamma = keccak.squeeze(b"gamma")?;
    let alpha = keccak.squeeze(b"alpha")?;

    /*
     * Grand product checks for RS & WS
     */

    // TODO: remove this PP from here
    let ops_pp = PublicParams::<E>::setup(&ops_circuit, &*default_ck_hint(), &*default_ck_hint());

    // Inputs for ops_circuit proving

    // ops_z0 = [gamma, alpha, ts=0, h_RS=1, h_WS=1]
    let ops_z0 = vec![
      gamma,
      alpha,
      E::Scalar::ZERO,
      E::Scalar::ONE,
      E::Scalar::ONE,
    ];
    let mut ops_rs: RecursiveSNARK<E> = RecursiveSNARK::new(&ops_pp, &ops_circuit, &ops_z0)?;
    let mut ops_IC_i = E::Scalar::ZERO;
    ops_rs.prove_step(&ops_pp, &ops_circuit, ops_IC_i)?;
    ops_IC_i = ops_rs.increment_commitment(&ops_pp, &ops_circuit);
    let ops_zi = ops_rs.verify(&ops_pp, ops_rs.num_steps(), &ops_z0, ops_IC_i)?;

    /*
     * Grand product checks for IS & FS
     */

    // TODO: remove this PP from here
    let scan_pp = PublicParams::<E>::setup(&scan_circuit, &*default_ck_hint(), &*default_ck_hint());

    // Inputs for scan_circuit proving

    // scan_z0 = [gamma, alpha, h_IS=1, h_FS=1]
    let scan_z0 = vec![gamma, alpha, E::Scalar::ONE, E::Scalar::ONE];
    let mut scan_rs: RecursiveSNARK<E> = RecursiveSNARK::new(&scan_pp, &scan_circuit, &scan_z0)?;
    let mut scan_IC_i = E::Scalar::ZERO;
    scan_rs.prove_step(&scan_pp, &scan_circuit, scan_IC_i)?;
    scan_IC_i = scan_rs.increment_commitment(&scan_pp, &scan_circuit);
    let scan_zi = scan_rs.verify(&scan_pp, scan_rs.num_steps(), &scan_z0, scan_IC_i)?;

    let (h_is, h_rs, h_ws, h_fs) = { (scan_zi[2], ops_zi[3], ops_zi[4], scan_zi[3]) };

    // TODO: remove this from `prove()`, verifier should be doing this check
    // 4. check h_IS · h_WS = h_RS · h_FS.
    assert_eq!(h_is * h_ws, h_rs * h_fs);

    Ok(rs)
  }
}

/// Multiplexer circuit for WASM module's computation
#[derive(Clone, Debug, Default)]
pub struct WASMTransitionCircuit {
  vm: WitnessVM,
  RS: Vec<(usize, u64, u64)>,
  WS: Vec<(usize, u64, u64)>,
}

impl<F> StepCircuit<F> for WASMTransitionCircuit
where
  F: PrimeField,
{
  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let inst_j = self.vm.J;

    // Allocate the witness
    let (X, Y, Z) = self.alloc_witness(cs.namespace(|| "alloc_witness"))?;

    let J_bits = parse_J(cs.namespace(|| "parse_J"), inst_j)?;

    // different values Z could be
    let mut ZJ = Vec::new();

    // I64Const
    imm_const_opc(cs.namespace(|| "imm_const_opc"), &Z, &mut ZJ)?;

    alu(cs.namespace(|| "alu"), &X, &Y, &mut ZJ)?;

    // constrain Z according to instruction index J
    let mut JZ = Vec::new();
    for j in 0..Instruction::MAX_J {
      let JZ_j = AllocatedNum::alloc(cs.namespace(|| format!("JZ{j}")), || {
        Ok(F::from(if j == inst_j { self.vm.Z } else { 0 }))
      })?;

      cs.enforce(
        || format!("J={j} * Z{j} = JZ{j}"),
        |lc| lc + J_bits[j as usize].get_variable(),
        |lc| lc + ZJ[j as usize].get_variable(),
        |lc| lc + JZ_j.get_variable(),
      );

      JZ.push(JZ_j)
    }

    // Z = Z[J]
    cs.enforce(
      || "Z = Z[J]",
      |lc| JZ.iter().fold(lc, |lc, JZ_j| lc + JZ_j.get_variable()),
      |lc| lc + CS::one(),
      |lc| lc + Z.get_variable(),
    );

    Ok(z.to_vec())
  }

  fn non_deterministic_advice(&self) -> Vec<F> {
    self
      .RS
      .iter()
      .zip_eq(self.WS.iter())
      .flat_map(|(rs, ws)| {
        avt_tuple_to_scalar_vec::<F>(*rs)
          .into_iter()
          .chain(avt_tuple_to_scalar_vec::<F>(*ws))
      })
      .collect()
  }
}

impl WASMTransitionCircuit {
  /// Allocate the witness variables
  pub fn alloc_witness<CS, F>(
    &self,
    mut cs: CS,
  ) -> Result<
    (
      AllocatedNum<F>, // X
      AllocatedNum<F>, // Y
      AllocatedNum<F>, // Z
    ),
    SynthesisError,
  >
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let X = AllocatedNum::alloc(cs.namespace(|| "X"), || Ok(F::from(self.vm.X)))?;
    let Y = AllocatedNum::alloc(cs.namespace(|| "Y"), || Ok(F::from(self.vm.Y)))?;
    let Z = AllocatedNum::alloc(cs.namespace(|| "Z"), || Ok(F::from(self.vm.Z)))?;

    Ok((X, Y, Z))
  }
}
