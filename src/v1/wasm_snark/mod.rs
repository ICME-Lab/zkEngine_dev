//! Implements SNARK proving the WASM module computation
use std::{cell::RefCell, rc::Rc};

use bellpepper_core::{self, num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, PrimeFieldBits};
use gadgets::{
  int::{add, and, eqz, or, popcount, shl_64, shr_s_64, sub, xor},
  utils::{alloc_one, conditionally_select},
};
use itertools::Itertools;
use mcc::{
  multiset_ops::{avt_tuple_to_scalar_vec, step_RS_WS},
  OpsCircuit, ScanCircuit,
};
use nova::{
  nebula::{
    ic::IC,
    rs::{PublicParams, RecursiveSNARK, StepCircuit},
  },
  traits::{snark::default_ck_hint, CurveCycleEquipped, Engine, TranscriptEngineTrait},
};

use serde::{Deserialize, Serialize};
use wasmi::{AddressOffset, BranchOffset, DropKeep, Instruction as Instr, Tracer, WitnessVM};

use crate::v1::utils::tracing::{execute_wasm, unwrap_rc_refcell};

use super::{error::ZKWASMError, wasm_ctx::WASMCtx};

mod gadgets;
mod mcc;

#[derive(Clone, Debug)]
/// BatchedWasmTransitionCircuit
pub struct BatchedWasmTransitionCircuit {
  circuits: Vec<WASMTransitionCircuit>,
}

impl<F> StepCircuit<F> for BatchedWasmTransitionCircuit
where
  F: PrimeField + PrimeFieldBits,
{
  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut z = z.to_vec();

    for circuit in self.circuits.iter() {
      z = circuit.synthesize(cs, &z)?;
    }

    Ok(z)
  }

  fn non_deterministic_advice(&self) -> Vec<F> {
    self
      .circuits
      .iter()
      .flat_map(|circuit| circuit.non_deterministic_advice())
      .collect()
  }
}

impl BatchedWasmTransitionCircuit {
  /// Create an empty instance of [`BatchedWasmTransitionCircuit`]
  pub fn empty(step_size: usize) -> Self {
    Self {
      circuits: vec![WASMTransitionCircuit::default(); step_size],
    }
  }
}

#[derive(Clone, Debug)]
/// BatchedWasmTransitionCircuit
pub struct BatchedOpsCircuit {
  circuits: Vec<OpsCircuit>,
}

impl<F> StepCircuit<F> for BatchedOpsCircuit
where
  F: PrimeField,
{
  fn arity(&self) -> usize {
    5
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut z = z.to_vec();

    for circuit in self.circuits.iter() {
      z = circuit.synthesize(cs, &z)?;
    }

    Ok(z)
  }

  fn non_deterministic_advice(&self) -> Vec<F> {
    self
      .circuits
      .iter()
      .flat_map(|circuit| circuit.non_deterministic_advice())
      .collect()
  }
}

impl BatchedOpsCircuit {
  /// Create an empty instance of [`BatchedOpsCircuit`]
  pub fn empty(step_size: usize) -> Self {
    Self {
      circuits: vec![OpsCircuit::default(); step_size],
    }
  }
}

/// Maximum number of memory ops allowed per step of the zkVM
pub const MEMORY_OPS_PER_STEP: usize = 8;

/// Public i/o for WASM execution proving
pub struct ZKWASMInstance<E>
where
  E: CurveCycleEquipped,
{
  // execution instance
  execution_z0: Vec<<E as Engine>::Scalar>,
  IC_i: <E as Engine>::Scalar,

  // ops instance
  ops_z0: Vec<<E as Engine>::Scalar>,
  ops_IC_i: <E as Engine>::Scalar,

  // scan instance
  scan_z0: Vec<<E as Engine>::Scalar>,
  scan_IC_i: <E as Engine>::Scalar,
}

/// [`WasmSNARK`] public parameters
pub struct WASMPublicParams<E>
where
  E: CurveCycleEquipped,
{
  execution_pp: PublicParams<E>,
  ops_pp: PublicParams<E>,
  scan_pp: PublicParams<E>,
}

impl<E> WASMPublicParams<E>
where
  E: CurveCycleEquipped,
{
  /// Get the execution public params
  pub fn execution(&self) -> &PublicParams<E> {
    &self.execution_pp
  }

  /// Get the ops public params
  pub fn ops(&self) -> &PublicParams<E> {
    &self.ops_pp
  }

  /// Get the scan public params
  pub fn scan(&self) -> &PublicParams<E> {
    &self.scan_pp
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// A SNARK that proves the correct execution of a WASM modules execution
pub struct WasmSNARK<E>
where
  E: CurveCycleEquipped,
{
  execution_rs: RecursiveSNARK<E>,
  ops_rs: RecursiveSNARK<E>,
  scan_rs: RecursiveSNARK<E>,
}

impl<E> WasmSNARK<E>
where
  E: CurveCycleEquipped,
{
  /// Fn used to obtain setup material for producing succinct arguments for
  /// WASM program executions
  pub fn setup(step_size: usize) -> WASMPublicParams<E> {
    let execution_pp = PublicParams::<E>::setup(
      &BatchedWasmTransitionCircuit::empty(step_size),
      &*default_ck_hint(),
      &*default_ck_hint(),
    );

    let ops_pp = PublicParams::<E>::setup(
      &BatchedOpsCircuit::empty(step_size),
      &*default_ck_hint(),
      &*default_ck_hint(),
    );

    let scan_pp = PublicParams::<E>::setup(
      &ScanCircuit::empty(step_size),
      &*default_ck_hint(),
      &*default_ck_hint(),
    );

    WASMPublicParams {
      execution_pp,
      ops_pp,
      scan_pp,
    }
  }

  #[tracing::instrument(skip_all, name = "WasmSNARK::prove")]
  /// Produce a SNARK for WASM program input
  pub fn prove(
    pp: &WASMPublicParams<E>,
    program: &WASMCtx,
    step_size: usize,
  ) -> Result<(Self, ZKWASMInstance<E>), ZKWASMError> {
    // Execute WASM module and build execution trace documenting vm state at
    // each step. Also get meta-date from execution like the max height of the [`ValueStack`]
    let tracer = Rc::new(RefCell::new(Tracer::new()));
    execute_wasm(program, tracer.clone())?;
    let tracer = unwrap_rc_refcell(tracer);

    /*
     * Get MCC values:
     */

    // We maintain a timestamp counter `globa_ts` that is initialized to
    // the highest timestamp value in IS.
    let mut global_ts = 0;

    // Compute multisets to perform grand product checks (uses global_ts)
    let IS_stack_len = tracer.IS_stack_len();
    tracing::debug!("stack len: {}", IS_stack_len);
    let mut IS = tracer.IS();
    tracing::debug!("IS_mem.len: {}", IS.len() - IS_stack_len);

    let mut RS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
    let mut WS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
    let mut FS = IS.clone();

    let mut execution_trace = tracer.into_execution_trace();

    // Pad the execution trace, so the length is a multiple of step_size
    {
      let len = execution_trace.len();
      let pad_len = step_size - (len % step_size);
      (0..pad_len).for_each(|_| {
        execution_trace.push(WitnessVM::default());
      })
    }

    tracing::debug!("execution trace length: {:#?}", execution_trace.len());
    tracing::trace!("execution trace: {:#?}", execution_trace);

    // Build the WASMTransitionCircuit from each traced execution frame.
    let circuits: Vec<WASMTransitionCircuit> = execution_trace
      .into_iter()
      .map(|vm| {
        let (step_rs, step_ws) = step_RS_WS(&vm, &mut FS, &mut global_ts, IS_stack_len);

        RS.push(step_rs.clone());
        WS.push(step_ws.clone());

        WASMTransitionCircuit {
          vm,
          RS: step_rs,
          WS: step_ws,
          stack_len: IS_stack_len,
        }
      })
      .collect();

    let circuits = circuits
      .chunks(step_size)
      .map(|chunk| BatchedWasmTransitionCircuit {
        circuits: chunk.to_vec(),
      })
      .collect::<Vec<_>>();

    /*
     * ***** WASM Transition Circuit Proving *****
     */
    let mut rs_option: Option<RecursiveSNARK<E>> = None;
    let z0 = vec![E::Scalar::ZERO];
    let mut IC_i = E::Scalar::ZERO;

    // F represents the transition function of the WASM (stack-based) VM.
    // commitment-carrying IVC to prove the repeated execution of F
    let execution_pp = pp.execution();
    for circuit in circuits.iter() {
      let mut rs = rs_option.unwrap_or_else(|| {
        RecursiveSNARK::new(execution_pp, circuit, &z0)
          .expect("failed to construct initial recursive SNARK")
      });

      rs.prove_step(execution_pp, circuit, IC_i)?;
      IC_i = rs.increment_commitment(execution_pp, circuit);

      rs_option = Some(rs)
    }

    // Do an internal check on the final recursive SNARK
    debug_assert!(rs_option.is_some());
    let rs = rs_option.ok_or(ZKWASMError::MalformedRS)?;
    let num_steps = rs.num_steps();
    rs.verify(execution_pp, num_steps, &z0, IC_i)?;

    /*
     * Prove grand products for MCC
     */

    // Get public parameters
    let ops_pp = pp.ops();
    let scan_pp = pp.scan();

    // Build ops circuits
    let ops_circuits = RS
      .into_iter()
      .zip_eq(WS.into_iter())
      .map(|(rs, ws)| OpsCircuit::new(rs, ws))
      .collect::<Vec<_>>();

    let ops_circuits = ops_circuits
      .chunks(step_size)
      .map(|chunk| BatchedOpsCircuit {
        circuits: chunk.to_vec(),
      })
      .collect::<Vec<_>>();

    // build scan circuits
    let mut scan_IC_i = E::Scalar::ZERO;
    let mut IC_pprime = E::Scalar::ZERO;

    let mut scan_circuits = Vec::new();

    // Pad IS and FS , so length is a multiple of step_size
    {
      let len = IS.len();
      let pad_len = step_size - (len % step_size);
      (0..pad_len).for_each(|i| {
        IS.push((len + i, 0, 0));
        FS.push((len + i, 0, 0));
      })
    }
    // sanity check
    assert_eq!(IS.len() % step_size, 0);

    for (IS_chunk, FS_chunk) in IS.chunks(step_size).zip_eq(FS.chunks(step_size)) {
      let scan_circuit = ScanCircuit::new(IS_chunk.to_vec(), FS_chunk.to_vec());
      IC_pprime = IC::<E>::commit(
        &scan_pp.ck_primary,
        &scan_pp.ro_consts_primary,
        IC_pprime,
        scan_circuit.non_deterministic_advice(),
      );
      scan_circuits.push(scan_circuit);
    }

    // Get alpha and gamma
    let mut keccak = E::TE::new(b"compute MCC challenges");
    keccak.absorb(b"C_n", &IC_i);
    keccak.absorb(b"C_pprime", &IC_pprime);
    let gamma = keccak.squeeze(b"gamma")?;
    let alpha = keccak.squeeze(b"alpha")?;

    /*
     * Grand product checks for RS & WS
     */

    /*
     * ***** F_ops proving *****
     */

    // ops_z0 = [gamma, alpha, ts=0, h_RS=1, h_WS=1]
    let ops_z0 = vec![
      gamma,
      alpha,
      E::Scalar::ZERO,
      E::Scalar::ONE,
      E::Scalar::ONE,
    ];
    let mut ops_IC_i = E::Scalar::ZERO;
    let mut ops_rs_option: Option<RecursiveSNARK<E>> = None;

    for ops_circuit in ops_circuits.iter() {
      let mut ops_rs = ops_rs_option.unwrap_or_else(|| {
        RecursiveSNARK::new(ops_pp, ops_circuit, &ops_z0)
          .expect("failed to construct initial recursive SNARK")
      });

      ops_rs.prove_step(ops_pp, ops_circuit, ops_IC_i)?;
      ops_IC_i = ops_rs.increment_commitment(ops_pp, ops_circuit);

      ops_rs_option = Some(ops_rs)
    }

    // internal check
    let ops_rs = ops_rs_option.ok_or(ZKWASMError::MalformedRS)?;
    ops_rs.verify(ops_pp, ops_rs.num_steps(), &ops_z0, ops_IC_i)?;

    /*
     * Grand product checks for IS & FS
     */

    // scan_z0 = [gamma, alpha, h_IS=1, h_FS=1]
    let scan_z0 = vec![gamma, alpha, E::Scalar::ONE, E::Scalar::ONE];
    let mut scan_rs_option: Option<RecursiveSNARK<E>> = None;

    for scan_circuit in scan_circuits.iter() {
      let mut scan_rs = scan_rs_option.unwrap_or_else(|| {
        RecursiveSNARK::new(scan_pp, scan_circuit, &scan_z0)
          .expect("failed to construct initial recursive SNARK")
      });

      scan_rs.prove_step(scan_pp, scan_circuit, scan_IC_i)?;
      scan_IC_i = scan_rs.increment_commitment(scan_pp, scan_circuit);

      scan_rs_option = Some(scan_rs)
    }

    // internal check
    let scan_rs = scan_rs_option.ok_or(ZKWASMError::MalformedRS)?;
    scan_rs.verify(scan_pp, scan_rs.num_steps(), &scan_z0, scan_IC_i)?;

    debug_assert_eq!(scan_IC_i, IC_pprime);

    // Public i/o
    let U = ZKWASMInstance {
      execution_z0: z0,
      IC_i,
      ops_z0,
      ops_IC_i,
      scan_z0,
      scan_IC_i,
    };

    Ok((
      Self {
        execution_rs: rs,
        ops_rs,
        scan_rs,
      },
      U,
    ))
  }

  /// Verify the [`WasmSNARK`]
  pub fn verify(&self, pp: &WASMPublicParams<E>, U: &ZKWASMInstance<E>) -> Result<(), ZKWASMError> {
    // verify F
    self.execution_rs.verify(
      pp.execution(),
      self.execution_rs.num_steps(),
      &U.execution_z0,
      U.IC_i,
    )?;

    // verify F_ops
    let ops_zi = self
      .ops_rs
      .verify(pp.ops(), self.ops_rs.num_steps(), &U.ops_z0, U.ops_IC_i)?;

    // verify F_scan
    let scan_zi =
      self
        .scan_rs
        .verify(pp.scan(), self.scan_rs.num_steps(), &U.scan_z0, U.scan_IC_i)?;

    // 1. check h_IS = h_RS = h_WS = h_FS = 1 // initial values are correct
    let (init_h_is, init_h_rs, init_h_ws, init_h_fs) =
      { (U.scan_z0[2], U.ops_z0[3], U.ops_z0[4], U.scan_z0[3]) };
    if init_h_is != E::Scalar::ONE
      || init_h_rs != E::Scalar::ONE
      || init_h_ws != E::Scalar::ONE
      || init_h_fs != E::Scalar::ONE
    {
      return Err(ZKWASMError::MultisetVerificationError);
    }

    // 2. check Cn′ = Cn // commitments carried in both Πops and ΠF are the same
    if U.IC_i != U.ops_IC_i {
      return Err(ZKWASMError::MultisetVerificationError);
    }

    // 3. check γ and γ are derived by hashing C and C′′.
    // Get alpha and gamma
    let mut keccak = E::TE::new(b"compute MCC challenges");
    keccak.absorb(b"C_n", &U.IC_i);
    keccak.absorb(b"C_pprime", &U.scan_IC_i);
    let gamma = keccak.squeeze(b"gamma")?;
    let alpha = keccak.squeeze(b"alpha")?;

    if U.ops_z0[0] != gamma || U.ops_z0[1] != alpha {
      return Err(ZKWASMError::MultisetVerificationError);
    }

    // 4. check h_IS' · h_WS' = h_RS' · h_FS'.

    // Inputs for multiset check
    let (h_is, h_rs, h_ws, h_fs) = { (scan_zi[2], ops_zi[3], ops_zi[4], scan_zi[3]) };
    if h_is * h_ws != h_rs * h_fs {
      return Err(ZKWASMError::MultisetVerificationError);
    }

    Ok(())
  }
}

/// Multiplexer circuit representing a step in a WASM module's computation
#[derive(Clone, Debug)]
pub struct WASMTransitionCircuit {
  vm: WitnessVM,
  RS: Vec<(usize, u64, u64)>,
  WS: Vec<(usize, u64, u64)>,
  stack_len: usize,
}

impl<F> StepCircuit<F> for WASMTransitionCircuit
where
  F: PrimeField + PrimeFieldBits,
{
  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    /*
     * **** Switchboard circuit ****
     */
    let mut switches = Vec::new();
    self.visit_unreachable(cs.namespace(|| "unreachable"), &mut switches)?;
    self.visit_const(cs.namespace(|| "const"), &mut switches)?;
    self.visit_local_get(cs.namespace(|| "local.get"), &mut switches)?;
    self.visit_local_set(cs.namespace(|| "local.set"), &mut switches)?;
    self.visit_local_tee(cs.namespace(|| "local.tee"), &mut switches)?;
    self.visit_i64_add(cs.namespace(|| "i64.add"), &mut switches)?;
    self.visit_i64_sub(cs.namespace(|| "i64.sub"), &mut switches)?;
    self.visit_i64_mul(cs.namespace(|| "i64.mul"), &mut switches)?;
    self.visit_i64_div_s(cs.namespace(|| "i64.div_s"), &mut switches)?;
    self.visit_i64_div_u(cs.namespace(|| "i64.div_u"), &mut switches)?;
    self.visit_i64_rem_s(cs.namespace(|| "i64.rem_s"), &mut switches)?;
    self.visit_i64_rem_u(cs.namespace(|| "i64.rem_u"), &mut switches)?;
    self.visit_i64_and(cs.namespace(|| "i64.and"), &mut switches)?;
    self.visit_i64_or(cs.namespace(|| "i64.or"), &mut switches)?;
    self.visit_i64_shl(cs.namespace(|| "i64.shl"), &mut switches)?;
    self.visit_i64_shr_u(cs.namespace(|| "i64.shr_u"), &mut switches)?;
    self.visit_i64_shr_s(cs.namespace(|| "i64.shr_s"), &mut switches)?;
    self.visit_i64_rotl(cs.namespace(|| "i64.rotl"), &mut switches)?;
    self.visit_i64_rotr(cs.namespace(|| "i64.rotr"), &mut switches)?;
    self.visit_i64_xor(cs.namespace(|| "i64.xor"), &mut switches)?;
    self.visit_i64_clz(cs.namespace(|| "i64.clz"), &mut switches)?;
    self.visit_i64_ctz(cs.namespace(|| "i64.ctz"), &mut switches)?;
    self.visit_br_if_eqz(cs.namespace(|| "Instr::BrIfEqz"), &mut switches)?;
    self.visit_br_if_nez(cs.namespace(|| "Instr::BrIfNez"), &mut switches)?;
    self.visit_br(cs.namespace(|| "Instr::Br"), &mut switches)?;
    self.drop_keep(cs.namespace(|| "drop keep"), &mut switches)?;
    self.visit_ret(cs.namespace(|| "return"), &mut switches)?;
    self.visit_store(cs.namespace(|| "store"), &mut switches)?;
    self.visit_load(cs.namespace(|| "load"), &mut switches)?;
    self.visit_popcount(cs.namespace(|| "popcount"), &mut switches)?;
    self.visit_unary(cs.namespace(|| "visit_unary"), &mut switches)?;
    self.visit_binary(cs.namespace(|| "visit_binary"), &mut switches)?;
    self.visit_eqz(cs.namespace(|| "visit_eqz"), &mut switches)?;

    /*
     *  Switch constraints
     */

    // 1. Single switch constraint:
    cs.enforce(
      || "single switch",
      |lc| {
        switches
          .iter()
          .fold(lc, |lc, switch| lc + switch.get_variable())
      },
      |lc| lc + CS::one(),
      |lc| lc + CS::one(),
    );

    // 2. Binary switch constraints:
    for (i, switch) in switches.iter().enumerate() {
      cs.enforce(
        || format!("binary switch {i}"),
        |lc| lc + switch.get_variable(),
        |lc| lc + CS::one() - switch.get_variable(),
        |lc| lc,
      );
    }

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
  /// Allocate if switch is on or off depending on the instruction
  fn switch<CS, F>(
    &self,
    cs: &mut CS,
    J: u64,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<F, SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let switch = if J == self.vm.J { F::ONE } else { F::ZERO };
    switches.push(AllocatedNum::alloc(cs.namespace(|| "switch"), || {
      Ok(switch)
    })?);
    Ok(switch)
  }

  /// Allocate a num into the zkWASM CS
  fn alloc_num<CS, F, A, AR, Fo>(
    cs: &mut CS,
    annotation: A,
    value: Fo,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
    A: FnOnce() -> AR,
    AR: Into<String>,
    Fo: FnOnce() -> Result<F, SynthesisError>,
  {
    AllocatedNum::alloc(cs.namespace(annotation), || {
      let res = value()?;
      Ok(res * switch)
    })
  }

  /// Allocate a (addr, val, timestamp) tuple into the CS
  fn alloc_avt<CS, F>(
    mut cs: CS,
    avt: &(usize, u64, u64),
    switch: F,
  ) -> Result<(AllocatedNum<F>, AllocatedNum<F>, AllocatedNum<F>), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let (addr, val, ts) = *avt;
    let addr = Self::alloc_num(&mut cs, || "addr", || Ok(F::from(addr as u64)), switch)?;
    let val = Self::alloc_num(&mut cs, || "val", || Ok(F::from(val)), switch)?;
    let ts = Self::alloc_num(&mut cs, || "ts", || Ok(F::from(ts)), switch)?;

    Ok((addr, val, ts))
  }

  /// Pefrom a read to zkVM read-write memory.  for a read operation, the advice is (a, v, rt) and
  /// (a, v, wt); F checks that the address a in the advice matches the address it requested and
  /// then uses the provided value v (e.g., in the rest of its computation).
  fn read<CS, F>(
    mut cs: CS,
    addr: &AllocatedNum<F>,
    advice: &(usize, u64, u64),
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let (advice_addr, advice_val, _) =
      Self::alloc_avt(cs.namespace(|| "(addr, val, ts)"), advice, switch)?;

    // F checks that the address a in the advice matches the address it requested
    cs.enforce(
      || "addr == advice_addr",
      |lc| lc + addr.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + advice_addr.get_variable(),
    );

    Ok(advice_val)
  }

  /// Perform a write to zkVM read-write memory.  For a write operation, the advice is (a, v, rt)
  /// and (a, v′, wt); F checks that the address a and the value v′ match the address and value it
  /// wishes to write. Otherwise, F ignores the remaining components in the provided advice.
  fn write<CS, F>(
    mut cs: CS,
    addr: &AllocatedNum<F>,
    val: &AllocatedNum<F>,
    advice: &(usize, u64, u64),
    switch: F,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let (advice_addr, advice_val, _) =
      Self::alloc_avt(cs.namespace(|| "(addr, val, ts)"), advice, switch)?;

    // F checks that the address a  match the address it wishes to write to.
    cs.enforce(
      || "addr == advice_addr",
      |lc| lc + addr.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + advice_addr.get_variable(),
    );

    // F checks that the value v′ match value it wishes to write.
    cs.enforce(
      || "val == advice_val",
      |lc| lc + val.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + advice_val.get_variable(),
    );

    Ok(())
  }

  /// Unreacable
  fn visit_unreachable<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Unreachable }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// Push a const onto the stack
  fn visit_const<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Const32(0) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let pre_sp = Self::alloc_num(
      &mut cs,
      || "pre_sp",
      || Ok(F::from(self.vm.pre_sp as u64)),
      switch,
    )?;

    let I = Self::alloc_num(&mut cs, || "I", || Ok(F::from(self.vm.I)), switch)?;

    Self::write(
      cs.namespace(|| "push I on stack"),
      &pre_sp,
      &I,
      &self.WS[0],
      switch,
    )?;

    Ok(())
  }

  /// local.get
  fn visit_local_get<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::local_get(0).unwrap() }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let local_depth = Self::alloc_num(
      &mut cs,
      || "local depth",
      || Ok(F::from(self.vm.pre_sp as u64 - self.vm.I)),
      switch,
    )?;

    let read_val = Self::read(
      cs.namespace(|| "read at local_depth"),
      &local_depth,
      &self.RS[0],
      switch,
    )?;

    let pre_sp = Self::alloc_num(
      &mut cs,
      || "pre_sp",
      || Ok(F::from(self.vm.pre_sp as u64)),
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push local on stack"),
      &pre_sp,
      &read_val,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// local.set
  fn visit_local_set<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::local_set(0).unwrap() }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "last addr",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;
    let depth = Self::alloc_num(&mut cs, || "depth addr", || Ok(F::from(self.vm.I)), switch)?;

    let depth_addr = sub(cs.namespace(|| "last - depth"), &last_addr, &depth)?;

    Self::write(
      cs.namespace(|| "set local"),
      &depth_addr,
      &Y,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// local.tee
  fn visit_local_tee<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::local_tee(0).unwrap() }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let pre_sp = Self::alloc_num(
      &mut cs,
      || "pre_sp",
      || Ok(F::from((self.vm.pre_sp) as u64)),
      switch,
    )?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "last addr",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;
    let depth = Self::alloc_num(&mut cs, || "depth addr", || Ok(F::from(self.vm.I)), switch)?;

    let depth_addr = sub(cs.namespace(|| "pre_sp - depth"), &pre_sp, &depth)?;

    Self::write(
      cs.namespace(|| "tee local"),
      &depth_addr,
      &Y,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// i64.sub
  fn visit_i64_sub<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Sub }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let _Y = Self::alloc_num(
      &mut cs,
      || "-Y",
      || Ok(F::from((-(self.vm.Y as i64)) as u64)),
      switch,
    )?;

    // let Z = add(cs.namespace(|| "X - Y"), &X, &Y)?;
    let Z = Self::alloc_num(&mut cs, || "Z=sub(X, Y)", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.add
  fn visit_i64_add<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Add }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    // let Z = add(cs.namespace(|| "X + Y"), &X, &Y)?;
    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.mul
  fn visit_i64_mul<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Mul }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    // let Z = mul(cs.namespace(|| "X * Y"), &X, &Y)?;
    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.and
  fn visit_i64_and<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64And }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = and(cs.namespace(|| "X & Y"), &X, &Y)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.or
  fn visit_i64_or<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Or }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = or(cs.namespace(|| "X | Y"), &X, &Y)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.xor
  fn visit_i64_xor<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Xor }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = xor(cs.namespace(|| "X XOR Y"), &X, &Y)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// Instr::BrIfEqz
  fn visit_br_if_eqz<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrIfEqz(BranchOffset::uninit()) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let one = alloc_one(cs.namespace(|| "one"));

    let pc = Self::alloc_num(&mut cs, || "pc", || Ok(F::from(self.vm.pc as u64)), switch)?;
    let next_pc = add(cs.namespace(|| "pc + 1"), &pc, &one)?;

    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;

    let branch_pc = add(cs.namespace(|| "pc + branch_offset"), &pc, &branch_offset)?;

    // addr of last value on stack
    let last = Self::alloc_num(
      &mut cs,
      || "last",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let condition = Self::read(cs.namespace(|| "condition"), &last, &self.RS[0], switch)?;
    let condition_eqz = eqz(cs.namespace(|| "condition == 0"), &condition)?;

    // if condtion == 0 then new_pc = branch_pc else new_pc = next_pc
    //
    // In other words if condition_eqz is true then new_pc = branch_pc else new_pc = next_pc
    let _new_pc = conditionally_select(
      cs.namespace(|| "new_pc"),
      &branch_pc,
      &next_pc,
      &condition_eqz,
    )?; // TODO: constrain pc

    Ok(())
  }

  /// Instr::BrIfNez
  fn visit_br_if_nez<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrIfNez(BranchOffset::uninit()) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let one = alloc_one(cs.namespace(|| "one"));

    let pc = Self::alloc_num(&mut cs, || "pc", || Ok(F::from(self.vm.pc as u64)), switch)?;
    let next_pc = add(cs.namespace(|| "pc + 1"), &pc, &one)?;

    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;

    let branch_pc = add(cs.namespace(|| "pc + branch_offset"), &pc, &branch_offset)?;

    // addr of last value on stack
    let last = Self::alloc_num(
      &mut cs,
      || "last",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let condition = Self::read(cs.namespace(|| "condition"), &last, &self.RS[0], switch)?;
    let condition_eqz = eqz(cs.namespace(|| "condition == 0"), &condition)?;

    // if condtion == 0 then new_pc = next_pc  else  new_pc = branch_pc
    //
    // In other words if condition_eqz is true then new_pc = next_pc else new_pc = branch_pc
    let _new_pc = conditionally_select(
      cs.namespace(|| "new_pc"),
      &next_pc,
      &branch_pc,
      &condition_eqz,
    )?; // TODO: constrain pc

    Ok(())
  }

  /// Instr::Br
  fn visit_br<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Br(BranchOffset::uninit()) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let pc = Self::alloc_num(&mut cs, || "pc", || Ok(F::from(self.vm.pc as u64)), switch)?;

    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;

    let _branch_pc = add(cs.namespace(|| "pc + branch_offset"), &pc, &branch_offset)?;

    Ok(())
  }

  /// drop_keep
  fn drop_keep<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::DropKeep }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let drop = self.vm.I;
    let keep = self.vm.P;
    let pre_sp_u64 = self.vm.pre_sp as u64;

    let read_addr = Self::alloc_num(
      &mut cs,
      || "read_addr",
      || {
        let read_addr_u64 = pre_sp_u64 - keep;
        Ok(F::from(read_addr_u64))
      },
      switch,
    )?;

    let read_val = Self::read(cs.namespace(|| "read val"), &read_addr, &self.RS[0], switch)?;

    let write_addr = Self::alloc_num(
      &mut cs,
      || "write addr",
      || {
        let write_addr_u64 = pre_sp_u64 - drop - keep;
        Ok(F::from(write_addr_u64))
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "drop keep write"),
      &write_addr,
      &read_val,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// Return instruction
  fn visit_ret<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Return(DropKeep::new(0, 0).unwrap()) }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// Store instruction
  fn visit_store<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Store(AddressOffset::from(0)) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    // Stack ops
    let raw_last = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _ = Self::read(cs.namespace(|| "raw_addr"), &raw_last, &self.RS[0], switch)?;

    let val_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _ = Self::read(cs.namespace(|| "val"), &val_addr, &self.RS[1], switch)?;

    // linear mem ops
    let effective_addr = self.vm.I;

    let write_addr_1 = Self::alloc_num(
      &mut cs,
      || "write_addr_1",
      || {
        let write_addr_1 = effective_addr / 8 + self.stack_len as u64;
        Ok(F::from(write_addr_1))
      },
      switch,
    )?;

    let write_addr_2 = Self::alloc_num(
      &mut cs,
      || "write_addr_2",
      || {
        let write_addr_2 = effective_addr / 8 + 1 + self.stack_len as u64;
        Ok(F::from(write_addr_2))
      },
      switch,
    )?;

    let write_val_1 =
      Self::alloc_num(&mut cs, || "write_val_1", || Ok(F::from(self.vm.P)), switch)?;
    let write_val_2 =
      Self::alloc_num(&mut cs, || "write_val_2", || Ok(F::from(self.vm.Q)), switch)?;

    Self::write(
      cs.namespace(|| "store 1"),
      &write_addr_1,
      &write_val_1,
      &self.WS[2],
      switch,
    )?;

    Self::write(
      cs.namespace(|| "store 2"),
      &write_addr_2,
      &write_val_2,
      &self.WS[3],
      switch,
    )?;

    Ok(())
  }

  /// Store instruction
  fn visit_load<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Load(AddressOffset::from(0)) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    // Stack ops
    let last = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _ = Self::read(cs.namespace(|| "val"), &last, &self.RS[0], switch)?;

    // linear mem ops
    let effective_addr = self.vm.I;

    let read_addr_1 = Self::alloc_num(
      &mut cs,
      || "read_addr_1",
      || {
        let read_addr_1 = effective_addr / 8 + self.stack_len as u64;
        Ok(F::from(read_addr_1))
      },
      switch,
    )?;

    let read_addr_2 = Self::alloc_num(
      &mut cs,
      || "read_addr_2",
      || {
        let read_addr_2 = effective_addr / 8 + 1 + self.stack_len as u64;
        Ok(F::from(read_addr_2))
      },
      switch,
    )?;

    let _ = Self::read(
      cs.namespace(|| "block_val_1"),
      &read_addr_1,
      &self.RS[1],
      switch,
    )?;
    let _ = Self::read(
      cs.namespace(|| "block_val_1"),
      &read_addr_2,
      &self.RS[2],
      switch,
    )?;

    let stack_write_val =
      Self::alloc_num(&mut cs, || "stack write", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "store 1"),
      &last,
      &stack_write_val,
      &self.WS[3],
      switch,
    )?;

    Ok(())
  }

  /// i64.clz
  fn visit_i64_clz<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Clz }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z=clz(Y)", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &last_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// i64.ctz
  fn visit_i64_ctz<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Ctz }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z=ctz(Y)", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &last_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// i64.shl
  fn visit_i64_shl<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Shl }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = shl_64(cs.namespace(|| "shl_64"), &X, self.vm.Y as usize)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.shr_s
  fn visit_i64_shr_s<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64ShrS }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = shr_s_64(cs.namespace(|| "shr_s_64"), &X, self.vm.Y as usize)?;
    // let Z = Self::alloc_num(&mut cs, || "unary_op(Y)", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.shr_u
  fn visit_i64_shr_u<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64ShrU }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.rotl
  fn visit_i64_rotl<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Rotl }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.rotr
  fn visit_i64_rotr<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Rotr }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.div_s
  fn visit_i64_div_s<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64DivS }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.div_u
  fn visit_i64_div_u<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64DivU }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.rem_s
  fn visit_i64_rem_s<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64RemS }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// visit_binary
  fn visit_i64_rem_u<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64RemU }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.eqz, i32.eqz
  fn visit_eqz<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Eqz }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _ = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    let Z = Self::alloc_num(&mut cs, || "unary_op(Y)", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &last_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// Popcount
  fn visit_popcount<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Popcnt }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z=popcnt(Y)", || Ok(F::from(self.vm.Z)), switch)?;

    popcount(cs.namespace(|| "popcnt"), &Y, &Z)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &last_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// Unary op
  fn visit_unary<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::F32Abs }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _ = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    let Z = Self::alloc_num(&mut cs, || "unary_op(Y)", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &last_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// visit_binary
  fn visit_binary<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::F32Eq }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }
}

impl Default for WASMTransitionCircuit {
  fn default() -> Self {
    Self {
      vm: WitnessVM::default(),
      // max memory ops per recursive step is 8
      RS: vec![(0, 0, 0); MEMORY_OPS_PER_STEP / 2],
      WS: vec![(0, 0, 0); MEMORY_OPS_PER_STEP / 2],
      stack_len: 0,
    }
  }
}
