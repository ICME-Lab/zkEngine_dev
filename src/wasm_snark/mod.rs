//! Implements SNARK proving the WASM module computation
use std::cell::OnceCell;

use super::{
  error::ZKWASMError,
  wasm_ctx::{ISMemSizes, ZKWASMCtx},
};
use crate::utils::tracing::split_vector;
use ff::Field;
use itertools::Itertools;
use mcc::{
  multiset_ops::{avt_tuple_to_scalar_vec, step_RS_WS},
  BatchedOpsCircuit, OpsCircuit, ScanCircuit,
};
use nova::{
  nebula::{
    audit_rs::{AuditPublicParams, AuditRecursiveSNARK},
    compression::{CompressedSNARK, NebulaInstance, ProverKey, VerifierKey},
    ic::IC,
    rs::{PublicParams, RecursiveSNARK},
    traits::{Layer1PPTrait, Layer1RSTrait, MemoryCommitmentsTraits},
  },
  traits::{
    snark::{default_ck_hint, BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
    CurveCycleEquipped, Dual, Engine, TranscriptEngineTrait,
  },
};
use serde::{Deserialize, Serialize};
use wasmi::WitnessVM;
mod gadgets;
mod mcc;
mod switchboard;
use switchboard::{BatchedWasmTransitionCircuit, WASMTransitionCircuit};

/// Maximum number of memory ops allowed per step of the zkVM
pub const MEMORY_OPS_PER_STEP: usize = 8;

/// [`WasmSNARK`] public parameters
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct WASMPublicParams<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  execution_pp: PublicParams<E>,
  ops_pp: PublicParams<E>,
  scan_pp: AuditPublicParams<E>,
  /// Prover and verifier key for final proof compression
  #[serde(skip)]
  pk_and_vk: OnceCell<(ProverKey<E, S1, S2>, VerifierKey<E, S1, S2>)>,
}

impl<E, S1, S2> WASMPublicParams<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  /// provides a reference to a ProverKey suitable for producing a CompressedProof
  pub fn pk(&self) -> &ProverKey<E, S1, S2> {
    let (pk, _vk) = self
      .pk_and_vk
      .get_or_init(|| CompressedSNARK::<E, S1, S2>::setup(self).unwrap());
    pk
  }

  /// provides a reference to a VerifierKey suitable for verifying a CompressedProof
  pub fn vk(&self) -> &VerifierKey<E, S1, S2> {
    let (_pk, vk) = self
      .pk_and_vk
      .get_or_init(|| CompressedSNARK::<E, S1, S2>::setup(self).unwrap());
    vk
  }
}

impl<E, S1, S2> Layer1PPTrait<E> for WASMPublicParams<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  fn into_parts(self) -> (PublicParams<E>, PublicParams<E>, AuditPublicParams<E>) {
    (self.execution_pp, self.ops_pp, self.scan_pp)
  }

  fn F(&self) -> &PublicParams<E> {
    &self.execution_pp
  }

  fn ops(&self) -> &PublicParams<E> {
    &self.ops_pp
  }

  fn scan(&self) -> &AuditPublicParams<E> {
    &self.scan_pp
  }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
/// A SNARK that proves the correct execution of a WASM modules execution
pub struct RecursiveWasmSNARK<E>
where
  E: CurveCycleEquipped,
{
  execution_rs: RecursiveSNARK<E>,
  ops_rs: RecursiveSNARK<E>,
  scan_rs: AuditRecursiveSNARK<E>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
/// A SNARK that proves the correct execution of a WASM modules execution
pub enum WasmSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  /// RecursiveSNARK for WASM execution
  Recursive(Box<RecursiveWasmSNARK<E>>),
  /// CompressedSNARK for WASM execution
  Compressed(Box<CompressedSNARK<E, S1, S2>>),
}

impl<E, S1, S2> WasmSNARK<E, S1, S2>
where
  E: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E>,
  S2: RelaxedR1CSSNARKTrait<Dual<E>>,
{
  /// Fn used to obtain setup material for producing succinct arguments for
  /// WASM program executions
  pub fn setup(step_size: StepSize) -> WASMPublicParams<E, S1, S2> {
    let execution_pp = PublicParams::<E>::setup(
      &BatchedWasmTransitionCircuit::empty(step_size.execution),
      &*default_ck_hint(),
      &*default_ck_hint(),
    );
    let ops_pp = PublicParams::<E>::setup(
      &BatchedOpsCircuit::empty(step_size.execution),
      &*default_ck_hint(),
      &*default_ck_hint(),
    );
    let scan_pp = AuditPublicParams::<E>::setup(
      &ScanCircuit::empty(step_size.memory),
      &*default_ck_hint(),
      &*default_ck_hint(),
    );
    WASMPublicParams {
      execution_pp,
      ops_pp,
      scan_pp,
      pk_and_vk: OnceCell::new(),
    }
  }

  #[tracing::instrument(skip_all, name = "WasmSNARK::prove")]
  /// Produce a SNARK for WASM program input
  pub fn prove(
    pp: &WASMPublicParams<E, S1, S2>,
    program: &impl ZKWASMCtx,
    step_size: StepSize,
  ) -> Result<(Self, ZKWASMInstance<E>), ZKWASMError> {
    // Run the vm and get the execution trace of the program.
    //
    // # Note:
    //
    // `start_execution_trace` is an execution trace starting from opcode 0 to opcode `end` from the
    // WASM program `TraceSliceValues`
    //
    // We do not slice the execution trace at `TraceSliceValues` `start` value because we need the
    // values of the execution trace from *opcode 0 to opcode `start`* to construct the IS for
    // memory checking in continuations/sharding
    let (start_execution_trace, mut IS, IS_sizes) = program.execution_trace()?;

    /*
     * Construct IS multiset
     */

    // Split the execution trace at `TraceSliceValues` `start` value. Use the first half to
    // construct IS and use the second half for the actual proving of the shard
    let start = program.args().start();
    let (IS_execution_trace, mut execution_trace) = split_vector(start_execution_trace, start);

    // We maintain a timestamp counter `globa_ts` that is initialized to
    // the highest timestamp value in IS.
    let mut global_ts = 0;

    // If we are proving a shard of a WASM program: calculate shard size & construct correct shard IS
    let is_sharded = program.args().is_sharded();
    let shard_size = program.args().shard_size().unwrap_or(execution_trace.len());
    construct_IS(
      shard_size,
      step_size,
      is_sharded,
      IS_execution_trace,
      &mut IS,
      &mut global_ts,
      &IS_sizes,
    );

    // Get the highest timestamp in the IS
    let IS_gts = global_ts;

    // Construct RS, WS, & FS multisets for MCC
    //
    // # Note:
    //
    // * Initialize the RS, and WS multisets as empty, as these will be filled in when we construct
    //   the step circuits for execution proving
    //
    // * IS is already constructed.
    //
    // * Initialize the FS multiset to IS, because that will be the starting state of the zkVM which
    //   we will then modify when we build the execution proving step circuits to derive the actual
    //   FS.
    let mut RS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
    let mut WS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
    let mut FS = IS.clone();

    // Pad the execution trace, so its length is a multiple of `step_size`.
    //
    // 1. This: `step_size.execution - (execution_trace.len() % step_size.execution))` calculates
    //    the
    // number of pads needed for execution trace to be a multiple of `step_size.execution`
    //
    // 2. We then mod the above value by `step_size.execution` because if the execution trace is
    //    already a multiple of `step_size.execution` this additional mod makes the pad_len 0
    let pad_len =
      (step_size.execution - (execution_trace.len() % step_size.execution)) % step_size.execution;
    execution_trace.extend((0..pad_len).map(|_| WitnessVM::default()));
    let (pc, sp) = {
      let pc = E::Scalar::from(execution_trace[0].pc as u64);
      let sp = E::Scalar::from(execution_trace[0].pre_sp as u64);
      (pc, sp)
    };

    // Build the WASMTransitionCircuit from each traced execution frame and then batch them into
    // size `step_size`
    let circuits: Vec<WASMTransitionCircuit> = execution_trace
      .into_iter()
      .map(|vm| {
        let (step_rs, step_ws) = step_RS_WS(&vm, &mut FS, &mut global_ts, &IS_sizes);
        RS.push(step_rs.clone());
        WS.push(step_ws.clone());
        WASMTransitionCircuit::new(vm, step_rs, step_ws, IS_sizes)
      })
      .collect();
    let circuits = circuits
      .chunks(step_size.execution)
      .map(|chunk| BatchedWasmTransitionCircuit::new(chunk.to_vec()))
      .collect::<Vec<_>>();

    /*
     * ************** WASM Transition Circuit Proving **************
     */

    // F represents the transition function of the WASM VM.
    //
    // We use commitment-carrying IVC to prove the repeated execution of F
    let mut rs_option: Option<RecursiveSNARK<E>> = None;
    let z0 = vec![pc, sp];
    let mut IC_i = E::Scalar::ZERO;
    let execution_pp = pp.F();
    for (i, circuit) in circuits.iter().enumerate() {
      tracing::debug!("Proving step {}/{}", i + 1, circuits.len());
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
     * ************** Prove grand products for MCC **************
     */

    // Get MCC public parameters
    let ops_pp = pp.ops();
    let scan_pp = pp.scan();

    // Build ops circuits
    let ops_circuits = RS
      .into_iter()
      .zip_eq(WS.into_iter())
      .map(|(rs, ws)| OpsCircuit::new(rs, ws))
      .collect::<Vec<_>>();
    let ops_circuits = ops_circuits
      .chunks(step_size.execution)
      .map(|chunk| BatchedOpsCircuit::new(chunk.to_vec()))
      .collect::<Vec<_>>();

    // Pad IS and FS , so length is a multiple of step_size
    {
      let len = IS.len();
      let pad_len = (step_size.memory - (len % step_size.memory)) % step_size.memory;
      IS.extend((len..len + pad_len).map(|i| (i, 0, 0)));
      FS.extend((len..len + pad_len).map(|i| (i, 0, 0)));
    }

    // sanity check
    assert_eq!(IS.len() % step_size.memory, 0);

    // Build the Audit MCC circuits.
    //
    // 1. To get the challenges alpha and gamma we first have to compute the incremental
    //    commitmenents to the multisets IS and FS
    //
    // 2. We chunk IS and FS into `step_size.memory` sized chunks and build the [`ScanCircuit`]
    let mut scan_IC_i = (E::Scalar::ZERO, E::Scalar::ZERO);
    let mut IC_IS = E::Scalar::ZERO;
    let mut IC_FS = E::Scalar::ZERO;
    let mut scan_circuits = Vec::new();
    for (IS_chunk, FS_chunk) in IS
      .chunks(step_size.memory)
      .zip_eq(FS.chunks(step_size.memory))
    {
      IC_IS = IC::<E>::commit(
        &scan_pp.ck_primary,
        &scan_pp.ro_consts,
        IC_IS,
        IS_chunk
          .iter()
          .flat_map(|avt| avt_tuple_to_scalar_vec(*avt))
          .collect(),
      );
      IC_FS = IC::<E>::commit(
        &scan_pp.ck_primary,
        &scan_pp.ro_consts,
        IC_FS,
        FS_chunk
          .iter()
          .flat_map(|avt| avt_tuple_to_scalar_vec(*avt))
          .collect(),
      );
      let scan_circuit = ScanCircuit::new(IS_chunk.to_vec(), FS_chunk.to_vec());
      scan_circuits.push(scan_circuit);
    }

    // Get gamma and alpha
    let mut keccak = E::TE::new(b"compute MCC challenges");
    keccak.absorb(b"C_n", &IC_i);
    keccak.absorb(b"IC_IS", &IC_IS);
    keccak.absorb(b"IC_FS", &IC_FS);
    let gamma = keccak.squeeze(b"gamma")?;
    let alpha = keccak.squeeze(b"alpha")?;

    /*
     * Grand product checks for RS & WS
     */

    // z0 <- [gamma, alpha, ts=gts, h_RS=1, h_WS=1]
    let ops_z0 = vec![
      gamma,
      alpha,
      E::Scalar::from(IS_gts),
      E::Scalar::ONE,
      E::Scalar::ONE,
    ];
    let mut ops_IC_i = E::Scalar::ZERO;
    let mut ops_rs_option: Option<RecursiveSNARK<E>> = None;
    tracing::debug!("Proving MCC ops circuits");
    for (i, ops_circuit) in ops_circuits.iter().enumerate() {
      tracing::debug!("Proving step {}/{}", i + 1, ops_circuits.len());
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

    // z0 <- [gamma, alpha, h_IS=1, h_FS=1]
    let scan_z0 = vec![gamma, alpha, E::Scalar::ONE, E::Scalar::ONE];
    let mut scan_rs_option: Option<AuditRecursiveSNARK<E>> = None;
    tracing::debug!("Proving MCC audit circuits");
    for (i, scan_circuit) in scan_circuits.iter().enumerate() {
      tracing::debug!("Proving step {}/{}", i + 1, scan_circuits.len());
      let mut scan_rs = scan_rs_option.unwrap_or_else(|| {
        AuditRecursiveSNARK::new(scan_pp, scan_circuit, &scan_z0)
          .expect("failed to construct initial recursive SNARK")
      });
      scan_rs.prove_step(scan_pp, scan_circuit, scan_IC_i)?;
      scan_IC_i = scan_rs.increment_commitment(scan_pp, scan_circuit);
      scan_rs_option = Some(scan_rs)
    }

    // internal check
    let scan_rs = scan_rs_option.ok_or(ZKWASMError::MalformedRS)?;
    scan_rs.verify(scan_pp, scan_rs.num_steps(), &scan_z0, scan_IC_i)?;
    debug_assert_eq!(scan_IC_i, (IC_IS, IC_FS));

    // Instance for [`WasmSNARK`]
    let U = ZKWASMInstance {
      execution_z0: z0,
      IC_i,
      ops_z0,
      ops_IC_i,
      scan_z0,
      scan_IC_i,
    };

    Ok((
      Self::Recursive(Box::new(RecursiveWasmSNARK {
        execution_rs: rs,
        ops_rs,
        scan_rs,
      })),
      U,
    ))
  }

  /// Apply Spartan on top of the Nebula IVC proofs
  pub fn compress(
    &self,
    pp: &WASMPublicParams<E, S1, S2>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    match self {
      Self::Recursive(rs) => Ok(Self::Compressed(Box::new(CompressedSNARK::prove(
        pp,
        pp.pk(),
        rs.as_ref(),
        U.into(),
      )?))),
      Self::Compressed(..) => Err(ZKWASMError::NotRecursive),
    }
  }

  /// Verify the [`WasmSNARK`]
  pub fn verify(
    &self,
    pp: &WASMPublicParams<E, S1, S2>,
    U: &ZKWASMInstance<E>,
  ) -> Result<(), ZKWASMError> {
    match self {
      Self::Recursive(rs) => {
        // verify F
        rs.execution_rs
          .verify(pp.F(), rs.execution_rs.num_steps(), &U.execution_z0, U.IC_i)?;

        // verify F_ops
        let ops_zi = rs
          .ops_rs
          .verify(pp.ops(), rs.ops_rs.num_steps(), &U.ops_z0, U.ops_IC_i)?;

        // verify F_scan
        let scan_zi =
          rs.scan_rs
            .verify(pp.scan(), rs.scan_rs.num_steps(), &U.scan_z0, U.scan_IC_i)?;

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
        keccak.absorb(b"IC_IS", &U.scan_IC_i.0);
        keccak.absorb(b"IC_FS", &U.scan_IC_i.1);
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
      }
      Self::Compressed(snark) => snark.verify(pp, pp.vk())?,
    }

    Ok(())
  }
}

/// Helper function to construct IS when WASM program is being sharded
pub fn construct_IS(
  shard_size: usize,
  step_size: StepSize,
  is_sharded: bool,
  IS_execution_trace: Vec<WitnessVM>,
  IS: &mut [(usize, u64, u64)],
  global_ts: &mut u64,
  IS_sizes: &ISMemSizes,
) {
  // Calculate shard size
  let sharding_pad_len = if shard_size % step_size.execution != 0 && is_sharded {
    step_size.execution - (shard_size % step_size.execution)
  } else {
    0
  };

  IS_execution_trace.iter().enumerate().for_each(|(i, vm)| {
    if i != 0 && i % shard_size == 0 {
      IS_padding(sharding_pad_len, IS, global_ts, IS_sizes);
    }
    let _ = step_RS_WS(vm, IS, global_ts, IS_sizes);
  });
  if !IS_execution_trace.is_empty() && is_sharded {
    IS_padding(sharding_pad_len, IS, global_ts, IS_sizes);
  }
}

fn IS_padding(
  sharding_pad_len: usize,
  IS: &mut [(usize, u64, u64)],
  global_ts: &mut u64,
  IS_sizes: &ISMemSizes,
) {
  for _ in 0..sharding_pad_len {
    let _ = step_RS_WS(&WitnessVM::default(), IS, global_ts, IS_sizes);
  }
}

impl<E> Layer1RSTrait<E> for RecursiveWasmSNARK<E>
where
  E: CurveCycleEquipped,
{
  fn F(&self) -> &RecursiveSNARK<E> {
    &self.execution_rs
  }

  fn ops(&self) -> &RecursiveSNARK<E> {
    &self.ops_rs
  }

  fn scan(&self) -> &AuditRecursiveSNARK<E> {
    &self.scan_rs
  }
}

/// Public i/o for WASM execution proving
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ZKWASMInstance<E>
where
  E: CurveCycleEquipped,
{
  // execution instance
  execution_z0: Vec<E::Scalar>,
  IC_i: E::Scalar,

  // ops instance
  ops_z0: Vec<E::Scalar>,
  ops_IC_i: E::Scalar,

  // scan instance
  scan_z0: Vec<E::Scalar>,
  scan_IC_i: (E::Scalar, E::Scalar),
}

impl<E> From<&ZKWASMInstance<E>> for NebulaInstance<E>
where
  E: CurveCycleEquipped,
{
  fn from(value: &ZKWASMInstance<E>) -> Self {
    NebulaInstance::new(
      value.execution_z0.clone(),
      value.IC_i,
      value.ops_z0.clone(),
      value.ops_IC_i,
      value.scan_z0.clone(),
      value.scan_IC_i,
    )
  }
}

impl<E> MemoryCommitmentsTraits<E> for ZKWASMInstance<E>
where
  E: CurveCycleEquipped,
{
  fn C_IS(&self) -> <E as Engine>::Scalar {
    self.scan_IC_i.0
  }

  fn C_FS(&self) -> <E as Engine>::Scalar {
    self.scan_IC_i.1
  }
}
/// Step size of used for zkVM execution
#[derive(Clone, Debug, Copy)]
pub struct StepSize {
  execution: usize,
  memory: usize,
}

impl StepSize {
  /// Create a new instance of [`StepSize`]
  ///
  /// Sets both execution and memory step size to `step_size`
  pub fn new(step_size: usize) -> Self {
    Self {
      execution: step_size,
      memory: step_size,
    }
  }

  /// Set the memory step size
  ///
  /// Returns a modified instance of [`StepSize`]
  pub fn set_memory_step_size(mut self, memory: usize) -> Self {
    self.memory = memory;
    self
  }
}
