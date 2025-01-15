//! Implements SNARK proving the WASM module computation
use crate::v1::utils::tracing::split_vector;
use ff::Field;
use itertools::Itertools;
use mcc::{
  multiset_ops::{avt_tuple_to_scalar_vec, step_RS_WS},
  BatchedOpsCircuit, OpsCircuit, ScanCircuit,
};
use nova::{
  nebula::{
    audit_rs::{AuditPublicParams, AuditRecursiveSNARK},
    ic::IC,
    rs::{PublicParams, RecursiveSNARK},
    traits::{Layer1PPTrait, Layer1RSTrait, MemoryCommitmentsTraits},
  },
  traits::{snark::default_ck_hint, CurveCycleEquipped, Engine, TranscriptEngineTrait},
};
use serde::{Deserialize, Serialize};
use wasmi::WitnessVM;

use super::{
  error::ZKWASMError,
  wasm_ctx::{ISMemSizes, ZKWASMCtx},
};
mod gadgets;
mod mcc;
mod switchboard;
use switchboard::{BatchedWasmTransitionCircuit, WASMTransitionCircuit};
/// Maximum number of memory ops allowed per step of the zkVM
pub const MEMORY_OPS_PER_STEP: usize = 8;

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
  IC_IS: E::Scalar,
  IC_FS: E::Scalar,
}

impl<E> MemoryCommitmentsTraits<E> for ZKWASMInstance<E>
where
  E: CurveCycleEquipped,
{
  fn C_IS(&self) -> <E as Engine>::Scalar {
    self.IC_IS
  }

  fn C_FS(&self) -> <E as Engine>::Scalar {
    self.IC_FS
  }
}

/// [`WasmSNARK`] public parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct WASMPublicParams<E>
where
  E: CurveCycleEquipped,
{
  execution_pp: PublicParams<E>,
  ops_pp: PublicParams<E>,
  scan_pp: AuditPublicParams<E>,
}

impl<E> Layer1PPTrait<E> for WASMPublicParams<E>
where
  E: CurveCycleEquipped,
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
pub struct WasmSNARK<E>
where
  E: CurveCycleEquipped,
{
  execution_rs: RecursiveSNARK<E>,
  ops_rs: RecursiveSNARK<E>,
  scan_rs: AuditRecursiveSNARK<E>,
}

impl<E> WasmSNARK<E>
where
  E: CurveCycleEquipped,
{
  /// Fn used to obtain setup material for producing succinct arguments for
  /// WASM program executions
  pub fn setup(step_size: StepSize) -> WASMPublicParams<E> {
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
    }
  }

  #[tracing::instrument(skip_all, name = "WasmSNARK::prove")]
  /// Produce a SNARK for WASM program input
  pub fn prove(
    pp: &WASMPublicParams<E>,
    program: &impl ZKWASMCtx,
    step_size: StepSize,
  ) -> Result<(Self, ZKWASMInstance<E>), ZKWASMError> {
    // We maintain a timestamp counter `globa_ts` that is initialized to
    // the highest timestamp value in IS.
    let mut global_ts = 0;

    // `start_execution_trace` is execution trace starting from opcode 0 to opcode `end` in the WASM
    // program `TraceSliceValues`
    //
    // We do not slice the execution trace at `TraceSliceValues` `start` value because we need the
    // execution trace from opcode 0 to opcode `start` to construct the IS for memory checking and
    // continuations/sharding
    let (start_execution_trace, mut IS, IS_sizes) = program.execution_trace()?;

    // Split the execution trace at `TraceSliceValues` `start` value. Use the first half to
    // construct IS and use the second half for the actual proving of the shard
    let start = program.args().start();
    let (IS_execution_trace, mut execution_trace) = split_vector(start_execution_trace, start);

    // If this is a shard of a WASM program calculate shard size & construct IS
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

    // Construct multisets for MCC
    let mut RS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
    let mut WS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
    let mut FS = IS.clone();

    // Pad the execution trace, so the length is a multiple of step_size
    let non_padded_len = execution_trace.len();
    if non_padded_len % step_size.execution != 0 {
      let pad_len = step_size.execution - (non_padded_len % step_size.execution);
      (0..pad_len).for_each(|_| {
        execution_trace.push(WitnessVM::default());
      })
    }

    tracing::debug!("execution trace length: {:#?}", execution_trace.len());
    tracing::trace!("execution trace: {:#?}", execution_trace);

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
     * ***** WASM Transition Circuit Proving *****
     */
    let mut rs_option: Option<RecursiveSNARK<E>> = None;
    let z0 = vec![E::Scalar::ZERO];
    let mut IC_i = E::Scalar::ZERO;

    // F represents the transition function of the WASM (stack-based) VM.
    // commitment-carrying IVC to prove the repeated execution of F
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
      .chunks(step_size.execution)
      .map(|chunk| BatchedOpsCircuit::new(chunk.to_vec()))
      .collect::<Vec<_>>();
    let mut scan_IC_i = (E::Scalar::ZERO, E::Scalar::ZERO);
    let mut IC_IS = E::Scalar::ZERO;
    let mut IC_FS = E::Scalar::ZERO;
    let mut scan_circuits = Vec::new();

    // Pad IS and FS , so length is a multiple of step_size
    {
      let len = IS.len();
      let pad_len = step_size.memory - (len % step_size.memory);
      (0..pad_len).for_each(|i| {
        IS.push((len + i, 0, 0));
        FS.push((len + i, 0, 0));
      })
    }
    // sanity check
    assert_eq!(IS.len() % step_size.memory, 0);

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

    // Get alpha and gamma
    let mut keccak = E::TE::new(b"compute MCC challenges");
    keccak.absorb(b"C_n", &IC_i);
    keccak.absorb(b"IC_IS", &IC_IS);
    keccak.absorb(b"IC_FS", &IC_FS);
    let gamma = keccak.squeeze(b"gamma")?;
    let alpha = keccak.squeeze(b"alpha")?;

    /*
     * Grand product checks for RS & WS
     */

    /*
     * ***** F_ops proving *****
     */

    // ops_z0 = [gamma, alpha, ts=gts, h_RS=1, h_WS=1]
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

    // scan_z0 = [gamma, alpha, h_IS=1, h_FS=1]
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

    // Public i/o
    let U = ZKWASMInstance {
      execution_z0: z0,
      IC_i,
      ops_z0,
      ops_IC_i,
      scan_z0,
      scan_IC_i,
      IC_IS,
      IC_FS,
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
      pp.F(),
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

  tracing::debug!("shard size: {shard_size}, sharding pad len: {sharding_pad_len}");

  IS_execution_trace.iter().enumerate().for_each(|(i, vm)| {
    if i != 0 && i % shard_size == 0 {
      tracing::debug!("adding {sharding_pad_len} padding at step i: {i}");
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

impl<E> Layer1RSTrait<E> for WasmSNARK<E>
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
