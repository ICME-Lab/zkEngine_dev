//! Implements SNARK proving the WASM module computation

use super::{
  error::ZKWASMError,
  wasm_ctx::{MemorySize, ZKWASMCtx},
};
use crate::wasm_ctx::{InitMemData, MemorySetupTrait};

use itertools::Itertools;

use memory_trace::memory_ops_trace;
use nova::{
  errors::NovaError,
  nova::nebula::api::{
    NebulaInstance, NebulaPublicParams, NebulaSNARK, RecursiveSNARKEngine,
    StepSize as NebulaStepSize,
  },
  traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};
use serde::{Deserialize, Serialize};
use switchboard::{BatchedWasmTransitionCircuit, WASMTransitionCircuit};
use wasmi::WitnessVM;

mod gadgets;
pub(crate) mod memory_trace;
mod switchboard;

/// Maximum number of memory ops allowed per step of the zkVM
pub const MEMORY_OPS_PER_STEP: usize = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
/// A SNARK that proves the correct execution of a WASM modules execution
pub struct WasmSNARK<E1, E2, S1, S2>
where
  E1: Engine<Base = <E2 as Engine>::Scalar>,
  E2: Engine<Base = <E1 as Engine>::Scalar>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<E2>,
{
  nebula_snark: NebulaSNARK<E1, E2, S1, S2, MEMORY_OPS_PER_STEP>,
}

impl<E1, E2, S1, S2> WasmSNARK<E1, E2, S1, S2>
where
  E1: Engine<Base = <E2 as Engine>::Scalar>,
  E2: Engine<Base = <E1 as Engine>::Scalar>,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<E2>,
  <E1 as Engine>::Scalar: PartialOrd,
{
  /// Fn used to obtain setup material for producing succinct arguments for
  /// WASM program executions
  pub fn setup(
    step_size: StepSize,
  ) -> Result<NebulaPublicParams<E1, E2, S1, S2, MEMORY_OPS_PER_STEP>, ZKWASMError> {
    NebulaSNARK::setup(
      &BatchedWasmTransitionCircuit::empty(step_size.execution),
      step_size.into(),
    )
    .map_err(Into::into)
  }

  #[tracing::instrument(skip_all, name = "WasmSNARK::prove")]
  /// Produce a SNARK for WASM execution context
  pub fn prove(
    pp: &NebulaPublicParams<E1, E2, S1, S2, MEMORY_OPS_PER_STEP>,
    program: &impl ZKWASMCtx,
    step_size: StepSize,
  ) -> Result<(Self, NebulaInstance<E1>), ZKWASMError> {
    let (execution_trace, (init_memory, final_memory, read_ops, write_ops), memory_size) =
      WASMVirtualMachine::execution_and_memory_trace(program, step_size)?;

    // --- Run the F (transition) circuit ---
    //
    // We use commitment-carrying IVC to prove the repeated execution of F
    let F_engine = FetchDecodeExecuteEngine::new(
      read_ops.clone(),
      write_ops.clone(),
      execution_trace,
      memory_size,
      step_size,
    );

    // Prove vm execution and memory consistency
    let (nebula_snark, U) = NebulaSNARK::prove(
      pp,
      step_size.into(),
      (init_memory, final_memory, read_ops, write_ops),
      F_engine,
    )?;
    Ok((Self { nebula_snark }, U))
  }

  #[tracing::instrument(skip_all, name = "WasmSNARK::verify")]
  /// Verify a SNARK for WASM execution context
  pub fn verify(
    &self,
    pp: &NebulaPublicParams<E1, E2, S1, S2, MEMORY_OPS_PER_STEP>,
    U: &NebulaInstance<E1>,
  ) -> Result<(), ZKWASMError> {
    self.nebula_snark.verify(pp, U).map_err(Into::into)
  }

  #[tracing::instrument(skip_all, name = "WasmSNARK::compress")]
  /// Use Spartan to prove knowledge of a valid IVC proof
  pub fn compress(
    &self,
    pp: &NebulaPublicParams<E1, E2, S1, S2, MEMORY_OPS_PER_STEP>,
    U: &NebulaInstance<E1>,
  ) -> Result<Self, ZKWASMError> {
    Ok(Self {
      nebula_snark: self.nebula_snark.compress(pp, U)?,
    })
  }
}

// IS, FS, RS, WS
type VMMultiSets = (
  Vec<(usize, u64, u64)>,
  Vec<(usize, u64, u64)>,
  Vec<Vec<(usize, u64, u64)>>,
  Vec<Vec<(usize, u64, u64)>>,
);

struct WASMVirtualMachine;

impl WASMVirtualMachine {
  fn execution_and_memory_trace(
    program: &impl ZKWASMCtx,
    step_size: StepSize,
  ) -> Result<(Vec<WitnessVM>, VMMultiSets, MemorySize), ZKWASMError> {
    let (
      mut execution_trace,
      InitMemData {
        mut init_memory,
        memory_size,
        mut global_ts,
      },
    ) = program
      .execution_trace()?
      .setup_init_memory(program.args(), step_size)?;

    // --- Pad the execution trace, so its length is a multiple of `step_size`. ---
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
    let mut zkvm_memory = init_memory.clone();
    let mut read_ops: Vec<Vec<(usize, u64, u64)>> = Vec::new();
    let mut write_ops: Vec<Vec<(usize, u64, u64)>> = Vec::new();
    Self::memory_ops(
      &execution_trace,
      &mut read_ops,
      &mut write_ops,
      &mut zkvm_memory,
      &mut global_ts,
      memory_size,
    );
    // Pad IS and FS , so length is a multiple of step_size
    Self::pad_multisets(&mut init_memory, &mut zkvm_memory, step_size.memory);
    Ok((
      execution_trace,
      (init_memory, zkvm_memory, read_ops, write_ops),
      memory_size,
    ))
  }

  fn memory_ops(
    execution_trace: &[WitnessVM],
    read_ops: &mut Vec<Vec<(usize, u64, u64)>>,
    write_ops: &mut Vec<Vec<(usize, u64, u64)>>,
    zkvm_memory: &mut [(usize, u64, u64)],
    global_ts: &mut u64,
    memory_size: MemorySize,
  ) {
    execution_trace.iter().for_each(|vm| {
      let (step_rs, step_ws) = memory_ops_trace(vm, zkvm_memory, global_ts, memory_size);
      read_ops.push(step_rs);
      write_ops.push(step_ws);
    });
  }

  fn pad_multisets(
    ms_a: &mut Vec<(usize, u64, u64)>,
    ms_b: &mut Vec<(usize, u64, u64)>,
    size: usize,
  ) {
    let len = ms_a.len();
    let pad_len = (size - (len % size)) % size;
    ms_a.extend((len..len + pad_len).map(|i| (i, 0, 0)));
    ms_b.extend((len..len + pad_len).map(|i| (i, 0, 0)));
  }
}

struct FetchDecodeExecuteEngine {
  read_ops: Vec<Vec<(usize, u64, u64)>>,
  write_ops: Vec<Vec<(usize, u64, u64)>>,
  execution_trace: Vec<WitnessVM>,
  memory_size: MemorySize,
  step_size: StepSize,
}

impl FetchDecodeExecuteEngine {
  fn new(
    read_ops: Vec<Vec<(usize, u64, u64)>>,
    write_ops: Vec<Vec<(usize, u64, u64)>>,
    execution_trace: Vec<WitnessVM>,
    memory_size: MemorySize,
    step_size: StepSize,
  ) -> Self {
    Self {
      read_ops,
      write_ops,
      execution_trace,
      memory_size,
      step_size,
    }
  }
}

impl<E1, E2> RecursiveSNARKEngine<E1, E2> for FetchDecodeExecuteEngine
where
  E1: Engine<Base = <E2 as Engine>::Scalar>,
  E2: Engine<Base = <E1 as Engine>::Scalar>,
{
  type Circuit = BatchedWasmTransitionCircuit;

  fn circuits(&mut self) -> Result<Vec<Self::Circuit>, NovaError> {
    // Build WASMTransitionCircuit from the stored RS and WS multisets.
    let circuits = self
      .execution_trace
      .iter()
      .zip_eq(self.read_ops.iter().zip_eq(self.write_ops.iter()))
      .map(|(vm, (r, w))| WASMTransitionCircuit::new(*vm, r.clone(), w.clone(), self.memory_size))
      .collect_vec();
    Ok(
      circuits
        .chunks(self.step_size.execution)
        .map(|chunk| BatchedWasmTransitionCircuit::new(chunk.to_vec()))
        .collect::<Vec<_>>(),
    )
  }

  fn z0(&self) -> Vec<E1::Scalar> {
    // The F initial input is [pc, pre_sp]
    vec![
      E1::Scalar::from(self.execution_trace[0].pc as u64),
      E1::Scalar::from(self.execution_trace[0].pre_sp as u64),
    ]
  }
}

/// Step size of used for zkVM execution
#[derive(Clone, Debug, Copy)]
pub struct StepSize {
  /// How many opcodes to execute per recursive step
  pub execution: usize,
  /// How many memory addresses to audit per recursive step
  pub memory: usize,
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

impl From<StepSize> for NebulaStepSize {
  fn from(value: StepSize) -> Self {
    Self {
      execution: value.execution,
      memory: value.memory,
    }
  }
}
