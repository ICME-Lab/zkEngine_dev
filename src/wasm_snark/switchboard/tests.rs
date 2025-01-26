use crate::{
  error::ZKWASMError,
  wasm_ctx::ZKWASMCtx,
  wasm_snark::{mcc::multiset_ops::step_RS_WS, StepSize},
};
use ff::Field;
use nova::{
  nebula::rs::{PublicParams, RecursiveSNARK},
  traits::{snark::default_ck_hint, CurveCycleEquipped},
};
use wasmi::WitnessVM;

use super::{BatchedWasmTransitionCircuit, WASMTransitionCircuit};

fn gen_pp<E>(step_size: StepSize) -> PublicParams<E>
where
  E: CurveCycleEquipped,
{
  PublicParams::<E>::setup(
    &BatchedWasmTransitionCircuit::empty(step_size.execution),
    &*default_ck_hint(),
    &*default_ck_hint(),
  )
}

fn test_wasm_ctx_with<E>(
  pp: &PublicParams<E>,
  program: impl ZKWASMCtx,
  step_size: StepSize,
) -> Result<(), ZKWASMError>
where
  E: CurveCycleEquipped,
{
  let (mut execution_trace, IS, IS_sizes) = program.execution_trace()?;
  let pad_len =
    (step_size.execution - (execution_trace.len() % step_size.execution)) % step_size.execution;
  execution_trace.extend((0..pad_len).map(|_| WitnessVM::default()));
  let mut RS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
  let mut WS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
  let mut FS = IS.clone();
  let mut global_ts = 0;
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
  let mut rs_option: Option<RecursiveSNARK<E>> = None;
  let z0 = vec![E::Scalar::ZERO];
  let mut IC_i = E::Scalar::ZERO;
  for (i, circuit) in circuits.iter().enumerate() {
    tracing::debug!("Proving step {}/{}", i + 1, circuits.len());
    let mut rs = rs_option.unwrap_or_else(|| {
      RecursiveSNARK::new(pp, circuit, &z0).expect("failed to construct initial recursive SNARK")
    });
    rs.prove_step(pp, circuit, IC_i)?;
    IC_i = rs.increment_commitment(pp, circuit);
    rs_option = Some(rs)
  }
  let rs = rs_option.ok_or(ZKWASMError::MalformedRS)?;
  let num_steps = rs.num_steps();
  rs.verify(pp, num_steps, &z0, IC_i)?;
  Ok(())
}
