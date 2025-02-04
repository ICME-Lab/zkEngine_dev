use std::path::PathBuf;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use nova::{provider::Bn256EngineIPA, traits::Engine};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
  error::ZKWASMError,
  utils::logging::init_logger,
  wasm_ctx::{wasi::WasiWASMCtx, WASMArgsBuilder, WASMCtx, ZKWASMCtx},
  wasm_snark::mcc::multiset_ops::step_RS_WS,
};

/// Curve Cycle to prove/verify on
type E = Bn256EngineIPA;
type F = <E as Engine>::Scalar;

#[allow(dead_code)]
fn alloc_scalar_vec<F, CS>(mut cs: CS, z: &[F]) -> Result<Vec<AllocatedNum<F>>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  z.iter()
    .enumerate()
    .map(|(i, zi)| AllocatedNum::alloc(cs.namespace(|| format!("z{i}")), || Ok(*zi)))
    .collect()
}

fn test_mcc<F>(program: impl ZKWASMCtx, mut rng: impl RngCore) -> Result<(), ZKWASMError>
where
  F: PrimeField,
{
  // We maintain a timestamp counter `globa_ts` that is initialized to
  // the highest timestamp value in IS.
  let mut global_ts = 0;

  // Compute multisets to perform grand product checks (uses global_ts)

  let (execution_trace, IS, IS_sizes) = program.execution_trace()?;

  let mut RS: Vec<(usize, u64, u64)> = Vec::new();
  let mut WS: Vec<(usize, u64, u64)> = Vec::new();
  let mut FS = IS.clone();

  tracing::debug!("execution trace length: {:#?}", execution_trace.len());
  tracing::trace!("execution trace: {:#?}", execution_trace);

  // Build the WASMTransitionCircuit from each traced execution frame.
  execution_trace.into_iter().for_each(|vm| {
    let (step_rs, step_ws) = step_RS_WS(&vm, &mut FS, &mut global_ts, &IS_sizes);

    RS.extend(step_rs);
    WS.extend(step_ws);
  });

  let gamma = F::random(&mut rng);
  let gamma_squared = gamma.square();
  let alpha = F::random(&mut rng);

  let hash_func = |avt: (F, F, F)| -> F { avt.0 + avt.1 * gamma + avt.2 * gamma_squared - alpha };
  let int_to_fe =
    |(a, v, t): (usize, u64, u64)| -> (F, F, F) { (F::from(a as u64), F::from(v), F::from(t)) };

  let F_ops = |RS: Vec<(usize, u64, u64)>, WS: Vec<(usize, u64, u64)>| -> (F, F) {
    let h_RS = RS
      .into_iter()
      .map(int_to_fe)
      .map(hash_func)
      .fold(F::ONE, |acc, x| acc * x);
    let h_WS = WS
      .into_iter()
      .map(int_to_fe)
      .map(hash_func)
      .fold(F::ONE, |acc, x| acc * x);

    (h_RS, h_WS)
  };

  let F_scan = |IS: Vec<(usize, u64, u64)>, FS: Vec<(usize, u64, u64)>| {
    let h_IS = IS
      .into_iter()
      .map(int_to_fe)
      .map(hash_func)
      .fold(F::ONE, |acc, x| acc * x);
    let h_FS = FS
      .into_iter()
      .map(int_to_fe)
      .map(hash_func)
      .fold(F::ONE, |acc, x| acc * x);

    (h_IS, h_FS)
  };

  let (h_RS, h_WS) = F_ops(RS, WS);
  let (h_IS, h_FS) = F_scan(IS, FS);

  // Check that the grand product of RS and WS is equal to the grand product of IS and FS
  assert_eq!(h_IS * h_WS, h_RS * h_FS);
  Ok(())
}

#[test]
fn test_mcc_integer_hash() {
  let mut rng = StdRng::from_seed([1; 32]);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/integer_hash.wasm"))
    .unwrap()
    .func_args(vec!["100".to_string()])
    .invoke("integer_hash")
    .build();

  let wasm_ctx = WASMCtx::new(wasm_args);
  test_mcc::<F>(wasm_ctx, &mut rng).unwrap();
}

#[test]
fn test_mcc_gradient_boosting() {
  init_logger();
  let mut rng = StdRng::from_seed([1; 32]);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
    .unwrap()
    .invoke("_start")
    .build();

  let wasm_ctx = WasiWASMCtx::new(wasm_args);
  test_mcc::<F>(wasm_ctx, &mut rng).unwrap();
}
