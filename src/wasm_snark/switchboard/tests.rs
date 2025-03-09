use crate::{
  error::ZKWASMError,
  utils::logging::init_logger,
  wasm_ctx::{wasi::WasiWASMCtx, TraceSliceValues, WASMArgsBuilder, WASMCtx, ZKWASMCtx},
  wasm_snark::{FetchDecodeExecuteEngine, StepSize, WASMVirtualMachine},
};
use nova::frontend::ConstraintSystem;
use nova::frontend::{num::AllocatedNum, test_cs::TestConstraintSystem};
use std::path::PathBuf;

pub type E = Bn256EngineIPA;

fn test_wasm_ctx_with<E>(program: &impl ZKWASMCtx, step_size: StepSize) -> Result<(), ZKWASMError>
where
  E: CurveCycleEquipped,
{
  let (execution_trace, (init_memory, final_memory, read_ops, write_ops), memory_size) =
    WASMVirtualMachine::execution_and_memory_trace(program, step_size)?;

  // --- Run the F (transition) circuit ---
  //
  // We use commitment-carrying IVC to prove the repeated execution of F
  let mut F_engine = FetchDecodeExecuteEngine::new(
    read_ops.clone(),
    write_ops.clone(),
    execution_trace,
    memory_size,
    step_size,
  );

  let circuits = <FetchDecodeExecuteEngine as RecursiveSNARKEngine<E>>::circuits(&mut F_engine)
    .expect("circuits should be constructed");
  let mut zi = <FetchDecodeExecuteEngine as RecursiveSNARKEngine<E>>::z0(&F_engine);
  for (i, circuit) in circuits.iter().enumerate() {
    tracing::info!("prove step: {:#?}", i);
    let mut cs = TestConstraintSystem::<E::Scalar>::new();
    let zi_allocated: Vec<_> = zi
      .iter()
      .enumerate()
      .map(|(i, x)| AllocatedNum::alloc(cs.namespace(|| format!("z{i}_1")), || Ok(*x)))
      .collect::<Result<_, _>>()
      .map_err(|err| ZKWASMError::NovaError(err.into()))?;
    let new_zi_allocated = circuit
      .synthesize(&mut cs, &zi_allocated)
      .map_err(|err| ZKWASMError::NovaError(err.into()))?;
    zi = new_zi_allocated
      .iter()
      .map(|x| x.get_value().unwrap())
      .collect::<Vec<_>>();
    assert!(cs.is_satisfied());
  }

  Ok(())
}

#[test]
fn test_sb_basic() {
  init_logger();
  let step_size = StepSize::new(1);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/basic.wat"))
    .unwrap()
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_basic_i64() {
  init_logger();
  let step_size = StepSize::new(1);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/basic_i64.wat"))
    .unwrap()
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_bit_check() {
  init_logger();
  let step_size = StepSize::new(1);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/bit_check.wat"))
    .unwrap()
    .invoke("bit_check")
    .func_args(vec!["255".to_string(), "255".to_string()])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_eq_func() {
  init_logger();
  let step_size = StepSize::new(600);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/eq_func.wat"))
    .unwrap()
    .invoke("eq_func")
    .func_args(vec!["255".to_string(), "255".to_string()])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_factorial() {
  init_logger();
  let step_size = StepSize::new(500);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/factorial.wasm"))
    .unwrap()
    .invoke("main")
    .func_args(vec!["1000".to_string()])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_poly_transform() {
  init_logger();
  let step_size = StepSize::new(10);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/polynomial-transform.wasm"))
    .unwrap()
    .invoke("main")
    .func_args(vec![
      "1000".to_string(),
      "1000".to_string(),
      "1000".to_string(),
    ])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_small_funcs() {
  init_logger();
  let step_size = StepSize::new(1000);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/small-funcs.wasm"))
    .unwrap()
    .invoke("main")
    .func_args(vec!["10".to_string(), "10".to_string()])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_rotl() {
  init_logger();
  let step_size = StepSize::new(100);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/rotl.wasm"))
    .unwrap()
    .invoke("main")
    .func_args(vec!["100".to_string(), "100".to_string(), "10".to_string()])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_small_ml() {
  init_logger();
  let step_size = StepSize::new(1000);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/small-ml.wasm"))
    .unwrap()
    .invoke("main")
    .func_args(vec![
      "50".to_string(),
      "1".to_string(),
      "2".to_string(),
      "1".to_string(),
    ])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_bulk_ops() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(1000).set_memory_step_size(10_000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/bulk-ops.wat"))?
    .func_args(vec!["200".to_string()])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
  Ok(())
}

#[test]
fn test_sb_memsize() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(1);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/memory/mem_size.wat"))?
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
  Ok(())
}

#[test]
fn test_sb_bradjust0() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(1);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/br_adjust/br_adjust_0.wat"))?
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
  Ok(())
}

#[test]
fn test_sb_integer_hash() {
  let step_size = StepSize::new(500).set_memory_step_size(50_000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/integer_hash.wasm"))
    .unwrap()
    .func_args(vec!["100".to_string()])
    .invoke("integer_hash")
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_gradient_boosting() {
  let step_size = StepSize::new(1000);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
    .unwrap()
    .trace_slice(TraceSliceValues::new(184_000, None))
    .invoke("_start")
    .build();
  let wasm_ctx = WasiWASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_call_indirect() {
  let step_size = StepSize::new(10);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/call_indirect.wasm"))
    .unwrap()
    .func_args(vec!["2".to_string(), "10".to_string(), "10".to_string()])
    .invoke("main")
    .build();
  let wasm_ctx = WasiWASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

#[test]
fn test_sb_dk() {
  init_logger();
  let step_size = StepSize::new(1);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/dk.wat"))
    .unwrap()
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}
