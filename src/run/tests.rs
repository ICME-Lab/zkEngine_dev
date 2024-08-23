use std::{collections::HashMap, path::PathBuf};

use wasmi::mtable::{MTable, MemoryTableEntry};

use crate::{
  args::{WASMArgs, WASMArgsBuilder, WASMCtx},
  traits::{args::ZKWASMContext, zkvm::ZKVM},
  utils::{logging::init_logger, memory::set_linear_addr},
  BatchedZKEngine,
};

#[test]
fn test_gradient_boosting() -> anyhow::Result<()> {
  init_logger();

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
    .invoke(Some(String::from("_start")))
    .build();

  // Create a WASM execution context for proving.
  let pp = BatchedZKEngine::setup(&mut WASMCtx::new_from_file(&args)?)?;

  let mut wasm_ctx = WASMCtx::new_from_file(&args)?;

  let (proof, public_values, _) = BatchedZKEngine::prove_wasm(&mut wasm_ctx, &pp)?;

  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}

#[test]
fn test_zk_ads() -> anyhow::Result<()> {
  init_logger();

  let input_x = "200.05";
  let input_y = "-30.0";

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/zk_ads.wasm"))
    .invoke(Some(String::from("is_user_close_enough")))
    .func_args(vec![
      String::from("0"),
      String::from(input_x),
      String::from(input_y),
    ])
    .build();

  // Create a WASM execution context for proving.
  let pp = BatchedZKEngine::setup(&mut WASMCtx::new_from_file(&args)?)?;

  let mut wasm_ctx = WASMCtx::new_from_file(&args)?;

  let (proof, public_values, _) = BatchedZKEngine::prove_wasm(&mut wasm_ctx, &pp)?;

  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}

#[test]
fn test_gradient_boosting_rand() -> anyhow::Result<()> {
  init_logger();
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
    .invoke(Some(String::from("_start")))
    .build();

  test_rand_with(&args)?;

  Ok(())
}

fn test_rand_with(args: &WASMArgs) -> anyhow::Result<()> {
  let (mtrace_0, mtrace_1) = {
    let mut wasm_ctx_0 = WASMCtx::new_from_file(args)?;
    let mut wasm_ctx_1 = WASMCtx::new_from_file(args)?;

    let mtable_0 = get_mtable(&mut wasm_ctx_0)?;

    let mtable_1 = get_mtable(&mut wasm_ctx_1)?;
    assert_eq!(mtable_0.len(), mtable_1.len());
    (mtable_0, mtable_1)
  };

  for (mtrace_0, mtrace_1) in mtrace_0.iter().zip(mtrace_1.iter()) {
    assert_eq!(mtrace_0, mtrace_1);
  }

  Ok(())
}

fn make_m_entries_linear(mut m_entries: Vec<MemoryTableEntry>) -> Vec<MemoryTableEntry> {
  let mut hash_map = HashMap::new();

  for m_entry in m_entries.iter_mut() {
    set_linear_addr(m_entry, &mut hash_map);
  }

  m_entries
}

fn get_mtable(ctx: &mut WASMCtx<WASMArgs>) -> anyhow::Result<Vec<MemoryTableEntry>> {
  let (etable, _) = ctx.build_execution_trace()?;

  // Get imtable
  let tracer = ctx.tracer()?;
  let tracer_binding = tracer.borrow();
  let imtable = tracer_binding.imtable();
  tracing::debug!("imtable: {:?}", imtable.entries().len());

  // Get mtable
  let mtable = etable.mtable(imtable);
  let m_entries = mtable.into_entries();

  Ok(make_m_entries_linear(m_entries))
}

#[test]
fn test_rand() -> anyhow::Result<()> {
  // Example Args
  let example_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();

  // ZK-ADS
  let input_x = "200.05";
  let input_y = "-30.0";

  let zk_ads_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/zk_ads.wasm"))
    .invoke(Some(String::from("is_user_close_enough")))
    .func_args(vec![
      String::from("0"),
      String::from(input_x),
      String::from(input_y),
    ])
    .build();

  test_rand_with(&example_args)?;
  test_rand_with(&zk_ads_args)?;

  Ok(())
}
