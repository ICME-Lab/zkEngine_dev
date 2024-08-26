use std::{collections::HashMap, path::PathBuf};

use wasmi::{
  etable::ETable,
  mtable::{LocationType, MemoryTableEntry},
};

use crate::{
  args::{WASMArgs, WASMArgsBuilder, WASMCtx},
  traits::{args::ZKWASMContext, zkvm::ZKVM},
  utils::logging::init_logger,
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

  test_rand_with_mcc(&args)?;

  Ok(())
}

#[test]
fn test_uni_poly_eval() -> anyhow::Result<()> {
  init_logger();
  let x = "1";
  let size = "10";

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/uni-poly-eval.wasm"))
    .invoke(Some(String::from("eval")))
    .func_args(vec![String::from(x), String::from(size)])
    .build();

  test_rand_with_etable(&args)?;

  Ok(())
}

fn test_rand_with_mcc(args: &WASMArgs) -> anyhow::Result<()> {
  let (mtrace_0, mtrace_1) = {
    let mut wasm_ctx_0 = WASMCtx::new_from_file(args)?;
    let mut wasm_ctx_1 = WASMCtx::new_from_file(args)?;

    tracing::info!("Execution trace 0");
    let mtable_0 = get_mtable(&mut wasm_ctx_0)?;

    tracing::info!("Execution trace 1");
    let mtable_1 = get_mtable(&mut wasm_ctx_1)?;
    assert_eq!(mtable_0.len(), mtable_1.len());
    (mtable_0, mtable_1)
  };

  for (mtrace_0, mtrace_1) in mtrace_0.iter().zip(mtrace_1.iter()) {
    // assert_eq!(mtrace_0.value, mtrace_1.value);
    assert_eq!(mtrace_0, mtrace_1);
  }

  Ok(())
}

fn test_rand_with_etable(args: &WASMArgs) -> anyhow::Result<()> {
  let mut wasm_ctx_0 = WASMCtx::new_from_file(args)?;
  let mut wasm_ctx_1 = WASMCtx::new_from_file(args)?;

  tracing::info!("Execution trace 0");
  let (etable_0, _) = wasm_ctx_0.build_execution_trace()?;
  tracing::info!("Execution trace 1");
  let (etable_1, _) = wasm_ctx_1.build_execution_trace()?;
  assert_eq!(etable_0.len(), etable_1.len());

  let mut sp_map_0 = HashMap::new();
  let mut sp_map_1 = HashMap::new();

  for (eentry_0, eentry_1) in etable_0.entries().iter().zip(etable_1.entries().iter()) {
    let mut sp_0 = eentry_0.sp.get_addr();
    let mut sp_1 = eentry_1.sp.get_addr();

    if sp_map_0.contains_key(&sp_0) {
      sp_0 = *sp_map_0.get(&sp_0).unwrap();
    } else {
      // Else new address is the length of the map
      let new_addr = sp_map_0.len();

      // Map the new address to the string address
      sp_map_0.insert(sp_0, new_addr);

      // Set the memory entry address to the new linear address
      sp_0 = new_addr;
    }

    if sp_map_1.contains_key(&sp_1) {
      sp_1 = *sp_map_1.get(&sp_1).unwrap();
    } else {
      // Else new address is the length of the map
      let new_addr = sp_map_1.len();

      // Map the new address to the string address
      sp_map_1.insert(sp_1, new_addr);

      // Set the memory entry address to the new linear address
      sp_1 = new_addr;
    }

    assert_eq!(eentry_0.eid, eentry_1.eid);
    assert_eq!(
      eentry_0.allocated_memory_pages,
      eentry_1.allocated_memory_pages
    );

    if sp_0 != sp_1 {
      tracing::info!("sp_0: {}, sp_1: {}", sp_0, sp_1);
      tracing::info!("eentry_0 {:#?}", eentry_0);
      tracing::info!("eentry_1 {:#?}", eentry_1);
      panic!("sp_0 != sp_1");
    }
  }

  Ok(())
}

fn make_m_entries_linear(
  mut m_entries: Vec<MemoryTableEntry>,
  etable: ETable,
) -> Vec<MemoryTableEntry> {
  let etable = etable.into_entries();
  let mut map = HashMap::new();

  for m_entry in m_entries.iter_mut() {
    if m_entry.ltype != LocationType::Stack {
      continue;
    }
    let addr = m_entry.addr;
    if map.contains_key(&addr) {
      m_entry.addr = *map.get(&addr).unwrap();
    } else {
      // Else new address is the length of the map
      let new_addr = map.len();

      // Map the new address to the string address
      map.insert(addr, new_addr);

      // Set the memory entry address to the new linear address
      m_entry.addr = new_addr;
      tracing::trace!("{:#?}", m_entry);
      let delta = if m_entry.eid == 0 { 0 } else { 1 };
      tracing::trace!("{:#?}", etable[m_entry.eid as usize - delta]);
    }
  }

  m_entries
}

fn get_mtable(ctx: &mut WASMCtx<WASMArgs>) -> anyhow::Result<Vec<MemoryTableEntry>> {
  let (etable, _) = ctx.build_execution_trace()?;
  // Get imtable
  let tracer = ctx.tracer()?;
  let tracer_binding = tracer.borrow();
  let imtable = tracer_binding.imtable();

  // Get mtable
  let mtable = etable.mtable(imtable);
  let m_entries = mtable.into_entries();

  Ok(make_m_entries_linear(m_entries, etable))
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

  test_rand_with_mcc(&example_args)?;
  test_rand_with_mcc(&zk_ads_args)?;

  Ok(())
}
