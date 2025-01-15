use super::{gen_sharding_pp, ShardingSNARK};
use crate::{
  utils::logging::init_logger,
  v1::{
    utils::{
      macros::{start_timer, stop_timer},
      tracing::estimate_wasm,
    },
    wasm_ctx::{TraceSliceValues, WASMArgsBuilder, WasiWASMCtx, ZKWASMCtx},
    wasm_snark::{StepSize, WASMPublicParams, WasmSNARK, ZKWASMInstance},
  },
};
use nova::provider::Bn256EngineIPA;
use std::{path::PathBuf, time::Instant};

/// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

#[test]
fn test_sharding_eq_func_mismatch() {
  init_logger();
  let step_size = StepSize::new(100);
  let wasm_args_builder = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/eq_func.wat"))
    .unwrap()
    .invoke("eq_func")
    .func_args(vec!["255".to_string(), "255".to_string()]);

  let shard_opcode_size = 499;

  sim_nodes_and_orchestrator_node(&wasm_args_builder, step_size, shard_opcode_size);
}

#[test]
fn test_sharding_zk_ads() {
  init_logger();
  let step_size = StepSize::new(100).set_memory_step_size(50_000);
  let input_x = "200.05";
  let input_y = "-30.0";
  let wasm_args_builder = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/zk_ads.wasm"))
    .unwrap()
    .func_args(vec![
      String::from("0"),
      String::from(input_x),
      String::from(input_y),
    ])
    .invoke("is_user_close_enough");

  let shard_opcode_size = 500;
  sim_nodes_and_orchestrator_node(&wasm_args_builder, step_size, shard_opcode_size);
}

#[test]
fn test_sharding_bulk_ops() {
  init_logger();
  let step_size = StepSize::new(200).set_memory_step_size(10_000);
  let wasm_args_builder = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/bulk-ops.wat"))
    .unwrap()
    .func_args(vec!["200".to_string()]);

  let shard_opcode_size = 1000;
  sim_nodes_and_orchestrator_node(&wasm_args_builder, step_size, shard_opcode_size);
}

#[test]
fn test_sharding_kth_factor() {
  init_logger();
  let step_size = StepSize::new(200).set_memory_step_size(50_000);
  let wasm_args_builder = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/kth_factor.wat"))
    .unwrap()
    .func_args(vec!["250".to_string(), "15".to_string()])
    .invoke("kth_factor");

  let shard_opcode_size = 1000;
  sim_nodes_and_orchestrator_node(&wasm_args_builder, step_size, shard_opcode_size);
}

#[test]
fn test_sharding_integer_hash() {
  init_logger();
  let step_size = StepSize::new(1_000).set_memory_step_size(50_000);
  let wasm_args_builder = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/integer_hash.wasm"))
    .unwrap()
    .func_args(vec!["100".to_string()])
    .invoke("integer_hash");

  let shard_opcode_size = 10_000;
  sim_nodes_and_orchestrator_node(&wasm_args_builder, step_size, shard_opcode_size);
}

#[test]
fn test_sharding_gradient_boosting() {
  init_logger();
  let step_size = StepSize::new(1_000).set_memory_step_size(50_000);
  let wasm_args_builder = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
    .unwrap()
    .invoke("_start");

  let shard_opcode_size = 10_000;
  sim_nodes_and_orchestrator_node(&wasm_args_builder, step_size, shard_opcode_size);
}

fn sim_nodes_and_orchestrator_node(
  wasm_args_builder: &WASMArgsBuilder,
  step_size: StepSize,
  shard_opcode_size: usize,
) {
  /*
   * ********** Node Network proving **********
   */

  // Public parameters used by [`WasmSNARK`]
  //
  // All nodes will use the same public parameters
  let node_pp = WasmSNARK::<E>::setup(step_size);

  // calculate number of shards from number of opcodes and shard opcode size
  let num_shards = num_shards(
    &WasiWASMCtx::new(wasm_args_builder.clone().build()),
    shard_opcode_size,
  );
  tracing::info!("Number of shards: {num_shards}");
  let (node_snarks, node_instances) = node_nw(
    &node_pp,
    wasm_args_builder,
    num_shards,
    step_size,
    shard_opcode_size,
  );

  /*
   * ********** Sharding proving (Orchestrator Node work) **********
   */

  // Generate sharding public parameters
  //
  // This is the public parameters used by the orchestrator node
  let sharding_pp = gen_sharding_pp(node_pp);

  // Create a new instance of ShardingSNARK with the first node SNARK and instance
  //
  // # Note
  //
  // * You will still need to pass in this first node SNARK and instance when proving sharding
  //
  // * This SNARK will testify that all node SNARKs are correct
  let mut sharding_snark =
    ShardingSNARK::new(&sharding_pp, &node_snarks[0], &node_instances[0]).unwrap();

  // Prove sharding,
  // i.e do some checks and aggregate all the node SNARKS into one
  let sharding_proof_timer = start_timer!(format!("Proving Sharding"));
  sharding_snark
    .prove_sharding(&sharding_pp, &node_snarks, &node_instances)
    .unwrap();
  stop_timer!(sharding_proof_timer);

  // Verify sharding was done correctly
  sharding_snark.verify(&sharding_pp).unwrap();
}

fn num_shards(program: &impl ZKWASMCtx, shard_opcode_size: usize) -> usize {
  let (trace, _, _) = estimate_wasm(program).unwrap();
  let trace_len = trace.len();

  let mut num_shards = trace_len / shard_opcode_size;
  // if there are remainder opcodes, add one more shard
  if trace_len % shard_opcode_size != 0 {
    num_shards += 1;
  }
  num_shards
}

fn node_nw(
  node_pp: &WASMPublicParams<E>,
  wasm_args_builder: &WASMArgsBuilder,
  num_shards: usize,
  step_size: StepSize,
  shard_opcode_size: usize,
) -> (Vec<WasmSNARK<E>>, Vec<ZKWASMInstance<E>>) {
  let mut start = 0;
  let mut end = shard_opcode_size;
  let mut node_snarks = Vec::new();
  let mut node_instances = Vec::new();
  for i in 0..num_shards {
    let shard_proving_timer = start_timer!(format!("Proving Shard {}/{}", i + 1, num_shards));
    let wasm_ctx = WasiWASMCtx::new(
      wasm_args_builder
        .clone()
        .trace_slice(TraceSliceValues::new(start, end))
        .build(),
    );
    let (snark, U) = WasmSNARK::<E>::prove(node_pp, &wasm_ctx, step_size).unwrap();
    snark.verify(node_pp, &U).unwrap();
    node_snarks.push(snark);
    node_instances.push(U);
    start = end;
    end += shard_opcode_size;
    stop_timer!(shard_proving_timer);
  }

  (node_snarks, node_instances)
}

mod test_mismatches {
  use super::*;

  #[test]
  fn test_sharding_zk_ads_mismatch1() {
    init_logger();
    let step_size = StepSize::new(100).set_memory_step_size(50_000);
    let input_x = "200.05";
    let input_y = "-30.0";
    let wasm_args_builder = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/zk_ads.wasm"))
      .unwrap()
      .func_args(vec![
        String::from("0"),
        String::from(input_x),
        String::from(input_y),
      ])
      .invoke("is_user_close_enough");

    let shard_opcode_size = 499;
    sim_nodes_and_orchestrator_node(&wasm_args_builder, step_size, shard_opcode_size);
  }

  #[test]
  fn test_sharding_zk_ads_mismatch2() {
    init_logger();
    let step_size = StepSize::new(99).set_memory_step_size(50_000);
    let input_x = "200.05";
    let input_y = "-30.0";
    let wasm_args_builder = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/zk_ads.wasm"))
      .unwrap()
      .func_args(vec![
        String::from("0"),
        String::from(input_x),
        String::from(input_y),
      ])
      .invoke("is_user_close_enough");

    let shard_opcode_size = 500;
    sim_nodes_and_orchestrator_node(&wasm_args_builder, step_size, shard_opcode_size);
  }

  #[test]
  fn test_sharding_zk_ads_mismatch3() {
    init_logger();
    let step_size = StepSize::new(177).set_memory_step_size(50_000);
    let input_x = "200.05";
    let input_y = "-30.0";
    let wasm_args_builder = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/zk_ads.wasm"))
      .unwrap()
      .func_args(vec![
        String::from("0"),
        String::from(input_x),
        String::from(input_y),
      ])
      .invoke("is_user_close_enough");

    let shard_opcode_size = 1011;
    sim_nodes_and_orchestrator_node(&wasm_args_builder, step_size, shard_opcode_size);
  }
}
