use crate::{
  error::ZKWASMError,
  utils::{
    logging::init_logger,
    macros::{start_timer, stop_timer},
  },
  wasm_ctx::{wasi::WasiWASMCtx, WASMArgsBuilder, WASMCtx, ZKWASMCtx},
  wasm_snark::{StepSize, WASMPublicParams, WasmSNARK, ZKWASMInstance},
};
use nova::{
  provider::{ipa_pc, Bn256EngineIPA},
  spartan,
  traits::Dual,
};
use std::{path::PathBuf, time::Instant};

use super::AggregationSNARK;

/// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;
pub type EE1 = ipa_pc::EvaluationEngine<E>;
pub type EE2 = ipa_pc::EvaluationEngine<Dual<E>>;
pub type S1 = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1>;
pub type S2 = spartan::snark::RelaxedR1CSSNARK<Dual<E>, EE2>;

#[test]
fn test_aggregation_bit_check() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(16);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/bit_check.wat"))
    .unwrap()
    .invoke("bit_check")
    .func_args(vec!["255".to_string(), "255".to_string()])
    .build();

  let wasm_program = WASMCtx::new(wasm_args);
  let num_nodes = 10;

  sim_nodes_and_orchestrator_node(&wasm_program, step_size, num_nodes);

  Ok(())
}

#[test]
fn test_aggregation_int_opcodes() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(100);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/int_opcodes.wat"))
    .unwrap()
    .build();

  let wasm_program = WASMCtx::new(wasm_args);
  let num_nodes = 10;

  sim_nodes_and_orchestrator_node(&wasm_program, step_size, num_nodes);

  Ok(())
}

#[test]
fn test_aggregation_eq_func() -> Result<(), ZKWASMError> {
  let step_size = StepSize::new(500);
  init_logger();
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/eq_func.wat"))
    .unwrap()
    .invoke("eq_func")
    .func_args(vec!["255".to_string(), "255".to_string()])
    .build();

  let wasm_program = WASMCtx::new(wasm_args);
  let num_nodes = 10;

  sim_nodes_and_orchestrator_node(&wasm_program, step_size, num_nodes);

  Ok(())
}

#[test]
fn test_aggregation_zk_ads() {
  init_logger();
  let step_size = StepSize::new(500).set_memory_step_size(50_000);
  let input_x = "200.05";
  let input_y = "-30.0";
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/zk_ads.wasm"))
    .unwrap()
    .func_args(vec![
      String::from("0"),
      String::from(input_x),
      String::from(input_y),
    ])
    .invoke("is_user_close_enough")
    .build();

  let wasm_program = WasiWASMCtx::new(wasm_args);
  let num_nodes = 10;

  sim_nodes_and_orchestrator_node(&wasm_program, step_size, num_nodes);
}

fn sim_nodes_and_orchestrator_node(
  wasm_program: &impl ZKWASMCtx,
  step_size: StepSize,
  num_nodes: usize,
) {
  // Public parameters used by [`WasmSNARK`]
  //
  // All nodes will use the same public parameters
  let node_pp = WasmSNARK::<E, S1, S2>::setup(step_size);

  let (node_snarks, node_instances) = node_nw(&node_pp, wasm_program, num_nodes, step_size);

  /*
   * ********** Aggregation (Orchestrator Node work) **********
   */

  let aggregation_pp = AggregationSNARK::setup(node_pp);

  // This SNARK will testify that all node SNARKs are correct
  let mut aggregation_snark =
    AggregationSNARK::new(&aggregation_pp, &node_snarks[0], &node_instances[0]).unwrap();

  let aggregation_proof_timer = start_timer!("Proving Aggregation");
  aggregation_snark
    .aggregate(&aggregation_pp, &node_snarks, &node_instances)
    .unwrap();

  aggregation_snark.verify(&aggregation_pp).unwrap();
  stop_timer!(aggregation_proof_timer);

  let compressed_snark = aggregation_snark.compress(&aggregation_pp).unwrap();
  compressed_snark
    .verify(aggregation_pp.inner(), aggregation_pp.vk())
    .unwrap();
}

fn node_nw(
  node_pp: &WASMPublicParams<E, S1, S2>,
  wasm_program: &impl ZKWASMCtx,
  num_nodes: usize,
  step_size: StepSize,
) -> (Vec<WasmSNARK<E, S1, S2>>, Vec<ZKWASMInstance<E>>) {
  let mut node_snarks = Vec::new();
  let mut node_instances = Vec::new();

  for i in 0..num_nodes {
    let node_timer = start_timer!(format!("Node Proving {}/{}", i + 1, num_nodes));

    let (snark, U) = WasmSNARK::<E, S1, S2>::prove(node_pp, wasm_program, step_size).unwrap();
    snark.verify(node_pp, &U).unwrap();

    node_snarks.push(snark);
    node_instances.push(U);
    stop_timer!(node_timer);
  }

  (node_snarks, node_instances)
}
