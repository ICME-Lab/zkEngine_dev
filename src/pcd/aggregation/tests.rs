use std::path::PathBuf;

use crate::{
  run::batched::WasmSNARK,
  traits::{be_engine::AggregationEngine, zkvm::WasmSNARKTrait},
  utils::logging::init_logger,
  wasm::{
    args::{WASMArgs, WASMArgsBuilder},
    ctx::wasi::WasiWASMCtx,
  },
};

use super::Aggregator;

/// Use Aggregation Engine as backend for proving the SNARK's to be aggregated
type E = AggregationEngine;

#[test]
#[ignore]
fn test_aggregator_single() -> anyhow::Result<()> {
  init_logger();

  let num_snarks = 1;
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();
  let wasm_pp = WasmSNARK::<E>::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  let snarks = gen_snarks(num_snarks, &args)?;
  tracing::info!("setting up aggregator");
  let (pp, pk, vk, snarks_data) = Aggregator::setup(&wasm_pp, &snarks)?;
  let snark = Aggregator::prove(&pp, &pk, &snarks_data)?;

  Ok(snark.verify(&vk)?)
}

#[test]
#[ignore]
fn test_aggregator() -> anyhow::Result<()> {
  init_logger();

  let num_snarks = 2;
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();
  let wasm_pp = WasmSNARK::<E>::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  let snarks = gen_snarks(num_snarks, &args)?;
  tracing::info!("setting up aggregator");
  let (pp, pk, vk, snarks_data) = Aggregator::setup(&wasm_pp, &snarks)?;
  let snark = Aggregator::prove(&pp, &pk, &snarks_data)?;

  Ok(snark.verify(&vk)?)
}

fn gen_snarks(num_snarks: usize, args: &WASMArgs) -> anyhow::Result<Vec<WasmSNARK<E>>> {
  let mut snarks = Vec::with_capacity(num_snarks);
  for _ in 0..num_snarks {
    let pp = WasmSNARK::<E>::setup(&mut WasiWASMCtx::new_from_file(args)?)?;

    let (snark, _, _) = WasmSNARK::<E>::prove_wasm(&mut WasiWASMCtx::new_from_file(args)?, &pp)?;

    snarks.push(snark)
  }

  Ok(snarks)
}
