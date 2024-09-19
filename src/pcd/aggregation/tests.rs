use std::path::PathBuf;

use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan::{self, snark::RelaxedR1CSSNARK},
  traits::Dual,
};

use crate::{
  run::batched::BatchedZKEProof,
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
  wasm::{
    args::{WASMArgs, WASMArgsBuilder},
    ctx::wasi::WasiWASMCtx,
  },
};

use super::Aggregator;

#[test]
fn test_aggregator_single() -> anyhow::Result<()> {
  init_logger();

  let num_snarks = 1;
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();
  let wasm_pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  let snarks = gen_snarks(num_snarks, &args)?;
  tracing::info!("setting up aggregator");
  let (pp, pk, vk, snarks_data) = Aggregator::setup(&wasm_pp, &snarks)?;
  let snark = Aggregator::prove(&pp, &pk, &snarks_data)?;

  Ok(snark.verify(&vk)?)
}

#[test]
fn test_aggregator() -> anyhow::Result<()> {
  init_logger();

  let num_snarks = 2;
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();
  let wasm_pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  let snarks = gen_snarks(num_snarks, &args)?;
  tracing::info!("setting up aggregator");
  let (pp, pk, vk, snarks_data) = Aggregator::setup(&wasm_pp, &snarks)?;
  let snark = Aggregator::prove(&pp, &pk, &snarks_data)?;

  Ok(snark.verify(&vk)?)
}
#[test]
fn test_aggregator_setup() -> anyhow::Result<()> {
  init_logger();

  let num_snarks = 1;
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();
  let wasm_pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  let snarks = gen_snarks(num_snarks, &args)?;
  tracing::info!("setting up aggregator");
  let (_pp, _pk, _vk, _snarks_data) = Aggregator::setup(&wasm_pp, &snarks)?;
  Ok(())
}

type E1 = PallasEngine;
type BS1 = spartan::verify_circuit::ipa_prover_poseidon::batched::BatchedRelaxedR1CSSNARK<E1>;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

pub type ZKEngine = BatchedZKEProof<E1, BS1, S1, S2>;

fn gen_snarks(num_snarks: usize, args: &WASMArgs) -> anyhow::Result<Vec<ZKEngine>> {
  let mut snarks = Vec::with_capacity(num_snarks);
  for _ in 0..num_snarks {
    let pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(args)?)?;

    let (snark, _, _) = ZKEngine::prove_wasm(&mut WasiWASMCtx::new_from_file(args)?, &pp)?;

    snarks.push(snark)
  }

  Ok(snarks)
}
