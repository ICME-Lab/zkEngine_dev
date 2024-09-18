use std::path::PathBuf;

use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan::{
    self,
    snark::RelaxedR1CSSNARK,
    verify_circuit::aggregator::{self, AggregatedSNARK, AggregatorSNARKData},
  },
  traits::{snark::default_ck_hint, Dual},
};

use crate::{
  run::batched::BatchedZKEProof,
  traits::{public_values::ZKVMPublicParams, zkvm::ZKVM},
  utils::logging::init_logger,
  wasm::{
    args::{WASMArgs, WASMArgsBuilder},
    ctx::wasi::WasiWASMCtx,
  },
};

use super::Aggregator;

#[test]
fn test_aggregator() -> anyhow::Result<()> {
  init_logger();

  let num_snarks = 1;
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();

  let snarks = gen_snarks(num_snarks, &args)?;
  tracing::info!("setting up aggregator");
  let (pp, pk, vk, snarks_data) = Aggregator::setup(&args, &snarks)?;
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

  let snarks = gen_snarks(num_snarks, &args)?;
  tracing::info!("setting up aggregator");
  Aggregator::setup(&args, &snarks)?;

  Ok(())
}

type E1 = PallasEngine;
type BS1 = spartan::verify_circuit::ipa_prover_poseidon::batched::BatchedRelaxedR1CSSNARK<E1>;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

pub type ZKEngine = BatchedZKEProof<E1, BS1, S1, S2>;

type AS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
type AS2 = spartan::batched::BatchedRelaxedR1CSSNARK<Dual<E1>, EE2>;

#[test]
fn test_dummy_aggregator() -> anyhow::Result<()> {
  init_logger();

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();

  let pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  let (proof, public_values, _) =
    ZKEngine::prove_wasm(&mut WasiWASMCtx::new_from_file(&args)?, &pp)?;

  let (s1, U) = proof.execution_proof.agg_snark_data();

  let vk = pp.execution().vk().primary().clone();
  let agg_snark_data = AggregatorSNARKData::new(s1, vk, U);
  let snarks_data = vec![agg_snark_data];

  let agg_pp =
    aggregator::PublicParams::setup(&snarks_data, &default_ck_hint(), &default_ck_hint())?;

  let (agg_pk, agg_vk) = AggregatedSNARK::<E1, AS1, AS2>::setup(&agg_pp)?;
  let snark = AggregatedSNARK::prove(&agg_pp, &agg_pk, &snarks_data)?;

  snark.verify(&agg_vk)?;

  Ok(())
}

#[test]
fn test_vk() -> anyhow::Result<()> {
  init_logger();

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();

  let pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  let (_, public_values, _) = ZKEngine::prove_wasm(&mut WasiWASMCtx::new_from_file(&args)?, &pp)?;

  let snarks = gen_snarks(3, &args)?;

  for snark in snarks.into_iter() {
    snark.verify(public_values.clone(), &pp)?;
  }

  Ok(())
}

fn gen_snarks(num_snarks: usize, args: &WASMArgs) -> anyhow::Result<Vec<ZKEngine>> {
  let mut snarks = Vec::with_capacity(num_snarks);
  for _ in 0..num_snarks {
    let pp = ZKEngine::setup(&mut WasiWASMCtx::new_from_file(args)?)?;

    let (snark, _, _) = ZKEngine::prove_wasm(&mut WasiWASMCtx::new_from_file(args)?, &pp)?;

    snarks.push(snark)
  }

  Ok(snarks)
}
