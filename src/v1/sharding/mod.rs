//! This module implements the sharding logic for the zkWASM.
//!
//! i.e. continuations

use super::{
  error::ZKWASMError,
  wasm_snark::{WASMPublicParams, WasmSNARK, ZKWASMInstance},
};
use nova::{
  nebula::l2::sharding::{ShardingPublicParams, ShardingRecursiveSNARK},
  traits::CurveCycleEquipped,
};
/// Generate sharding public parameters
pub fn gen_sharding_pp<E>(wasm_pp: WASMPublicParams<E>) -> ShardingPublicParams<E>
where
  E: CurveCycleEquipped,
{
  ShardingPublicParams::setup(wasm_pp)
}

/// Sharding SNARK used to aggregate [`WasmSNARK`]'s
pub struct ShardingSNARK<E>
where
  E: CurveCycleEquipped,
{
  rs: ShardingRecursiveSNARK<E>,
}

impl<E> ShardingSNARK<E>
where
  E: CurveCycleEquipped,
{
  /// Create a new instance of [`ShardingSNARK`]
  pub fn new(
    pp: &ShardingPublicParams<E>,
    wasm_snark: &WasmSNARK<E>,
    U: &ZKWASMInstance<E>,
  ) -> Result<Self, ZKWASMError> {
    let rs = ShardingRecursiveSNARK::new(pp, wasm_snark, U)?;
    Ok(Self { rs })
  }

  /// Combine the shards [`WasmSNARK`]s
  pub fn prove_sharding(
    &mut self,
    pp: &ShardingPublicParams<E>,
    wasm_snarks: &[WasmSNARK<E>],
    U: &ZKWASMInstance<E>,
  ) -> Result<(), ZKWASMError> {
    for snark in wasm_snarks {
      self.rs.prove_step(pp, snark, U)?;
    }

    Ok(())
  }

  /// Verify the [`ShardingSNARK`]
  pub fn verify(&self, pp: &ShardingPublicParams<E>) -> Result<(), ZKWASMError> {
    self.rs.verify(pp)?;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use nova::{
    nebula::l2::sharding::MemoryCommitmentsTraits, provider::Bn256EngineIPA, traits::Engine,
  };
  use tracing::info_span;

  use super::{gen_sharding_pp, ShardingSNARK};
  use crate::{
    utils::logging::init_logger,
    v1::{
      utils::{
        macros::{start_timer, stop_timer},
        tracing::estimate_wasm,
      },
      wasm_ctx::{TraceSliceValues, WASMArgsBuilder, WasiWASMCtx},
      wasm_snark::{StepSize, WasmSNARK, ZKWASMInstance},
    },
  };
  use ff::Field;
  use std::time::Instant;

  /// Curve Cycle to prove/verify on
  pub type E = Bn256EngineIPA;

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

    let pp = WasmSNARK::<E>::setup(step_size);

    let shard_opcode_size = 500;
    let mut start = 0;
    let mut end = shard_opcode_size;

    let mut node_snarks: Vec<(WasmSNARK<E>, ZKWASMInstance<E>)> = Vec::new();

    let (trace, _, _, _) =
      estimate_wasm(WasiWASMCtx::new(wasm_args_builder.clone().build())).unwrap();
    let trace_len = trace.len();

    let num_shards = {
      let mut res = trace_len / shard_opcode_size;
      if trace_len % shard_opcode_size != 0 {
        res += 1;
      }
      res
    };

    for i in 0..num_shards {
      let shard_proving_timer = start_timer!(format!("Proving Shard {i}"));
      let wasm_ctx = WasiWASMCtx::new(
        wasm_args_builder
          .clone()
          .trace_slice(TraceSliceValues::new(start, end))
          .build(),
      );

      let (snark, U) = WasmSNARK::<E>::prove(&pp, wasm_ctx, step_size).unwrap();
      snark.verify(&pp, &U).unwrap();
      node_snarks.push((snark, U));
      start = end;
      end += shard_opcode_size;
      stop_timer!(shard_proving_timer);
    }

    let sharding_pp_timer = start_timer!("Producing sharding PP");
    let sharding_pp = gen_sharding_pp(pp);
    stop_timer!(sharding_pp_timer);

    let mut sharding_snark =
      ShardingSNARK::new(&sharding_pp, &node_snarks[0].0, &node_snarks[0].1).unwrap();

    for (i, (snark, U)) in node_snarks.iter().enumerate() {
      let sharding_proof_timer = start_timer!(format!("Proving Sharding: shard {i}"));
      sharding_snark
        .prove_sharding(&sharding_pp, &[snark.clone()], U)
        .unwrap();
      stop_timer!(sharding_proof_timer);
    }

    sharding_snark.verify(&sharding_pp).unwrap();
  }
}
