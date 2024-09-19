//! This module contains util function to check Public Params hash
use nova::traits::{
  snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
  CurveCycleEquipped, Dual, Engine,
};

use crate::{
  circuits::{execution::batched::super_nova_public_params, supernova::batched_rom::BatchedROM},
  traits::wasm::ZKWASMContext,
  utils::nivc::batch_execution_trace,
};

/// Check if the hash of the public params is correct
pub fn pp_hash_check<E1, BS1, S2>(
  wasm_ctx: &mut impl ZKWASMContext,
  pp_digest: <E1 as Engine>::Scalar,
) -> anyhow::Result<bool>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd,
  BS1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  // Get execution trace
  let (etable, _) = wasm_ctx.build_execution_trace()?;

  // Batch execution trace in batched
  let (execution_trace, rom) = batch_execution_trace(&etable)?;

  // Build large step circuits
  let batched_rom = BatchedROM::<E1>::new(rom, execution_trace.to_vec());

  // Get SuperNova public params and prove execution
  let pp = super_nova_public_params::<E1, BS1, S2>(&batched_rom)?;

  Ok(pp.digest() == pp_digest)
}

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use nova::{
    provider::{ipa_pc, PallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::Dual,
  };

  use crate::{
    provider::BatchedWasmSNARK,
    traits::zkvm::WasmSNARKTrait,
    utils::logging::init_logger,
    wasm::{args::WASMArgsBuilder, ctx::wasi::WasiWASMCtx},
  };

  use super::pp_hash_check;

  #[test]
  fn test_pp_hash_check() -> anyhow::Result<()> {
    type E1 = PallasEngine;
    type EE1<E> = ipa_pc::EvaluationEngine<E>;
    type EE2<E> = ipa_pc::EvaluationEngine<Dual<E>>;

    type BS1<E> = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1<E>>;
    type S2<E> = RelaxedR1CSSNARK<Dual<E>, EE2<E>>;
    init_logger();

    let args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/misc/fib.wat"))
      .invoke(Some(String::from("fib")))
      .func_args(vec![String::from("1000")])
      .build();

    let mut wasm_ctx = WasiWASMCtx::new_from_file(&args)?;
    let mut cloned_wasm_ctx = WasiWASMCtx::new_from_file(&args)?;

    let pp = BatchedWasmSNARK::setup(&mut wasm_ctx)?;
    let digest = pp.execution_pp.digest();

    let verified = pp_hash_check::<E1, BS1<_>, S2<E1>>(&mut cloned_wasm_ctx, digest)?;
    assert!(verified, "PP hash check failed");
    Ok(())
  }
}
