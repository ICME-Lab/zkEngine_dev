//! The run module contains the different run strategies that can be used to run the zkVM.

pub mod batched;
pub mod default;

#[cfg(test)]
mod tests;

#[cfg(not(target_arch = "wasm32"))]
pub mod cli_utils {
  //! This module contains the CLI utilities for the zkEngine.
  use crate::{
    traits::zkvm::ZKVM,
    wasm::{args::WASMArgs, ctx::wasi::WasiWASMCtx},
    E,
  };

  use super::{
    batched::{BatchedZKEExecutionProof, BatchedZKEProof},
    default::{ZKEExecutionProof, ZKEProof},
  };
  use crate::traits::wasm::ZKWASMArgs;

  /// Function for user to test the zkEngine
  ///
  /// # Note
  ///
  /// This is for testing purposes only
  pub fn prove_wasm_test(wasm_args: &WASMArgs, batched: bool) -> anyhow::Result<()> {
    // Get start flag or default to 0
    let start = wasm_args.trace_slice_values().start();

    // You cannot run MCC from any other starting point than 0
    // Therefore if start is not 0, we only run the execution proof
    // Otherwise we run both MCC and execution proof
    if start != 0 {
      tracing::info!("Adding start flag results in not running MCC proving");
      prove_execution(wasm_args, batched)
    } else {
      prove_mcc_and_execution(wasm_args, batched)
    }
  }

  /// Runs proving system on only execution trace
  pub fn prove_execution(wasm_args: &WASMArgs, batched: bool) -> anyhow::Result<()> {
    if batched {
      let pp = BatchedZKEExecutionProof::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      let _ = BatchedZKEExecutionProof::<E>::prove_wasm_execution(
        &mut WasiWASMCtx::new_from_file(wasm_args)?,
        &pp,
      )?;
    } else {
      let pp = ZKEExecutionProof::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      let _ = ZKEExecutionProof::<E>::prove_wasm_execution(
        &mut WasiWASMCtx::new_from_file(wasm_args)?,
        &pp,
      )?;
    }
    Ok(())
  }

  /// Runs proving system on execution trace and memory trace
  fn prove_mcc_and_execution(wasm_args: &WASMArgs, batched: bool) -> anyhow::Result<()> {
    if batched {
      let pp = BatchedZKEProof::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      BatchedZKEProof::<E>::prove_wasm(&mut WasiWASMCtx::new_from_file(wasm_args)?, &pp)?;
    } else {
      let pp = ZKEProof::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      ZKEProof::<E>::prove_wasm(&mut WasiWASMCtx::new_from_file(wasm_args)?, &pp)?;
    }
    Ok(())
  }
}
