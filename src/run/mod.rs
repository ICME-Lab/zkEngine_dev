//! The run module contains the different run strategies that can be used to run the zkVM.

pub mod batched;
pub mod default;

#[cfg(test)]
mod tests;

#[cfg(not(target_arch = "wasm32"))]
pub mod cli_utils {
  //! This module contains the CLI utilities for the zkEngine.
  use crate::{
    provider::E,
    traits::zkvm::WasmSNARKTrait,
    wasm::{args::WASMArgs, ctx::wasi::WasiWASMCtx},
  };

  use crate::traits::wasm::ZKWASMArgs;

  use super::{batched, default};

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
      let pp =
        batched::WasmExecutionSNARK::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      let _ = batched::WasmExecutionSNARK::<E>::prove_wasm_execution(
        &mut WasiWASMCtx::new_from_file(wasm_args)?,
        &pp,
      )?;
    } else {
      let pp =
        default::WasmExecutionSNARK::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      let _ = default::WasmExecutionSNARK::<E>::prove_wasm_execution(
        &mut WasiWASMCtx::new_from_file(wasm_args)?,
        &pp,
      )?;
    }
    Ok(())
  }

  /// Runs proving system on execution trace and memory trace
  fn prove_mcc_and_execution(wasm_args: &WASMArgs, batched: bool) -> anyhow::Result<()> {
    if batched {
      let pp = batched::WasmSNARK::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      batched::WasmSNARK::<E>::prove_wasm(&mut WasiWASMCtx::new_from_file(wasm_args)?, &pp)?;
    } else {
      let pp = default::WasmSNARK::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      default::WasmSNARK::<E>::prove_wasm(&mut WasiWASMCtx::new_from_file(wasm_args)?, &pp)?;
    }
    Ok(())
  }
}
