//! Methods for SuperNova PCD (Proof-Carrying Data) network.
//!
//! Methods to prepare and prove WASM files for distributed proving.

pub mod receipt;

#[cfg(test)]
mod tests;
use anyhow::anyhow;
use nova::provider::PallasEngine;
use wasmi_wasi::WasiCtx;

use crate::{
  circuits::{supernova::etable_rom::wasm_nivc, verify::verify_receipts},
  errors::ProvingError,
  utils::nivc::build_rom,
  wasm_ctx::ZKWASMContext,
};

use receipt::Receipt;

// TODO: improve time complexity
/// Prove WASM shard. (Top-Down approach)
/// Returns a receipt which can be used to verify the proof & show that related shards are
/// connected.
///
/// `start` and `end` are parameters to specify the shards range of opcodes to prove.
pub fn prove_shard(
  wasm_ctx: &mut impl ZKWASMContext,
  should_stop: impl Fn() -> bool,
) -> Result<String, ProvingError> {
  // Get the execution trace of Wasm module
  let (etable, _) = wasm_ctx.build_execution_trace().map_err(|_| {
    ProvingError::WasmError(String::from("failed to parse WASM and get execution trace"))
  })?;
  let execution_trace = etable.plain_execution_trace();

  // Build ROM: constrains the sequence of execution order for the opcodes
  let (rom, tracer_values) = build_rom(&execution_trace);

  // TODO: Convert this to Top-Down approach
  // Produce proof by running execution trace through SuperNova (NIVC)
  wasm_nivc::<PallasEngine>(rom, tracer_values, true, &should_stop)?;

  let tracer = &wasm_ctx
    .tracer()
    .map_err(|_| ProvingError::WasmError(String::from("failed to get memory snapshot")))?;
  // Get memory snapshot info to build `Receipt`
  let memory_snapshot = &tracer.borrow().memory_snapshot;
  let system_state = memory_snapshot.system_state().clone();

  // Reciept used to verify the proof & prove related shards are connected
  let receipt = Receipt::new(system_state);
  serde_json::to_string(&receipt).map_err(|error| ProvingError::Unknown(error.to_string()))
}

/// Connects proofs received from parallel proving (sharding).
///
/// Returns a proof to testify that the shards are connected and that their individual proofs are
/// valid.
pub fn connect_shards(receipts: &[Receipt]) -> anyhow::Result<String> {
  verify_receipts(receipts)
}

/// Deserialize JSON receipts into `Receipt`s and call `connect_shards()`.
pub fn verify_json_receipts(receipts: Vec<String>) -> anyhow::Result<String> {
  let num_receipts = receipts.len();
  let receipts = receipts
    .into_iter()
    .filter_map(|receipt| serde_json::from_str(&receipt).ok())
    .collect::<Vec<Receipt>>();

  if num_receipts != receipts.len() {
    return Err(anyhow!("one or more invalid receipts"));
  }

  verify_receipts(&receipts)
}
