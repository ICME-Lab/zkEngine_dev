//! The run module contains the different run strategies that can be used to run the zkVM.

use crate::traits::{args::ZKWASMContext, zkvm::ZKVM};
// use batched::{BatchedZKEExecutionProof, BatchedZKEProof};
// use default::{ZKEExecutionProof, ZKEProof};

use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan::{self, snark::RelaxedR1CSSNARK},
  traits::Dual,
};
use wasmi_wasi::WasiCtx;

// pub mod batched;
pub mod default;

#[cfg(test)]
mod tests;

// type E1 = PallasEngine;
// type EE1<E> = ipa_pc::EvaluationEngine<E>;
// type EE2<E> = ipa_pc::EvaluationEngine<Dual<E>>;

// type BS1<E> = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1<E>>;
// type S1<E> = RelaxedR1CSSNARK<E, EE1<E>>;
// type S2<E> = RelaxedR1CSSNARK<Dual<E>, EE2<E>>;

// /// Function for user to test the zkEngine
// ///
// /// # Note
// ///
// /// This is for testing purposes only
// pub fn prove_wasm_test(
//   wasm_ctx: &mut impl ZKWASMContext<WasiCtx>,
//   batched: bool,
// ) -> anyhow::Result<()> {
//   // Get start flag or default to 0
//   let start = wasm_ctx.args().trace_slice_values().start();

//   // You cannot run MCC from any other starting point than 0
//   // Therefore if start is not 0, we only run the execution proof
//   // Otherwise we run both MCC and execution proof
//   if start != 0 {
//     tracing::info!("Adding start flag results in not running MCC proving");
//     prove_execution(wasm_ctx, batched)
//   } else {
//     prove_mcc_and_execution(wasm_ctx, batched)
//   }
// }

// /// Runs proving system on only execution trace
// pub fn prove_execution(ctx: &mut impl ZKWASMContext<WasiCtx>, batched: bool) ->
// anyhow::Result<()> {   if batched {
//     let _ = BatchedZKEExecutionProof::<E1, BS1<_>, S1<_>, S2<E1>>::prove_wasm_execution(ctx)?;
//   } else {
//     let _ = ZKEExecutionProof::<E1, BS1<_>, S1<_>, S2<E1>>::prove_wasm_execution(ctx)?;
//   }
//   Ok(())
// }

// /// Runs proving system on execution trace and memory trace
// fn prove_mcc_and_execution(
//   ctx: &mut impl ZKWASMContext<WasiCtx>,
//   batched: bool,
// ) -> anyhow::Result<()> {
//   if batched {
//     BatchedZKEProof::<E1, BS1<_>, S1<_>, S2<E1>>::prove_wasm(ctx)?;
//   } else {
//     ZKEProof::<E1, BS1<_>, S1<_>, S2<E1>>::prove_wasm(ctx)?;
//   }
//   Ok(())
// }
