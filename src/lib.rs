//! This library implements zkEngine, a zkWASM with a SuperNova backend.
#![feature(macro_metavar_expr, concat_idents)]
#![allow(non_snake_case)]
#![deny(missing_docs)]

mod circuits;
pub mod errors;
pub mod pcd;
pub mod run;
pub mod traits;
pub mod utils;
pub mod wasm;

use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan::{self, snark::RelaxedR1CSSNARK},
  traits::Dual,
};
use run::{batched::BatchedZKEProof, default::ZKEProof};
// re-export the wasi module
pub use wasmi::TraceSliceValues;

#[cfg(not(target_arch = "wasm32"))]
pub use wasmi_wasi::WasiCtx;

// re-export `nova`
pub use nova;

type E1 = PallasEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;
type BS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

/// The default zkEngine type alias.
pub type ZKEngine = ZKEProof<E1, BS1, S1, S2>;

/// The Batched zkEngine type alias.
pub type BatchedZKEngine = BatchedZKEProof<E1, BS1, S1, S2>;
