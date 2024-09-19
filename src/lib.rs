//! This library implements zkEngine, a zkWASM with a SuperNova backend.
#![feature(macro_metavar_expr, concat_idents)]
#![allow(non_snake_case)]
#![deny(missing_docs)]

mod circuits;
pub mod errors;
pub mod pcd;
pub mod run;
pub mod snark;
pub mod traits;
pub mod utils;
pub mod wasm;

use run::{batched::BatchedZKEProof, default::ZKEProof};
use traits::be_engine::PastaEngine;
// re-export the wasi module
pub use wasmi::TraceSliceValues;

#[cfg(not(target_arch = "wasm32"))]
pub use wasmi_wasi::WasiCtx;

// re-export `nova`
pub use nova;

/// Backend Engine used for testing
pub type E = PastaEngine;

/// The default zkEngine type alias.
pub type ZKEngine = ZKEProof<E>;
/// The Batched zkEngine type alias.
pub type BatchedZKEngine = BatchedZKEProof<E>;
