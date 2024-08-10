//! This library implements zkEngine, a zkWASM with a SuperNova backend.
#![feature(macro_metavar_expr, concat_idents)]
#![allow(non_snake_case)]

// TODO: uncomment
// #![deny(missing_docs)]

pub mod args;
mod circuits;
pub mod errors;
pub mod pcd;
pub mod run;
pub mod traits;
pub mod utils;

// re-export the wasi module
pub use wasmi::TraceSliceValues;
pub use wasmi_wasi::WasiCtx;

// TODO: remove these
pub use circuits::execution::batched::{BatchedExecutionProof, BatchedExecutionPublicParams};
pub use nova::supernova::PublicParams as SuperNovaPublicParams;
pub use run::batched::ExecutionPublicValues;

// re-export `nova`
pub use nova;
