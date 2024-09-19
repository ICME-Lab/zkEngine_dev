//! This library implements zkEngine, a zkWASM with a SuperNova backend.
#![feature(macro_metavar_expr, concat_idents)]
#![allow(non_snake_case)]
#![deny(missing_docs)]

mod circuits;
pub mod errors;
pub mod pcd;
pub mod provider;
pub mod run;
pub mod snark;
pub mod traits;
pub mod utils;
pub mod wasm;

// re-export the wasi module
pub use wasmi::TraceSliceValues;

#[cfg(not(target_arch = "wasm32"))]
pub use wasmi_wasi::WasiCtx;

// re-export `nova`
pub use nova;
