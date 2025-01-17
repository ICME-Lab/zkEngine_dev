//! This library implements zkEngine, a zkWASM with a SuperNova backend.
#![feature(macro_metavar_expr, concat_idents)]
#![allow(non_snake_case)]
#![deny(missing_docs)]

pub mod v1;

#[cfg(not(target_arch = "wasm32"))]
pub use wasmi_wasi::WasiCtx;

// re-export `nova`
pub use nova;
