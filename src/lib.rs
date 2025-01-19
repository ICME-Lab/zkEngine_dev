//! Nebula based zkVM for WASM ISA
#![allow(clippy::type_complexity)]
#![allow(non_snake_case)]
#![deny(missing_docs)]
// pub mod aggregation;
pub mod error;
// pub mod sharding;
pub mod utils;
pub mod wasm_ctx;
pub mod wasm_snark;

#[cfg(test)]
mod tests;

#[cfg(not(target_arch = "wasm32"))]
pub use wasmi_wasi::WasiCtx;

// re-export
pub use nova;
