//! V1 of zkEngine: Implements the Nebula paper for WASM ISA
#![allow(clippy::type_complexity)]
pub mod error;
#[cfg(test)]
mod tests;
mod utils;
pub mod wasm_snark;
