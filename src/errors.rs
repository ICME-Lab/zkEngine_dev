//! This module contains custom Errors for zkWASM
use bellpepper_core::SynthesisError;
use nova::{errors::NovaError, supernova::error::SuperNovaError};
use thiserror::Error;

/// Errors that occur when generating a WASM proof
#[derive(Error, Debug)]
pub enum ProofError {
  /// Errors returned by Nova
  #[error("Nova error")]
  Nova(#[from] NovaError),
  /// Errors returned by SuperNova
  #[error("SuperNova error")]
  SuperNova(#[from] SuperNovaError),
  /// This is an error that could occur during circuit synthesis contexts, such as CRS generation,
  /// proving or verification.
  #[error("Synthesis error: {0}")]
  Synthesis(#[from] SynthesisError),
}

/// Error that was encountered while proving.
#[derive(Debug)]
pub enum ProvingError {
  /// Proving was interrupted.
  Interrupted,

  /// Failed to create public parameters.
  PublicParameters(String),

  /// Unknown error occurred.
  Unknown(String),

  /// Failed to load WASM module
  WasmError(String),

  /// Failed to prove WASM execution
  AnyhowError(anyhow::Error),
}

impl From<anyhow::Error> for ProvingError {
  fn from(error: anyhow::Error) -> Self {
    ProvingError::AnyhowError(error)
  }
}
