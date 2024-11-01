//! This module defines errors returned by the library.

use nova::errors::NovaError;
use thiserror::Error;

/// Errors returned by Spark compiler
#[derive(Debug, Error)]
pub enum ZKWASMError {
  /// Nova error
  #[error("NovaError")]
  NovaError(#[from] NovaError),
  /// returned RecursiveSNARK is badly formed
  #[error("MalformedRS")]
  MalformedRS,
  /// Anyhow Error
  #[error("AnyhowError")]
  AnyhowError(#[from] anyhow::Error),
  /// Wasmi Error
  #[error("WasmiError")]
  WasmiError(wasmi::Error),
}

impl From<wasmi::Error> for ZKWASMError {
  fn from(error: wasmi::Error) -> Self {
    Self::WasmiError(error)
  }
}
