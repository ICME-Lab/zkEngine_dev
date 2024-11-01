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
}
