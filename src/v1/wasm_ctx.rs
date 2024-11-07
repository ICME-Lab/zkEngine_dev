//! Componets:
//! - WASMCtx: defines the the WASM execution context that will be used for proving
//! - WASMCtxMetaData: defines the metadata for the WASM execution context
//! - WASMCtxBuilder: builds the WASM execution context

use std::path::PathBuf;

use crate::utils::wasm::read_wasm_or_wat;

use super::error::ZKWASMError;

/// Builder for [`WASMCtx`]. Defines the WASM execution context that will be used for proving
#[derive(Debug, Default)]
pub struct WASMCtxBuilder {
  program: Vec<u8>,
  meta_data: WASMCtxMetaData,
}

impl WASMCtxBuilder {
  /// Set the program bytecode from file
  pub fn file_path(mut self, path: PathBuf) -> Result<Self, ZKWASMError> {
    let bytecode =
      read_wasm_or_wat(&path).map_err(|err| ZKWASMError::WASMError(err.to_string()))?;
    self.program = bytecode;
    Ok(self)
  }

  /// Set the program bytecode
  pub fn bytecode(mut self, program: Vec<u8>) -> Self {
    self.program = program;
    self
  }

  /// Set the WASM function to invoke
  pub fn invoke(mut self, invoke: &str) -> Self {
    self.meta_data.invoke = invoke.to_string();
    self
  }

  /// Set the function arguments
  pub fn func_args(mut self, func_args: Vec<String>) -> Self {
    self.meta_data.func_args = func_args;
    self
  }

  /// Build the WASM context
  pub fn build(self) -> WASMCtx {
    WASMCtx {
      program: self.program,
      meta_data: self.meta_data,
    }
  }
}

/// WASM execution context: contains the WASM program and its [`WASMCtxMetaData`]
pub struct WASMCtx {
  pub(in crate::v1) program: Vec<u8>,
  pub(in crate::v1) meta_data: WASMCtxMetaData,
}

/// Metadata for the WASM execution context. For example to prove a WASM program execution you would
/// need to define the WASM function to invoke and the function arguments
#[derive(Debug)]
pub struct WASMCtxMetaData {
  pub(in crate::v1) invoke: String,
  pub(in crate::v1) func_args: Vec<String>,
}

impl Default for WASMCtxMetaData {
  fn default() -> Self {
    Self {
      invoke: String::from("main"), /* Use "main" as the default entry point for a wasm execution
                                     * context */
      func_args: Vec::new(),
    }
  }
}
