use std::path::PathBuf;

use crate::{traits::wasm::ZKWASMArgs, wasm::args::WASMArgsBuilder};

use super::error::ZKWASMError;

#[test]
fn test_tracing() -> Result<(), ZKWASMError> {
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/ams_isa.wat"))
    .build()
    .bytecode()
    .map_err(ZKWASMError::AnyhowError)?;

  Ok(())
}
