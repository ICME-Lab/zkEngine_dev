use std::{path::PathBuf, time::Instant};

use nova::provider::Bn256EngineIPA;

use crate::utils::{logging::init_logger, wasm::wat2wasm};

use super::{
  wasm_ctx::{WASMCtx, WASMCtxBuilder},
  wasm_snark::WasmSNARK,
};

/// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

fn test_wasm_snark_with(wasm_ctx: WASMCtx) {
  let pp = WasmSNARK::<E>::setup(1);

  let (snark, U) = WasmSNARK::<E>::prove(&pp, &wasm_ctx, 1).unwrap();
  let time = Instant::now();
  snark.verify(&pp, &U).unwrap();
  tracing::info!("Verification time: {:?}", time.elapsed());
}

#[test]
fn test_bit_check() {
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/bit_check.wat"))
    .unwrap()
    .invoke("bit_check")
    .func_args(vec!["255".to_string(), "255".to_string()])
    .build();

  test_wasm_snark_with(wasm_ctx);
}
