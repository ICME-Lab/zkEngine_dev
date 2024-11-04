use std::{cell::RefCell, path::PathBuf, rc::Rc};

use nova::provider::Bn256EngineIPA;
use wasmi::Tracer;

use crate::{
  utils::{logging::init_logger, wasm::wat2wasm},
  v1::utils::tracing::{execute_wasm, unwrap_rc_refcell},
};

use super::{error::ZKWASMError, wasm_ctx::WASMCtxBuilder, wasm_snark::WasmSNARK};

/// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

#[test]
fn test_implicit_return_with_value() {
  init_logger();
  let wasm = wat2wasm(
    r#"
    (module
        (func (export "main") (result i64)
            i64.const 100
        )
    )
"#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default()
    .bytecode(wasm)
    .invoke("main")
    .build();

  let pp = WasmSNARK::<E>::setup();

  let _snark = WasmSNARK::<E>::prove(&pp, &wasm_ctx).unwrap();
}

// #[test]
// fn test_basic_arith() -> Result<(), ZKWASMError> {
//   let wasm_ctx = WASMCtxBuilder::default()
//     .file_path(PathBuf::from("wasm/nebula/basic_arith.wat"))?
//     .invoke("main")
//     .build();

//   let pp = WasmSNARK::<E>::setup();

//   let _snark = WasmSNARK::<E>::prove(&pp, &wasm_ctx)?;
//   Ok(())
// }

// #[test]
// fn test_get_local() {
//   init_logger();
//   let wasm = wat2wasm(
//     r#"
//     (module
//         (func (export "main") (param i32) (result i32)
//             local.get 0
//         )
//     )
// "#,
//   )
//   .unwrap();

//   let wasm_ctx = WASMCtxBuilder::default()
//     .bytecode(wasm)
//     .invoke("main")
//     .func_args(vec!["42".to_string()])
//     .build();

//   let pp = WasmSNARK::<E>::setup();

//   let _snark = WasmSNARK::<E>::prove(&pp, &wasm_ctx).unwrap();
// }
