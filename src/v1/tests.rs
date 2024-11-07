use std::{cell::RefCell, path::PathBuf, rc::Rc};

use nova::provider::Bn256EngineIPA;
use wasmi::Tracer;

use crate::{
  utils::{logging::init_logger, wasm::wat2wasm},
  v1::utils::tracing::{execute_wasm, unwrap_rc_refcell},
};

use super::{
  error::ZKWASMError,
  wasm_ctx::{WASMCtx, WASMCtxBuilder},
  wasm_snark::WasmSNARK,
};

/// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

fn test_wasm_snark_with(wasm_ctx: WASMCtx) {
  let pp = WasmSNARK::<E>::setup();

  let _snark = WasmSNARK::<E>::prove(&pp, &wasm_ctx).unwrap();
}

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

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn test_get_local() {
  init_logger();
  let wasm = wat2wasm(
    r#"
    (module
        (func (export "main") (param i32) (result i32)
            local.get 0
        )
    )
"#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default()
    .bytecode(wasm)
    .invoke("main")
    .func_args(vec!["42".to_string()])
    .build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn test_add_mul() {
  init_logger();
  let wasm = wat2wasm(
    r#"
    (module
        (func (export "main") (param i64) (param i64) (result i64)
            local.get 0
            local.get 1
            local.get 0
            local.get 1
            i64.add
            i64.add
            i64.mul
        )
    )
"#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default()
    .bytecode(wasm)
    .invoke("main")
    .func_args(vec!["42".to_string(), "10".to_string()])
    .build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn if_without_else() {
  let wasm = wat2wasm(
    r#"
        (module
            (func (export "main") (result i64)
                i32.const 1
                if
                    i64.const 2
                    return
                end
                i64.const 3
            )
        )
    "#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default().bytecode(wasm).build();

  test_wasm_snark_with(wasm_ctx);
}
