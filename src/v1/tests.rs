use std::path::PathBuf;

use nova::provider::Bn256EngineIPA;

use crate::utils::{logging::init_logger, wasm::wat2wasm};

use super::{
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
  init_logger();
  let wasm = wat2wasm(
    r#"
        (module
            (func (export "main") (result i64)
                i32.const 0
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

#[test]
fn drop_locals() {
  let wasm = wat2wasm(
    r#"
        (module
            (func (export "main") (param i64)
                (local i64)
                local.get 0
                local.set 1
            )
        )
    "#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default()
    .bytecode(wasm)
    .func_args(vec![String::from("42")])
    .build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn if_else() {
  init_logger();
  let wasm = wat2wasm(
    r#"
        (module
            (func (export "main")
                (local i64)
                i32.const 0
                if
                    i64.const 2
                    local.set 0
                else
                    i64.const 3
                    local.set 0
                end
            )
        )
    "#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default().bytecode(wasm).build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn if_else_branch_from_true_branch() {
  init_logger();
  let wasm = wat2wasm(
    r#"
        (module
            (func (export "main")
                i32.const 1
                if (result i64)
                    i64.const 1
                    i32.const 1
                    br_if 0
                    drop
                    i64.const 2
                else
                    i64.const 3
                end
                drop
            )
        )
    "#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default().bytecode(wasm).build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn if_else_branch_from_false_branch() {
  init_logger();
  let wasm = wat2wasm(
    r#"
        (module
            (func (export "main")
                i32.const 1
                if (result i64)
                    i64.const 1
                else
                    i64.const 2
                    i32.const 1
                    br_if 0
                    drop
                    i64.const 3
                end
                drop
            )
        )
    "#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default().bytecode(wasm).build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn calls_01() {
  init_logger();
  let wasm = wat2wasm(
    r#"
      (module
          (func $f0 (result i64)
              (i64.const 24)
          )
          (func (export "main") (result i64)
              (call $f0)
              i64.const 18
              i64.add
          )
      )
  "#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default().bytecode(wasm).build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn test_if_else_wat() {
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .func_args(vec![String::from("1")])
    .file_path(PathBuf::from("wasm/control_flow/if_else.wat"))
    .unwrap()
    .build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn store_01() {
  init_logger();
  let wasm = wat2wasm(
    r#"
        (module
            (memory 1)
            (func (export "main") (param $dst i32) (param $value i64)
                (i64.store
                    (local.get $dst) (local.get $value)
                )
            )
        )
    "#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default()
    .bytecode(wasm)
    .func_args(vec![String::from("1"), String::from("100")])
    .build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn store_02() {
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .func_args(vec![String::from("1")])
    .file_path(PathBuf::from("wasm/memory/store_op_i64.wat"))
    .unwrap()
    .build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn load_01() {
  init_logger();
  let wasm = wat2wasm(
    r#"
    (module
        (memory 1)
        (func (export "main") (param $src i32) (result i64)
            (i64.load (local.get $src))
        )
    )
"#,
  )
  .unwrap();

  let wasm_ctx = WASMCtxBuilder::default()
    .bytecode(wasm)
    .func_args(vec![String::from("1")])
    .build();

  test_wasm_snark_with(wasm_ctx);
}

#[test]
fn load_02() {
  init_logger();
  let wasm_ctx = WASMCtxBuilder::default()
    .func_args(vec![String::from("1")])
    .file_path(PathBuf::from("wasm/memory/load_op_i64.wat"))
    .unwrap()
    .build();

  test_wasm_snark_with(wasm_ctx);
}
