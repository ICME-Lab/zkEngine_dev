use zk_engine::{
  provider::WasmSNARK,
  traits::zkvm::WasmSNARKTrait,
  utils::{logging::init_logger, wasm::wat2wasm},
  wasm::{args::WASMArgsBuilder, ctx::WASMCtx},
};

fn main() -> anyhow::Result<()> {
  init_logger();

  // Configure the arguments needed for WASM execution
  //
  // Here we are configuring the path to the WASM file
  let wasm = r#"(module
  (func (export "main") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add))"#;

  let args = WASMArgsBuilder::default()
    .func_args(vec![String::from("1"), String::from("2")])
    .build();

  let wasm_bytes = wat2wasm(wasm)?;

  // Run setup step for ZKVM
  let pp = WasmSNARK::setup(&mut WASMCtx::new_from_bytecode(&wasm_bytes, &args)?)?;

  // Prove execution and run memory consistency checks
  //
  // Get proof for verification and corresponding public values
  //
  // Above type alias's (for the backend config) get used here
  let (proof, public_values, _) =
    WasmSNARK::prove_wasm(&mut WASMCtx::new_from_bytecode(&wasm_bytes, &args)?, &pp)?;

  // Verify proof
  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}
