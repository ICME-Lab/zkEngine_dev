use std::path::PathBuf;
use zk_engine::{
  provider::{WasmSNARK, E},
  run::default::public_values::PublicValues,
  traits::{be_engine::BackendEngine, zkvm::WasmSNARKTrait},
  utils::logging::init_logger,
  wasm::{args::WASMArgsBuilder, ctx::wasi::WasiWASMCtx},
};

fn main() -> anyhow::Result<()> {
  init_logger();

  // Some WASM' modules require the function to invoke and it's functions arguments.
  // The below code is an example of how to configure the WASM arguments for such cases.
  //
  // This WASM module (fib.wat) has a fib fn which will
  // produce the n'th number in the fibonacci sequence.
  // The function we want to invoke has the following signature:
  //
  // fib(n: i32) -> i32;
  //
  // This means the higher the user input is for `n` the more opcodes will need to be proven
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .invoke(Some(String::from("fib")))
    .func_args(vec![String::from("10")]) // This will generate 152 opcodes
    .build();

  let pp = WasmSNARK::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;

  // Use `BatchedZKEProof` for batched proving
  let (proof, public_values, _) =
    WasmSNARK::prove_wasm(&mut WasiWASMCtx::new_from_file(&args)?, &pp)?;

  // Serialize the proof and public values
  let proof_str = serde_json::to_string(&proof)?;
  let public_values_str = serde_json::to_string(&public_values)?;

  // Deserialize the proof and public values
  let proof: WasmSNARK = serde_json::from_str(&proof_str)?;
  let public_values: PublicValues<<E as BackendEngine>::E1> =
    serde_json::from_str(&public_values_str)?;

  // Verify proof
  let pp = WasmSNARK::setup(&mut WasiWASMCtx::new_from_file(&args)?)?;
  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}
