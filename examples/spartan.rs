use std::path::PathBuf;

use zk_engine::{
  snark::non_uniform::LiteProver,
  utils::logging::init_logger,
  wasm::{args::WASMArgsBuilder, ctx::WASMCtx},
};

fn main() -> anyhow::Result<()> {
  init_logger();
  let x = "1000";

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .invoke(Some(String::from("fib")))
    .func_args(vec![String::from(x)])
    .build();

  tracing::info!("running setup");
  let (pk, vk, pp) = LiteProver::setup(&mut WASMCtx::new_from_file(&args)?)?;

  //let pp_str = serde_json::to_string(&pp)?;
  //println!("Number of opcodes in the execution trace: {}", &pp);
  //fs::write("pp.json", &pp_str)?;

  let mut wasm_ctx = WASMCtx::new_from_file(&args)?;

  tracing::info!("running prover");
  let proof = LiteProver::prove(&mut wasm_ctx, &pp, &pk)?;

  tracing::info!("running verifier");
  proof.verify(&vk)?;
  Ok(())
}
