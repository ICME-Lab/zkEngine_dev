use std::path::PathBuf;

use super::batched::BatchedZKEProof;
use crate::{
  args::{WASMArgsBuilder, WASMCtx},
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
};

use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan::{self, snark::RelaxedR1CSSNARK},
  traits::Dual,
};

// Curve cycle to use for proving
type E1 = PallasEngine;
// PCS used for final SNARK at the end of (N)IVC
type EE1<E> = ipa_pc::EvaluationEngine<E>;
// PCS on secondary curve
type EE2<E> = ipa_pc::EvaluationEngine<Dual<E>>;

// Spartan SNARKS used for compressing at then end of (N)IVC
type BS1<E> = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1<E>>;
type S1<E> = RelaxedR1CSSNARK<E, EE1<E>>;
type S2<E> = RelaxedR1CSSNARK<Dual<E>, EE2<E>>;

#[test]
fn test_zk_ads() -> anyhow::Result<()> {
  init_logger();

  let input_x = "200.05";
  let input_y = "-30.0";

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/zk_ads.wasm"))
    .invoke(Some(String::from("is_user_close_enough")))
    .func_args(vec![
      String::from("0"),
      String::from(input_x),
      String::from(input_y),
    ])
    .build();

  // Create a WASM execution context for proving.
  let mut wasm_ctx = WASMCtx::new_from_file(args)?;

  let (proof, public_values, _) =
    BatchedZKEProof::<E1, BS1<E1>, S1<E1>, S2<E1>>::prove_wasm(&mut wasm_ctx)?;

  // Verify proof
  let result = proof.verify(public_values)?;
  Ok(assert!(result))
}

#[test]
fn test_gradient_boosting() -> anyhow::Result<()> {
  init_logger();

  // Configure the arguments needed for WASM execution
  //
  // Here we are configuring the path to the WASM file
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
    .invoke(Some(String::from("_start")))
    .build();

  // Create a WASM execution context for proving.
  let mut wasm_ctx = WASMCtx::new_from_file(args)?;

  // Prove execution and run memory consistency checks
  //
  // Get proof for verification and corresponding public values
  //
  // Above type alias's (for the backend config) get used here
  let (proof, public_values, _) =
    BatchedZKEProof::<E1, BS1<E1>, S1<E1>, S2<E1>>::prove_wasm(&mut wasm_ctx)?;

  // Verify proof
  let result = proof.verify(public_values)?;
  Ok(assert!(result))
}

mod k3 {
  use std::path::PathBuf;

  use crate::{
    args::{WASMArgs, WASMArgsBuilder, WASMCtx},
    run::batched::BatchedZKEExecutionProof,
    traits::args::ZKWASMContext,
    utils::logging::init_logger,
  };
  use anyhow::anyhow;

  type E1 = PallasEngine;
  type EE1<E> = ipa_pc::EvaluationEngine<E>;
  type EE2<E> = ipa_pc::EvaluationEngine<Dual<E>>;

  type BS1<E> = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1<E>>;
  type S1<E> = RelaxedR1CSSNARK<E, EE1<E>>;
  type S2<E> = RelaxedR1CSSNARK<Dual<E>, EE2<E>>;

  use nova::{
    provider::{ipa_pc, PallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::Dual,
  };
  #[cfg(feature = "k3")]
  use wasmi::{Caller, Linker};
  #[cfg(feature = "k3")]
  use wasmi_wasi::WasiCtx;

  /// K3 WASM exports
  const K3_HANDLER_NAME: &str = "__k3_handler__get";
  const K3_ALLOC: &str = "__k3_alloc";
  const K3_WRITE_INPUTS: &str = "__k3_write_inputs";
  const K3_INIT_ENV: &str = "__k3_init_env";
  const MEMORY: &str = "memory";

  const REQ_BUFFER_BODY: [u8; 69] = [
    71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 67, 111, 110, 116, 101, 110,
    116, 45, 84, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47,
    106, 115, 111, 110, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 76, 101, 110, 103, 116, 104,
    58, 32, 48, 13, 10, 13, 10,
  ];

  #[cfg(feature = "k3")]
  pub fn get(url: &str) -> Option<Vec<u8>> {
    let res = reqwest::blocking::get(url);
    if let Ok(res) = res {
      Some(res.bytes().unwrap().to_vec())
    } else {
      None
    }
  }

  #[cfg(feature = "k3")]
  pub fn get_with_auth(url: &str, auth: &str) -> Option<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
      .default_headers({
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
          reqwest::header::AUTHORIZATION,
          reqwest::header::HeaderValue::from_str(auth).unwrap(),
        );
        headers
      })
      .build()
      .unwrap();

    let res = client.get(url).send();

    match res {
      Ok(res) => Some(res.bytes().unwrap().to_vec()),
      Err(_) => None,
    }
  }

  #[cfg(feature = "k3")]
  pub fn link(linker: &mut Linker<WasiCtx>) {
    linker
      .func_wrap(
        "env",
        "__k3_http_get",
        |mut caller: Caller<WasiCtx>, url_ptr: u32| -> u32 {
          let mem = caller
            .get_export("memory")
            .unwrap()
            .into_memory()
            .unwrap()
            .data_mut(&mut caller);

          let url_len = u32::from_le_bytes(
            mem[url_ptr as usize..url_ptr as usize + 4]
              .try_into()
              .unwrap(),
          ) as usize;
          let buf = &mem[url_ptr as usize + 4..url_ptr as usize + 4 + url_len];
          let url = std::str::from_utf8(buf).unwrap();

          let res = get(url);

          let alloc_func = caller
            .get_export("__k3_alloc")
            .expect("Alloc function should be exported")
            .into_func()
            .unwrap();

          if let Some(res) = res {
            let mut results = [wasmi::Value::I32(0)];
            alloc_func
              .call(
                &mut caller,
                &[wasmi::Value::I32((res.len() + 4) as i32)],
                &mut results,
              )
              .unwrap();

            let mem = caller
              .get_export("memory")
              .unwrap()
              .into_memory()
              .unwrap()
              .data_mut(&mut caller);

            let res_ptr = results[0].i32().unwrap();
            mem[res_ptr as usize..res_ptr as usize + 4]
              .copy_from_slice(&(res.len() as u32).to_le_bytes());
            mem[res_ptr as usize + 4..res_ptr as usize + 4 + res.len()]
              .copy_from_slice(res.as_slice());

            res_ptr as u32
          } else {
            0
          }
        },
      )
      .unwrap();

    linker
      .func_wrap(
        "env",
        "__k3_http_get_auth",
        |mut caller: Caller<WasiCtx>, url_ptr: u32, auth_ptr: u32| -> u32 {
          let mem = caller
            .get_export("memory")
            .unwrap()
            .into_memory()
            .unwrap()
            .data_mut(&mut caller);

          let url_len = u32::from_le_bytes(
            mem[url_ptr as usize..url_ptr as usize + 4]
              .try_into()
              .unwrap(),
          ) as usize;
          let buf = &mem[url_ptr as usize + 4..url_ptr as usize + 4 + url_len];
          let url = std::str::from_utf8(buf).unwrap();

          let auth_len = u32::from_le_bytes(
            mem[auth_ptr as usize..auth_ptr as usize + 4]
              .try_into()
              .unwrap(),
          ) as usize;
          let buf = &mem[auth_ptr as usize + 4..auth_ptr as usize + 4 + auth_len];
          let auth = std::str::from_utf8(buf).unwrap();

          let res = get_with_auth(url, auth);

          let alloc_func = caller
            .get_export("__k3_alloc")
            .expect("Alloc function should be exported")
            .into_func()
            .unwrap();

          if let Some(res) = res {
            let mut results = [wasmi::Value::I32(0)];
            alloc_func
              .call(
                &mut caller,
                &[wasmi::Value::I32((res.len() + 4) as i32)],
                &mut results,
              )
              .unwrap();

            let mem = caller
              .get_export("memory")
              .unwrap()
              .into_memory()
              .unwrap()
              .data_mut(&mut caller);

            let res_ptr = results[0].i32().unwrap();
            mem[res_ptr as usize..res_ptr as usize + 4]
              .copy_from_slice(&(res.len() as u32).to_le_bytes());
            mem[res_ptr as usize + 4..res_ptr as usize + 4 + res.len()]
              .copy_from_slice(res.as_slice());

            res_ptr as u32
          } else {
            0
          }
        },
      )
      .unwrap();
  }

  /// Allocate memory in the WASM linear memory and copy the data into the allocated memory
  ///
  /// Returns a pointer to the allocated memory
  fn k3_alloc(ctx: &mut WASMCtx<WASMArgs>, data: &[u8]) -> anyhow::Result<i32> {
    let alloc_func = ctx.func(K3_ALLOC)?;
    let tracer = ctx.tracer()?;

    // init ptr
    let mut alloc_results = [wasmi::Value::I32(0)];

    // Get the pointer to the allocated memory
    alloc_func.call_with_trace(
      ctx.store_mut(),
      &[wasmi::Value::I32(data.len() as i32)],
      &mut alloc_results,
      tracer,
    )?;

    let ptr = alloc_results[0].i32().ok_or(anyhow!("expected i32"))?;

    // Copy the data into the allocated memory using the pointer and the length of the data
    let mem = ctx.memory(MEMORY)?;
    mem.data_mut(ctx.store_mut())[ptr as usize..ptr as usize + data.len()].copy_from_slice(data);

    Ok(ptr)
  }

  /// Run the k3 init env function in the WASM
  pub fn k3_init_env(
    ctx: &mut WASMCtx<WASMArgs>,
    env_ptr: i32,
    env_len: i32,
  ) -> anyhow::Result<()> {
    let tracer = ctx.tracer()?;
    let env_func = ctx.func(K3_INIT_ENV)?;
    let mut env_results = [wasmi::Value::I32(0)];

    // This  needs to be run to use the environment variables in the WASM
    Ok(env_func.call_with_trace(
      ctx.store_mut(),
      &[wasmi::Value::I32(env_ptr), wasmi::Value::I32(env_len)],
      &mut env_results,
      tracer,
    )?)
  }

  /// Write inputs to WASM
  fn write_inputs(ctx: &mut WASMCtx<WASMArgs>, inputs: &str) -> anyhow::Result<()> {
    let inputs_ptr = k3_alloc(ctx, inputs.as_bytes())?;

    let input_func = ctx.func(K3_WRITE_INPUTS)?;

    let tracer = ctx.tracer()?;
    input_func
      .typed::<(i32, i32), i32>(ctx.store_mut())?
      .call_with_trace(ctx.store_mut(), (inputs_ptr, inputs.len() as i32), tracer)?;
    Ok(())
  }

  /// Runs steps needed to initialize the environment variables in the WASM
  ///
  /// 1. Get env var from user input and structure it.
  /// 2. Allocate the env in WASM memory.
  /// 3. Run the init env function.
  fn wasm_init_env(ctx: &mut WASMCtx<WASMArgs>, env: &str) -> anyhow::Result<()> {
    // Structure the environment variables as a byte array to be written into the WASM linear memory
    let env_str = env.replace(',', "\n");
    let env_vars = env_str.as_bytes();

    // Allocate memory for the environment variables and write the environment variables into the
    // allocated memory
    let env_ptr = k3_alloc(ctx, env_vars)?;

    // Initialize the environment variables in the WASM
    k3_init_env(ctx, env_ptr, env_vars.len() as i32)
  }

  #[test]
  fn test_hello_env() -> anyhow::Result<()> {
    init_logger();

    // First create a WASM instance from the bytecode from the file path
    let args_builder =
      WASMArgsBuilder::default().file_path(PathBuf::from("wasm/k3/hello_env.wasm"));
    let mut wasm_ctx = WASMCtx::new_from_file(args_builder.clone().build())?;

    // Set the environment variable inside the wasm
    //
    // In this case we are setting the environment variable `NAME` to `bob`
    //
    // The `hello_env.wasm` requires the `NAME` environment variable to be set to run the
    // `k3_handler_get` function
    wasm_init_env(&mut wasm_ctx, "NAME=bob")?;

    // Allocate memory for the request buffer and get its pointer that points to allocated memory in
    // the WASM linear memory
    let req_ptr = k3_alloc(&mut wasm_ctx, &REQ_BUFFER_BODY)?;

    // Build the arguments for the `k3_handler_get` function to invoke
    //
    // fn k3_handler_get(req_ptr: i32, req_len: i32);
    let wasm_args = args_builder
      .func_args(vec![req_ptr.to_string(), REQ_BUFFER_BODY.len().to_string()])
      .invoke(Some(K3_HANDLER_NAME.to_string()))
      .build();

    // Tell wasm_ctx to use the arguments we just built
    wasm_ctx.set_args(wasm_args);

    // Execute the WASM function and get its execution trace
    let (proof, public_values) =
      BatchedZKEExecutionProof::<E1, BS1<_>, S1<_>, S2<E1>>::prove_wasm_execution(&mut wasm_ctx)?;

    // Verify the proof
    let res = proof.verify_wasm_execution(public_values)?;
    Ok(assert!(res))
  }

  #[test]
  fn test_if_conditional() -> anyhow::Result<()> {
    init_logger();

    // First create a WASM instance from the bytecode from the file path
    let args_builder =
      WASMArgsBuilder::default().file_path(PathBuf::from("wasm/k3/if_conditional.wasm"));
    let mut wasm_ctx = WASMCtx::new_from_file(args_builder.clone().build())?;

    let inputs = r#"{"input_1": "20", "input_2": "1000", "condition": "gt"}"#;
    write_inputs(&mut wasm_ctx, inputs)?;

    // Allocate memory for the request buffer and get its pointer that points to allocated memory in
    // the WASM linear memory
    let req_ptr = k3_alloc(&mut wasm_ctx, &REQ_BUFFER_BODY)?;

    // Build the arguments for the `k3_handler_get` function to invoke
    //
    // fn k3_handler_get(req_ptr: i32, req_len: i32);
    let wasm_args = args_builder
      .func_args(vec![req_ptr.to_string(), REQ_BUFFER_BODY.len().to_string()])
      .invoke(Some(K3_HANDLER_NAME.to_string()))
      .build();

    // Tell wasm_ctx to use the arguments we just built
    wasm_ctx.set_args(wasm_args);

    // Execute the WASM function and get its execution trace
    let (proof, public_values) =
      BatchedZKEExecutionProof::<E1, BS1<_>, S1<_>, S2<E1>>::prove_wasm_execution(&mut wasm_ctx)?;

    // Verify the proof
    let res = proof.verify_wasm_execution(public_values)?;
    Ok(assert!(res))
  }

  #[test]
  #[cfg(feature = "k3")]
  fn test_read_api() -> anyhow::Result<()> {
    init_logger();

    // First create a WASM instance from the bytecode from the file path
    let args_builder = WASMArgsBuilder::default().file_path(PathBuf::from("wasm/k3/read_api.wasm"));
    let mut wasm_ctx = WASMCtx::new_from_file_with_linking(args_builder.clone().build(), link)?;

    // Set the environment variable inside the wasm
    //
    // In this case we are setting the environment variable `NAME` to `bob`
    //
    // The `hello_env.wasm` requires the `NAME` environment variable to be set to run the
    // `k3_handler_get` function
    let env_str = "JSON_SELECTOR=title,JSON_ENDPOINT=https://dummyjson.com/products/2,NAME=Levi,SC_ADDRESS=0xbFeF878B55257F1287F5Cf13A6314481919dca3f,EXECUTOR=[private-key]";
    wasm_init_env(&mut wasm_ctx, env_str)?;

    // Allocate memory for the request buffer and get its pointer that points to allocated memory in
    // the WASM linear memory
    let req_ptr = k3_alloc(&mut wasm_ctx, &REQ_BUFFER_BODY)?;

    // Build the arguments for the `k3_handler_get` function to invoke
    //
    // fn k3_handler_get(req_ptr: i32, req_len: i32);
    let wasm_args = args_builder
      .func_args(vec![req_ptr.to_string(), REQ_BUFFER_BODY.len().to_string()])
      .invoke(Some(K3_HANDLER_NAME.to_string()))
      .build();

    // Tell wasm_ctx to use the arguments we just built
    wasm_ctx.set_args(wasm_args);

    // Execute the WASM function and get its execution trace
    let (proof, public_values) =
      BatchedZKEExecutionProof::<E1, BS1<_>, S1<_>, S2<E1>>::prove_wasm_execution(&mut wasm_ctx)?;

    // Verify the proof
    let res = proof.verify_wasm_execution(public_values)?;
    Ok(assert!(res))
  }
}
