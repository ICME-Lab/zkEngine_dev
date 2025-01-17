The zkEngine is an (NIVC) zkWASM implementation based on the [Nebula](https://eprint.iacr.org/2024/1605) proving scheme.
It aims to be memory efficient and highly portable for constrained enviroments. With these traits it can be used for
local verifiable compute and privacy on a large array of devices.

The zkEngine is the backend for the [NovaNet](https://novanet.xyz) incentive and prover network. 

## Usage: as Rust dependency

### Cargo

```toml
[dependencies]
zk-engine = { git = "https://github.com/ICME-Lab/zkEngine_dev", branch= "main" }
```

### Example

#### First steps: Producing setup material.

To prove and verify WASM program executions a prover and verifier both given the specification of the virtual machine (e.g., the instruction set architecture and semantics), which they have preprocess to obtain setup material. 

This is done in form of producing a type exported from zk-engine called `WASMPublicParams`.

```rust
  let pp = WasmSNARK::<E>::setup(step_size);
```

You will notice to produce the public parameters you need to provide a `step_size` which is the number of instructions the zkWASM will execute at each step of the proving process. For example if you have a program with 100 instructions/opcodes and you set the `step_size` to 10, the proving process will be divided into 10 steps, each proving 10 instructions.

```rust
  let step_size = StepSize::new(10);
  let pp = WasmSNARK::<E>::setup(step_size);
```

Choosing a bigger `step_size` can improve the proving time but will increase the memory consumption and vice versa. Make sure to choose a `step_size` that fits your use case.

#### Fibonacci example

Get the 16th fibonacci number using the wasm program in `wasm/misc/fib.wat`. The wasm program is a simple recursive function that calculates the fibonacci number of the input number.

```bash
RUST_LOG=debug cargo run --release --example fib
```

```rust
use std::path::PathBuf;
use zk_engine::{
  nova::provider::Bn256EngineIPA,
  utils::logging::init_logger,
  {
    error::ZKWASMError,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK},
  },
};

// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

fn main() -> Result<(), ZKWASMError> {
  init_logger();

  // Specify step size.
  //
  // Here we choose `10` as the step size because the wasm execution of fib(16) is 253 opcodes.
  // meaning zkWASM will run for 26 steps.
  let step_size = StepSize::new(10);

  // Produce setup material
  let pp = WasmSNARK::<E>::setup(step_size);

  // Specify arguments to the WASM and use it to build a `WASMCtx`
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .unwrap()
    .invoke("fib")
    .func_args(vec![String::from("16")])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);

  // Prove wasm execution of fib.wat::fib(16)
  let (snark, instance) = WasmSNARK::<E>::prove(&pp, &wasm_ctx, step_size)?;

  // Verify the proof
  snark.verify(&pp, &instance)?;

  Ok(())
}
```

## Note

One thing to note about setting up your WASM program is this step
```rust
  // Specify arguments to the WASM and use it to build a `WASMCtx`
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .unwrap()
    .invoke("fib")
    .func_args(vec![String::from("16")])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
```

This is where you specify the wasm program to run and the function to invoke. The `func_args` is a vector of strings that are the arguments to the function you are invoking. In this case we are invoking the `fib` function with the argument `16`.

Also if your WASM program uses `WASI` you would use:
```rust
  let wasm_ctx = WasiWASMCtx::new(wasm_args);
```

## Further Note
*Public Parameters and WasmSNARK have to take the same `step_size` as an argument.*

#### Bigger steps for better performance

if you were to run fib(1000), this would take a long time to prove because the wasm program has 16,981 opcodes. To improve the proving time you can increase the `step_size` to 1000.

```bash
RUST_LOG=debug cargo run --release --example fib_large
```

```rust
use std::path::PathBuf;
use zk_engine::{
  nova::provider::Bn256EngineIPA,
  utils::logging::init_logger,
  {
    error::ZKWASMError,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK},
  },
};

// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

fn main() -> Result<(), ZKWASMError> {
  init_logger();

  // Specify step size.
  //
  // Here we choose `1_000` as the step size because the wasm execution of fib(1000) is 16,981
  // opcodes. meaning zkWASM will run for 17 steps (rounds up).
  let step_size = StepSize::new(1_000);

  // Produce setup material
  let pp = WasmSNARK::<E>::setup(step_size);

  // Specify arguments to the WASM and use it to build a `WASMCtx`
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .unwrap()
    .invoke("fib")
    .func_args(vec![String::from("1000")])
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);

  // Prove wasm execution of fib.wat::fib(1000)
  let (snark, instance) = WasmSNARK::<E>::prove(&pp, &wasm_ctx, step_size)?;

  // Verify the proof
  snark.verify(&pp, &instance)?;

  Ok(())
}
```

## A better setup for Memory consistency checks

Very often your WASM execution only produces a few thousand opcodes but sometimes the WASM linear memory is over hundreds of thousands of addresses. In this case since the memory consistency checks are proportional to the step size of proving execution, and so your proving time will be dominated by the memory consistency checks. To improve the memory proving time you can increase set memory_step_size on the `StepSize` struct.

like so

```rust
  let step_size = StepSize::new(1000).set_memory_step_size(50_000);
```

#### Example

In this WASM example (where the WASM calculates the kth factor of a number) the WASM execution produces 7601 opcodes so we choose a step size of 1,000. However the memory size is 147,456 address spaces, so we set memory step size to 50_000.
Meaning the MCC will run in 3 steps.

```bash
RUST_LOG=debug cargo run --release --example kth_factor
```

```rust
use std::path::PathBuf;
use zk_engine::{
  nova::provider::Bn256EngineIPA,
  utils::logging::init_logger,
  {
    error::ZKWASMError,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK},
  },
};

// Curve Cycle to prove/verify on
pub type E = Bn256EngineIPA;

fn main() -> Result<(), ZKWASMError> {
  init_logger();

  // Here we chose execution step size of 1000 since the WASM execution is 7601 opcodes.
  //
  // However the memory size is 147456 address spaces, so we set memory step size to 50_000.
  // Resulting in 3 steps for MCC
  let step_size = StepSize::new(1000).set_memory_step_size(50_000);

  // Produce setup material
  let pp = WasmSNARK::<E>::setup(step_size);

  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/nebula/kth_factor.wat"))?
    .func_args(vec!["250".to_string(), "15".to_string()])
    .invoke("kth_factor")
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);

  let (snark, instance) = WasmSNARK::<E>::prove(&pp, &wasm_ctx, step_size)?;

  // Verify the proof
  snark.verify(&pp, &instance)?;

  Ok(())
}
```