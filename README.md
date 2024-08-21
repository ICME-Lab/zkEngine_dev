 **THIS HAS NOT BEEN AUDITED YET AND SHOULD BE USED ONLY FOR TESTING PURPOSES AND NOT IN PRODUCTION.**

# zkEngine

The zkEngine is an (NIVC) zkWASM implementation based on the [SuperNova](https://eprint.iacr.org/2022/1758) proving scheme.
It aims to be memory efficient and highly portable for constrained enviroments. With these traits it can be used for
local verifiable compute and privacy on a large array of devices.

The zkEngine is the backend for the [NovaNet](https://novanet.xyz) incentive and prover network. 


## Usage: as Rust dependency

### Cargo

```toml
[dependencies]
zk-engine = { git = "https://github.com/ICME-Lab/zkEngine_dev", branch= "main" }
anyhow = "1.0"
```
Run with:

```
RUST_LOG=debug cargo +nightly run --release
```

### Default mode

Default mode runs one WASM opcode per each step of NIVC in execution proving and one memory read/write for each step in the MCC (which uses IVC)

```bash
RUST_LOG=debug cargo +nightly run --release --example default
````

```rust
use std::path::PathBuf;
use zk_engine::{
  args::{WASMArgsBuilder, WASMCtx},
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
  ZKEngine,
};

fn main() -> anyhow::Result<()> {
  init_logger();

  // Configure the arguments needed for WASM execution
  //
  // Here we are configuring the path to the WASM file
  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/example.wasm"))
    .build();

  // Run setup step for ZKVM
  let pp = ZKEngine::setup(&mut WASMCtx::new_from_file(&args)?)?;

  // Prove execution and run memory consistency checks
  //
  // Get proof for verification and corresponding public values
  //
  // Above type alias's (for the backend config) get used here
  let (proof, public_values, _) = ZKEngine::prove_wasm(&mut WASMCtx::new_from_file(&args)?, &pp)?;

  // Verify proof
  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}
```

### Batched mode

Batched mode should be used when you have a large number of opcodes to prove (e.g., 10,000 opcodes). In batched mode, the opcodes are divided into 10 steps. For example, a 10,000-opcode WASM will be proven in 10 steps, with each step of NIVC proving 1,000 opcodes. The memory consistency checks will also be batched into 10 steps.

```bash
RUST_LOG=debug cargo +nightly run --release --example batched
````

```rust
use std::path::PathBuf;
use zk_engine::{
  args::{WASMArgsBuilder, WASMCtx},
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
  BatchedZKEngine,
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
    .func_args(vec![String::from("1000")]) // This will generate 16,000 + opcodes
    .build();

  let pp = BatchedZKEngine::setup(&mut WASMCtx::new_from_file(&args)?)?;

  // Use `BatchedZKEProof` for batched proving
  let (proof, public_values, _) =
    BatchedZKEngine::prove_wasm(&mut WASMCtx::new_from_file(&args)?, &pp)?;

  // Verify proof
  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}

```

### Enable zero-knowledge

To enable zero-knowlege see below code snippet on configaration.

Example: 
`type E1 = PallasEngine;` becomes -> `type E1 = ZKPallasEngine;`

```bash
RUST_LOG=debug cargo +nightly run --release --example zk
````

```rust
use nova::provider::ZKPallasEngine;
use std::path::PathBuf;
use zk_engine::{
  args::{WASMArgsBuilder, WASMCtx},
  // Backend imports for ZK
  nova::{
    provider::ipa_pc,
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::Dual,
  },
  run::batched::BatchedZKEProof,
  traits::zkvm::ZKVM,
  utils::logging::init_logger,
};

// Configs to enable ZK
type E1 = ZKPallasEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;
type BS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
type S1 = RelaxedR1CSSNARK<E1, EE1>;
type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

type ZKEngine = BatchedZKEProof<E1, BS1, S1, S2>;

fn main() -> anyhow::Result<()> {
  init_logger();

  let args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/misc/fib.wat"))
    .invoke(Some(String::from("fib")))
    .func_args(vec![String::from("1000")]) // This will generate 16,000 + opcodes
    .build();

  let pp = ZKEngine::setup(&mut WASMCtx::new_from_file(&args)?)?;

  // ZKPallasEngine get's used here
  let (proof, public_values, _) = ZKEngine::prove_wasm(&mut WASMCtx::new_from_file(&args)?, &pp)?;

  // Verify proof
  let result = proof.verify(public_values, &pp)?;
  Ok(assert!(result))
}
  ```


