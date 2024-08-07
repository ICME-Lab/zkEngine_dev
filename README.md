 **THIS HAS NOT BEEN AUDITED YET AND SHOULD BE USED ONLY FOR TESTING PURPOSES AND NOT IN PRODUCTION.**

# zkEngine

zkEngine is a zkWASM with a SuperNova backend

## Usage: as Rust dependency

### Cargo

```toml
[dependencies]
zk-engine = { git = "https://github.com/ICME-Lab/zkEngine_dev", branch= "main" }
```

### Default mode

Default mode runs one WASM opcode per each step of NIVC in execution proving and one memory read/write for each step in the MCC (which uses IVC)

```rust
  use std::path::PathBuf;
  // Backend imports
  use zk_engine::nova::{
    provider::{ipa_pc, PallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::{
      snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
      CurveCycleEquipped, Dual, Engine,
    },
  };
  use zk_engine::{
    args::{WASMArgsBuilder, WASMCtx},
    run::default::ZKEProof,
    traits::zkvm::ZKVM,
    utils::logging::init_logger,
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

  fn main() -> anyhow::Result<()>
  {
    init_logger();

    // Configure the arguments needed for WASM execution
    //
    // Here we are configuring the path to the WASM file
    let args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/example.wasm"))
      .build();
    
    // Create a WASM execution context for proving.
    let mut wasm_ctx = WASMCtx::new_from_file(args)?;

    // Prove execution and run memory consistency checks
    //
    // Get proof for verification and corresponding public values
    //
    // Above type alias's get used here
    let (proof, public_values) = ZKEProof::<E1, BS1, S1, S2>::prove_wasm(&mut wasm_ctx)?;

    // Verify proof
    let result = proof.verify(public_values)?;
    Ok(assert!(result))
  }
```

### Batched mode

Batched mode should be used when you have a lot of opcodes to prove. (Ex: 10,000 opcodes).
Batched mode will batch the opcodes into 10 steps, for example a 10,000 opcode WASM, when being proven each step of NIVC will prove 1,000 opcodes.
The memory consisteny checks will also be batched into 10 steps.

```rust
  use std::path::PathBuf;
  // Backend imports
  use zk_engine::nova::{
    provider::{ipa_pc, PallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::{
      snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
      CurveCycleEquipped, Dual, Engine,
    },
  };
  use zk_engine::{
    args::{WASMArgsBuilder, WASMCtx},
    run::batched::BatchedZKEProof,
    traits::zkvm::ZKVM,
    utils::logging::init_logger,
  };

  // Backend configs
  type E1 = PallasEngine;
  type EE1<E> = ipa_pc::EvaluationEngine<E>;
  type EE2<E> = ipa_pc::EvaluationEngine<Dual<E>>;
  type BS1<E> = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1<E>>;
  type S1<E> = RelaxedR1CSSNARK<E, EE1<E>>;
  type S2<E> = RelaxedR1CSSNARK<Dual<E>, EE2<E>>;

  fn main() -> anyhow::Result<()>
  {
    init_logger();

    // Some WASM's require the function to invoke and the functions arguments
    // 
    // You can specify both like so
    let args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/misc/fib.wat"))
      .invoke(Some(String::from("fib")))
      .func_args(vec![String::from("1000")]) // This will generate 16,000 + opcodes
      .build();
    let mut wasm_ctx = WASMCtx::new_from_file(args)?;

    // Use `BatchedZKEProof` for batched proving
    let (proof, public_values) = BatchedZKEProof::<E1, BS1, S1, S2>::prove_wasm(&mut wasm_ctx)?;
    let result = proof.verify(public_values)?;
    Ok(assert!(result))
  }
```

### Enable zero-knowledge

To enable zero-knowlege simply change the type alias for the curve cycle to 
`ZKPallasEngine`

Example: 
`type E1 = PallasEngine;` becomes -> `type E1 = ZKPallasEngine;`

```rust
  use std::path::PathBuf;
  // Backend imports for ZK
  use zk_engine::nova::{
    provider::{ipa_pc, ZKPallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::{
      snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
      CurveCycleEquipped, Dual, Engine,
    },
  };
  use zk_engine::{
    args::{WASMArgsBuilder, WASMCtx},
    run::batched::BatchedZKEProof,
    traits::zkvm::ZKVM,
    utils::logging::init_logger,
  };

  // Configs to enable ZK
  type E1 = ZKPallasEngine;
  type EE1<E> = ipa_pc::EvaluationEngine<E>;
  type EE2<E> = ipa_pc::EvaluationEngine<Dual<E>>;
  type BS1<E> = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1<E>>;
  type S1<E> = RelaxedR1CSSNARK<E, EE1<E>>;
  type S2<E> = RelaxedR1CSSNARK<Dual<E>, EE2<E>>;

  fn main() -> anyhow::Result<()>
  {
    init_logger();

    // Some WASM's require the function to invoke and the functions arguments
    // 
    // You can specify both like so
    let args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/misc/fib.wat"))
      .invoke(Some(String::from("fib")))
      .func_args(vec![String::from("1000")])
      .build();
    let mut wasm_ctx = WASMCtx::new_from_file(args)?;

    // ZKPallasEngine get's used here
    let (proof, public_values) = BatchedZKEProof::<E1, BS1, S1, S2>::prove_wasm(&mut wasm_ctx)?;
    let result = proof.verify(public_values)?;
    Ok(assert!(result))
  }
  ```