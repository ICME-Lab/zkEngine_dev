use crate::v1::{
  error::ZKWASMError,
  wasm_ctx::{ExecutionTrace, ZKWASMCtx},
};
use std::{cell::RefCell, rc::Rc};

/// Get inner value of [`Rc<RefCell<T>>`]
///
/// # Panics
///
/// Panics if [`Rc`] is not the sole owner of the underlying data,
pub fn unwrap_rc_refcell<T>(last_elem: Rc<RefCell<T>>) -> T {
  let inner: RefCell<T> = Rc::try_unwrap(last_elem)
    .unwrap_or_else(|_| panic!("The last_elem was shared, failed to unwrap"));
  inner.into_inner()
}

#[allow(dead_code)]
#[tracing::instrument(skip_all, name = "estimate_wasm")]
/// Get estimations of the WASM execution trace size
pub fn estimate_wasm(program: &impl ZKWASMCtx) -> Result<ExecutionTrace, ZKWASMError> {
  program.execution_trace()
}

/// Split vector and return Vec's
pub fn split_vector<T>(mut vec: Vec<T>, split_index: usize) -> (Vec<T>, Vec<T>) {
  let second_part = vec.split_off(split_index);
  (vec, second_part)
}

#[cfg(test)]
mod test {
  use wasmi::WitnessVM;

  use crate::v1::wasm_ctx::{WASMArgsBuilder, WASMCtx, WasiWASMCtx, ZKWASMCtx};
  use std::{collections::HashMap, path::PathBuf};

  /// Count how many time an opcode gets used. Uses the J index of the opcode
  fn count_opcodes(vms: &[WitnessVM]) -> HashMap<u64, usize> {
    let capacity = wasmi::Instruction::MAX_J + 1;

    let mut opcodes_count = HashMap::with_capacity(capacity as usize);

    for c in 0..capacity {
      opcodes_count.insert(c, 0);
    }

    for vm in vms {
      let instr_J = vm.instr.index_j();
      let count = opcodes_count.entry(instr_J).or_insert(0);
      *count += 1;
    }

    opcodes_count
  }

  fn test_count_with(program: &impl ZKWASMCtx) {
    let (vms, _, _) = program.execution_trace().unwrap();
    println!("vms.len(): {:#?}", vms.len());

    let opcodes_count = count_opcodes(&vms);

    let instrs_to_count = [
      // i64 and i32
      wasmi::Instruction::I64Eqz,
      wasmi::Instruction::I64Eq,
      wasmi::Instruction::I64Ne,
      // i64
      wasmi::Instruction::I64Add,
      wasmi::Instruction::I64Mul,
      wasmi::Instruction::I64Sub,
      wasmi::Instruction::I64LtU,
      wasmi::Instruction::I64GtU,
      wasmi::Instruction::I64DivS,
      wasmi::Instruction::I64DivU,
      wasmi::Instruction::I64And,
      wasmi::Instruction::I64Popcnt,
      wasmi::Instruction::I64Shl,
      // i32
      wasmi::Instruction::I32Add,
      wasmi::Instruction::I32Mul,
      wasmi::Instruction::I32Sub,
      wasmi::Instruction::I32LtU,
      wasmi::Instruction::I32GtU,
      wasmi::Instruction::I32DivS,
      wasmi::Instruction::I32DivU,
      wasmi::Instruction::I32And,
      wasmi::Instruction::I32Popcnt,
      wasmi::Instruction::I32Shl,
    ];

    for instr_to_count in instrs_to_count.iter() {
      println!(
        "{:?}: {:#?}",
        instr_to_count,
        opcodes_count[&instr_to_count.index_j()]
      );
    }
  }

  #[test]
  fn test_count_defi_transaction() {
    // Simulated user and pool balances
    let user_input_balance = "1000"; // User's balance of token A
    let pool_input_reserve = "10000"; // Pool's reserve of token A
    let pool_output_reserve = "10000"; // Pool's reserve of token B
    let swap_amount = "500"; // Amount of token A to swap for token B
    let price = "100"; // Price of token A in terms of token B

    let wasm_args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/use_cases/defi_transaction.wasm"))
      .unwrap()
      .func_args(vec![
        user_input_balance.to_string(),
        pool_input_reserve.to_string(),
        pool_output_reserve.to_string(),
        swap_amount.to_string(),
        price.to_string(),
      ])
      .invoke("main")
      .build();
    let wasm_ctx = WASMCtx::new(wasm_args);

    test_count_with(&wasm_ctx);
  }

  #[test]
  fn test_count_energy_usage() {
    let total_produced = "5000"; // Total energy produced by the microgrid in some time frame (e.g., in watt-hours).
    let total_consumed = "4900"; // Total energy consumed by all devices in the microgrid for the same period.
    let device_count = "100"; // Number of IoT devices or meters in the network.
    let baseline_price = "100"; // A baseline price or factor used for further calculations (e.g., cost per watt-hour or an
                                // index).

    let wasm_args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/use_cases/energy_usage.wasm"))
      .unwrap()
      .func_args(vec![
        total_produced.to_string(),
        total_consumed.to_string(),
        device_count.to_string(),
        baseline_price.to_string(),
      ])
      .invoke("main")
      .build();

    let wasm_ctx = WASMCtx::new(wasm_args);

    test_count_with(&wasm_ctx);
  }

  #[test]
  fn test_count_toy_rsa() {
    let p_candidate = "1009"; // A candidate prime number p.
    let q_candidate = "1013"; // A candidate prime number q.
    let e = "17"; // A public exponent e.
    let message = "65"; // A message to encrypt.
    let use_crt = "1"; // A flag to use the Chinese Remainder Theorem (CRT) optimization.

    let wasm_args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/use_cases/toy_rsa.wasm"))
      .unwrap()
      .func_args(vec![
        p_candidate.to_string(),
        q_candidate.to_string(),
        e.to_string(),
        message.to_string(),
        use_crt.to_string(),
      ])
      .invoke("main")
      .build();

    let wasm_ctx = WASMCtx::new(wasm_args);

    test_count_with(&wasm_ctx);
  }

  #[test]
  fn test_financial_protocol() {
    //  Moderately healthy loan, moderate staking, moderate interest
    let collateral_amount = "2000";
    let borrowed_amount = "1000";
    let stake_ratio = "50";
    let annual_interest_bps = "600"; // 6% annual interest

    let wasm_args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/use_cases/financial_protocol.wasm"))
      .unwrap()
      .func_args(vec![
        collateral_amount.to_string(),
        borrowed_amount.to_string(),
        stake_ratio.to_string(),
        annual_interest_bps.to_string(),
      ])
      .invoke("main")
      .build();

    let wasm_ctx = WASMCtx::new(wasm_args);

    test_count_with(&wasm_ctx);
  }

  #[test]
  fn test_count_integer_hash() {
    let wasm_args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/nebula/integer_hash.wasm"))
      .unwrap()
      .func_args(vec!["100".to_string()])
      .invoke("integer_hash")
      .build();

    let wasm_ctx = WASMCtx::new(wasm_args);

    test_count_with(&wasm_ctx);
  }

  #[test]
  fn test_count_gradient_boosting() {
    let wasm_args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
      .unwrap()
      .invoke("_start")
      .build();

    let wasm_ctx = WasiWASMCtx::new(wasm_args);

    test_count_with(&wasm_ctx);
  }
}
