use ff::PrimeField;
use wasmi::{Instruction as Instr, WitnessVM};

use crate::v1::wasm_snark::MEMORY_OPS_PER_STEP;

/// Get the RS & WS for a single execution step. A RS (read-set) & a WS (write-set) are of the form
/// of a vector of (address, value, timestamp) tuples
pub fn step_RS_WS(
  vm: &WitnessVM,
  FS: &mut [(u64, u64)],
  global_ts: &mut u64,
) -> (
  Vec<(usize, u64, u64)>, // RS
  Vec<(usize, u64, u64)>, // WS
) {
  let instr = vm.instr;
  let mut RS: Vec<(usize, u64, u64)> = Vec::with_capacity(MEMORY_OPS_PER_STEP / 2);
  let mut WS: Vec<(usize, u64, u64)> = Vec::with_capacity(MEMORY_OPS_PER_STEP / 2);

  match instr {
    Instr::I64Const32(_) | Instr::Const32(..) => {
      write_op(vm.pre_sp, vm.I, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::LocalGet(_) => {
      read_op(vm.pre_sp - vm.I as usize, global_ts, FS, &mut RS, &mut WS);
      write_op(vm.pre_sp, vm.P, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::LocalSet(_) => {
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS);
      write_op(
        vm.pre_sp - 1 - (vm.I as usize),
        vm.Y,
        global_ts,
        FS,
        &mut RS,
        &mut WS,
      );
    }
    Instr::I64Add | Instr::I64Mul => {
      read_op(vm.pre_sp - 2, global_ts, FS, &mut RS, &mut WS); // X
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // Y

      write_op(vm.pre_sp - 2, vm.Z, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::BrIfEqz(_) | Instr::BrIfNez(_) => {
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // condition
    }
    Instr::Br(_) => {}
    Instr::Drop => {}
    _ => unimplemented!("{:?}", instr),
  }

  // If the number of memory operations is not equal to MEMORY_OPS_PER_STEP, then we need to pad
  // the RS & WS with dummy values
  for _ in RS.len()..MEMORY_OPS_PER_STEP / 2 {
    read_op(0, global_ts, FS, &mut RS, &mut WS);
  }

  (RS, WS)
}

/// Read operation between an untrusted memory and a checker
fn read_op(
  addr: usize,
  global_ts: &mut u64,
  FS: &mut [(u64, u64)],
  RS: &mut Vec<(usize, u64, u64)>,
  WS: &mut Vec<(usize, u64, u64)>,
) {
  // 1. ts ← ts + 1
  *global_ts += 1;

  // untrusted memory responds with a value-timestamp pair (v, t)
  let (r_val, r_ts) = FS[addr];

  // 2. assert t < ts
  debug_assert!(r_ts < *global_ts);

  // 3. RS ← RS ∪ {(a,v,t)};
  RS.push((addr, r_val, r_ts));

  // 4. store (v, ts) at address a in the untrusted memory; and
  FS[addr] = (r_val, *global_ts);

  // 5. WS ← WS ∪ {(a,v,ts)}.
  WS.push((addr, r_val, *global_ts));
}

/// Write operation between an untrusted memory and a checker
fn write_op(
  addr: usize,
  val: u64,
  global_ts: &mut u64,
  FS: &mut [(u64, u64)],
  RS: &mut Vec<(usize, u64, u64)>,
  WS: &mut Vec<(usize, u64, u64)>,
) {
  // 1. ts ← ts + 1
  *global_ts += 1;

  // untrusted memory responds with a value-timestamp pair (v, t)
  let (r_val, r_ts) = FS[addr];

  // 2. assert t < ts
  debug_assert!(r_ts < *global_ts);

  // 3. RS ← RS ∪ {(a,v,t)};
  RS.push((addr, r_val, r_ts));

  // 4. store (v', ts) at address a in the untrusted memory; and
  FS[addr] = (val, *global_ts);

  // 5. WS ← WS ∪ {(a,v',ts)}.
  WS.push((addr, val, *global_ts));
}

/// Converts an addr, val, ts tuple `(usize, u64, u64)` to a `Vec<Scalar>`
pub fn avt_tuple_to_scalar_vec<F>(tuple: (usize, u64, u64)) -> Vec<F>
where
  F: PrimeField,
{
  let (addr, val, ts) = tuple;
  vec![F::from(addr as u64), F::from(val), F::from(ts)]
}
