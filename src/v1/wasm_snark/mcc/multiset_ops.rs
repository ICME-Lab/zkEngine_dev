use ff::PrimeField;
use wasmi::{Instruction as Instr, WitnessVM};

use crate::v1::wasm_snark::MEMORY_OPS_PER_STEP;

/// Get the RS & WS for a single execution step. A RS (read-set) & a WS (write-set) are of the form
/// of a vector of (address, value, timestamp) tuples
pub fn step_RS_WS(
  vm: &WitnessVM,
  FS: &mut [(usize, u64, u64)],
  global_ts: &mut u64,
  stack_len: usize,
  mem_len: usize,
) -> (
  Vec<(usize, u64, u64)>, // RS
  Vec<(usize, u64, u64)>, // WS
) {
  let instr = vm.instr;
  let mut RS: Vec<(usize, u64, u64)> = Vec::with_capacity(MEMORY_OPS_PER_STEP / 2);
  let mut WS: Vec<(usize, u64, u64)> = Vec::with_capacity(MEMORY_OPS_PER_STEP / 2);

  match instr {
    Instr::Unreachable => {}
    Instr::Select => {
      read_op(vm.pre_sp - 3, global_ts, FS, &mut RS, &mut WS); // X
      read_op(vm.pre_sp - 2, global_ts, FS, &mut RS, &mut WS); // Y
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // condition
      write_op(vm.pre_sp - 3, vm.Z, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::I64Const32(_) | Instr::Const32(..) | Instr::ConstRef(..) | Instr::F64Const32(..) => {
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

    Instr::LocalTee(_) => {
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS);
      write_op(
        vm.pre_sp - (vm.I as usize),
        vm.Y,
        global_ts,
        FS,
        &mut RS,
        &mut WS,
      );
    }
    Instr::I64Add
    | Instr::I64Mul
    | Instr::I64And
    | Instr::I64Or
    | Instr::I64Xor
    | Instr::I64Sub
    | Instr::I64Shl
    | Instr::I64Rotl
    | Instr::I64Rotr
    | Instr::I64ShrU
    | Instr::I64DivS
    | Instr::I64DivU
    | Instr::I64RemS
    | Instr::I64RemU
    | Instr::I64ShrS => {
      read_op(vm.pre_sp - 2, global_ts, FS, &mut RS, &mut WS); // X
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // Y

      write_op(vm.pre_sp - 2, vm.Z, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::BrIfEqz(_) | Instr::BrIfNez(_) => {
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // condition
    }
    Instr::Br(_) => {}
    Instr::BrTable(_) => {}
    Instr::BrAdjust(_) => {}
    Instr::Drop => {}
    Instr::CallInternal(..) => {}
    Instr::DropKeep => {
      let drop = vm.I as usize;
      let keep = vm.P as usize;
      let read_addr = vm.pre_sp - keep;
      let write_addr = vm.pre_sp - drop - keep;

      read_op(read_addr, global_ts, FS, &mut RS, &mut WS);
      write_op(write_addr, vm.Y, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::Return(..) => {}
    Instr::I64Store(..)
    | Instr::I64Store8(..)
    | Instr::I64Store16(..)
    | Instr::I64Store32(..)
    | Instr::I32Store(..)
    | Instr::I32Store8(..)
    | Instr::I32Store16(..)
    | Instr::F32Store(..)
    | Instr::F64Store(..) => {
      // Stack ops
      read_op(vm.pre_sp - 2, global_ts, FS, &mut RS, &mut WS); // raw addr
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // value

      // Linear mem ops
      let effective_addr = vm.I as usize;

      let write_addr_1 = effective_addr / 8 + stack_len;
      let write_addr_2 = effective_addr / 8 + 1 + stack_len;
      write_op(write_addr_1, vm.P, global_ts, FS, &mut RS, &mut WS);
      write_op(write_addr_2, vm.Q, global_ts, FS, &mut RS, &mut WS);
    }

    Instr::I32Load(..)
    | Instr::I32Load8U(..)
    | Instr::I32Load8S(..)
    | Instr::I32Load16U(..)
    | Instr::I32Load16S(..)
    | Instr::F32Load(..)
    | Instr::F64Load(..)
    | Instr::I64Load(..)
    | Instr::I64Load8S(..)
    | Instr::I64Load8U(..)
    | Instr::I64Load16S(..)
    | Instr::I64Load16U(..)
    | Instr::I64Load32S(..)
    | Instr::I64Load32U(..) => {
      // stack ops
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // addr

      // linear mem ops
      let effective_addr = vm.I as usize;

      let read_addr_1 = effective_addr / 8 + stack_len;
      let read_addr_2 = effective_addr / 8 + 1 + stack_len;

      read_op(read_addr_1, global_ts, FS, &mut RS, &mut WS);
      read_op(read_addr_2, global_ts, FS, &mut RS, &mut WS);

      write_op(vm.pre_sp - 1, vm.Z, global_ts, FS, &mut RS, &mut WS);
    }

    Instr::I64Clz | Instr::I64Ctz | Instr::I64Popcnt | Instr::I64Eqz | Instr::I32Eqz => {
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // Y
      write_op(vm.pre_sp - 1, vm.Z, global_ts, FS, &mut RS, &mut WS); // Z
    }

    // visit_unary
    Instr::F32Abs
    | Instr::F32Neg
    | Instr::F32Ceil
    | Instr::F32Floor
    | Instr::F32Trunc
    | Instr::F32Nearest
    | Instr::F32Sqrt
    | Instr::F64Abs
    | Instr::F64Neg
    | Instr::F64Ceil
    | Instr::F64Floor
    | Instr::F64Trunc
    | Instr::F64Nearest
    | Instr::F64Sqrt
    | Instr::I32WrapI64
    | Instr::I32TruncF32S
    | Instr::I32TruncF32U
    | Instr::I32TruncF64S
    | Instr::I32TruncF64U
    | Instr::I64ExtendI32S
    | Instr::I64ExtendI32U
    | Instr::I64TruncF32S
    | Instr::I64TruncF32U
    | Instr::I64TruncF64S
    | Instr::I64TruncF64U
    | Instr::F32ConvertI32S
    | Instr::F32ConvertI32U
    | Instr::F32ConvertI64S
    | Instr::F32ConvertI64U
    | Instr::F32DemoteF64
    | Instr::F64ConvertI32S
    | Instr::F64ConvertI32U
    | Instr::F64ConvertI64S
    | Instr::F64ConvertI64U
    | Instr::F64PromoteF32
    | Instr::I32Extend8S
    | Instr::I32Extend16S
    | Instr::I64Extend8S
    | Instr::I64Extend16S
    | Instr::I64Extend32S
    | Instr::I32TruncSatF32S
    | Instr::I32TruncSatF32U
    | Instr::I32TruncSatF64S
    | Instr::I32TruncSatF64U
    | Instr::I64TruncSatF32S
    | Instr::I64TruncSatF32U
    | Instr::I64TruncSatF64S
    | Instr::I64TruncSatF64U
    | Instr::I32Clz
    | Instr::I32Ctz
    | Instr::I32Popcnt => {
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // Y
      write_op(vm.pre_sp - 1, vm.Z, global_ts, FS, &mut RS, &mut WS); // Z
    }

    // visit_binary
    Instr::F32Eq
    | Instr::F32Ne
    | Instr::F32Lt
    | Instr::F32Gt
    | Instr::F32Le
    | Instr::F32Ge
    | Instr::F64Eq
    | Instr::F64Ne
    | Instr::F64Lt
    | Instr::F64Gt
    | Instr::F64Le
    | Instr::F64Ge
    | Instr::F32Add
    | Instr::F32Sub
    | Instr::F32Mul
    | Instr::F32Div
    | Instr::F32Min
    | Instr::F32Max
    | Instr::F32Copysign
    | Instr::F64Add
    | Instr::F64Sub
    | Instr::F64Mul
    | Instr::F64Div
    | Instr::F64Min
    | Instr::F64Max
    | Instr::F64Copysign
    | Instr::I64Eq
    | Instr::I64Ne
    | Instr::I64LtS
    | Instr::I64LtU
    | Instr::I64GtS
    | Instr::I64GtU
    | Instr::I64LeS
    | Instr::I64LeU
    | Instr::I64GeS
    | Instr::I64GeU
    | Instr::I32Eq
    | Instr::I32Ne
    | Instr::I32LtS
    | Instr::I32LtU
    | Instr::I32GtS
    | Instr::I32GtU
    | Instr::I32LeS
    | Instr::I32LeU
    | Instr::I32GeS
    | Instr::I32GeU
    | Instr::I32Add
    | Instr::I32Sub
    | Instr::I32Mul
    | Instr::I32DivS
    | Instr::I32DivU
    | Instr::I32RemS
    | Instr::I32RemU
    | Instr::I32And
    | Instr::I32Or
    | Instr::I32Xor
    | Instr::I32Shl
    | Instr::I32ShrS
    | Instr::I32ShrU
    | Instr::I32Rotl
    | Instr::I32Rotr => {
      read_op(vm.pre_sp - 2, global_ts, FS, &mut RS, &mut WS); // X
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // Y

      write_op(vm.pre_sp - 2, vm.Z, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::GlobalGet(..) => {
      let read_addr = stack_len + mem_len + vm.I as usize;
      read_op(read_addr, global_ts, FS, &mut RS, &mut WS); // Y
      write_op(vm.pre_sp, vm.Y, global_ts, FS, &mut RS, &mut WS);
    }

    Instr::GlobalSet(..) => {
      let write_addr = stack_len + mem_len + vm.I as usize;
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS); // Y
      write_op(write_addr, vm.Y, global_ts, FS, &mut RS, &mut WS);
    }

    Instr::MemoryFill => {}
    Instr::MemoryCopy => {}
    Instr::MemoryFillStep => {
      let read_addr = vm.Y as usize + stack_len;
      read_op(read_addr, global_ts, FS, &mut RS, &mut WS);

      let write_addr = vm.X as usize + stack_len;
      write_op(write_addr, vm.P, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::MemoryCopyStep => {
      let write_addr = vm.X as usize + stack_len;
      write_op(write_addr, vm.P, global_ts, FS, &mut RS, &mut WS);
    }

    Instr::HostCallStep => {
      let write_addr = vm.Y as usize + stack_len;
      write_op(write_addr, vm.P, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::HostCallStackStep => {
      write_op(vm.pre_sp, vm.P, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::CallIndirect(..) => {}

    Instr::MemorySize => {
      write_op(vm.pre_sp, vm.Y, global_ts, FS, &mut RS, &mut WS);
    }
    Instr::MemoryGrow => {
      read_op(vm.pre_sp - 1, global_ts, FS, &mut RS, &mut WS);
      write_op(vm.pre_sp - 1, vm.P, global_ts, FS, &mut RS, &mut WS);
    }
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
  FS: &mut [(usize, u64, u64)],
  RS: &mut Vec<(usize, u64, u64)>,
  WS: &mut Vec<(usize, u64, u64)>,
) {
  // 1. ts ← ts + 1
  *global_ts += 1;

  // untrusted memory responds with a value-timestamp pair (v, t)
  let (_, r_val, r_ts) = FS[addr];

  // 2. assert t < ts
  debug_assert!(r_ts < *global_ts);

  // 3. RS ← RS ∪ {(a,v,t)};
  RS.push((addr, r_val, r_ts));

  // 4. store (v, ts) at address a in the untrusted memory; and
  FS[addr] = (addr, r_val, *global_ts);

  // 5. WS ← WS ∪ {(a,v,ts)}.
  WS.push((addr, r_val, *global_ts));
}

/// Write operation between an untrusted memory and a checker
fn write_op(
  addr: usize,
  val: u64,
  global_ts: &mut u64,
  FS: &mut [(usize, u64, u64)],
  RS: &mut Vec<(usize, u64, u64)>,
  WS: &mut Vec<(usize, u64, u64)>,
) {
  // 1. ts ← ts + 1
  *global_ts += 1;

  // untrusted memory responds with a value-timestamp pair (v, t)
  let (_, r_val, r_ts) = FS[addr];

  // 2. assert t < ts
  debug_assert!(r_ts < *global_ts);

  // 3. RS ← RS ∪ {(a,v,t)};
  RS.push((addr, r_val, r_ts));

  // 4. store (v', ts) at address a in the untrusted memory; and
  FS[addr] = (addr, val, *global_ts);

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
