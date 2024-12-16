use super::{
  gadgets::{
    int::{add, eqz_bit, sub},
    utils::{alloc_one, conditionally_select},
  },
  mcc::multiset_ops::avt_tuple_to_scalar_vec,
  MEMORY_OPS_PER_STEP,
};
use alu::{
  eq, eqz,
  int64::{
    add64, bitops_64, div_rem_s_64, div_rem_u_64, le_gt_s, lt_ge_s, mul64, shift_rotate_64, sub64,
    unary_ops_64,
  },
};
use bellpepper_core::{
  self, boolean::AllocatedBit, num::AllocatedNum, ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use itertools::Itertools;
use nova::nebula::rs::StepCircuit;
use wasmi::{
  AddressOffset, BCGlobalIdx, BranchOffset, BranchTableTargets, DropKeep, Instruction as Instr,
  WitnessVM,
};

mod alu;

#[derive(Clone, Debug)]
/// BatchedWasmTransitionCircuit
pub struct BatchedWasmTransitionCircuit {
  circuits: Vec<WASMTransitionCircuit>,
}

impl<F> StepCircuit<F> for BatchedWasmTransitionCircuit
where
  F: PrimeField + PrimeFieldBits,
{
  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut z = z.to_vec();

    for circuit in self.circuits.iter() {
      z = circuit.synthesize(cs, &z)?;
    }

    Ok(z)
  }

  fn non_deterministic_advice(&self) -> Vec<F> {
    self
      .circuits
      .iter()
      .flat_map(|circuit| circuit.non_deterministic_advice())
      .collect()
  }
}

impl BatchedWasmTransitionCircuit {
  /// Create an empty instance of [`BatchedWasmTransitionCircuit`]
  pub fn empty(step_size: usize) -> Self {
    Self {
      circuits: vec![WASMTransitionCircuit::default(); step_size],
    }
  }

  /// Create a new instance of [`BatchedWasmTransitionCircuit`]
  pub fn new(circuits: Vec<WASMTransitionCircuit>) -> Self {
    Self { circuits }
  }
}

/// Switchboard circuit representing a step in a WASM module's computation
#[derive(Clone, Debug)]
pub struct WASMTransitionCircuit {
  vm: WitnessVM,
  RS: Vec<(usize, u64, u64)>,
  WS: Vec<(usize, u64, u64)>,
  stack_len: usize,
}

impl<F> StepCircuit<F> for WASMTransitionCircuit
where
  F: PrimeField + PrimeFieldBits,
{
  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    /*
     * **** Switchboard circuit ****
     */
    let mut switches = Vec::new();
    self.visit_unreachable(cs.namespace(|| "unreachable"), &mut switches)?;

    self.visit_const(cs.namespace(|| "const"), &mut switches)?;

    self.visit_local_get(cs.namespace(|| "local.get"), &mut switches)?;
    self.visit_local_set(cs.namespace(|| "local.set"), &mut switches)?;
    self.visit_local_tee(cs.namespace(|| "local.tee"), &mut switches)?;
    self.visit_global_get(cs.namespace(|| "global.get"), &mut switches)?;
    self.visit_global_set(cs.namespace(|| "global.set"), &mut switches)?;

    self.visit_i64_add(cs.namespace(|| "i64.add"), &mut switches)?;
    self.visit_i64_sub(cs.namespace(|| "i64.sub"), &mut switches)?;
    self.visit_i64_mul(cs.namespace(|| "i64.mul"), &mut switches)?;
    self.visit_i64_div_rem_u(cs.namespace(|| "visit_i64_div_rem_u"), &mut switches)?;
    self.visit_i64_div_rem_s(cs.namespace(|| "visit_i64_div_rem_s"), &mut switches)?;

    self.visit_i64_bitops(cs.namespace(|| "visit_i64_bitops"), &mut switches)?;
    self.visit_i64_unary_ops(cs.namespace(|| "visit_i64_unary_ops"), &mut switches)?;

    self.visit_shift_rotate_64(cs.namespace(|| "visit_shift_rotate_64"), &mut switches)?;

    // self.visit_i64_shl(cs.namespace(|| "i64.shl"), &mut switches)?;
    // self.visit_i64_shr_u(cs.namespace(|| "i64.shr_u"), &mut switches)?;
    // self.visit_i64_shr_s(cs.namespace(|| "i64.shr_s"), &mut switches)?;
    // self.visit_i64_rotl(cs.namespace(|| "i64.rotl"), &mut switches)?;
    // self.visit_i64_rotr(cs.namespace(|| "i64.rotr"), &mut switches)?;

    self.visit_eqz(cs.namespace(|| "visit_eqz"), &mut switches)?;
    self.visit_eq(cs.namespace(|| "visit_eq"), &mut switches)?;
    self.visit_ne(cs.namespace(|| "visit_ne"), &mut switches)?;
    self.visit_i64_lt_ge_s(cs.namespace(|| "visit_i64_lt_ge_s"), &mut switches)?;
    self.visit_i64_le_gt_s(cs.namespace(|| "visit_i64_le_gt_s"), &mut switches)?;

    self.visit_br_if_eqz(cs.namespace(|| "Instr::BrIfEqz"), &mut switches)?;
    self.visit_br_if_nez(cs.namespace(|| "Instr::BrIfNez"), &mut switches)?;
    self.visit_br(cs.namespace(|| "Instr::Br"), &mut switches)?;
    self.visit_br_table(cs.namespace(|| "Instr::BrTable"), &mut switches)?;
    self.visit_br_adjust(cs.namespace(|| "visit_br_adjust"), &mut switches)?;

    self.visit_store(cs.namespace(|| "store"), &mut switches)?;
    self.visit_load(cs.namespace(|| "load"), &mut switches)?;

    self.visit_select(cs.namespace(|| "visit_select"), &mut switches)?;

    self.visit_memory_copy(cs.namespace(|| "visit_memory_copy"), &mut switches)?;
    self.visit_memory_copy_step(cs.namespace(|| "visit_memory_copy_step"), &mut switches)?;
    self.visit_memory_fill(cs.namespace(|| "visit_memory_fill"), &mut switches)?;
    self.visit_memory_fill_step(cs.namespace(|| "visit_memory_fill_step"), &mut switches)?;
    self.visit_memory_size(cs.namespace(|| "visit_memory_size"), &mut switches)?;
    self.visit_memory_grow(cs.namespace(|| "visit_memory_grow"), &mut switches)?;

    self
      .visit_host_call_stack_step(cs.namespace(|| "visit_host_call_stack_step"), &mut switches)?;
    self.visit_host_call_step(cs.namespace(|| "visit_host_call_step"), &mut switches)?;
    self.visit_call_internal_step(cs.namespace(|| "visit_call_internal_step"), &mut switches)?;

    self.visit_unary(cs.namespace(|| "visit_unary"), &mut switches)?;
    self.visit_binary(cs.namespace(|| "visit_binary"), &mut switches)?;

    self.drop_keep(cs.namespace(|| "drop keep"), &mut switches)?;
    self.visit_ret(cs.namespace(|| "return"), &mut switches)?;

    /*
     *  Switch constraints
     */

    // 1. Single switch constraint:
    cs.enforce(
      || "single switch",
      |lc| {
        switches
          .iter()
          .fold(lc, |lc, switch| lc + switch.get_variable())
      },
      |lc| lc + CS::one(),
      |lc| lc + CS::one(),
    );

    // 2. Binary switch constraints:
    for (i, switch) in switches.iter().enumerate() {
      cs.enforce(
        || format!("binary switch {i}"),
        |lc| lc + switch.get_variable(),
        |lc| lc + CS::one() - switch.get_variable(),
        |lc| lc,
      );
    }

    Ok(z.to_vec())
  }

  fn non_deterministic_advice(&self) -> Vec<F> {
    self
      .RS
      .iter()
      .zip_eq(self.WS.iter())
      .flat_map(|(rs, ws)| {
        let rs_vec = avt_tuple_to_scalar_vec::<F>(*rs);
        let ws_vec = avt_tuple_to_scalar_vec::<F>(*ws);
        rs_vec.into_iter().chain(ws_vec)
      })
      .collect()
  }
}

impl WASMTransitionCircuit {
  /// Allocate if switch is on or off depending on the instruction
  fn switch<CS, F>(
    &self,
    cs: &mut CS,
    J: u64,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<F, SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let switch = if J == self.vm.J { F::ONE } else { F::ZERO };
    switches.push(AllocatedNum::alloc(cs.namespace(|| "switch"), || {
      Ok(switch)
    })?);
    Ok(switch)
  }

  /// Allocate a num into the zkWASM CS
  fn alloc_num<CS, F, A, AR, Fo>(
    cs: &mut CS,
    annotation: A,
    value: Fo,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
    A: FnOnce() -> AR,
    AR: Into<String>,
    Fo: FnOnce() -> Result<F, SynthesisError>,
  {
    AllocatedNum::alloc(cs.namespace(annotation), || {
      let res = value()?;
      Ok(res * switch)
    })
  }

  /// Allocate a bit into the zkWASM CS
  fn alloc_bit<CS, F, A, AR>(
    cs: &mut CS,
    annotation: A,
    value: Option<bool>,
    switch: F,
  ) -> Result<AllocatedBit, SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
    A: FnOnce() -> AR,
    AR: Into<String>,
  {
    if switch == F::ONE {
      AllocatedBit::alloc(cs.namespace(annotation), value)
    } else {
      AllocatedBit::alloc(cs.namespace(annotation), Some(false))
    }
  }

  /// Allocate a (addr, val, timestamp) tuple into the CS
  fn alloc_avt<CS, F>(
    mut cs: CS,
    avt: &(usize, u64, u64),
    switch: F,
  ) -> Result<(AllocatedNum<F>, AllocatedNum<F>, AllocatedNum<F>), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let (addr, val, ts) = *avt;
    let addr = Self::alloc_num(&mut cs, || "addr", || Ok(F::from(addr as u64)), switch)?;
    let val = Self::alloc_num(&mut cs, || "val", || Ok(F::from(val)), switch)?;
    let ts = Self::alloc_num(&mut cs, || "ts", || Ok(F::from(ts)), switch)?;

    Ok((addr, val, ts))
  }

  /// Pefrom a read to zkVM read-write memory.  for a read operation, the advice is (a, v, rt) and
  /// (a, v, wt); F checks that the address a in the advice matches the address it requested and
  /// then uses the provided value v (e.g., in the rest of its computation).
  fn read<CS, F>(
    mut cs: CS,
    addr: &AllocatedNum<F>,
    advice: &(usize, u64, u64),
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let (advice_addr, advice_val, _) =
      Self::alloc_avt(cs.namespace(|| "(addr, val, ts)"), advice, switch)?;

    // F checks that the address a in the advice matches the address it requested
    cs.enforce(
      || "addr == advice_addr",
      |lc| lc + addr.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + advice_addr.get_variable(),
    );

    Ok(advice_val)
  }

  /// Perform a write to zkVM read-write memory.  For a write operation, the advice is (a, v, rt)
  /// and (a, v′, wt); F checks that the address a and the value v′ match the address and value it
  /// wishes to write. Otherwise, F ignores the remaining components in the provided advice.
  fn write<CS, F>(
    mut cs: CS,
    addr: &AllocatedNum<F>,
    val: &AllocatedNum<F>,
    advice: &(usize, u64, u64),
    switch: F,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let (advice_addr, advice_val, _) =
      Self::alloc_avt(cs.namespace(|| "(addr, val, ts)"), advice, switch)?;

    // F checks that the address a  match the address it wishes to write to.
    cs.enforce(
      || "addr == advice_addr",
      |lc| lc + addr.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + advice_addr.get_variable(),
    );

    // F checks that the value v′ match value it wishes to write.
    cs.enforce(
      || "val == advice_val",
      |lc| lc + val.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + advice_val.get_variable(),
    );

    Ok(())
  }

  /// Unreacable
  fn visit_unreachable<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Unreachable }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// memory.size
  fn visit_call_internal_step<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::CallZeroWrite }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// memory.copy
  fn visit_memory_copy<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryCopy }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// memory.size
  fn visit_memory_size<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemorySize }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// memory.size
  fn visit_memory_grow<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryGrow }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// memory.copy step
  fn visit_memory_copy_step<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryCopyStep }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// memory.fill
  fn visit_memory_fill<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryFill }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// memory.fill step
  fn visit_memory_fill_step<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryFillStep }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// host call stack step
  fn visit_host_call_stack_step<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::HostCallStackStep }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// host call step
  fn visit_host_call_step<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::HostCallStep }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// global.get
  fn visit_global_get<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::GlobalGet(BCGlobalIdx::from(0)) }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// BrTable
  fn visit_br_table<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrTable(BranchTableTargets::try_from(0).unwrap()) }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// BrTable
  fn visit_br_adjust<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrAdjust(BranchOffset::uninit()) }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// global.set
  fn visit_global_set<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::GlobalSet(BCGlobalIdx::from(0)) }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// Select
  fn visit_select<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Select }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// Push a const onto the stack
  fn visit_const<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Const32(0) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let pre_sp = Self::alloc_num(
      &mut cs,
      || "pre_sp",
      || Ok(F::from(self.vm.pre_sp as u64)),
      switch,
    )?;

    let I = Self::alloc_num(&mut cs, || "I", || Ok(F::from(self.vm.I)), switch)?;

    Self::write(
      cs.namespace(|| "push I on stack"),
      &pre_sp,
      &I,
      &self.WS[0],
      switch,
    )?;

    Ok(())
  }

  /// local.get
  fn visit_local_get<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::local_get(0).unwrap() }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let local_depth = Self::alloc_num(
      &mut cs,
      || "local depth",
      || Ok(F::from(self.vm.pre_sp as u64 - self.vm.I)),
      switch,
    )?;

    let read_val = Self::read(
      cs.namespace(|| "read at local_depth"),
      &local_depth,
      &self.RS[0],
      switch,
    )?;

    // let read_val = Self::alloc_num(&mut cs, || "read_val", || Ok(F::from(self.vm.P)), switch)?;

    let pre_sp = Self::alloc_num(
      &mut cs,
      || "pre_sp",
      || Ok(F::from(self.vm.pre_sp as u64)),
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push local on stack"),
      &pre_sp,
      &read_val,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// local.set
  fn visit_local_set<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::local_set(0).unwrap() }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "last addr",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;
    let depth = Self::alloc_num(&mut cs, || "depth addr", || Ok(F::from(self.vm.I)), switch)?;

    let depth_addr = sub(cs.namespace(|| "last - depth"), &last_addr, &depth)?;

    Self::write(
      cs.namespace(|| "set local"),
      &depth_addr,
      &Y,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// local.tee
  fn visit_local_tee<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::local_tee(0).unwrap() }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let pre_sp = Self::alloc_num(
      &mut cs,
      || "pre_sp",
      || Ok(F::from((self.vm.pre_sp) as u64)),
      switch,
    )?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "last addr",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;
    let depth = Self::alloc_num(&mut cs, || "depth addr", || Ok(F::from(self.vm.I)), switch)?;

    let depth_addr = sub(cs.namespace(|| "pre_sp - depth"), &pre_sp, &depth)?;

    Self::write(
      cs.namespace(|| "tee local"),
      &depth_addr,
      &Y,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// i64.sub
  fn visit_i64_sub<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Sub }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = sub64(
      cs.namespace(|| "X - Y"),
      &X,
      &Y,
      self.vm.X,
      self.vm.Y,
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.add
  fn visit_i64_add<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Add }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = add64(
      cs.namespace(|| "X + Y"),
      &X,
      &Y,
      self.vm.X,
      self.vm.Y,
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.mul
  fn visit_i64_mul<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Mul }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = mul64(
      cs.namespace(|| "X * Y"),
      &X,
      &Y,
      self.vm.X,
      self.vm.Y,
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.div_u, i64.rem_u
  fn visit_i64_div_rem_u<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64DivU }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let (quotient, rem) = div_rem_u_64(
      cs.namespace(|| "div_rem_u_64"),
      &X,
      &Y,
      self.vm.X,
      self.vm.Y,
      switch,
    )?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I64DivU => Ok(
          quotient
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        Instr::I64RemU => Ok(rem.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        _ => Ok(F::ZERO),
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.div_s, i64.rem_s
  fn visit_i64_div_rem_s<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64DivS }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let (quotient, rem) = div_rem_s_64(
      cs.namespace(|| "div_rem_s_64"),
      &X,
      &Y,
      self.vm.X,
      self.vm.Y,
      switch,
    )?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I64DivS => Ok(
          quotient
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        Instr::I64RemS => Ok(rem.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        _ => Ok(F::ZERO),
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.and, i64.xor, i64.or
  fn visit_i64_bitops<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64And }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let (and, xor, or) = bitops_64(cs.namespace(|| "bitops_64"), &X, &Y)?;
    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I64And => Ok(and.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64Xor => Ok(xor.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64Or => Ok(or.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        _ => Ok(F::ZERO),
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.popcnt, i64.clz, i64.ctz
  fn visit_i64_unary_ops<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Popcnt }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    let (popcnt, clz, ctz) = unary_ops_64(cs.namespace(|| "unary_ops_64"), &Y, self.vm.Y, switch)?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I64Popcnt => Ok(
          popcnt
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        Instr::I64Clz => Ok(clz.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64Ctz => Ok(ctz.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        _ => Ok(F::ZERO),
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &last_addr, // pre_sp - 1
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// Instr::BrIfEqz
  fn visit_br_if_eqz<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrIfEqz(BranchOffset::uninit()) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let one = alloc_one(cs.namespace(|| "one"));

    let pc = Self::alloc_num(&mut cs, || "pc", || Ok(F::from(self.vm.pc as u64)), switch)?;
    let next_pc = add(cs.namespace(|| "pc + 1"), &pc, &one)?;

    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;

    let branch_pc = add(cs.namespace(|| "pc + branch_offset"), &pc, &branch_offset)?;

    // addr of last value on stack
    let last = Self::alloc_num(
      &mut cs,
      || "last",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let condition = Self::read(cs.namespace(|| "condition"), &last, &self.RS[0], switch)?;
    let condition_eqz = eqz_bit(cs.namespace(|| "condition == 0"), &condition)?;

    // if condtion == 0 then new_pc = branch_pc else new_pc = next_pc
    //
    // In other words if condition_eqz is true then new_pc = branch_pc else new_pc = next_pc
    let _new_pc = conditionally_select(
      cs.namespace(|| "new_pc"),
      &branch_pc,
      &next_pc,
      &condition_eqz,
    )?; // TODO: constrain pc

    Ok(())
  }

  /// Instr::BrIfNez
  fn visit_br_if_nez<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrIfNez(BranchOffset::uninit()) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let one = alloc_one(cs.namespace(|| "one"));

    let pc = Self::alloc_num(&mut cs, || "pc", || Ok(F::from(self.vm.pc as u64)), switch)?;
    let next_pc = add(cs.namespace(|| "pc + 1"), &pc, &one)?;

    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;

    let branch_pc = add(cs.namespace(|| "pc + branch_offset"), &pc, &branch_offset)?;

    // addr of last value on stack
    let last = Self::alloc_num(
      &mut cs,
      || "last",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let condition = Self::read(cs.namespace(|| "condition"), &last, &self.RS[0], switch)?;
    let condition_eqz = eqz_bit(cs.namespace(|| "condition == 0"), &condition)?;

    // if condtion == 0 then new_pc = next_pc  else  new_pc = branch_pc
    //
    // In other words if condition_eqz is true then new_pc = next_pc else new_pc = branch_pc
    let _new_pc = conditionally_select(
      cs.namespace(|| "new_pc"),
      &next_pc,
      &branch_pc,
      &condition_eqz,
    )?; // TODO: constrain pc

    Ok(())
  }

  /// Instr::Br
  fn visit_br<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Br(BranchOffset::uninit()) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let pc = Self::alloc_num(&mut cs, || "pc", || Ok(F::from(self.vm.pc as u64)), switch)?;

    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;

    let _branch_pc = add(cs.namespace(|| "pc + branch_offset"), &pc, &branch_offset)?;

    Ok(())
  }

  /// drop_keep
  fn drop_keep<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::DropKeep }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let drop = self.vm.I;
    let keep = self.vm.P;
    let pre_sp_u64 = self.vm.pre_sp as u64;

    let read_addr = Self::alloc_num(
      &mut cs,
      || "read_addr",
      || {
        let read_addr_u64 = pre_sp_u64 - keep;
        Ok(F::from(read_addr_u64))
      },
      switch,
    )?;

    let read_val = Self::read(cs.namespace(|| "read val"), &read_addr, &self.RS[0], switch)?;

    let write_addr = Self::alloc_num(
      &mut cs,
      || "write addr",
      || {
        let write_addr_u64 = pre_sp_u64 - drop - keep;
        Ok(F::from(write_addr_u64))
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "drop keep write"),
      &write_addr,
      &read_val,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// Return instruction
  fn visit_ret<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Return(DropKeep::new(0, 0).unwrap()) }.index_j();
    let _ = self.switch(&mut cs, J, switches)?;
    Ok(())
  }

  /// Store instruction
  fn visit_store<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Store(AddressOffset::from(0)) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    // Stack ops
    let raw_last = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _ = Self::read(cs.namespace(|| "raw_addr"), &raw_last, &self.RS[0], switch)?;

    let val_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _ = Self::read(cs.namespace(|| "val"), &val_addr, &self.RS[1], switch)?;

    // linear mem ops
    let effective_addr = self.vm.I;

    let write_addr_1 = Self::alloc_num(
      &mut cs,
      || "write_addr_1",
      || {
        let write_addr_1 = effective_addr / 8 + self.stack_len as u64;
        Ok(F::from(write_addr_1))
      },
      switch,
    )?;

    let write_addr_2 = Self::alloc_num(
      &mut cs,
      || "write_addr_2",
      || {
        let write_addr_2 = effective_addr / 8 + 1 + self.stack_len as u64;
        Ok(F::from(write_addr_2))
      },
      switch,
    )?;

    let write_val_1 =
      Self::alloc_num(&mut cs, || "write_val_1", || Ok(F::from(self.vm.P)), switch)?;
    let write_val_2 =
      Self::alloc_num(&mut cs, || "write_val_2", || Ok(F::from(self.vm.Q)), switch)?;

    Self::write(
      cs.namespace(|| "store 1"),
      &write_addr_1,
      &write_val_1,
      &self.WS[2],
      switch,
    )?;

    Self::write(
      cs.namespace(|| "store 2"),
      &write_addr_2,
      &write_val_2,
      &self.WS[3],
      switch,
    )?;

    Ok(())
  }

  /// Store instruction
  fn visit_load<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Load(AddressOffset::from(0)) }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    // Stack ops
    let last = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _ = Self::read(cs.namespace(|| "val"), &last, &self.RS[0], switch)?;

    // linear mem ops
    let effective_addr = self.vm.I;

    let read_addr_1 = Self::alloc_num(
      &mut cs,
      || "read_addr_1",
      || {
        let read_addr_1 = effective_addr / 8 + self.stack_len as u64;
        Ok(F::from(read_addr_1))
      },
      switch,
    )?;

    let read_addr_2 = Self::alloc_num(
      &mut cs,
      || "read_addr_2",
      || {
        let read_addr_2 = effective_addr / 8 + 1 + self.stack_len as u64;
        Ok(F::from(read_addr_2))
      },
      switch,
    )?;

    let _ = Self::read(
      cs.namespace(|| "block_val_1"),
      &read_addr_1,
      &self.RS[1],
      switch,
    )?;
    let _ = Self::read(
      cs.namespace(|| "block_val_1"),
      &read_addr_2,
      &self.RS[2],
      switch,
    )?;

    let stack_write_val =
      Self::alloc_num(&mut cs, || "stack write", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "store 1"),
      &last,
      &stack_write_val,
      &self.WS[3],
      switch,
    )?;

    Ok(())
  }

  /// i64.lt_u, i64.lt_s, i64.ge_u, i64.ge_s
  fn visit_i64_lt_ge_s<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64LtS }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let (lt, ge, lt_s, ge_s) = lt_ge_s(
      cs.namespace(|| "lt_ge_s"),
      &X,
      &Y,
      self.vm.X,
      self.vm.Y,
      switch,
    )?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I64LtU => Ok(lt.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64GeU => Ok(ge.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64LtS => Ok(lt_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64GeS => Ok(ge_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        _ => Ok(F::ZERO),
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.le_u, i64.gt_s, i64.le_u, i64.gt_s
  fn visit_i64_le_gt_s<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64LeS }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let (le, gt, le_s, gt_s) = le_gt_s(
      cs.namespace(|| "le_gt_s"),
      &X,
      &Y,
      self.vm.X,
      self.vm.Y,
      switch,
    )?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I64LeU => Ok(le.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64GtU => Ok(gt.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64LeS => Ok(le_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64GtS => Ok(gt_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        _ => Ok(F::ZERO),
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.shl, i64.shr_u, i64.shr_s, i64.rotr, i64.rotl
  fn visit_shift_rotate_64<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Shl }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let (shl, shr_u, shr_s, rotr, rotl) =
      shift_rotate_64(cs.namespace(|| "shift_rotate_64"), &X, self.vm.Y as usize)?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I64Shl => Ok(shl.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64ShrU => Ok(shr_u.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64ShrS => Ok(shr_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64Rotr => Ok(rotr.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I64Rotl => Ok(rotl.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        _ => Ok(F::ZERO),
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64., i32.eqz
  fn visit_eqz<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Eqz }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    let Z = eqz(cs.namespace(|| "eqz"), &Y, switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &last_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// i64.eq, i32.eq
  fn visit_eq<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Eq }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = eq(cs.namespace(|| "X == Y"), &X, &Y, switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// i64.ne, i32.ne
  fn visit_ne<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Ne }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = alu::ne(cs.namespace(|| "X != Y"), &X, &Y, switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }

  /// Unary op
  fn visit_unary<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::F32Abs }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let last_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _ = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    let Z = Self::alloc_num(&mut cs, || "unary_op(Y)", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &last_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    Ok(())
  }

  /// visit_binary
  fn visit_binary<CS, F>(
    &self,
    mut cs: CS,
    switches: &mut Vec<AllocatedNum<F>>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::F32Eq }.index_j();
    let switch = self.switch(&mut cs, J, switches)?;

    let X_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 2",
      || Ok(F::from((self.vm.pre_sp - 2) as u64)),
      switch,
    )?;

    let _X = Self::read(cs.namespace(|| "X"), &X_addr, &self.RS[0], switch)?;

    let Y_addr = Self::alloc_num(
      &mut cs,
      || "pre_sp - 1",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;

    let _Y = Self::read(cs.namespace(|| "Y"), &Y_addr, &self.RS[1], switch)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    Ok(())
  }
}

impl WASMTransitionCircuit {
  /// Create a new instance of the [`WASMTransitionCircuit`]
  pub fn new(
    vm: WitnessVM,
    RS: Vec<(usize, u64, u64)>,
    WS: Vec<(usize, u64, u64)>,
    stack_len: usize,
  ) -> Self {
    Self {
      vm,
      RS,
      WS,
      stack_len,
    }
  }
}
impl Default for WASMTransitionCircuit {
  fn default() -> Self {
    Self {
      vm: WitnessVM::default(),
      // max memory ops per recursive step is 8
      RS: vec![(0, 0, 0); MEMORY_OPS_PER_STEP / 2],
      WS: vec![(0, 0, 0); MEMORY_OPS_PER_STEP / 2],
      stack_len: 0,
    }
  }
}
