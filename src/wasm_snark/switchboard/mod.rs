use std::ops::Deref;

use super::{
  gadgets::utils::conditionally_select, mcc::multiset_ops::avt_tuple_to_scalar_vec,
  MEMORY_OPS_PER_STEP,
};
use crate::wasm_ctx::ISMemSizes;
use alu::{
  eq, eqz, eqz_bit,
  int32::{
    bitops_32, div_rem_s_32, div_rem_u_32, le_gt_s_32, lt_ge_s_32, shift_rotate_32, unary_ops_32,
  },
  int64::{bitops_64, div_rem_s_64, div_rem_u_64, le_gt_s, lt_ge_s, shift_rotate_64, unary_ops_64},
  ALUGadget,
};
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  self,
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use itertools::Itertools;
use nova::nebula::rs::StepCircuit;
use wasmi::{
  AddressOffset, BCGlobalIdx, BranchOffset, BranchTableTargets, CompiledFunc, DropKeep,
  Instruction as Instr, WitnessVM,
};

mod alu;

#[cfg(test)]
mod tests;
use crate::wasm_snark::switchboard::alu::IntegerOps;

/// The circuit representing a step in the execution of a WASM program. Each step in WASM execution
/// corresponds to an opcode (from the WASM ISA) that gets executed.
///
/// This circuit performs checks on the VM state, ensuring it is valid and that it correctly
/// transitions from the previous VM state, hence the name [`WASMTransitionCircuit`].
#[derive(Clone, Debug)]
pub struct WASMTransitionCircuit {
  vm: WitnessVM,
  RS: Vec<(usize, u64, u64)>,
  WS: Vec<(usize, u64, u64)>,
  IS_sizes: ISMemSizes,
}

impl<F> StepCircuit<F> for WASMTransitionCircuit
where
  F: PrimeField + PrimeFieldBits,
{
  fn arity(&self) -> usize {
    2
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    /*
     * ***************** Switchboard Circuit *****************
     */

    // Allocate switchboard "global" variables (pc, sp and switches).
    //
    // This also stores the switch variables for each instruction. The switch variables are needed to
    // turn sub-circuits on or off.
    let pc = z[0].clone();
    let sp = AllocatedStackPtr { sp: z[1].clone() };
    let mut switchboard_vars = SwitchBoardCircuitVars::new(pc, sp);

    // unreachable, i.e. nop
    self.visit_unreachable(cs.namespace(|| "unreachable"), &mut switchboard_vars)?;

    // local.get, local.set, local.tee
    self.visit_local_get(cs.namespace(|| "local.get"), &mut switchboard_vars)?;
    self.visit_local_set(cs.namespace(|| "local.set"), &mut switchboard_vars)?;
    self.visit_local_tee(cs.namespace(|| "local.tee"), &mut switchboard_vars)?;

    // branch opcodes
    self.visit_br(cs.namespace(|| "br"), &mut switchboard_vars)?;
    self.visit_br_if_eqz(cs.namespace(|| "Instr::BrIfEqz"), &mut switchboard_vars)?;
    self.visit_br_if_nez(cs.namespace(|| "Instr::BrIfNez"), &mut switchboard_vars)?;
    self.visit_br_adjust(cs.namespace(|| "visit_br_adjust"), &mut switchboard_vars)?;
    self.visit_br_table(cs.namespace(|| "Instr::BrTable"), &mut switchboard_vars)?;

    // return opcodes
    self.visit_drop(cs.namespace(|| "visit_drop"), &mut switchboard_vars)?;
    self.drop_keep(cs.namespace(|| "drop keep"), &mut switchboard_vars)?;
    self.visit_ret(cs.namespace(|| "return"), &mut switchboard_vars)?;

    // call related opcodes
    self.visit_call_internal_step(
      cs.namespace(|| "visit_call_internal_step"),
      &mut switchboard_vars,
    )?;
    self.visit_call_internal(
      cs.namespace(|| "visit_call_internal"),
      &mut switchboard_vars,
    )?;
    self.visit_call_indirect_step(
      cs.namespace(|| "visit_call_indirect_step"),
      &mut switchboard_vars,
    )?;
    self.visit_host_call_stack_step(
      cs.namespace(|| "visit_host_call_stack_step"),
      &mut switchboard_vars,
    )?;
    self.visit_host_call_step(
      cs.namespace(|| "visit_host_call_step"),
      &mut switchboard_vars,
    )?;

    // select opcode
    self.visit_select(cs.namespace(|| "visit_select"), &mut switchboard_vars)?;

    // global opcodes
    self.visit_global_get(cs.namespace(|| "global.get"), &mut switchboard_vars)?;
    self.visit_global_set(cs.namespace(|| "global.set"), &mut switchboard_vars)?;

    // store and load opcodes
    self.visit_store(cs.namespace(|| "store"), &mut switchboard_vars)?;
    self.visit_load(cs.namespace(|| "load"), &mut switchboard_vars)?;

    // specific linear memory opcodes
    self.visit_memory_size(cs.namespace(|| "visit_memory_size"), &mut switchboard_vars)?;
    self.visit_memory_grow(cs.namespace(|| "visit_memory_grow"), &mut switchboard_vars)?;
    self.visit_memory_fill(cs.namespace(|| "visit_memory_fill"), &mut switchboard_vars)?;
    self.visit_memory_fill_step(
      cs.namespace(|| "visit_memory_fill_step"),
      &mut switchboard_vars,
    )?;
    self.visit_memory_copy(cs.namespace(|| "visit_memory_copy"), &mut switchboard_vars)?;
    self.visit_memory_copy_step(
      cs.namespace(|| "visit_memory_copy_step"),
      &mut switchboard_vars,
    )?;

    // const opcodes
    self.visit_const(cs.namespace(|| "const"), &mut switchboard_vars)?;

    // i32 opcodes
    self.visit_i32_add(cs.namespace(|| "i32.add"), &mut switchboard_vars)?;
    self.visit_i32_sub(cs.namespace(|| "i32.sub"), &mut switchboard_vars)?;
    self.visit_i32_mul(cs.namespace(|| "i32.mul"), &mut switchboard_vars)?;
    self.visit_i32_div_rem_u(
      cs.namespace(|| "visit_i32_div_rem_u"),
      &mut switchboard_vars,
    )?;
    self.visit_i32_div_rem_s(
      cs.namespace(|| "visit_i32_div_rem_s"),
      &mut switchboard_vars,
    )?;
    self.visit_i32_bitops(cs.namespace(|| "visit_i32_bitops"), &mut switchboard_vars)?;
    self.visit_i32_unary_ops(
      cs.namespace(|| "visit_i32_unary_ops"),
      &mut switchboard_vars,
    )?;
    self.visit_i32_shift_rotate(
      cs.namespace(|| "visit_i32_shift_rotate"),
      &mut switchboard_vars,
    )?;
    self.visit_i32_lt_ge_s(cs.namespace(|| "visit_i32_lt_ge_s"), &mut switchboard_vars)?;
    self.visit_i32_le_gt_s(cs.namespace(|| "visit_i32_le_gt_s"), &mut switchboard_vars)?;

    // i64 opcodes
    self.visit_i64_add(cs.namespace(|| "i64.add"), &mut switchboard_vars)?;
    self.visit_i64_sub(cs.namespace(|| "i64.sub"), &mut switchboard_vars)?;
    self.visit_i64_mul(cs.namespace(|| "i64.mul"), &mut switchboard_vars)?;
    self.visit_i64_div_rem_u(
      cs.namespace(|| "visit_i64_div_rem_u"),
      &mut switchboard_vars,
    )?;
    self.visit_i64_div_rem_s(
      cs.namespace(|| "visit_i64_div_rem_s"),
      &mut switchboard_vars,
    )?;
    self.visit_i64_bitops(cs.namespace(|| "visit_i64_bitops"), &mut switchboard_vars)?;
    self.visit_i64_unary_ops(
      cs.namespace(|| "visit_i64_unary_ops"),
      &mut switchboard_vars,
    )?;
    self.visit_i64_shift_rotate(
      cs.namespace(|| "visit_i64_shift_rotate"),
      &mut switchboard_vars,
    )?;
    self.visit_i64_lt_ge_s(cs.namespace(|| "visit_i64_lt_ge_s"), &mut switchboard_vars)?;
    self.visit_i64_le_gt_s(cs.namespace(|| "visit_i64_le_gt_s"), &mut switchboard_vars)?;

    // eq, eqz, ne for i32 and i64
    self.visit_eqz(cs.namespace(|| "visit_eqz"), &mut switchboard_vars)?;
    self.visit_eq(cs.namespace(|| "visit_eq"), &mut switchboard_vars)?;
    self.visit_ne(cs.namespace(|| "visit_ne"), &mut switchboard_vars)?;

    // unary and binary ops
    self.visit_unary(cs.namespace(|| "visit_unary"), &mut switchboard_vars)?;
    self.visit_binary(cs.namespace(|| "visit_binary"), &mut switchboard_vars)?;

    /*
     *  ***************** Switch constraints *****************
     */
    let switches = switchboard_vars.switches();

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

    // Check program counter and stack pointer
    let PC = AllocatedNum::alloc(cs.namespace(|| "PC"), || {
      Ok(F::from(self.vm.post_pc as u64))
    })?;
    let post_sp = AllocatedNum::alloc(cs.namespace(|| "post_sp"), || {
      Ok(F::from(self.vm.post_sp as u64))
    })?;
    for (i, ((pc, switch), sp)) in switchboard_vars
      .program_counters()
      .iter()
      .zip_eq(switchboard_vars.switches().iter())
      .zip_eq(switchboard_vars.stack_pointers().iter())
      .enumerate()
    {
      cs.enforce(
        || format!("PC == post_pc {i}"),
        |lc| lc + PC.get_variable(),
        |lc| lc + switch.get_variable(),
        |lc| lc + pc.get_variable(),
      );
      cs.enforce(
        || format!("sp == post_sp {i}"),
        |lc| lc + post_sp.get_variable(),
        |lc| lc + switch.get_variable(),
        |lc| lc + sp.get_variable(),
      );
    }

    Ok(vec![PC, post_sp])
  }

  fn non_deterministic_advice(&self) -> Vec<F> {
    self
      .RS
      .iter()
      .zip_eq(self.WS.iter())
      .flat_map(|(rs, ws)| {
        avt_tuple_to_scalar_vec::<F>(*rs)
          .into_iter()
          .chain(avt_tuple_to_scalar_vec::<F>(*ws))
      })
      .collect()
  }
}

impl WASMTransitionCircuit {
  /// Allocate a switch. Depending on the instruction it could be on or off.
  fn allocate_opcode_vars<CS, F>(
    &self,
    cs: &mut CS,
    J: u64,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<
    (
      F,
      AllocatedNum<F>,
      AllocatedStackPtr<F>,
      AllocatedNum<F>,
      AllocatedNum<F>,
    ), // switch, pre_sp, 1, -1
    SynthesisError,
  >
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    // Check if instruction is on or off
    let switch = if J == self.vm.J { F::ONE } else { F::ZERO };
    let alloc_switch = AllocatedNum::alloc(cs.namespace(|| "switch"), || Ok(switch))?;

    // Allocate pre_pc and check it is equal to z_i[0]
    let pre_pc =
      WASMTransitionCircuit::alloc_num(cs, || "pre pc", || Ok(F::from(self.vm.pc as u64)), switch)?;
    cs.enforce(
      || "vm.pc == opcode.pc",
      |lc| lc + switchboard_vars.pre_pc().get_variable(),
      |lc| lc + alloc_switch.get_variable(),
      |lc| lc + pre_pc.get_variable(),
    );

    // Allocate pre_sp and check it is equal to z_i[1]
    let pre_sp = WASMTransitionCircuit::alloc_num(
      cs,
      || "pre sp",
      || Ok(F::from(self.vm.pre_sp as u64)),
      switch,
    )?;
    cs.enforce(
      || "vm.pre_sp == opcode.pre_sp",
      |lc| lc + switchboard_vars.pre_sp().get_variable(),
      |lc| lc + alloc_switch.get_variable(),
      |lc| lc + pre_sp.get_variable(),
    );
    let pre_sp = AllocatedStackPtr { sp: pre_sp };

    // Push the allocated switch to the switches vector to be used in the switch constraints
    switchboard_vars.push_switch(alloc_switch);

    // Used to calculate stack pointer and program counter
    let minus_one = WASMTransitionCircuit::alloc_minus_one(cs.namespace(|| "-one"), switch);
    let one = WASMTransitionCircuit::alloc_one(cs.namespace(|| "one"), switch);

    // return the switch as a constant
    Ok((switch, pre_pc, pre_sp, one, minus_one))
  }

  fn alloc_one<CS, F>(mut cs: CS, switch: F) -> AllocatedNum<F>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    AllocatedNum::alloc_infallible(cs.namespace(|| "one"), || F::ONE * switch)
  }

  fn alloc_minus_one<CS, F>(mut cs: CS, switch: F) -> AllocatedNum<F>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    AllocatedNum::alloc_infallible(cs.namespace(|| "one"), || (-F::ONE) * switch)
  }

  fn next_instr<CS, F>(
    &self,
    mut cs: CS,
    pc: &AllocatedNum<F>,
    sp: AllocatedStackPtr<F>,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
    one: &AllocatedNum<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    // Save variable to global switchboard memory space so we can use it later to build constraints for stack pointer
    switchboard_vars.push_sp(sp);

    // Update pc and push to global switchboard memory space
    let new_pc = pc.add(cs.namespace(|| "pc + 1"), one)?;
    switchboard_vars.push_pc(new_pc);
    Ok(())
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

  /// # Unreacable instruction
  ///
  /// Basically a no-op instruction.
  fn visit_unreachable<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Unreachable }.index_j();

    // Check if instruction is on or off
    let switch = if J == self.vm.J { F::ONE } else { F::ZERO };
    let alloc_switch = AllocatedNum::alloc(cs.namespace(|| "switch"), || Ok(switch))?;

    // Allocate pre_pc and pre_sp
    let post_pc = WASMTransitionCircuit::alloc_num(
      &mut cs,
      || "pre pc",
      || Ok(F::from(self.vm.post_pc as u64)),
      switch,
    )?;
    let post_sp = WASMTransitionCircuit::alloc_num(
      &mut cs,
      || "pre sp",
      || Ok(F::from(self.vm.post_sp as u64)),
      switch,
    )?;
    switchboard_vars.push_pc(post_pc);
    switchboard_vars.push_sp(AllocatedStackPtr { sp: post_sp });
    switchboard_vars.push_switch(alloc_switch);
    Ok(())
  }

  /// # local.get
  fn visit_local_get<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::local_get(0).unwrap() }.index_j();
    let (switch, pre_pc, pre_sp, one, _) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    // Read value from local depth
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

    // write that value to the top of the stack
    let sp = pre_sp.push(
      cs.namespace(|| "push local on stack"),
      switch,
      &read_val,
      &one,
      &self.WS[1],
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # local.set
  fn visit_local_set<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::local_set(0).unwrap() }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    // pop value from stack
    let (Y, Y_addr) = pre_sp.pop(cs.namespace(|| "pop Y"), switch, &minus_one, &self.RS[0])?;

    // write value to local depth
    let depth_addr = Self::alloc_num(
      &mut cs,
      || "depth addr",
      || Ok(F::from(self.vm.pre_sp as u64 - 1 - self.vm.I)), // the -1 is to account for the pop
      switch,
    )?;
    Self::write(
      cs.namespace(|| "set local write"),
      &depth_addr,
      &Y,
      &self.WS[1],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      Y_addr,
      switchboard_vars,
      &one,
    )
  }

  /// # local.tee
  fn visit_local_tee<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::local_tee(0).unwrap() }.index_j();
    let (switch, pre_pc, pre_sp, one, _) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    // read last value from stack (doesn't pop)
    let last_addr = Self::alloc_num(
      &mut cs,
      || "last addr",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;
    let Y = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    // write value to local depth
    let depth_addr = Self::alloc_num(
      &mut cs,
      || "depth addr",
      || Ok(F::from(self.vm.pre_sp as u64 - self.vm.I)),
      switch,
    )?;
    Self::write(
      cs.namespace(|| "tee local write"),
      &depth_addr,
      &Y,
      &self.WS[1],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      pre_sp,
      switchboard_vars,
      &one,
    )
  }

  /// # Instr::Br
  fn visit_br<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Br(BranchOffset::uninit()) }.index_j();
    let (switch, pre_pc, pre_sp, _, _) = self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;
    let branch_pc = ALUGadget::i32_add(
      &mut cs,
      &pre_pc,
      &branch_offset,
      self.vm.pc as u64,
      self.vm.I,
      switch,
    )?;
    switchboard_vars.push_sp(pre_sp);
    switchboard_vars.push_pc(branch_pc);
    Ok(())
  }

  /// # Instr::BrIfEqz
  fn visit_br_if_eqz<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrIfEqz(BranchOffset::uninit()) }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (condition, condition_addr) = pre_sp.pop(
      cs.namespace(|| "pop condition"),
      switch,
      &minus_one,
      &self.RS[0],
    )?;
    let next_pc = pre_pc.add(cs.namespace(|| "pc + 1"), &one)?;
    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;
    let branch_pc = ALUGadget::i32_add(
      &mut cs,
      &pre_pc,
      &branch_offset,
      self.vm.pc as u64,
      self.vm.I,
      switch,
    )?;
    let reversed_condition = eqz_bit(cs.namespace(|| "condition == 0"), &condition, switch)?;

    let new_pc = conditionally_select(
      cs.namespace(|| "new_pc"),
      &branch_pc,
      &next_pc,
      &reversed_condition,
    )?;
    switchboard_vars.push_sp(condition_addr);
    switchboard_vars.push_pc(new_pc);
    Ok(())
  }
  /// # Instr::BrIfNez
  fn visit_br_if_nez<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrIfNez(BranchOffset::uninit()) }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (condition, condition_addr) = pre_sp.pop(
      cs.namespace(|| "pop condition"),
      switch,
      &minus_one,
      &self.RS[0],
    )?;
    let next_pc = pre_pc.add(cs.namespace(|| "pc + 1"), &one)?;
    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;
    let branch_pc = ALUGadget::i32_add(
      &mut cs,
      &pre_pc,
      &branch_offset,
      self.vm.pc as u64,
      self.vm.I,
      switch,
    )?;
    let reversed_condition = eqz_bit(cs.namespace(|| "condition == 0"), &condition, switch)?;

    // if reversed_condition then new_pc = next_pc  else  new_pc = branch_pc
    //
    // In other words if reversed_condition is true then new_pc = next_pc else new_pc = branch_pc
    let new_pc = conditionally_select(
      cs.namespace(|| "new_pc"),
      &next_pc,
      &branch_pc,
      &reversed_condition,
    )?;
    switchboard_vars.push_sp(condition_addr);
    switchboard_vars.push_pc(new_pc);
    Ok(())
  }

  /// # BrAdjust
  fn visit_br_adjust<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrAdjust(BranchOffset::uninit()) }.index_j();
    let (switch, pre_pc, pre_sp, _, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let drop = Self::alloc_num(&mut cs, || "drop", || Ok(F::from(self.vm.P)), switch)?;
    let neg_drop = drop.mul(cs.namespace(|| "drop * -1"), &minus_one)?;
    let new_sp = pre_sp.dec_by(cs.namespace(|| "ret sp"), &neg_drop)?;
    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;
    let branch_pc = ALUGadget::i32_add(
      &mut cs,
      &pre_pc,
      &branch_offset,
      self.vm.pc as u64,
      self.vm.I,
      switch,
    )?;
    switchboard_vars.push_sp(new_sp);
    switchboard_vars.push_pc(branch_pc);
    Ok(())
  }

  /// # BrTable
  fn visit_br_table<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::BrTable(BranchTableTargets::try_from(0).unwrap()) }.index_j();
    let (switch, pre_pc, pre_sp, _, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (_, index_addr) = pre_sp.pop(
      cs.namespace(|| "pop index"),
      switch,
      &minus_one,
      &self.RS[0],
    )?;
    let branch_offset = Self::alloc_num(
      &mut cs,
      || "branch_offset",
      || Ok(F::from(self.vm.I)),
      switch,
    )?;
    let branch_pc = ALUGadget::i32_add(
      &mut cs,
      &pre_pc,
      &branch_offset,
      self.vm.pc as u64,
      self.vm.I,
      switch,
    )?;
    switchboard_vars.push_sp(index_addr);
    switchboard_vars.push_pc(branch_pc);
    Ok(())
  }

  /// # drop.set
  fn visit_drop<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Drop }.index_j();
    let (_, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let new_sp = pre_sp.dec_by(cs.namespace(|| "drop sp"), &minus_one)?;
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      new_sp,
      switchboard_vars,
      &one,
    )
  }

  /// # drop_keep
  ///
  /// Read the keep value at `pre_sp - keep` and write it to `pre_sp - drop - keep`
  fn drop_keep<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::DropKeep }.index_j();
    let (switch, pre_pc, pre_sp, _, _) = self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    let drop = self.vm.I;
    let keep = self.vm.P;
    let pre_sp_u64 = self.vm.pre_sp as u64;

    // keep value address
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

    // write value address for keep value
    let write_addr = Self::alloc_num(
      &mut cs,
      || "write addr",
      || {
        let write_addr_u64 = pre_sp_u64 - drop - keep;
        Ok(F::from(write_addr_u64))
      },
      switch,
    )?;

    // write keep value to new write address
    Self::write(
      cs.namespace(|| "drop keep write"),
      &write_addr,
      &read_val,
      &self.WS[1],
      switch,
    )?;

    switchboard_vars.push_pc(pre_pc);
    switchboard_vars.push_sp(pre_sp);
    Ok(())
  }

  /// # Return instruction
  ///
  /// # Note
  ///
  /// - wasmi ensures that each return instruction is preceded by a drop keep instruction.
  fn visit_ret<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Return(DropKeep::new(0, 0).unwrap()) }.index_j();
    let (switch, _, pre_sp, _, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let drop = Self::alloc_num(&mut cs, || "drop", || Ok(F::from(self.vm.I)), switch)?;
    let neg_drop = drop.mul(cs.namespace(|| "drop * -1"), &minus_one)?;
    let new_sp = pre_sp.dec_by(cs.namespace(|| "ret sp"), &neg_drop)?;
    let new_pc = Self::alloc_num(
      &mut cs,
      || "new_pc",
      || Ok(F::from(self.vm.post_pc as u64)),
      switch,
    )?;
    switchboard_vars.push_pc(new_pc);
    switchboard_vars.push_sp(new_sp);
    Ok(())
  }

  /// # visit_call_internal_step
  ///
  /// Performs the necessary zero-writes to stack when preparing for a call instruction.
  fn visit_call_internal_step<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::CallZeroWrite }.index_j();
    let (switch, pre_pc, pre_sp, one, _) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let write_val = Self::alloc_num(&mut cs, || "write val", || Ok(F::from(self.vm.P)), switch)?;
    let sp = pre_sp.push(
      cs.namespace(|| "push zero"),
      switch,
      &write_val,
      &one,
      &self.WS[0],
    )?;
    switchboard_vars.push_sp(sp);
    switchboard_vars.push_pc(pre_pc);
    Ok(())
  }

  /// # visit_call_indirect_step
  ///
  /// Performs the necessary zero-writes to stack when preparing for a call instruction.
  fn visit_call_indirect_step<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::CallZeroWriteIndirect }.index_j();
    // Check if instruction is on or off
    let switch = if J == self.vm.J { F::ONE } else { F::ZERO };
    let alloc_switch = AllocatedNum::alloc(cs.namespace(|| "switch"), || Ok(switch))?;
    let one = Self::alloc_one(cs.namespace(|| "one"), switch);
    let pre_sp = AllocatedStackPtr {
      sp: WASMTransitionCircuit::alloc_num(
        &mut cs,
        || "pre sp",
        || Ok(F::from(self.vm.pre_sp as u64)),
        switch,
      )?,
    };
    // Allocate pre_pc and pre_sp
    let post_pc = WASMTransitionCircuit::alloc_num(
      &mut cs,
      || "pre pc",
      || Ok(F::from(self.vm.post_pc as u64)),
      switch,
    )?;
    let write_val = Self::alloc_num(&mut cs, || "write val", || Ok(F::from(self.vm.P)), switch)?;
    let sp = pre_sp.push(
      cs.namespace(|| "push zero"),
      switch,
      &write_val,
      &one,
      &self.WS[0],
    )?;
    switchboard_vars.push_sp(sp);
    switchboard_vars.push_pc(post_pc);
    switchboard_vars.push_switch(alloc_switch);
    Ok(())
  }

  /// # visit_call_internal
  fn visit_call_internal<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::CallInternal(CompiledFunc::from_u32(0)) }.index_j();
    let switch = if J == self.vm.J { F::ONE } else { F::ZERO };
    let alloc_switch = AllocatedNum::alloc(cs.namespace(|| "switch"), || Ok(switch))?;
    switchboard_vars.push_switch(alloc_switch);
    let sp = WASMTransitionCircuit::alloc_num(
      &mut cs,
      || "sp",
      || {
        let sp_val = *switchboard_vars.pre_sp.sp.get_value().get()?;
        Ok(sp_val)
      },
      switch,
    )?;
    let post_pc = WASMTransitionCircuit::alloc_num(
      &mut cs,
      || "post pc",
      || Ok(F::from(self.vm.post_pc as u64)),
      switch,
    )?;
    switchboard_vars.push_sp(AllocatedStackPtr { sp });
    switchboard_vars.push_pc(post_pc);
    Ok(())
  }

  /// # host call step
  ///
  /// Host calls can make changes to WASM linear memory, thus we have to account for this
  fn visit_host_call_step<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::HostCallStep }.index_j();
    let switch = if J == self.vm.J { F::ONE } else { F::ZERO };
    let alloc_switch = AllocatedNum::alloc(cs.namespace(|| "switch"), || Ok(switch))?;
    // Allocate pre_pc and pre_sp
    let post_pc = WASMTransitionCircuit::alloc_num(
      &mut cs,
      || "pre pc",
      || Ok(F::from(self.vm.post_pc as u64)),
      switch,
    )?;
    let post_sp = AllocatedStackPtr {
      sp: WASMTransitionCircuit::alloc_num(
        &mut cs,
        || "post sp",
        || Ok(F::from(self.vm.post_sp as u64)),
        switch,
      )?,
    };
    let write_addr = Self::alloc_num(
      &mut cs,
      || "write addr",
      || Ok(F::from(self.vm.Y + self.IS_sizes.stack_len() as u64)),
      switch,
    )?;
    let write_val = Self::alloc_num(&mut cs, || "write val", || Ok(F::from(self.vm.P)), switch)?;
    Self::write(
      cs.namespace(|| "perform write"),
      &write_addr,
      &write_val,
      &self.WS[0],
      switch,
    )?;
    switchboard_vars.push_sp(post_sp);
    switchboard_vars.push_pc(post_pc);
    switchboard_vars.push_switch(alloc_switch);
    Ok(())
  }

  /// # host call stack step
  ///
  /// Performs the necessary zero-writes to stack when preparing for a call instruction.
  fn visit_host_call_stack_step<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::HostCallStackStep }.index_j();
    let switch = if J == self.vm.J { F::ONE } else { F::ZERO };
    let alloc_switch = AllocatedNum::alloc(cs.namespace(|| "switch"), || Ok(switch))?;
    // Allocate pre_pc and pre_sp
    let post_pc = WASMTransitionCircuit::alloc_num(
      &mut cs,
      || "pre pc",
      || Ok(F::from(self.vm.post_pc as u64)),
      switch,
    )?;
    let post_sp = AllocatedStackPtr {
      sp: WASMTransitionCircuit::alloc_num(
        &mut cs,
        || "post sp",
        || Ok(F::from(self.vm.post_sp as u64)),
        switch,
      )?,
    };
    let write_addr = Self::alloc_num(
      &mut cs,
      || "write addr",
      || Ok(F::from(self.vm.pre_sp as u64)),
      switch,
    )?;
    let write_val = Self::alloc_num(&mut cs, || "write val", || Ok(F::from(self.vm.P)), switch)?;
    Self::write(
      cs.namespace(|| "perform write"),
      &write_addr,
      &write_val,
      &self.WS[0],
      switch,
    )?;
    switchboard_vars.push_sp(post_sp);
    switchboard_vars.push_pc(post_pc);
    switchboard_vars.push_switch(alloc_switch);
    Ok(())
  }

  /// # Select
  ///
  /// if condition return X else return Y
  fn visit_select<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::Select }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (condition, condition_addr) = pre_sp.pop(
      cs.namespace(|| "pop condition"),
      switch,
      &minus_one,
      &self.RS[0],
    )?;
    let (Y, Y_addr) =
      condition_addr.pop(cs.namespace(|| "pop Y"), switch, &minus_one, &self.RS[1])?;
    let (X, X_addr) = Y_addr.pop(cs.namespace(|| "pop X"), switch, &minus_one, &self.RS[2])?;
    let condition_bit_const = condition.get_value().map(|c| c != F::ZERO);
    let condition_bit = Self::alloc_bit(&mut cs, || "condition_bit", condition_bit_const, switch)?;

    // Calculate Z and write it to the stack
    let Z = conditionally_select(cs.namespace(|| "Z"), &X, &Y, &Boolean::Is(condition_bit))?;
    Self::write(cs.namespace(|| "write Z"), &X_addr, &Z, &self.WS[3], switch)?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      Y_addr,
      switchboard_vars,
      &one,
    )
  }

  /// global.get
  fn visit_global_get<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::GlobalGet(BCGlobalIdx::from(0)) }.index_j();
    let (switch, pre_pc, pre_sp, one, _) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    // Read global value at global address
    let read_addr = Self::alloc_num(
      &mut cs,
      || "read_addr",
      || {
        Ok(F::from(
          (self.IS_sizes.stack_len() + self.IS_sizes.mem_len()) as u64 + self.vm.I,
        ))
      },
      switch,
    )?;
    let read_val = Self::read(
      cs.namespace(|| "read at global"),
      &read_addr,
      &self.RS[0],
      switch,
    )?;

    // write that value to the top of the stack
    let sp = pre_sp.push(
      cs.namespace(|| "push global"),
      switch,
      &read_val,
      &one,
      &self.WS[1],
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # global.set
  fn visit_global_set<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::GlobalSet(BCGlobalIdx::from(0)) }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    // pop value from stack
    let (Y, Y_addr) = pre_sp.pop(
      cs.namespace(|| "pop global"),
      switch,
      &minus_one,
      &self.RS[0],
    )?;

    // write value to global depth
    let write_addr = Self::alloc_num(
      &mut cs,
      || "write addr",
      || {
        Ok(F::from(
          (self.IS_sizes.stack_len() + self.IS_sizes.mem_len()) as u64 + self.vm.I,
        ))
      },
      switch,
    )?;
    Self::write(
      cs.namespace(|| "set global write"),
      &write_addr,
      &Y,
      &self.WS[1],
      switch,
    )?;

    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      Y_addr,
      switchboard_vars,
      &one,
    )
  }

  /// # Store instruction
  fn visit_store<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Store(AddressOffset::from(0)) }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    // stack ops
    let (_, val_addr) = pre_sp.pop(cs.namespace(|| "pop val"), switch, &minus_one, &self.RS[0])?;
    let (_, addr_addr) =
      val_addr.pop(cs.namespace(|| "pop addr"), switch, &minus_one, &self.RS[1])?;

    // linear mem ops
    let effective_addr = self.vm.I;
    let write_addr_1 = Self::alloc_num(
      &mut cs,
      || "write_addr_1",
      || {
        let write_addr_1 = effective_addr / 8 + self.IS_sizes.stack_len() as u64;
        Ok(F::from(write_addr_1))
      },
      switch,
    )?;
    let write_addr_2 = Self::alloc_num(
      &mut cs,
      || "write_addr_2",
      || {
        let write_addr_2 = effective_addr / 8 + 1 + self.IS_sizes.stack_len() as u64;
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
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      addr_addr,
      switchboard_vars,
      &one,
    )
  }

  /// # Load instruction
  fn visit_load<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Load(AddressOffset::from(0)) }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    // Stack ops
    let (_, addr_addr) =
      pre_sp.pop(cs.namespace(|| "pop addr"), switch, &minus_one, &self.RS[0])?;

    // linear mem ops
    let effective_addr = self.vm.I;
    let read_addr_1 = Self::alloc_num(
      &mut cs,
      || "read_addr_1",
      || {
        let read_addr_1 = effective_addr / 8 + self.IS_sizes.stack_len() as u64;
        Ok(F::from(read_addr_1))
      },
      switch,
    )?;
    let read_addr_2 = Self::alloc_num(
      &mut cs,
      || "read_addr_2",
      || {
        let read_addr_2 = effective_addr / 8 + 1 + self.IS_sizes.stack_len() as u64;
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
      cs.namespace(|| "block_val_2"),
      &read_addr_2,
      &self.RS[2],
      switch,
    )?;
    let stack_write_val =
      Self::alloc_num(&mut cs, || "stack write", || Ok(F::from(self.vm.Z)), switch)?;
    Self::write(
      cs.namespace(|| "store 1"),
      &addr_addr,
      &stack_write_val,
      &self.WS[3],
      switch,
    )?;
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      pre_sp,
      switchboard_vars,
      &one,
    )
  }

  /// # memory.size
  fn visit_memory_size<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemorySize }.index_j();
    let (switch, pre_pc, pre_sp, one, _) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    let write_val = Self::alloc_num(&mut cs, || "write val", || Ok(F::from(self.vm.Y)), switch)?;
    let new_sp = pre_sp.push(
      cs.namespace(|| "push memory size"),
      switch,
      &write_val,
      &one,
      &self.WS[0],
    )?;
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      new_sp,
      switchboard_vars,
      &one,
    )
  }

  /// # memory.grow
  ///
  /// This is handle via our MCC
  fn visit_memory_grow<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryGrow }.index_j();
    let (switch, pre_pc, pre_sp, one, _) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;

    // pop value from stack
    let last_addr = Self::alloc_num(
      &mut cs,
      || "last addr",
      || Ok(F::from((self.vm.pre_sp - 1) as u64)),
      switch,
    )?;
    let _ = Self::read(cs.namespace(|| "Y"), &last_addr, &self.RS[0], switch)?;

    // write result
    let res = Self::alloc_num(&mut cs, || "write val", || Ok(F::from(self.vm.P)), switch)?;
    Self::write(
      cs.namespace(|| "set memory.grow write"),
      &last_addr,
      &res,
      &self.WS[1],
      switch,
    )?;
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      pre_sp,
      switchboard_vars,
      &one,
    )
  }

  /// # memory.fill
  fn visit_memory_fill<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryFill }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (_, size_addr) = pre_sp.pop(
      cs.namespace(|| "pop condition"),
      switch,
      &minus_one,
      &self.RS[0],
    )?;
    let (_, val_addr) = size_addr.pop(cs.namespace(|| "pop Y"), switch, &minus_one, &self.RS[1])?;
    let (_, offset_addr) =
      val_addr.pop(cs.namespace(|| "pop X"), switch, &minus_one, &self.RS[2])?;
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      offset_addr,
      switchboard_vars,
      &one,
    )?;
    Ok(())
  }

  /// # memory.fill step
  fn visit_memory_fill_step<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryFillStep }.index_j();
    let (switch, pre_pc, pre_sp, _, _) = self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let write_addr = Self::alloc_num(
      &mut cs,
      || "write addr",
      || Ok(F::from(self.vm.X + self.IS_sizes.stack_len() as u64)),
      switch,
    )?;
    let write_val = Self::alloc_num(&mut cs, || "write val", || Ok(F::from(self.vm.P)), switch)?;
    Self::write(
      cs.namespace(|| "perform write"),
      &write_addr,
      &write_val,
      &self.WS[0],
      switch,
    )?;
    switchboard_vars.push_pc(pre_pc);
    switchboard_vars.push_sp(pre_sp);
    Ok(())
  }

  /// # memory.copy
  fn visit_memory_copy<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryCopy }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (_, bytes_addr) = pre_sp.pop(
      cs.namespace(|| "pop condition"),
      switch,
      &minus_one,
      &self.RS[0],
    )?;
    let (_, src_addr) =
      bytes_addr.pop(cs.namespace(|| "pop Y"), switch, &minus_one, &self.RS[1])?;
    let (_, dest_addr) = src_addr.pop(cs.namespace(|| "pop X"), switch, &minus_one, &self.RS[2])?;
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      dest_addr,
      switchboard_vars,
      &one,
    )
  }

  /// # memory.copy step
  fn visit_memory_copy_step<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::MemoryCopyStep }.index_j();
    let (switch, pre_pc, pre_sp, _, _) = self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let write_addr = Self::alloc_num(
      &mut cs,
      || "write addr",
      || Ok(F::from(self.vm.X + self.IS_sizes.stack_len() as u64)),
      switch,
    )?;
    let write_val = Self::alloc_num(&mut cs, || "write val", || Ok(F::from(self.vm.P)), switch)?;
    Self::write(
      cs.namespace(|| "perform write"),
      &write_addr,
      &write_val,
      &self.WS[0],
      switch,
    )?;
    switchboard_vars.push_pc(pre_pc);
    switchboard_vars.push_sp(pre_sp);
    Ok(())
  }

  /// # Const instruction
  ///
  /// Push a const onto the stack
  fn visit_const<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Const32(0) }.index_j();
    let (switch, pre_pc, pre_sp, one, _) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let I = Self::alloc_num(&mut cs, || "I", || Ok(F::from(self.vm.I)), switch)?;
    let new_sp = pre_sp.push(cs.namespace(|| "push imm"), switch, &I, &one, &self.WS[0])?;
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      new_sp,
      switchboard_vars,
      &one,
    )?;
    Ok(())
  }
  /// # i32.sub
  fn visit_i32_sub<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    self.execute_binary(
      cs.namespace(|| "i32.sub"),
      switchboard_vars,
      Instr::I32Sub,
      ALUGadget::i32_sub,
    )
  }

  /// # i32.add
  fn visit_i32_add<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    self.execute_binary(
      cs.namespace(|| "i32.add"),
      switchboard_vars,
      Instr::I32Add,
      ALUGadget::i32_add,
    )
  }

  /// # i32.mul
  fn visit_i32_mul<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    self.execute_binary(
      cs.namespace(|| "i32.mul"),
      switchboard_vars,
      Instr::I32Mul,
      ALUGadget::i32_mul,
    )
  }

  /// # i32.div_u, i32.rem_u
  fn visit_i32_div_rem_u<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I32DivU }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    let (quotient, rem) = div_rem_u_32(
      cs.namespace(|| "div_rem_u_32"),
      &X,
      &Y,
      self.vm.X as u32,
      self.vm.Y as u32,
      switch,
    )?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I32DivU => Ok(
          quotient
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        Instr::I32RemU => Ok(rem.get_value().ok_or(SynthesisError::AssignmentMissing)?),
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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i32.div_s, i32.rem_s
  fn visit_i32_div_rem_s<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I32DivS }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    let (quotient, rem) = div_rem_s_32(
      cs.namespace(|| "div_rem_s_32"),
      &X,
      &Y,
      self.vm.X as u32,
      self.vm.Y as u32,
      switch,
    )?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I32DivS => Ok(
          quotient
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        Instr::I32RemS => Ok(rem.get_value().ok_or(SynthesisError::AssignmentMissing)?),
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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i32.and, i32.xor, i32.or
  fn visit_i32_bitops<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I32And }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    let (and, xor, or) = bitops_32(cs.namespace(|| "bitops_32"), &X, &Y)?;
    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I32And => Ok(and.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32Xor => Ok(xor.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32Or => Ok(or.get_value().ok_or(SynthesisError::AssignmentMissing)?),
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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i32.popcnt, i32.clz, i32.ctz
  fn visit_i32_unary_ops<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I32Popcnt }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, Y_addr) = pre_sp.pop(cs.namespace(|| "pop Y"), switch, &minus_one, &self.RS[0])?;

    let (popcnt, clz, ctz) = unary_ops_32(
      cs.namespace(|| "unary_ops_32"),
      &Y,
      self.vm.Y as u32,
      switch,
    )?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I32Popcnt => Ok(
          popcnt
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        Instr::I32Clz => Ok(clz.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32Ctz => Ok(ctz.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        _ => Ok(F::ZERO),
      },
      switch,
    )?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &Y_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      pre_sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i32.lt_u, i32.lt_s, i32.ge_u, i32.ge_s
  fn visit_i32_lt_ge_s<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I32LtS }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    let (lt, ge, lt_s, ge_s) = lt_ge_s_32(
      cs.namespace(|| "lt_ge_s"),
      &X,
      &Y,
      self.vm.X as u32,
      self.vm.Y as u32,
      switch,
    )?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I32LtU => Ok(lt.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32GeU => Ok(ge.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32LtS => Ok(lt_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32GeS => Ok(ge_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i32.le_u, i32.gt_s, i32.le_u, i32.gt_s
  fn visit_i32_le_gt_s<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I32LeS }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    let (le, gt, le_s, gt_s) = le_gt_s_32(
      cs.namespace(|| "le_gt_s"),
      &X,
      &Y,
      self.vm.X as u32,
      self.vm.Y as u32,
      switch,
    )?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I32LeU => Ok(le.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32GtU => Ok(gt.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32LeS => Ok(le_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32GtS => Ok(gt_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i32.shl, i32.shr_u, i32.shr_s, i32.rotr, i32.rotl
  fn visit_i32_shift_rotate<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I32Shl }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (_, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    let (shl, shr_u, shr_s, rotr, rotl) =
      shift_rotate_32(cs.namespace(|| "shift_rotate_32"), &X, self.vm.Y as usize)?;

    let Z = Self::alloc_num(
      &mut cs,
      || "Z",
      || match self.vm.instr {
        Instr::I32Shl => Ok(shl.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32ShrU => Ok(shr_u.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32ShrS => Ok(shr_s.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32Rotr => Ok(rotr.get_value().ok_or(SynthesisError::AssignmentMissing)?),
        Instr::I32Rotl => Ok(rotl.get_value().ok_or(SynthesisError::AssignmentMissing)?),
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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.sub
  fn visit_i64_sub<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    self.execute_binary(
      cs.namespace(|| "i64.sub"),
      switchboard_vars,
      Instr::I64Sub,
      ALUGadget::i64_sub,
    )
  }

  /// # i64.add
  fn visit_i64_add<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    self.execute_binary(
      cs.namespace(|| "i64.add"),
      switchboard_vars,
      Instr::I64Add,
      ALUGadget::i64_add,
    )
  }

  /// # i64.mul
  fn visit_i64_mul<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    self.execute_binary(
      cs.namespace(|| "i64.mul"),
      switchboard_vars,
      Instr::I64Mul,
      ALUGadget::i64_mul,
    )
  }

  /// # i64.div_u, i64.rem_u
  fn visit_i64_div_rem_u<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64DivU }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.div_s, i64.rem_s
  fn visit_i64_div_rem_s<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64DivS }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.and, i64.xor, i64.or
  fn visit_i64_bitops<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64And }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.popcnt, i64.clz, i64.ctz
  fn visit_i64_unary_ops<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Popcnt }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, Y_addr) = pre_sp.pop(cs.namespace(|| "pop Y"), switch, &minus_one, &self.RS[0])?;

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
      &Y_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      pre_sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.lt_u, i64.lt_s, i64.ge_u, i64.ge_s
  fn visit_i64_lt_ge_s<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64LtS }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.le_u, i64.gt_s, i64.le_u, i64.gt_s
  fn visit_i64_le_gt_s<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64LeS }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.shl, i64.shr_u, i64.shr_s, i64.rotr, i64.rotl
  fn visit_i64_shift_rotate<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Shl }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (_, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

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

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.eqz, i32.eqz
  fn visit_eqz<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Eqz }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, Y_addr) = pre_sp.pop(cs.namespace(|| "pop Y"), switch, &minus_one, &self.RS[0])?;

    let Z = eqz(cs.namespace(|| "eqz"), &Y, switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &Y_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      pre_sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.eq, i32.eq
  fn visit_eq<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Eq }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    let Z = eq(cs.namespace(|| "X == Y"), &X, &Y, switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # i64.ne, i32.ne
  fn visit_ne<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::I64Ne }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    let Z = alu::ne(cs.namespace(|| "X != Y"), &X, &Y, switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// # Unary op
  fn visit_unary<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::F32Abs }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (_, Y_addr) = pre_sp.pop(cs.namespace(|| "pop Y"), switch, &minus_one, &self.RS[0])?;

    let Z = Self::alloc_num(&mut cs, || "unary_op(Y)", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &Y_addr, // pre_sp - 1
      &Z,
      &self.WS[1],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      pre_sp,
      switchboard_vars,
      &one,
    )
  }

  /// # visit_binary
  fn visit_binary<CS, F>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    let J: u64 = { Instr::F32Eq }.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (_, sp, _, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    let Z = Self::alloc_num(&mut cs, || "Z", || Ok(F::from(self.vm.Z)), switch)?;

    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )
  }

  /// Execute binary opcodes
  fn execute_binary<CS, F, Func>(
    &self,
    mut cs: CS,
    switchboard_vars: &mut SwitchBoardCircuitVars<F>,
    instruction: Instr,
    f: Func,
  ) -> Result<(), SynthesisError>
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
    Func: FnOnce(
      &mut CS,
      &AllocatedNum<F>,
      &AllocatedNum<F>,
      u64,
      u64,
      F,
    ) -> Result<AllocatedNum<F>, SynthesisError>,
  {
    let J: u64 = instruction.index_j();
    let (switch, pre_pc, pre_sp, one, minus_one) =
      self.allocate_opcode_vars(&mut cs, J, switchboard_vars)?;
    let (Y, sp, X, X_addr) = self.top_2(cs.namespace(|| "top_2"), pre_sp, switch, &minus_one)?;

    // Compute Z = binary_op(X, Y)
    // & push Z on the stack
    let Z = f(&mut cs, &X, &Y, self.vm.X, self.vm.Y, switch)?;
    Self::write(
      cs.namespace(|| "push Z on stack"),
      &X_addr, // pre_sp - 2
      &Z,
      &self.WS[2],
      switch,
    )?;

    // Push final stack pointer and program counter
    self.next_instr(
      cs.namespace(|| "next instr"),
      &pre_pc,
      sp,
      switchboard_vars,
      &one,
    )?;
    Ok(())
  }

  fn top_2<CS, F>(
    &self,
    mut cs: CS,
    pre_sp: AllocatedStackPtr<F>,
    switch: F,
    minus_one: &AllocatedNum<F>,
  ) -> Result<
    (
      AllocatedNum<F>,
      AllocatedStackPtr<F>,
      AllocatedNum<F>,
      AllocatedStackPtr<F>,
    ),
    SynthesisError,
  >
  where
    F: PrimeField,
    CS: ConstraintSystem<F>,
  {
    // pop Y of the stack
    let (Y, sp) = pre_sp.pop(cs.namespace(|| "pop Y"), switch, minus_one, &self.RS[0])?;

    // Get X of from the stack
    let X_addr = sp.dec_by(cs.namespace(|| "sp - 1"), minus_one)?;
    let X = X_addr.get(cs.namespace(|| "get X"), &self.RS[1], switch)?;
    Ok((Y, sp, X, X_addr))
  }
}

impl WASMTransitionCircuit {
  /// Create a new instance of the [`WASMTransitionCircuit`]
  pub fn new(
    vm: WitnessVM,
    RS: Vec<(usize, u64, u64)>,
    WS: Vec<(usize, u64, u64)>,
    IS_sizes: ISMemSizes,
  ) -> Self {
    Self {
      vm,
      RS,
      WS,
      IS_sizes,
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
      IS_sizes: ISMemSizes::default(),
    }
  }
}

#[derive(Clone, Debug)]
/// Circuit that batches zkVM steps into one step.
pub struct BatchedWasmTransitionCircuit {
  circuits: Vec<WASMTransitionCircuit>,
}

impl<F> StepCircuit<F> for BatchedWasmTransitionCircuit
where
  F: PrimeField + PrimeFieldBits,
{
  fn arity(&self) -> usize {
    2
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut z = z.to_vec();

    for (i, circuit) in self.circuits.iter().enumerate() {
      z = circuit.synthesize(&mut cs.namespace(|| format!("circuit {i}")), &z)?;
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

pub struct AllocatedStackPtr<F>
where
  F: PrimeField,
{
  sp: AllocatedNum<F>,
}

impl<F> AllocatedStackPtr<F>
where
  F: PrimeField,
{
  fn pop<CS>(
    &self,
    mut cs: CS,
    switch: F,
    minus_one: &AllocatedNum<F>,
    advice: &(usize, u64, u64),
  ) -> Result<
    (AllocatedNum<F>, AllocatedStackPtr<F>), // value, sp
    SynthesisError,
  >
  where
    CS: ConstraintSystem<F>,
  {
    let popped_sp = self.dec_by(cs.namespace(|| "dec by"), minus_one)?;
    let X = WASMTransitionCircuit::read(cs.namespace(|| "X"), &popped_sp, advice, switch)?;
    Ok((X, popped_sp))
  }

  fn push<CS>(
    &self,
    mut cs: CS,
    switch: F,
    val: &AllocatedNum<F>,
    one: &AllocatedNum<F>,
    advice: &(usize, u64, u64),
  ) -> Result<AllocatedStackPtr<F>, SynthesisError>
  where
    CS: ConstraintSystem<F>,
  {
    WASMTransitionCircuit::write(cs.namespace(|| "X"), self, val, advice, switch)?;
    let new_sp = self.inc_by(cs.namespace(|| "inc by"), one)?;
    Ok(new_sp)
  }

  fn get<CS>(
    &self,
    mut cs: CS,
    advice: &(usize, u64, u64),
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>
  where
    CS: ConstraintSystem<F>,
  {
    WASMTransitionCircuit::read(cs.namespace(|| "val"), self, advice, switch)
  }

  fn dec_by<CS>(
    &self,
    mut cs: CS,
    minus_v: &AllocatedNum<F>,
  ) -> Result<AllocatedStackPtr<F>, SynthesisError>
  where
    CS: ConstraintSystem<F>,
  {
    let new_sp = self.sp.add(cs.namespace(|| "sp - v"), minus_v)?;
    Ok(AllocatedStackPtr { sp: new_sp })
  }

  fn inc_by<CS>(
    &self,
    mut cs: CS,
    v: &AllocatedNum<F>,
  ) -> Result<AllocatedStackPtr<F>, SynthesisError>
  where
    CS: ConstraintSystem<F>,
  {
    let new_sp = self.sp.add(cs.namespace(|| "sp + v"), v)?;
    Ok(AllocatedStackPtr { sp: new_sp })
  }
}

impl<F> Deref for AllocatedStackPtr<F>
where
  F: PrimeField,
{
  type Target = AllocatedNum<F>;

  fn deref(&self) -> &Self::Target {
    &self.sp
  }
}

pub struct SwitchBoardCircuitVars<F>
where
  F: PrimeField,
{
  switches: Vec<AllocatedNum<F>>,
  program_counters: Vec<AllocatedNum<F>>,
  stack_pointers: Vec<AllocatedStackPtr<F>>,
  pre_pc: AllocatedNum<F>,
  pre_sp: AllocatedStackPtr<F>,
}

impl<F> SwitchBoardCircuitVars<F>
where
  F: PrimeField,
{
  fn new(pre_pc: AllocatedNum<F>, pre_sp: AllocatedStackPtr<F>) -> Self {
    Self {
      switches: Vec::new(),
      program_counters: Vec::new(),
      stack_pointers: Vec::new(),
      pre_pc,
      pre_sp,
    }
  }

  fn push_switch(&mut self, switch: AllocatedNum<F>) {
    self.switches.push(switch);
  }

  fn push_pc(&mut self, pc: AllocatedNum<F>) {
    self.program_counters.push(pc);
  }

  fn push_sp(&mut self, sp: AllocatedStackPtr<F>) {
    self.stack_pointers.push(sp);
  }

  fn pre_pc(&self) -> &AllocatedNum<F> {
    &self.pre_pc
  }

  fn pre_sp(&self) -> &AllocatedStackPtr<F> {
    &self.pre_sp
  }

  fn switches(&self) -> &Vec<AllocatedNum<F>> {
    &self.switches
  }

  fn program_counters(&self) -> &Vec<AllocatedNum<F>> {
    &self.program_counters
  }

  fn stack_pointers(&self) -> &Vec<AllocatedStackPtr<F>> {
    &self.stack_pointers
  }
}
