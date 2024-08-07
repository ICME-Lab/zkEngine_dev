//! Control opcode circuits
#![allow(dead_code)]
use crate::circuits::supernova::helpers::next_rom_index_and_pc;
use bellpepper::gadgets::boolean_utils::conditionally_select;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use core::marker::PhantomData;
use ff::PrimeField;
use nova::supernova::StepCircuit;

/// br
#[derive(Clone, Debug)]
pub struct BrCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: u64,
}

impl<F> BrCircuit<F>
where
  F: PrimeField,
{
  /// Create a new BrCircuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: u64) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for BrCircuit<F> {
  fn arity(&self) -> usize {
    2
  }

  fn circuit_index(&self) -> usize {
    self.circuit_index
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F>>,
    z: &[AllocatedNum<F>],
  ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
    let rom_index = &z[1];

    let allocated_rom: Result<Vec<_>, _> = self
      .fixed_rom
      .iter()
      .map(|opcode| AllocatedNum::alloc(cs.namespace(|| "elem"), || Ok(*opcode)))
      .collect();

    let allocated_rom = allocated_rom.map_err(|_| SynthesisError::AssignmentMissing)?;

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      &allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let offset = AllocatedNum::alloc(cs.namespace(|| "offset"), || Ok(F::from(self.inputs)))?;

    let mut z_next = vec![offset];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

// Added for completeness
/// brifeqz
#[derive(Clone, Debug)]
pub struct BrIfEqzCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> BrIfEqzCircuit<F>
where
  F: PrimeField,
{
  /// Create a new BrIfEqzCircuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for BrIfEqzCircuit<F> {
  fn arity(&self) -> usize {
    2
  }

  fn circuit_index(&self) -> usize {
    self.circuit_index
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F>>,
    z: &[AllocatedNum<F>],
  ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
    let rom_index = &z[1];

    let allocated_rom: Result<Vec<_>, _> = self
      .fixed_rom
      .iter()
      .map(|opcode| AllocatedNum::alloc(cs.namespace(|| "elem"), || Ok(*opcode)))
      .collect();

    let allocated_rom = allocated_rom.map_err(|_| SynthesisError::AssignmentMissing)?;

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      &allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let (condition, offset) = self.inputs;
    let offset = AllocatedNum::alloc(cs.namespace(|| "offset"), || Ok(F::from(offset)))?;
    let no_offset = AllocatedNum::alloc(cs.namespace(|| "no_offset"), || Ok(F::from(0u64)))?;
    let condition_bit = AllocatedBit::alloc(cs.namespace(|| "cond bit"), Some(condition != 0))?;

    let res = conditionally_select(
      cs.namespace(|| "if condition: no_offset else offset"),
      &no_offset,
      &offset,
      &Boolean::Is(condition_bit),
    )?;

    let mut z_next = vec![res];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

// Added for completeness
/// brifnez
#[derive(Clone, Debug)]
pub struct BrIfNezCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> BrIfNezCircuit<F>
where
  F: PrimeField,
{
  /// Create a new BrIfNezCircuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for BrIfNezCircuit<F> {
  fn arity(&self) -> usize {
    2
  }

  fn circuit_index(&self) -> usize {
    self.circuit_index
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F>>,
    z: &[AllocatedNum<F>],
  ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
    let rom_index = &z[1];

    let allocated_rom: Result<Vec<_>, _> = self
      .fixed_rom
      .iter()
      .map(|opcode| AllocatedNum::alloc(cs.namespace(|| "elem"), || Ok(*opcode)))
      .collect();

    let allocated_rom = allocated_rom.map_err(|_| SynthesisError::AssignmentMissing)?;

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      &allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let (condition, offset) = self.inputs;
    let offset = AllocatedNum::alloc(cs.namespace(|| "offset"), || Ok(F::from(offset)))?;
    let no_offset = AllocatedNum::alloc(cs.namespace(|| "no_offset"), || Ok(F::from(0u64)))?;
    let condition_bit = AllocatedBit::alloc(cs.namespace(|| "cond bit"), Some(condition != 0))?;

    let res = conditionally_select(
      cs.namespace(|| "if condition: offset else no_offset"),
      &offset,
      &no_offset,
      &Boolean::Is(condition_bit),
    )?;

    let mut z_next = vec![res];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

// Added for completeness
/// BrAdjust
#[derive(Clone, Debug)]
pub struct BrAdjustCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> BrAdjustCircuit<F>
where
  F: PrimeField,
{
  /// Create a new BrAdjustCircuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for BrAdjustCircuit<F> {
  fn arity(&self) -> usize {
    2
  }

  fn circuit_index(&self) -> usize {
    self.circuit_index
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F>>,
    z: &[AllocatedNum<F>],
  ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
    let rom_index = &z[1];

    let allocated_rom: Result<Vec<_>, _> = self
      .fixed_rom
      .iter()
      .map(|opcode| AllocatedNum::alloc(cs.namespace(|| "elem"), || Ok(*opcode)))
      .collect();

    let allocated_rom = allocated_rom.map_err(|_| SynthesisError::AssignmentMissing)?;

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      &allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let dummy = AllocatedNum::alloc(cs.namespace(|| "dummy"), || Ok(F::from(0u64)))?;
    let mut z_next = vec![dummy];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

// Added for completeness
/// br_table
#[derive(Clone, Debug)]
pub struct BrTableCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> BrTableCircuit<F>
where
  F: PrimeField,
{
  /// Create a new BrTableCircuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for BrTableCircuit<F> {
  fn arity(&self) -> usize {
    2
  }

  fn circuit_index(&self) -> usize {
    self.circuit_index
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F>>,
    z: &[AllocatedNum<F>],
  ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
    let rom_index = &z[1];

    let allocated_rom: Result<Vec<_>, _> = self
      .fixed_rom
      .iter()
      .map(|opcode| AllocatedNum::alloc(cs.namespace(|| "elem"), || Ok(*opcode)))
      .collect();

    let allocated_rom = allocated_rom.map_err(|_| SynthesisError::AssignmentMissing)?;

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      &allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let dummy = AllocatedNum::alloc(cs.namespace(|| "dummy"), || Ok(F::from(0u64)))?;
    let mut z_next = vec![dummy];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

// Added for completeness
/// call
#[derive(Clone, Debug)]
pub struct CallInternalCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> CallInternalCircuit<F>
where
  F: PrimeField,
{
  /// Create a new Call Circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for CallInternalCircuit<F> {
  fn arity(&self) -> usize {
    2
  }

  fn circuit_index(&self) -> usize {
    self.circuit_index
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F>>,
    z: &[AllocatedNum<F>],
  ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
    let rom_index = &z[1];

    let allocated_rom: Result<Vec<_>, _> = self
      .fixed_rom
      .iter()
      .map(|opcode| AllocatedNum::alloc(cs.namespace(|| "elem"), || Ok(*opcode)))
      .collect();

    let allocated_rom = allocated_rom.map_err(|_| SynthesisError::AssignmentMissing)?;

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      &allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let dummy = AllocatedNum::alloc(cs.namespace(|| "dummy"), || Ok(F::from(0u64)))?;
    let mut z_next = vec![dummy];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

// Added for completeness
/// call_indirect
#[derive(Clone, Debug)]
pub struct CallIndirectCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> CallIndirectCircuit<F>
where
  F: PrimeField,
{
  /// Create a new CallIndirect Circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for CallIndirectCircuit<F> {
  fn arity(&self) -> usize {
    2
  }

  fn circuit_index(&self) -> usize {
    self.circuit_index
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F>>,
    z: &[AllocatedNum<F>],
  ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
    let rom_index = &z[1];

    let allocated_rom: Result<Vec<_>, _> = self
      .fixed_rom
      .iter()
      .map(|opcode| AllocatedNum::alloc(cs.namespace(|| "elem"), || Ok(*opcode)))
      .collect();

    let allocated_rom = allocated_rom.map_err(|_| SynthesisError::AssignmentMissing)?;

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      &allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let dummy = AllocatedNum::alloc(cs.namespace(|| "dummy"), || Ok(F::from(0u64)))?;
    let mut z_next = vec![dummy];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// return
#[derive(Clone, Debug)]
pub struct ReturnCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> ReturnCircuit<F>
where
  F: PrimeField,
{
  /// Create a new Return Circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for ReturnCircuit<F> {
  fn arity(&self) -> usize {
    2
  }

  fn circuit_index(&self) -> usize {
    self.circuit_index
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F>>,
    z: &[AllocatedNum<F>],
  ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
    let rom_index = &z[1];

    let allocated_rom: Result<Vec<_>, _> = self
      .fixed_rom
      .iter()
      .map(|opcode| AllocatedNum::alloc(cs.namespace(|| "elem"), || Ok(*opcode)))
      .collect();

    let allocated_rom = allocated_rom.map_err(|_| SynthesisError::AssignmentMissing)?;

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      &allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let res = &z[0];

    let mut z_next = vec![res.clone()];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}
