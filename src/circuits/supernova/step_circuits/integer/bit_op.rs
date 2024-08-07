//! Bit-op circuits
use crate::circuits::{gadgets::uint64::UInt64, supernova::helpers::next_rom_index_and_pc};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use core::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use nova::supernova::StepCircuit;

/// i32.and
/// i64.and
#[derive(Clone, Debug)]
pub struct AndCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> AndCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for AndCircuit<F> {
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

    let (a, b) = self.inputs;

    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let b = UInt64::alloc(cs.namespace(|| "b"), Some(b))?;
    let res = a.and(cs.namespace(|| "a & b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.or
/// i64.or
#[derive(Clone, Debug)]
pub struct OrCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> OrCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for OrCircuit<F> {
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

    let (a, b) = self.inputs;

    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let b = UInt64::alloc(cs.namespace(|| "b"), Some(b))?;
    let res = a.or(cs.namespace(|| "a | b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.xor
/// i64.xor
#[derive(Clone, Debug)]
pub struct XorCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> XorCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for XorCircuit<F> {
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

    let (a, b) = self.inputs;

    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let b = UInt64::alloc(cs.namespace(|| "b"), Some(b))?;
    let res = a.xor(cs.namespace(|| "a ^ b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}
