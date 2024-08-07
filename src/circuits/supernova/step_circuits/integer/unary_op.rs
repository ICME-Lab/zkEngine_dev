//! Unary operations circuits
use crate::circuits::{gadgets::uint64::UInt64, supernova::helpers::next_rom_index_and_pc};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use core::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use nova::supernova::StepCircuit;

/// i64.clz
#[derive(Clone, Debug)]
pub struct ClzCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> ClzCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new unary-op circuits
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for ClzCircuit<F> {
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

    let a = self.inputs.0;

    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.clz(cs.namespace(|| "clz"))?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}
/// i32.clz
#[derive(Clone, Debug)]
pub struct I32ClzCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> I32ClzCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new unary-op circuits
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for I32ClzCircuit<F> {
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

    let a = self.inputs.0;

    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.clz_32_bit(cs.namespace(|| "clz"))?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i64.ctz
#[derive(Clone, Debug)]
pub struct CtzCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> CtzCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new unary-op circuits
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for CtzCircuit<F> {
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

    let a = self.inputs.0;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.ctz(cs.namespace(|| "ctz"))?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.ctz
#[derive(Clone, Debug)]
pub struct I32CtzCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> I32CtzCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new unary-op circuits
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for I32CtzCircuit<F> {
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

    let a = self.inputs.0;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.ctz_32_bit(cs.namespace(|| "ctz"))?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.popcnt
/// i64.popcnt
#[derive(Clone, Debug)]
pub struct PopCntCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> PopCntCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new unary-op circuits
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for PopCntCircuit<F> {
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

    let a = self.inputs.0;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.popcnt(cs.namespace(|| "popcnt"))?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}
