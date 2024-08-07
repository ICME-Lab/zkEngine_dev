//! Shift operations circuits
use crate::circuits::{gadgets::uint64::UInt64, supernova::helpers::next_rom_index_and_pc};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use core::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use nova::supernova::StepCircuit;

/// i32.shl
/// i64.shl
#[derive(Clone, Debug)]
pub struct ShlCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> ShlCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new shift-op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for ShlCircuit<F> {
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

    let (a, by) = self.inputs;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.shl(cs.namespace(|| "res"), by as usize)?;
    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.shr_s
/// i64.shr_s
#[derive(Clone, Debug)]
pub struct ShrSignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> ShrSignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new shift-op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for ShrSignedCircuit<F> {
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

    let (a, by) = self.inputs;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.shr(cs.namespace(|| "res"), by as usize)?;
    let mut z_next = vec![res.alloc_num];

    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.shr_u
/// i64.shr_u
#[derive(Clone, Debug)]
pub struct ShrUnsignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> ShrUnsignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new shift-op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for ShrUnsignedCircuit<F> {
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

    let (a, by) = self.inputs;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.shr(cs.namespace(|| "res"), by as usize)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i64.rotl
#[derive(Clone, Debug)]
pub struct RotlCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> RotlCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new shift-op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for RotlCircuit<F> {
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

    let (a, by) = self.inputs;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.rotl(cs.namespace(|| "res"), by as usize)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.rotl
#[derive(Clone, Debug)]
pub struct I32RotlCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> I32RotlCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new shift-op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for I32RotlCircuit<F> {
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

    let (a, by) = self.inputs;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.rotl_32_bit(cs.namespace(|| "res"), by as usize)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i64.rotr
#[derive(Clone, Debug)]
pub struct RotrCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> RotrCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new shift-op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for RotrCircuit<F> {
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

    let (a, by) = self.inputs;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.rotr(cs.namespace(|| "res"), by as usize)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.rotr
#[derive(Clone, Debug)]
pub struct I32RotrCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> I32RotrCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new shift-op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for I32RotrCircuit<F> {
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

    let (a, by) = self.inputs;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.rotr_32_bit(cs.namespace(|| "res"), by as usize)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}
