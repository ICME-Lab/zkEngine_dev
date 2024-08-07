//! Bin-op circuits
use crate::circuits::{
  gadgets::{signed64::Int64, uint64::UInt64},
  supernova::helpers::next_rom_index_and_pc,
};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use core::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use nova::supernova::StepCircuit;

/// i32.add
#[derive(Clone, Debug)]
pub struct AddCircuit<F: PrimeField + PartialOrd + PrimeFieldBits> {
  _p: PhantomData<F>,
  circuit_index: usize,
  inputs: (u64, u64),
  fixed_rom: Vec<F>,
}

impl<F> AddCircuit<F>
where
  F: PrimeField + PartialOrd + PrimeFieldBits,
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

impl<F: PrimeField + PartialOrd + PrimeFieldBits> StepCircuit<F> for AddCircuit<F> {
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
    let value = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let other = UInt64::alloc(cs.namespace(|| "b"), Some(b))?;
    let res = value.add(cs.namespace(|| "add"), &other)?;
    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.sub
#[derive(Clone, Debug)]
pub struct SubCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> SubCircuit<F>
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

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for SubCircuit<F> {
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
    let b = UInt64::alloc(cs.namespace(|| "-b"), Some(b))?;
    let res = a.add(cs.namespace(|| "sub"), &b).unwrap();

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.mul
#[derive(Clone, Debug)]
pub struct MulCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> MulCircuit<F>
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

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for MulCircuit<F> {
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
    let res = a.mul(cs.namespace(|| "mul"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.div_u
/// i64.div_u
#[derive(Clone, Debug)]
pub struct DivUnsignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> DivUnsignedCircuit<F>
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

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for DivUnsignedCircuit<F> {
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
    let res = a.div(cs.namespace(|| "div"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.div_s
#[derive(Clone, Debug)]
pub struct DivSignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64, u64),
}

impl<F> DivSignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for DivSignedCircuit<F> {
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

    let (a, b, is_neg) = self.inputs;
    let is_neg =
      Boolean::from(AllocatedBit::alloc(cs.namespace(|| "is neg"), Some(is_neg != 0)).unwrap());
    let a = Int64::alloc(cs.namespace(|| "a"), Some(a))?;
    let b = Int64::alloc(cs.namespace(|| "b"), Some(b))?;
    let res = a.div(cs.namespace(|| "div"), is_neg, &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}
/// i32.rem_s
#[derive(Clone, Debug)]
pub struct RemSignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64, u64),
}

impl<F> RemSignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for RemSignedCircuit<F> {
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

    let (a, b, is_neg) = self.inputs;
    let is_neg =
      Boolean::from(AllocatedBit::alloc(cs.namespace(|| "is neg"), Some(is_neg != 0)).unwrap());

    let a = Int64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
    let b = Int64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();

    let res = a.rem(cs.namespace(|| "rem"), is_neg, &b).unwrap();

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.rem_u
/// i64.rem_u
#[derive(Clone, Debug)]
pub struct RemUnSignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> RemUnSignedCircuit<F>
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

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for RemUnSignedCircuit<F> {
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
    let res = a.rem(cs.namespace(|| "rem"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}
