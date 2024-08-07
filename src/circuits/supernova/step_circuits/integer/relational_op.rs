//! Relational-op circuits
use crate::circuits::{
  gadgets::{signed64::Int64, uint64::UInt64},
  supernova::helpers::next_rom_index_and_pc,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use core::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use nova::supernova::StepCircuit;

/// i32.eqz
#[derive(Clone, Debug)]
pub struct EqzCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> EqzCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for EqzCircuit<F> {
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

    let (_, a) = self.inputs;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let res = a.eqz(cs.namespace(|| "a == 0"))?;
    let mut z_next = vec![res.alloc_num];

    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.eq
#[derive(Clone, Debug)]
pub struct EqCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> EqCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for EqCircuit<F> {
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
    let res = a.eq(cs.namespace(|| "a == b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.ne
#[derive(Clone, Debug)]
pub struct NeCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> NeCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for NeCircuit<F> {
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
    let res = a.ne(cs.namespace(|| "a != b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.lt_s
#[derive(Clone, Debug)]
pub struct LtCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> LtCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for LtCircuit<F> {
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
    let a = Int64::alloc(cs.namespace(|| "a"), Some(a))?;
    let b = Int64::alloc(cs.namespace(|| "b"), Some(b))?;
    let res = a.lt(cs.namespace(|| "a < b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.lt_u
#[derive(Clone, Debug)]
pub struct LtUnsignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> LtUnsignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for LtUnsignedCircuit<F> {
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
    let res = a.lt(cs.namespace(|| "a < b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.gt_s
#[derive(Clone, Debug)]
pub struct GtSignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> GtSignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for GtSignedCircuit<F> {
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
    let a = Int64::alloc(cs.namespace(|| "a"), Some(a))?;
    let b = Int64::alloc(cs.namespace(|| "b"), Some(b))?;
    let res = a.gt(cs.namespace(|| "a > b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.gt_u
#[derive(Clone, Debug)]
pub struct GtUnsignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> GtUnsignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for GtUnsignedCircuit<F> {
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
    let res = a.gt(cs.namespace(|| "a > b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.le_s
#[derive(Clone, Debug)]
pub struct LeSignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> LeSignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for LeSignedCircuit<F> {
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
    let a = Int64::alloc(cs.namespace(|| "a"), Some(a))?;
    let b = Int64::alloc(cs.namespace(|| "b"), Some(b))?;
    let res = a.le(cs.namespace(|| "a <= b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.le_u
#[derive(Clone, Debug)]
pub struct LeUnsignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> LeUnsignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for LeUnsignedCircuit<F> {
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
    let res = a.le(cs.namespace(|| "a <= b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.ge_s
#[derive(Clone, Debug)]
pub struct GeSignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> GeSignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for GeSignedCircuit<F> {
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
    let a = Int64::alloc(cs.namespace(|| "a"), Some(a))?;
    let b = Int64::alloc(cs.namespace(|| "b"), Some(b))?;
    let res = a.ge(cs.namespace(|| "a >= b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}

/// i32.ge_u
#[derive(Clone, Debug)]
pub struct GeUnsignedCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64),
}

impl<F> GeUnsignedCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create new relational op circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for GeUnsignedCircuit<F> {
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
    let res = a.ge(cs.namespace(|| "a >= b"), &b)?;

    let mut z_next = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}
