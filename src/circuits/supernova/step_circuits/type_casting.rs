//! Conversion instruction circuits
#![allow(dead_code)]
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use core::marker::PhantomData;
use ff::PrimeField;
use nova::supernova::StepCircuit;

use crate::circuits::supernova::helpers::next_rom_index_and_pc;

/// i32.wrap_i64
// TODO: lookups
#[derive(Clone)]
pub struct I32WrapI64Circuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I32WrapI64Circuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I32WrapI64Circuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i32.trunc_f32_s
// TODO: lookups
#[derive(Clone)]
pub struct I32TruncF32SCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I32TruncF32SCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I32TruncF32SCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i32.trunc_f32_u
// TODO: lookups
#[derive(Clone)]

pub struct I32TruncF32UCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I32TruncF32UCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I32TruncF32UCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i32.trunc_f64_s
// TODO: lookups

#[derive(Clone)]
pub struct I32TruncF64SCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I32TruncF64SCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I32TruncF64SCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i32.trunc_f64_u
// TODO: lookups
#[derive(Clone)]
pub struct I32TruncF64UCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I32TruncF64UCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I32TruncF64UCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i64.extend_i32_s
// TODO: lookups
#[derive(Clone)]
pub struct I64ExtendI32SCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I64ExtendI32SCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I64ExtendI32SCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i64.extend_i32_u
// TODO: lookups
#[derive(Clone)]
pub struct I64ExtendI32UCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I64ExtendI32UCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I64ExtendI32UCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i64.trunc_f32_s
// TODO: lookups
#[derive(Clone)]
pub struct I64TruncF32SCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I64TruncF32SCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I64TruncF32SCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i64.trunc_f32_u
// TODO: lookups
#[derive(Clone)]
pub struct I64TruncF32UCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I64TruncF32UCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I64TruncF32UCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i64.trunc_f64_s
// TODO: lookups
#[derive(Clone)]
pub struct I64TruncF64SCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I64TruncF64SCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I64TruncF64SCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i64.trunc_f64_u
// TODO: lookups

#[derive(Clone)]
pub struct I64TruncF64UCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I64TruncF64UCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I64TruncF64UCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f32.convert_i32_s
// TODO: lookups
#[derive(Clone)]
pub struct F32ConvertI32SCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F32ConvertI32SCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F32ConvertI32SCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f32.convert_i32_u
// TODO: lookups
#[derive(Clone)]
pub struct F32ConvertI32UCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F32ConvertI32UCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F32ConvertI32UCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f32.convert_i64_s
// TODO: lookups
#[derive(Clone)]
pub struct F32ConvertI64SCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F32ConvertI64SCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F32ConvertI64SCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f32.convert_i64_u
// TODO: lookups
#[derive(Clone)]
pub struct F32ConvertI64UCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F32ConvertI64UCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F32ConvertI64UCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f32.demote_f64
// TODO: lookups
#[derive(Clone)]
pub struct F32DemoteF64Circuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F32DemoteF64Circuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F32DemoteF64Circuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f64.convert_i32_s
// TODO: lookups
#[derive(Clone)]
pub struct F64ConvertI32SCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F64ConvertI32SCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F64ConvertI32SCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f64.convert_i32_u
// TODO: lookups
#[derive(Clone)]
pub struct F64ConvertI32UCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F64ConvertI32UCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F64ConvertI32UCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f64.convert_i64_s
// TODO: lookups
#[derive(Clone)]
pub struct F64ConvertI64SCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F64ConvertI64SCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F64ConvertI64SCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f64.convert_i64_u
// TODO: lookups
#[derive(Clone)]
pub struct F64ConvertI64UCircuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F64ConvertI64UCircuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F64ConvertI64UCircuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f64.promote_f32
// TODO: lookups
#[derive(Clone)]
pub struct F64PromoteF32Circuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F64PromoteF32Circuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F64PromoteF32Circuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i32.reinterpret_f32
// TODO: lookups
#[derive(Clone)]
pub struct I32ReinterpretF32Circuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I32ReinterpretF32Circuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I32ReinterpretF32Circuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// i64.reinterpret_f64
// TODO: lookups
#[derive(Clone)]
pub struct I64ReinterpretF64Circuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> I64ReinterpretF64Circuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for I64ReinterpretF64Circuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f32.reinterpret_i32
// TODO: lookups
#[derive(Clone)]
pub struct F32ReinterpretI32Circuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F32ReinterpretI32Circuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F32ReinterpretI32Circuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}

/// f64.reinterpret_i64
// TODO: lookups
#[derive(Clone)]
pub struct F64ReinterpretI64Circuit<F: PrimeField> {
  _p: PhantomData<F>,
  circuit_index: usize,
  rom_size: usize,
  inputs: (u64, u64),
}

impl<F> F64ReinterpretI64Circuit<F>
where
  F: PrimeField,
{
  /// Create new opcode circuit
  pub fn new(circuit_index: usize, rom_size: usize, inputs: (u64, u64)) -> Self {
    Self {
      circuit_index,
      rom_size,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField> StepCircuit<F> for F64ReinterpretI64Circuit<F> {
  fn arity(&self) -> usize {
    2 + self.rom_size
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
    let allocated_rom = &z[2..];

    let (rom_index_next, pc_next) = next_rom_index_and_pc(
      &mut cs.namespace(|| "next and rom_index and pc"),
      rom_index,
      allocated_rom,
      pc.ok_or(SynthesisError::AssignmentMissing)?,
    )?;

    let placeholder = AllocatedNum::alloc(cs.namespace(|| "placeholder"), || Ok(F::ZERO))?;

    let mut z_next = vec![placeholder];
    z_next.push(rom_index_next);
    z_next.extend(z[2..].iter().cloned());

    Ok((Some(pc_next), z_next))
  }
}
