//! Parametric operations circuits
use std::marker::PhantomData;

use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use nova::supernova::StepCircuit;

use crate::circuits::{gadgets::uint64::UInt64, supernova::helpers::next_rom_index_and_pc};

/// Select
#[derive(Clone, Debug)]
pub struct SelectCircuit<F: PrimeField + PrimeFieldBits + PartialOrd> {
  _p: PhantomData<F>,
  circuit_index: usize,
  fixed_rom: Vec<F>,
  inputs: (u64, u64, u64),
}

impl<F> SelectCircuit<F>
where
  F: PrimeField + PrimeFieldBits + PartialOrd,
{
  /// Create a new select circuit
  pub fn new(circuit_index: usize, fixed_rom: Vec<F>, inputs: (u64, u64, u64)) -> Self {
    Self {
      circuit_index,
      fixed_rom,
      inputs,
      _p: PhantomData,
    }
  }
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> StepCircuit<F> for SelectCircuit<F> {
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

    let (a, b, cond) = self.inputs;
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a))?;
    let b = UInt64::alloc(cs.namespace(|| "b"), Some(b))?;
    let condition_bit = AllocatedBit::alloc(cs.namespace(|| "cond bit"), Some(cond != 0))?;
    let condition = Boolean::Is(condition_bit);
    let res = UInt64::conditionally_select(
      cs.namespace(|| "if cond select a else b"),
      &a,
      &b,
      condition,
    )?;

    let mut z_next: Vec<AllocatedNum<F>> = vec![res.alloc_num];
    z_next.push(rom_index_next);

    Ok((Some(pc_next), z_next))
  }
}
