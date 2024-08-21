use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use nova::{
  gadgets::lookup::LookupTrace,
  traits::{circuit::StepCircuit, CurveCycleEquipped},
};
use wasmi::mtable::{AccessType, MemoryTableEntry};

use crate::circuits::supernova::helpers::conditionally_select2;

#[derive(Clone)]
pub struct MCCCircuit<E1: CurveCycleEquipped> {
  lookup_trace: LookupTrace<E1>,
  m_entry: MemoryTableEntry,
}

impl<E1: CurveCycleEquipped> MCCCircuit<E1> {
  pub fn new(lookup_trace: LookupTrace<E1>, m_entry: MemoryTableEntry) -> Self {
    Self {
      lookup_trace,
      m_entry,
    }
  }
}

impl<F: PrimeField, E1: CurveCycleEquipped<Scalar = F>> StepCircuit<F> for MCCCircuit<E1>
where
  E1::Scalar: Ord,
{
  fn get_counter_type(&self) -> nova::StepCounterType {
    nova::StepCounterType::Incremental
  }

  fn arity(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    _z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut lookup_trace = self.lookup_trace.clone();

    let index = AllocatedNum::alloc(cs.namespace(|| "index"), || {
      Ok(F::from(self.m_entry.addr as u64))
    })?;

    let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(F::from(self.m_entry.value)))?;

    let is_read_op = AllocatedNum::alloc(cs.namespace(|| "is_read_op"), || {
      Ok(F::from(u64::from(self.m_entry.atype == AccessType::Read)))
    })?;

    let read_value = lookup_trace.read(cs.namespace(|| "read"), &index)?;

    let expected_read_value = conditionally_select2(
      cs.namespace(|| "expected_read_value"),
      &read_value,
      &value,
      &is_read_op,
    )?;

    // Check again that read value at address == previously written value at address
    cs.enforce(
      || "read_value == expected_read_value",
      |lc| lc + value.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + expected_read_value.get_variable(),
    );

    lookup_trace.write(cs.namespace(|| "write"), &index, &value)?;

    Ok(vec![])
  }
}
