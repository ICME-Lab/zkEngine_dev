//! This module contains a batched version of the memory checking argument.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use nova::{
  gadgets::lookup::LookupTrace,
  traits::{circuit::StepCircuit, CurveCycleEquipped, Engine},
};
use wasmi::mtable::{AccessType, MemoryTableEntry};

use crate::circuits::supernova::helpers::conditionally_select2;

/// Values used for batched memory checking argument.
#[derive(Clone)]
pub struct BatchedMCCCircuit<E1: CurveCycleEquipped>
where
  <E1 as Engine>::Scalar: Ord,
{
  lookup_trace: LookupTrace<E1>,
  memory_trace: Vec<MemoryTableEntry>,
}

impl<E1: CurveCycleEquipped> BatchedMCCCircuit<E1>
where
  E1::Scalar: Ord,
{
  /// Create a new batched memory checking argument.
  pub fn new(lookup_trace: LookupTrace<E1>, memory_trace: Vec<MemoryTableEntry>) -> Self {
    Self {
      lookup_trace,
      memory_trace,
    }
  }
}

impl<F: PrimeField, E1: CurveCycleEquipped<Scalar = F>> StepCircuit<F> for BatchedMCCCircuit<E1>
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

    for step in self.memory_trace.iter() {
      let index = AllocatedNum::alloc(cs.namespace(|| "index"), || Ok(F::from(step.addr as u64)))?;

      let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(F::from(step.value)))?;

      let is_read_op = AllocatedNum::alloc(cs.namespace(|| "is_read_op"), || {
        Ok(F::from(u64::from(step.atype == AccessType::Read)))
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
    }

    Ok(vec![])
  }
}
