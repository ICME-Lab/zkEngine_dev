use bellpepper_core::{num::AllocatedNum, ConstraintSystem, Namespace, SynthesisError};
use ff::PrimeField;
use nova::{
  gadgets::lookup::LookupTrace,
  traits::{circuit::StepCircuit, CurveCycleEquipped, Dual, ROConstantsCircuit},
};
use wasmi::mtable::{AccessType, MemoryTableEntry};

use crate::circuits::supernova::helpers::conditionally_select2;

#[derive(Clone)]
pub struct MCCCircuit<E1: CurveCycleEquipped> {
  lookup_trace: LookupTrace<E1>,
  ro_consts: ROConstantsCircuit<Dual<E1>>,
  m_entry: MemoryTableEntry,
}

impl<E1: CurveCycleEquipped> MCCCircuit<E1> {
  pub fn new(
    lookup_trace: LookupTrace<E1>,
    ro_consts: ROConstantsCircuit<Dual<E1>>,
    m_entry: MemoryTableEntry,
  ) -> Self {
    Self {
      lookup_trace,
      ro_consts,
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
    5
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut lookup_trace = self.lookup_trace.clone();
    let prev_intermediate_gamma = &z[0];
    let alpha = &z[1];
    let gamma = &z[2];
    let prev_RW_acc = &z[3];
    let prev_global_ts = &z[4];

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

    // commit the rw change
    let (next_RW_acc, next_global_ts, next_intermediate_gamma) = lookup_trace
      .commit::<Dual<E1>, Namespace<'_, F, <CS as ConstraintSystem<F>>::Root>>(
        cs.namespace(|| "commit"),
        self.ro_consts.clone(),
        prev_intermediate_gamma,
        &(alpha.clone(), gamma.clone()),
        prev_RW_acc,
        prev_global_ts,
      )?;

    Ok(vec![
      next_intermediate_gamma,
      alpha.clone(),
      gamma.clone(),
      next_RW_acc,
      next_global_ts,
    ])
  }
}
