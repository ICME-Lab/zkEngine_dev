use ff::PrimeField;
use nova::frontend::gadgets::Assignment;
use nova::frontend::{num::AllocatedNum, Boolean, ConstraintSystem, SynthesisError};

/// If condition return a otherwise b
pub fn conditionally_select<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  a: &AllocatedNum<Scalar>,
  b: &AllocatedNum<Scalar>,
  condition: &Boolean,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? {
      Ok(*a.get_value().get()?)
    } else {
      Ok(*b.get_value().get()?)
    }
  })?;

  // a * condition + b*(1-condition) = c ->
  // a * condition - b*condition = c - b
  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable() - b.get_variable(),
    |_| condition.lc(CS::one(), Scalar::ONE),
    |lc| lc + c.get_variable() - b.get_variable(),
  );

  Ok(c)
}
