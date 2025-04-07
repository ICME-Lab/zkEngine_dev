use ff::PrimeField;
use nova::frontend::gadgets::Assignment;
use nova::frontend::{num::AllocatedNum, Boolean, ConstraintSystem, SynthesisError};

#[allow(dead_code)]
/// Allocate a variable that is set to zero
pub fn alloc_zero<F: PrimeField, CS: ConstraintSystem<F>>(mut cs: CS) -> AllocatedNum<F> {
  let zero = AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || F::ZERO);
  cs.enforce(
    || "check zero is valid",
    |lc| lc,
    |lc| lc,
    |lc| lc + zero.get_variable(),
  );
  zero
}

/// Allocate a variable that is set to one
pub fn alloc_one<F: PrimeField, CS: ConstraintSystem<F>>(mut cs: CS) -> AllocatedNum<F> {
  let one = AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || F::ONE);
  cs.enforce(
    || "check one is valid",
    |lc| lc + CS::one(),
    |lc| lc + CS::one(),
    |lc| lc + one.get_variable(),
  );

  one
}

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
