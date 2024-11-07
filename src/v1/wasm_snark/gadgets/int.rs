use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use ff::PrimeField;

pub fn add<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let res = AllocatedNum::alloc(cs.namespace(|| "add_num"), || {
    let mut tmp = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
    tmp.add_assign(&b.get_value().ok_or(SynthesisError::AssignmentMissing)?);

    Ok(tmp)
  })?;

  // a + b = res
  sum(&mut cs, || "sum constraint", a, b, &res);

  Ok(res)
}

/// Adds a constraint to CS, enforcing a add relationship between the allocated
/// numbers a, b, and sum.
///
/// a + b = sum
pub fn sum<F: PrimeField, A, AR, CS: ConstraintSystem<F>>(
  cs: &mut CS,
  annotation: A,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  sum: &AllocatedNum<F>,
) where
  A: FnOnce() -> AR,
  AR: Into<String>,
{
  // (a + b) * 1 = sum
  cs.enforce(
    annotation,
    |lc| lc + a.get_variable() + b.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + sum.get_variable(),
  );
}

pub(crate) fn mul<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let res = AllocatedNum::alloc(cs.namespace(|| "mul_num"), || {
    let mut tmp = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
    tmp.mul_assign(&b.get_value().ok_or(SynthesisError::AssignmentMissing)?);

    Ok(tmp)
  })?;

  // a * b = res
  product(&mut cs, || "multiplication constraint", a, b, &res);

  Ok(res)
}

/// Adds a constraint to CS, enforcing a product relationship between the
/// allocated numbers a, b, and product.
///
/// a * b = product
pub(crate) fn product<F: PrimeField, A, AR, CS: ConstraintSystem<F>>(
  cs: &mut CS,
  annotation: A,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  product: &AllocatedNum<F>,
) where
  A: FnOnce() -> AR,
  AR: Into<String>,
{
  // a * b = product
  cs.enforce(
    annotation,
    |lc| lc + a.get_variable(),
    |lc| lc + b.get_variable(),
    |lc| lc + product.get_variable(),
  );
}

/// Adds a constraint to CS, enforcing a difference relationship between the
/// allocated numbers a, b, and difference.
///
/// a - b = difference
pub(crate) fn enforce_difference<F: PrimeField, A, AR, CS: ConstraintSystem<F>>(
  cs: &mut CS,
  annotation: A,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  difference: &AllocatedNum<F>,
) where
  A: FnOnce() -> AR,
  AR: Into<String>,
{
  //    difference = a-b
  // => difference + b = a
  // => (difference + b) * 1 = a
  cs.enforce(
    annotation,
    |lc| lc + difference.get_variable() + b.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + a.get_variable(),
  );
}

pub(crate) fn sub<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let res = AllocatedNum::alloc(cs.namespace(|| "sub_num"), || {
    let mut tmp = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
    tmp.sub_assign(&b.get_value().ok_or(SynthesisError::AssignmentMissing)?);

    Ok(tmp)
  })?;

  // a - b = res
  enforce_difference(&mut cs, || "subtraction constraint", a, b, &res);

  Ok(res)
}

/// Adds a constraint to CS, enforcing an equality relationship between the
/// allocated numbers a and b.
///
/// a == b
pub fn enforce_equal<F: PrimeField, A, AR, CS: ConstraintSystem<F>>(
  cs: &mut CS,
  annotation: A,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) where
  A: FnOnce() -> AR,
  AR: Into<String>,
{
  // debug_assert_eq!(a.get_value(), b.get_value());
  // a * 1 = b
  cs.enforce(
    annotation,
    |lc| lc + a.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + b.get_variable(),
  );
}

#[allow(unused)]
/// Check if a < b
pub(crate) fn lt<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  todo!()
}

/// Negate an AllocatedNum
pub fn alloc_negate<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let b = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(-*a.get_value().get()?))?;

  cs.enforce(
    || "check y = - self.y",
    |lc| lc + a.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc - b.get_variable(),
  );

  Ok(b)
}

/// Checks if AllocatedNum is zero
pub fn eqz<F, CS>(mut cs: CS, a: &AllocatedNum<F>) -> Result<Boolean, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let a_val = a.get_value();
  let is_zero = a_val.map(|val| val == F::ZERO);

  // result = (a == 0)
  let result = AllocatedBit::alloc(cs.namespace(|| "a == 0"), is_zero)?;

  // result * a = 0
  // This means that at least one of result or a is zero.
  cs.enforce(
    || "result or a is 0",
    |lc| lc + result.get_variable(),
    |lc| lc + a.get_variable(),
    |lc| lc,
  );

  // Inverse of `a`, if it exists, otherwise one.
  let a_fe = a_val.unwrap_or(F::ZERO);
  let q = cs.alloc(
    || "q",
    || {
      let tmp = a_fe.invert();
      if tmp.is_some().into() {
        Ok(tmp.unwrap())
      } else {
        Ok(F::ONE)
      }
    },
  )?;

  // (a + result) * q = 1.
  // This enforces that a and result are not both 0.
  cs.enforce(
    || "(a + result) * q = 1",
    |lc| lc + a.get_variable() + result.get_variable(),
    |lc| lc + q,
    |lc| lc + CS::one(),
  );

  // Taken together, these constraints enforce that exactly one of `a` and `result` is 0.
  // Since result is constrained to be boolean, that means `result` is true iff `a` is 0.

  Ok(Boolean::Is(result))
}
