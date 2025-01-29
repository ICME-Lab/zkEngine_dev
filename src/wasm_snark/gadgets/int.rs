use bellpepper::gadgets::Assignment;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
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

#[allow(dead_code)]
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
