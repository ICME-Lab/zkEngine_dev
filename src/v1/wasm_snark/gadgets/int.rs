use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use ff::{PrimeField, PrimeFieldBits};

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

/// Perform bitwise AND on two nums
pub fn and<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  let a_bits = to_u64_le_bits(cs.namespace(|| "a_bits"), a)?;
  let b_bits = to_u64_le_bits(cs.namespace(|| "b_bits"), b)?;

  let res_bits: Vec<Boolean> = a_bits
    .iter()
    .zip(b_bits.iter())
    .enumerate()
    .map(|(i, (a, b))| Boolean::and(cs.namespace(|| format!("and of bit {}", i)), a, b))
    .collect::<Result<_, _>>()?;

  u64_le_bits_to_num(cs.namespace(|| "pack bits"), &res_bits)
}

/// Perform bitwise XOR on two nums
pub fn xor<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  let a_bits = to_u64_le_bits(cs.namespace(|| "a_bits"), a)?;
  let b_bits = to_u64_le_bits(cs.namespace(|| "b_bits"), b)?;

  let res_bits: Vec<Boolean> = a_bits
    .iter()
    .zip(b_bits.iter())
    .enumerate()
    .map(|(i, (a, b))| Boolean::xor(cs.namespace(|| format!("and of bit {}", i)), a, b))
    .collect::<Result<_, _>>()?;

  u64_le_bits_to_num(cs.namespace(|| "pack bits"), &res_bits)
}

/// Perform bitwise OR on two nums
pub fn or<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  let a_bits = to_u64_le_bits(cs.namespace(|| "a_bits"), a)?;
  let b_bits = to_u64_le_bits(cs.namespace(|| "b_bits"), b)?;

  let res_bits: Vec<Boolean> = a_bits
    .iter()
    .zip(b_bits.iter())
    .enumerate()
    .map(|(i, (a, b))| Boolean::or(cs.namespace(|| format!("and of bit {}", i)), a, b))
    .collect::<Result<_, _>>()?;

  u64_le_bits_to_num(cs.namespace(|| "pack bits"), &res_bits)
}

fn to_u64_le_bits<F, CS>(mut cs: CS, a: &AllocatedNum<F>) -> Result<Vec<Boolean>, SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  let res = a
    .to_bits_le(cs.namespace(|| "to_bits_le"))?
    .into_iter()
    .take(64)
    .collect();
  Ok(res)
}

fn u64_le_bits_to_num<F, CS>(
  mut cs: CS,
  bits: &[Boolean],
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  assert_eq!(bits.len(), 64);

  let mut value = Some(0u64);
  for b in bits.iter().rev() {
    if let Some(v) = value.as_mut() {
      *v <<= 1;
    }

    match *b {
      Boolean::Constant(b) => {
        if b {
          if let Some(v) = value.as_mut() {
            *v |= 1;
          }
        }
      }
      Boolean::Is(ref b) => match b.get_value() {
        Some(true) => {
          if let Some(v) = value.as_mut() {
            *v |= 1;
          }
        }
        Some(false) => {}
        None => value = None,
      },
      Boolean::Not(ref b) => match b.get_value() {
        Some(false) => {
          if let Some(v) = value.as_mut() {
            *v |= 1;
          }
        }
        Some(true) => {}
        None => value = None,
      },
    }
  }

  let num = AllocatedNum::alloc(cs.namespace(|| "alloc num"), || {
    Ok(F::from(value.unwrap_or(0)))
  })?;

  Ok(num)
}

/// popcount
pub fn popcount<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  res: &AllocatedNum<F>,
) -> Result<(), SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  let a_bits = to_u64_le_bits(cs.namespace(|| "a_bits"), a)?;

  popcount_equal(
    cs.namespace(|| "pop_count_equal"),
    &a_bits,
    res.get_variable(),
  );

  Ok(())
}

/// Adds a constraint to CS, enforcing that the addition of the allocated numbers in vector `v`
/// is equal to the value of the variable, `sum`.
pub(crate) fn popcount_equal<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  v: &[Boolean],
  sum: Variable,
) {
  let popcount = popcount_lc::<F, CS>(v);

  // popcount * 1 = sum
  cs.enforce(
    || "popcount",
    |_| popcount,
    |lc| lc + CS::one(),
    |lc| lc + sum,
  );
}

pub(crate) fn add_to_lc<F: PrimeField, CS: ConstraintSystem<F>>(
  b: &Boolean,
  lc: LinearCombination<F>,
  scalar: F,
) -> LinearCombination<F> {
  match b {
    Boolean::Constant(c) => lc + (if *c { scalar } else { F::ZERO }, CS::one()),
    Boolean::Is(ref v) => lc + (scalar, v.get_variable()),
    Boolean::Not(ref v) => lc + (scalar, CS::one()) - (scalar, v.get_variable()),
  }
}

/// Creates a linear combination representing the popcount (sum of one bits) of `v`.
pub(crate) fn popcount_lc<F: PrimeField, CS: ConstraintSystem<F>>(
  v: &[Boolean],
) -> LinearCombination<F> {
  v.iter().fold(LinearCombination::<F>::zero(), |acc, bit| {
    add_to_lc::<F, CS>(bit, acc, F::ONE)
  })
}

/// Gadget to perform bitwise shl operation.
pub fn shl_bits_64<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  bits: &[Boolean],
  shift: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
  let shift = shift % 64;
  let fill = Boolean::Is(AllocatedBit::alloc(
    cs.namespace(|| "fill bit"),
    Some(false),
  )?);

  let res_bits: Vec<Boolean> = Some(&fill)
    .into_iter()
    .cycle()
    .take(shift)
    .chain(bits.iter())
    .take(64)
    .cloned()
    .collect();

  Ok(res_bits)
}

/// Performs bitwise shl operation on a `UInt64` value
pub fn shl_64<F: PrimeField + PrimeFieldBits, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  by: usize,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let a_bits = to_u64_le_bits(cs.namespace(|| "a_bits"), a)?;
  let res_bits = shl_bits_64(cs.namespace(|| "shl bits"), &a_bits, by)?;

  u64_le_bits_to_num(cs.namespace(|| "pack bits"), &res_bits)
}
