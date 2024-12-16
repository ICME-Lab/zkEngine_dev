use crate::v1::wasm_snark::switchboard::WASMTransitionCircuit as SwitchBoardCircuit;
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use ff::{PrimeField, PrimeFieldBits};
use wasmi::core::UntypedValue;

pub fn add64<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: u64,
  b_bits: u64,
  switch: F,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let zero = F::ZERO;
  let range = F::from_u128(1_u128 << 64);
  let ON: F = zero - range;

  let (c, of) = a_bits.overflowing_add(b_bits);
  let o = if of { ON } else { zero };

  // construct witness
  let c = SwitchBoardCircuit::alloc_num(&mut cs, || "c", || Ok(F::from(c)), switch)?;

  // note, this is "advice"
  let o = SwitchBoardCircuit::alloc_num(&mut cs, || "o", || Ok(o), switch)?;

  // check o * (o + range) == 0
  cs.enforce(
    || "check o * (o + range) == 0",
    |lc| lc + (range, CS::one()) + o.get_variable(),
    |lc| lc + o.get_variable(),
    |lc| lc,
  );

  // a + b + o = c
  cs.enforce(
    || "a + b + o = c",
    |lc| lc + a.get_variable() + b.get_variable() + o.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + c.get_variable(),
  );

  Ok(c)
}

pub fn mul64<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: u64,
  b_bits: u64,
  switch: F,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  // Get value WASM vm will spit out
  let c = a_bits.wrapping_mul(b_bits);
  let c = SwitchBoardCircuit::alloc_num(&mut cs, || "c", || Ok(F::from(c)), switch)?;

  // Calculate the product value in 128 bits
  let a_128_bits = a_bits as u128;
  let b_128_bits = b_bits as u128;
  let c_128_bits = a_128_bits * b_128_bits;

  // Calculate the left overs (value to subtract from c_128 to get c)
  //
  // # Note
  //
  // This is advice
  let range = F::from_u128(1_u128 << 64);

  let trunc = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "trunc",
    || Ok(F::from_u128(c_128_bits >> 64)),
    switch,
  )?;

  /*
   * Enforce c_128 is the product of a and b
   */
  let c_intermediate = a.mul(cs.namespace(|| "c_intermediate"), b)?;

  // c == c_128 - left_overs
  cs.enforce(
    || "c == c_128 - left_overs",
    |lc| lc + c.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + c_intermediate.get_variable() - (range, trunc.get_variable()),
  );

  Ok(c)
}

pub fn sub64<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: u64,
  b_bits: u64,
  switch: F,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let range = F::from_u128(1_u128 << 64);
  let (c, of) = a_bits.overflowing_sub(b_bits);
  let c = SwitchBoardCircuit::alloc_num(&mut cs, || "c", || Ok(F::from(c)), switch)?;
  let of = SwitchBoardCircuit::alloc_bit(&mut cs, || "of", Some(of), switch)?;

  cs.enforce(
    || "a - b + range*of = c",
    |lc| lc + a.get_variable() - b.get_variable() + (range, of.get_variable()),
    |lc| lc + CS::one(),
    |lc| lc + c.get_variable(),
  );

  Ok(c)
}

/// Computes unsigned and signed lt and ge
pub fn lt_ge_s<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: u64,
  b_bits: u64,
  switch: F,
) -> Result<
  (
    AllocatedNum<F>,
    AllocatedNum<F>,
    AllocatedNum<F>,
    AllocatedNum<F>,
  ),
  SynthesisError,
>
// Returns (lt, ge, slt, sge)
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let one = SwitchBoardCircuit::alloc_num(&mut cs, || "one", || Ok(F::ONE), switch)?;
  let range_const = F::from_u128(1_u128 << 64);
  let (c, of) = a_bits.overflowing_sub(b_bits);
  let c = SwitchBoardCircuit::alloc_num(&mut cs, || "c", || Ok(F::from(c)), switch)?;
  let lt = of;
  let lt_flag = SwitchBoardCircuit::alloc_num(&mut cs, || "lt", || Ok(F::from(lt as u64)), switch)?;

  cs.enforce(
    || "a - b + range*lt = c",
    |lc| lc + a.get_variable() - b.get_variable() + (range_const, lt_flag.get_variable()),
    |lc| lc + CS::one(),
    |lc| lc + c.get_variable(),
  );

  // GE flag
  let ge_flag = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "ge_num",
    || {
      if a_bits >= b_bits {
        Ok(F::ONE)
      } else {
        Ok(F::ZERO)
      }
    },
    switch,
  )?;

  // a<b + a>=b = 1
  cs.enforce(
    || "a<b + a>=b = 1",
    |lc| lc + lt_flag.get_variable() + ge_flag.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + one.get_variable(),
  );

  // signed lt and gte flags
  let slt_flag = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "slt",
    || {
      if (a_bits as i64) < (b_bits as i64) {
        Ok(F::ONE)
      } else {
        Ok(F::ZERO)
      }
    },
    switch,
  )?;

  let sge_flag = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "sge",
    || {
      if (a_bits as i64) >= (b_bits as i64) {
        Ok(F::ONE)
      } else {
        Ok(F::ZERO)
      }
    },
    switch,
  )?;

  // sge = !slt
  cs.enforce(
    || "sgt = !slt",
    |lc| lc + CS::one() - slt_flag.get_variable(),
    |lc| lc + one.get_variable(),
    |lc| lc + sge_flag.get_variable(),
  );

  // invert < if a and b differ in sign
  // different signs (ds)
  let a_sign_bit = a_bits >> 63;
  let a_sign = SwitchBoardCircuit::alloc_bit(&mut cs, || "a_sign", Some(a_sign_bit == 1), switch)?;
  let b_sign_bit = b_bits >> 63;
  let b_sign = SwitchBoardCircuit::alloc_bit(&mut cs, || "b_sign", Some(b_sign_bit == 1), switch)?;

  let ds = (a_sign_bit ^ b_sign_bit) != 0;

  let ds_flag = SwitchBoardCircuit::alloc_bit(&mut cs, || "ds", Some(ds), switch)?;

  // compute XOR of a and b sign bits
  let as_bs_bit = a_sign_bit * b_sign_bit;
  let as_bs = SwitchBoardCircuit::alloc_bit(&mut cs, || "as_bs", Some(as_bs_bit == 1), switch)?;

  // a_63 + b_63 - 2 a_63 b_63 = ds  (XOR)
  cs.enforce(
    || "a_63 + b_63 - 2 a_63 b_63 = ds",
    |lc| lc + a_sign.get_variable() + b_sign.get_variable() - (F::from(2u64), as_bs.get_variable()),
    |lc| lc + CS::one(),
    |lc| lc + ds_flag.get_variable(),
  );

  // slt = ds (1 - lt) + (1 - ds) lt
  let sltl = SwitchBoardCircuit::alloc_bit(&mut cs, || "sltl", Some(ds & !lt), switch)?;
  cs.enforce(
    || "sltl = ds (1 - lt)",
    |lc| lc + ds_flag.get_variable(),
    |lc| lc + CS::one() - lt_flag.get_variable(),
    |lc| lc + sltl.get_variable(),
  );

  let sltr = SwitchBoardCircuit::alloc_bit(&mut cs, || "sltr", Some(!ds & lt), switch)?;
  cs.enforce(
    || "sltr = (1 - ds) lt",
    |lc| lc + CS::one() - ds_flag.get_variable(),
    |lc| lc + lt_flag.get_variable(),
    |lc| lc + sltr.get_variable(),
  );

  // slt = sltl + sltr
  cs.enforce(
    || "slt = sltl + sltr",
    |lc| lc + sltl.get_variable() + sltr.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + slt_flag.get_variable(),
  );

  Ok((lt_flag, ge_flag, slt_flag, sge_flag))
}

/// Computes unsigned and signed le and gt
pub fn le_gt_s<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: u64,
  b_bits: u64,
  switch: F,
) -> Result<
  (
    AllocatedNum<F>,
    AllocatedNum<F>,
    AllocatedNum<F>,
    AllocatedNum<F>,
  ),
  SynthesisError,
>
// Returns (le, gt, sle, sgt)
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let one = SwitchBoardCircuit::alloc_num(&mut cs, || "one", || Ok(F::ONE), switch)?;
  let range_const = F::from_u128(1_u128 << 64);
  let (c, of) = b_bits.overflowing_sub(a_bits);
  let c = SwitchBoardCircuit::alloc_num(&mut cs, || "c", || Ok(F::from(c)), switch)?;
  let gt = of;
  let gt_flag = SwitchBoardCircuit::alloc_num(&mut cs, || "gt", || Ok(F::from(gt as u64)), switch)?;

  cs.enforce(
    || "b - a + range*lt = c",
    |lc| lc + b.get_variable() - a.get_variable() + (range_const, gt_flag.get_variable()),
    |lc| lc + CS::one(),
    |lc| lc + c.get_variable(),
  );

  // LE flag
  let le_flag = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "le",
    || {
      if a_bits <= b_bits {
        Ok(F::ONE)
      } else {
        Ok(F::ZERO)
      }
    },
    switch,
  )?;

  // a>b + a<=b = 1
  cs.enforce(
    || "a>b + a<=b = 1",
    |lc| lc + le_flag.get_variable() + gt_flag.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + one.get_variable(),
  );

  // signed le and gt flags
  let sgt_flag = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "sgt",
    || {
      if (a_bits as i64) > (b_bits as i64) {
        Ok(F::ONE)
      } else {
        Ok(F::ZERO)
      }
    },
    switch,
  )?;

  let sle_flag = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "sle",
    || {
      if (a_bits as i64) <= (b_bits as i64) {
        Ok(F::ONE)
      } else {
        Ok(F::ZERO)
      }
    },
    switch,
  )?;

  // sle = !sgt
  cs.enforce(
    || "sgt = !sle",
    |lc| lc + CS::one() - sgt_flag.get_variable(),
    |lc| lc + one.get_variable(),
    |lc| lc + sle_flag.get_variable(),
  );

  // invert < if a and b differ in sign
  // different signs (ds)
  let a_sign_bit = a_bits >> 63;
  let a_sign = SwitchBoardCircuit::alloc_bit(&mut cs, || "a_sign", Some(a_sign_bit == 1), switch)?;
  let b_sign_bit = b_bits >> 63;
  let b_sign = SwitchBoardCircuit::alloc_bit(&mut cs, || "b_sign", Some(b_sign_bit == 1), switch)?;

  let ds = (a_sign_bit ^ b_sign_bit) != 0;

  let ds_flag = SwitchBoardCircuit::alloc_bit(&mut cs, || "ds", Some(ds), switch)?;

  // compute XOR of a and b sign bits
  let as_bs_bit = a_sign_bit * b_sign_bit;
  let as_bs = SwitchBoardCircuit::alloc_bit(&mut cs, || "as_bs", Some(as_bs_bit == 1), switch)?;

  // a_63 + b_63 - 2 a_63 b_63 = ds  (XOR)
  cs.enforce(
    || "a_63 + b_63 - 2 a_63 b_63 = ds",
    |lc| lc + a_sign.get_variable() + b_sign.get_variable() - (F::from(2u64), as_bs.get_variable()),
    |lc| lc + CS::one(),
    |lc| lc + ds_flag.get_variable(),
  );

  // sgt = ds (1 - gt) + (1 - ds) gt
  let sgtl = SwitchBoardCircuit::alloc_bit(&mut cs, || "sltl", Some(ds & !gt), switch)?;
  cs.enforce(
    || "sgtl = ds (1 - gt)",
    |lc| lc + ds_flag.get_variable(),
    |lc| lc + CS::one() - gt_flag.get_variable(),
    |lc| lc + sgtl.get_variable(),
  );

  let sgtr = SwitchBoardCircuit::alloc_bit(&mut cs, || "sltr", Some(!ds & gt), switch)?;
  cs.enforce(
    || "sgtr = (1 - ds) gt",
    |lc| lc + CS::one() - ds_flag.get_variable(),
    |lc| lc + gt_flag.get_variable(),
    |lc| lc + sgtr.get_variable(),
  );

  // sgt = sgtl + sgtr
  cs.enforce(
    || "sgt = sgtl + sgtr",
    |lc| lc + sgtl.get_variable() + sgtr.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + sgt_flag.get_variable(),
  );

  Ok((le_flag, gt_flag, sle_flag, sgt_flag))
}

/// Gadget for zkWASM signed div and rem
///
/// # Note
///
/// * rhs will never zero due to wasmi validation
/// * operation result will not overflow due to wasmi validation
pub fn div_rem_s_64<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: u64,
  b_bits: u64,
  switch: F,
) -> Result<(AllocatedNum<F>, AllocatedNum<F>), SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let untyped_a = UntypedValue::from(a_bits);
  let untyped_b = UntypedValue::from(b_bits);

  let untyped_quotient = untyped_a
    .i64_div_s(untyped_b)
    .unwrap_or(UntypedValue::from(0));
  let untyped_b_star_quotient = untyped_b.i64_mul(untyped_quotient);

  let untyped_rem = untyped_a
    .i64_rem_s(untyped_b)
    .unwrap_or(UntypedValue::from(0));

  let quotient = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "quotient",
    || Ok(F::from(untyped_quotient.to_bits())),
    switch,
  )?;

  let rem = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "rem",
    || Ok(F::from(untyped_rem.to_bits())),
    switch,
  )?;

  /*
   * a = b * quotient + rem
   */

  let b_star_quotient = mul64(
    cs.namespace(|| "b_star_quotient"),
    b,
    &quotient,
    b_bits,
    untyped_quotient.to_bits(),
    switch,
  )?;

  let b_star_plus_rem = add64(
    cs.namespace(|| "b_star_plus_rem"),
    &b_star_quotient,
    &rem,
    untyped_b_star_quotient.to_bits(),
    untyped_rem.to_bits(),
    switch,
  )?;

  cs.enforce(
    || "a = b * quotient + rem",
    |lc| lc + b_star_plus_rem.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + a.get_variable(),
  );

  Ok((quotient, rem))
}

/// Gadget for zkWASM unsigned div and rem
///
/// # Note
///
/// * rhs will never zero due to wasmi validation
/// * operation result will not overflow due to wasmi validation
pub fn div_rem_u_64<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: u64,
  b_bits: u64,
  switch: F,
) -> Result<(AllocatedNum<F>, AllocatedNum<F>), SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let untyped_a = UntypedValue::from(a_bits);
  let untyped_b = UntypedValue::from(b_bits);

  let untyped_quotient = untyped_a
    .i64_div_u(untyped_b)
    .unwrap_or(UntypedValue::from(0));
  let untyped_b_star_quotient = untyped_b.i64_mul(untyped_quotient);

  let untyped_rem = untyped_a
    .i64_rem_u(untyped_b)
    .unwrap_or(UntypedValue::from(0));

  let quotient = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "quotient",
    || Ok(F::from(untyped_quotient.to_bits())),
    switch,
  )?;

  let rem = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "rem",
    || Ok(F::from(untyped_rem.to_bits())),
    switch,
  )?;

  /*
   * a = b * quotient + rem
   */

  let b_star_quotient = mul64(
    cs.namespace(|| "b_star_quotient"),
    b,
    &quotient,
    b_bits,
    untyped_quotient.to_bits(),
    switch,
  )?;

  let b_star_plus_rem = add64(
    cs.namespace(|| "b_star_plus_rem"),
    &b_star_quotient,
    &rem,
    untyped_b_star_quotient.to_bits(),
    untyped_rem.to_bits(),
    switch,
  )?;

  cs.enforce(
    || "a = b * quotient + rem",
    |lc| lc + b_star_plus_rem.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + a.get_variable(),
  );

  Ok((quotient, rem))
}

/// Computes the unary ops for 64 bit integers
///
/// i64.popcnt, i64.clz, i64.ctz
pub fn unary_ops_64<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  a_bits: u64,
  switch: F,
) -> Result<(AllocatedNum<F>, AllocatedNum<F>, AllocatedNum<F>), SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  let untyped_a = UntypedValue::from(a_bits);
  let untyped_popcnt = untyped_a.i64_popcnt();
  let untyped_clz = untyped_a.i64_clz();
  let untyped_ctz = untyped_a.i64_ctz();

  let popcnt = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "popcnt",
    || Ok(F::from(untyped_popcnt.to_bits())),
    switch,
  )?;

  let clz = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "clz",
    || Ok(F::from(untyped_clz.to_bits())),
    switch,
  )?;

  let ctz = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "ctz",
    || Ok(F::from(untyped_ctz.to_bits())),
    switch,
  )?;

  popcount(cs.namespace(|| "popcount"), a, &popcnt)?;

  Ok((popcnt, clz, ctz))
}

/// popcount
#[tracing::instrument(skip_all, name = "popcount")]
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
#[tracing::instrument(skip_all, name = "popcount_equal")]
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

/// Creates a linear combination representing the popcount (sum of one bits) of `v`.
#[tracing::instrument(skip_all, name = "popcount_lc")]
pub(crate) fn popcount_lc<F: PrimeField, CS: ConstraintSystem<F>>(
  v: &[Boolean],
) -> LinearCombination<F> {
  v.iter().fold(LinearCombination::<F>::zero(), |acc, bit| {
    add_to_lc::<F, CS>(bit, acc, F::ONE)
  })
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

#[tracing::instrument(skip_all, name = "to_u64_le_bits")]
fn to_u64_le_bits<F, CS>(mut cs: CS, a: &AllocatedNum<F>) -> Result<Vec<Boolean>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let mut a_u64 = a.get_value().and_then(|a| to_u64(a)).unwrap_or(0);

  let mut bits: Vec<Boolean> = Vec::with_capacity(64);
  for i in 0..64 {
    let b = a_u64 & 1;
    let b_bool = Boolean::Is(AllocatedBit::alloc(
      cs.namespace(|| format!("b.{i}")),
      Some(b == 1),
    )?);
    bits.push(b_bool);

    a_u64 /= 2;
  }
  Ok(bits)
}

/// Attempts to convert the field element to a u64
fn to_u64<F>(a: F) -> Option<u64>
where
  F: PrimeField,
{
  for x in &a.to_repr().as_ref()[8..] {
    if *x != 0 {
      return None;
    }
  }
  let mut byte_array = [0u8; 8];
  byte_array.copy_from_slice(&a.to_repr().as_ref()[0..8]);
  Some(u64::from_le_bytes(byte_array))
}

#[tracing::instrument(skip_all, name = "u64_le_bits_to_num")]
fn u64_le_bits_to_num<F, CS>(
  mut cs: CS,
  bits: &[Boolean],
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
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

pub fn bitops_64<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<(AllocatedNum<F>, AllocatedNum<F>, AllocatedNum<F>), SynthesisError>
where
  F: PrimeField + PrimeFieldBits,
  CS: ConstraintSystem<F>,
{
  let a_bits = to_u64_le_bits(cs.namespace(|| "a_bits"), a)?;
  let b_bits = to_u64_le_bits(cs.namespace(|| "b_bits"), b)?;

  let and_bits: Vec<Boolean> = a_bits
    .iter()
    .zip(b_bits.iter())
    .enumerate()
    .map(|(i, (a, b))| Boolean::and(cs.namespace(|| format!("and of bit {}", i)), a, b))
    .collect::<Result<_, _>>()?;

  let and = u64_le_bits_to_num(cs.namespace(|| "pack and bits"), &and_bits)?;

  let xor_bits: Vec<Boolean> = a_bits
    .iter()
    .zip(b_bits.iter())
    .enumerate()
    .map(|(i, (a, b))| Boolean::xor(cs.namespace(|| format!("xor of bit {}", i)), a, b))
    .collect::<Result<_, _>>()?;

  let xor = u64_le_bits_to_num(cs.namespace(|| "pack xor bits"), &xor_bits)?;

  let or_bits: Vec<Boolean> = a_bits
    .iter()
    .zip(b_bits.iter())
    .enumerate()
    .map(|(i, (a, b))| Boolean::or(cs.namespace(|| format!("or of bit {}", i)), a, b))
    .collect::<Result<_, _>>()?;

  let or = u64_le_bits_to_num(cs.namespace(|| "pack or bits"), &or_bits)?;

  Ok((and, xor, or))
}

/// Gadget to perform bitwise shl operation.
#[tracing::instrument(skip_all, name = "shl_bits_64")]
pub fn shl_bits_64<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  bits: &[Boolean],
  shift: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
  let fill = Boolean::Is(AllocatedBit::alloc(
    cs.namespace(|| "fill bit"),
    Some(false),
  )?);

  let res_bits: Vec<Boolean> = Some(&fill)
    .into_iter()
    .cycle()
    .take(shift & 0x3F)
    .chain(bits.iter())
    .take(64)
    .cloned()
    .collect();

  Ok(res_bits)
}

/// Perform a shifts and rotates on 64 bit integers
///
/// i64.shl, i64.shr_u, i64.shr_s, i64.rotr, i64.rotl
///
/// # Returns
///
/// (shl, shr_u, shr_s, rotr, rotl)
pub fn shift_rotate_64<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  by: usize,
) -> Result<
  (
    AllocatedNum<F>,
    AllocatedNum<F>,
    AllocatedNum<F>,
    AllocatedNum<F>,
    AllocatedNum<F>,
  ),
  SynthesisError,
>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let a_bits = to_u64_le_bits(cs.namespace(|| "a_bits"), a)?;

  // shl
  let shl_bits = shl_bits_64(cs.namespace(|| "shl bits"), &a_bits, by)?;
  let shl = u64_le_bits_to_num(cs.namespace(|| "pack shl bits"), &shl_bits)?;

  // shr_u
  let fill_bit = &Boolean::Is(AllocatedBit::alloc(
    cs.namespace(|| "fill bit"),
    Some(false),
  )?);

  let shr_u_bits: Vec<Boolean> = a_bits
    .iter()
    .skip(by & 0x3F)
    .chain(Some(fill_bit).into_iter().cycle())
    .take(64)
    .cloned()
    .collect();

  let shr_u = u64_le_bits_to_num(cs.namespace(|| "pack shr_u bits"), &shr_u_bits)?;

  // shr_s
  let sign_bit = *a_bits.last().get()?;
  let shr_s_bits: Vec<Boolean> = a_bits
    .iter()
    .skip(by & 0x3F)
    .chain(Some(sign_bit).into_iter().cycle())
    .take(64)
    .cloned()
    .collect();

  let shr_s = u64_le_bits_to_num(cs.namespace(|| "pack shr_s bits"), &shr_s_bits)?;

  // rotr
  let rotr_bits: Vec<Boolean> = a_bits
    .iter()
    .skip(by & 0x3F)
    .chain(a_bits.iter())
    .take(64)
    .cloned()
    .collect();

  let rotr = u64_le_bits_to_num(cs.namespace(|| "pack rotr bits"), &rotr_bits)?;

  // rotl
  let rotl_bits: Vec<Boolean> = a_bits
    .iter()
    .skip(64 - (by & 0x3F))
    .chain(a_bits.iter())
    .take(64)
    .cloned()
    .collect();

  let rotl = u64_le_bits_to_num(cs.namespace(|| "pack rotl bits"), &rotl_bits)?;

  Ok((shl, shr_u, shr_s, rotr, rotl))
}

#[cfg(test)]
mod tests {

  use crate::{
    utils::logging::init_logger,
    v1::wasm_snark::switchboard::{alu::int64::sub64, WASMTransitionCircuit as SwitchBoardCircuit},
  };
  use bellpepper_core::{test_cs::TestConstraintSystem, ConstraintSystem};
  use nova::{provider::Bn256EngineIPA, traits::Engine};
  use rand::{rngs::StdRng, Rng, SeedableRng};
  use wasmi::core::UntypedValue;

  use super::{add64, mul64};

  type E = Bn256EngineIPA;
  type F = <E as Engine>::Scalar;

  #[test]
  fn test_div_rem_s() {
    let mut rng = StdRng::from_seed([98u8; 32]);

    let switch = F::one();

    for _ in 0..1_000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = UntypedValue::from(rng.gen::<i64>());
      let expected_quotient = a.i64_div_s(b);
      let expected_rem = a.i64_rem_s(b);

      if expected_quotient.is_err() {
        continue;
      }

      let mut cs = TestConstraintSystem::<F>::new();
      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();

      let alloc_expected_quotient = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_quotient",
        || Ok(F::from(expected_quotient.unwrap().to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_rem = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_rem",
        || Ok(F::from(expected_rem.unwrap().to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();

      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let (quotient, rem) = super::div_rem_s_64(
        cs.namespace(|| "div_rem_s"),
        &alloc_a,
        &alloc_b,
        a.to_bits(),
        b.to_bits(),
        switch,
      )
      .unwrap();

      cs.enforce(
        || "expected_quotient ==  quotient",
        |lc| lc + alloc_expected_quotient.get_variable(),
        |lc| lc + one_var,
        |lc| lc + quotient.get_variable(),
      );

      cs.enforce(
        || "expected_rem ==  rem",
        |lc| lc + alloc_expected_rem.get_variable(),
        |lc| lc + one_var,
        |lc| lc + rem.get_variable(),
      );

      assert!(cs.is_satisfied());
    }

    for _ in 0..1_000 {
      let a = UntypedValue::from(0);
      let b = UntypedValue::from(0);
      let expected_quotient = a.i64_div_s(b);
      let expected_rem = a.i64_rem_s(b);

      if expected_quotient.is_err() {
        continue;
      }

      let mut cs = TestConstraintSystem::<F>::new();
      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();

      let alloc_expected_quotient = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_quotient",
        || Ok(F::from(expected_quotient.unwrap().to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_rem = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_rem",
        || Ok(F::from(expected_rem.unwrap().to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();

      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let (quotient, rem) = super::div_rem_s_64(
        cs.namespace(|| "div_rem_s"),
        &alloc_a,
        &alloc_b,
        a.to_bits(),
        b.to_bits(),
        switch,
      )
      .unwrap();

      cs.enforce(
        || "expected_quotient ==  quotient",
        |lc| lc + alloc_expected_quotient.get_variable(),
        |lc| lc + one_var,
        |lc| lc + quotient.get_variable(),
      );

      cs.enforce(
        || "expected_rem ==  rem",
        |lc| lc + alloc_expected_rem.get_variable(),
        |lc| lc + one_var,
        |lc| lc + rem.get_variable(),
      );

      assert!(cs.is_satisfied());
    }
  }

  #[test]
  fn test_div_rem_u() {
    let mut rng = StdRng::from_seed([90u8; 32]);

    let switch = F::one();

    for _ in 0..1_000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = UntypedValue::from(rng.gen::<i64>());
      let expected_quotient = a.i64_div_u(b);
      let expected_rem = a.i64_rem_u(b);

      if expected_quotient.is_err() {
        continue;
      }

      let mut cs = TestConstraintSystem::<F>::new();
      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();

      let alloc_expected_quotient = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_quotient",
        || Ok(F::from(expected_quotient.unwrap().to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_rem = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_rem",
        || Ok(F::from(expected_rem.unwrap().to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();

      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let (quotient, rem) = super::div_rem_u_64(
        cs.namespace(|| "div_rem_u"),
        &alloc_a,
        &alloc_b,
        a.to_bits(),
        b.to_bits(),
        switch,
      )
      .unwrap();

      cs.enforce(
        || "expected_quotient ==  quotient",
        |lc| lc + alloc_expected_quotient.get_variable(),
        |lc| lc + one_var,
        |lc| lc + quotient.get_variable(),
      );

      cs.enforce(
        || "expected_rem ==  rem",
        |lc| lc + alloc_expected_rem.get_variable(),
        |lc| lc + one_var,
        |lc| lc + rem.get_variable(),
      );

      assert!(cs.is_satisfied());
    }

    for _ in 0..1_000 {
      let a = UntypedValue::from(0);
      let b = UntypedValue::from(0);
      let expected_quotient = a.i64_div_u(b);
      let expected_rem = a.i64_rem_u(b);

      if expected_quotient.is_err() {
        continue;
      }

      let mut cs = TestConstraintSystem::<F>::new();
      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();

      let alloc_expected_quotient = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_quotient",
        || Ok(F::from(expected_quotient.unwrap().to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_rem = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_rem",
        || Ok(F::from(expected_rem.unwrap().to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();

      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let (quotient, rem) = super::div_rem_u_64(
        cs.namespace(|| "div_rem_s"),
        &alloc_a,
        &alloc_b,
        a.to_bits(),
        b.to_bits(),
        switch,
      )
      .unwrap();

      cs.enforce(
        || "expected_quotient ==  quotient",
        |lc| lc + alloc_expected_quotient.get_variable(),
        |lc| lc + one_var,
        |lc| lc + quotient.get_variable(),
      );

      cs.enforce(
        || "expected_rem ==  rem",
        |lc| lc + alloc_expected_rem.get_variable(),
        |lc| lc + one_var,
        |lc| lc + rem.get_variable(),
      );

      assert!(cs.is_satisfied());
    }
  }

  #[test]
  fn test_div_rem_s_edge_case() {
    let switch = F::one();
    let a = UntypedValue::from(0);
    let b = UntypedValue::from(0);

    let mut cs = TestConstraintSystem::<F>::new();

    let alloc_a =
      SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch).unwrap();

    let alloc_b =
      SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch).unwrap();

    let _ = super::div_rem_s_64(
      cs.namespace(|| "div_rem_s"),
      &alloc_a,
      &alloc_b,
      a.to_bits(),
      b.to_bits(),
      switch,
    )
    .unwrap();

    assert!(cs.is_satisfied());
  }

  #[test]
  fn test_add64() {
    let mut rng = StdRng::from_seed([99u8; 32]);

    let switch = F::one();

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = UntypedValue::from(rng.gen::<i64>());
      let expected = a.i64_add(b);

      let mut cs = TestConstraintSystem::<F>::new();

      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
      let alloc_expected = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected",
        || Ok(F::from(expected.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();
      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let c = add64(
        cs.namespace(|| "add64"),
        &alloc_a,
        &alloc_b,
        a.to_bits(),
        b.to_bits(),
        switch,
      )
      .unwrap();

      cs.enforce(
        || "expected ==  c",
        |lc| lc + alloc_expected.get_variable(),
        |lc| lc + one_var,
        |lc| lc + c.get_variable(),
      );

      assert!(cs.is_satisfied());
    }
  }

  #[test]
  fn test_mul64() {
    let mut rng = StdRng::from_seed([100u8; 32]);

    let switch = F::one();

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = UntypedValue::from(rng.gen::<i64>());
      let expected = a.i64_mul(b);

      let mut cs = TestConstraintSystem::<F>::new();

      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
      let alloc_expected = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected",
        || Ok(F::from(expected.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();
      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let c = mul64(
        cs.namespace(|| "mul64"),
        &alloc_a,
        &alloc_b,
        a.to_bits(),
        b.to_bits(),
        switch,
      )
      .unwrap();

      cs.enforce(
        || "expected ==  c",
        |lc| lc + alloc_expected.get_variable(),
        |lc| lc + one_var,
        |lc| lc + c.get_variable(),
      );

      assert!(cs.is_satisfied());
    }

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i8>());
      let b = UntypedValue::from(rng.gen::<i8>());
      let expected = a.i64_mul(b);

      let mut cs = TestConstraintSystem::<F>::new();

      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
      let alloc_expected = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected",
        || Ok(F::from(expected.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();
      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let c = mul64(
        cs.namespace(|| "mul64"),
        &alloc_a,
        &alloc_b,
        a.to_bits(),
        b.to_bits(),
        switch,
      )
      .unwrap();

      cs.enforce(
        || "expected ==  c",
        |lc| lc + alloc_expected.get_variable(),
        |lc| lc + one_var,
        |lc| lc + c.get_variable(),
      );

      assert!(cs.is_satisfied());
    }
  }

  #[test]
  fn test_sub64() {
    let mut rng = StdRng::from_seed([101u8; 32]);

    let switch = F::one();

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i8>());
      let b = UntypedValue::from(rng.gen::<i8>());
      let expected = a.i64_sub(b);

      let mut cs = TestConstraintSystem::<F>::new();

      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
      let alloc_expected = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected",
        || Ok(F::from(expected.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();
      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let c = sub64(
        cs.namespace(|| "add64"),
        &alloc_a,
        &alloc_b,
        a.to_bits(),
        b.to_bits(),
        switch,
      )
      .unwrap();

      cs.enforce(
        || "expected ==  c",
        |lc| lc + alloc_expected.get_variable(),
        |lc| lc + one_var,
        |lc| lc + c.get_variable(),
      );

      assert!(cs.is_satisfied());
    }

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = UntypedValue::from(rng.gen::<i64>());
      let expected = a.i64_sub(b);

      let mut cs = TestConstraintSystem::<F>::new();

      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
      let alloc_expected = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected",
        || Ok(F::from(expected.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();
      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let c = sub64(
        cs.namespace(|| "add64"),
        &alloc_a,
        &alloc_b,
        a.to_bits(),
        b.to_bits(),
        switch,
      )
      .unwrap();

      cs.enforce(
        || "expected ==  c",
        |lc| lc + alloc_expected.get_variable(),
        |lc| lc + one_var,
        |lc| lc + c.get_variable(),
      );

      assert!(cs.is_satisfied());
    }
  }

  #[test]
  fn test_lt_and_ge() {
    let instr = [
      wasmi::Instruction::I64LtU,
      wasmi::Instruction::I64GeU,
      wasmi::Instruction::I64LtS,
      wasmi::Instruction::I64GeS,
    ];
    let mut rng = StdRng::from_seed([102u8; 32]);

    let switch = F::one();

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = UntypedValue::from(rng.gen::<i64>());

      for instr in instr.iter() {
        let expected = match instr {
          wasmi::Instruction::I64LtU => a.i64_lt_u(b),
          wasmi::Instruction::I64GeU => a.i64_ge_u(b),
          wasmi::Instruction::I64LtS => a.i64_lt_s(b),
          wasmi::Instruction::I64GeS => a.i64_ge_s(b),
          _ => panic!("Invalid instruction"),
        };

        let mut cs = TestConstraintSystem::<F>::new();
        let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
        let alloc_expected = SwitchBoardCircuit::alloc_num(
          &mut cs,
          || "expected",
          || Ok(F::from(expected.to_bits())),
          switch,
        )
        .unwrap();

        let alloc_a =
          SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
            .unwrap();
        let alloc_b =
          SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
            .unwrap();

        let (lt, ge, slt, sge) = super::lt_ge_s(
          cs.namespace(|| "lt_and_ge"),
          &alloc_a,
          &alloc_b,
          a.to_bits(),
          b.to_bits(),
          switch,
        )
        .unwrap();

        let res = match instr {
          wasmi::Instruction::I64LtU => lt,
          wasmi::Instruction::I64GeU => ge,
          wasmi::Instruction::I64LtS => slt,
          wasmi::Instruction::I64GeS => sge,
          _ => panic!("Invalid instruction"),
        };

        cs.enforce(
          || "expected ==  res",
          |lc| lc + alloc_expected.get_variable(),
          |lc| lc + one_var,
          |lc| lc + res.get_variable(),
        );
        assert!(cs.is_satisfied());
      }
    }
  }

  #[test]
  fn test_le_and_gt() {
    let instr = [
      wasmi::Instruction::I64GtU,
      wasmi::Instruction::I64LeU,
      wasmi::Instruction::I64GtS,
      wasmi::Instruction::I64LeS,
    ];
    let mut rng = StdRng::from_seed([103u8; 32]);

    let switch = F::one();

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = UntypedValue::from(rng.gen::<i64>());

      for instr in instr.iter() {
        let expected = match instr {
          wasmi::Instruction::I64GtU => a.i64_gt_u(b),
          wasmi::Instruction::I64LeU => a.i64_le_u(b),
          wasmi::Instruction::I64GtS => a.i64_gt_s(b),
          wasmi::Instruction::I64LeS => a.i64_le_s(b),
          _ => panic!("Invalid instruction"),
        };

        let mut cs = TestConstraintSystem::<F>::new();
        let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
        let alloc_expected = SwitchBoardCircuit::alloc_num(
          &mut cs,
          || "expected",
          || Ok(F::from(expected.to_bits())),
          switch,
        )
        .unwrap();

        let alloc_a =
          SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
            .unwrap();
        let alloc_b =
          SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
            .unwrap();

        let (le, gt, sle, sgt) = super::le_gt_s(
          cs.namespace(|| "le_and_gt"),
          &alloc_a,
          &alloc_b,
          a.to_bits(),
          b.to_bits(),
          switch,
        )
        .unwrap();

        let res = match instr {
          wasmi::Instruction::I64GtU => gt,
          wasmi::Instruction::I64LeU => le,
          wasmi::Instruction::I64GtS => sgt,
          wasmi::Instruction::I64LeS => sle,
          _ => panic!("Invalid instruction"),
        };

        cs.enforce(
          || "expected ==  res",
          |lc| lc + alloc_expected.get_variable(),
          |lc| lc + one_var,
          |lc| lc + res.get_variable(),
        );
        assert!(cs.is_satisfied());
      }
    }
  }

  #[test]
  fn test_unary_ops() {
    let instr = [
      wasmi::Instruction::I64Popcnt,
      wasmi::Instruction::I64Ctz,
      wasmi::Instruction::I64Clz,
    ];

    let mut rng = StdRng::from_seed([104u8; 32]);

    let switch = F::one();

    for _ in 0..1_000 {
      let a = UntypedValue::from(rng.gen::<i64>());

      for instr in instr.iter() {
        let expected = match instr {
          wasmi::Instruction::I64Popcnt => a.i64_popcnt(),
          wasmi::Instruction::I64Ctz => a.i64_ctz(),
          wasmi::Instruction::I64Clz => a.i64_clz(),
          _ => panic!("Invalid instruction"),
        };

        let mut cs = TestConstraintSystem::<F>::new();
        let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
        let alloc_expected = SwitchBoardCircuit::alloc_num(
          &mut cs,
          || "expected",
          || Ok(F::from(expected.to_bits())),
          switch,
        )
        .unwrap();

        let alloc_a =
          SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
            .unwrap();

        let (popcnt, clz, ctz) = tracing_texray::examine(tracing::info_span!("cs popcount"))
          .in_scope(|| {
            super::unary_ops_64(cs.namespace(|| "unary_ops"), &alloc_a, a.to_bits(), switch)
              .unwrap()
          });

        let res = match instr {
          wasmi::Instruction::I64Popcnt => popcnt,
          wasmi::Instruction::I64Ctz => ctz,
          wasmi::Instruction::I64Clz => clz,
          _ => panic!("Invalid instruction"),
        };

        cs.enforce(
          || "expected ==  res",
          |lc| lc + alloc_expected.get_variable(),
          |lc| lc + one_var,
          |lc| lc + res.get_variable(),
        );
        assert!(cs.is_satisfied());
      }
    }
  }

  #[test]
  fn test_bitops() {
    init_logger();
    let mut rng = StdRng::from_seed([112u8; 32]);
    let switch = F::one();

    for _ in 0..1_000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = UntypedValue::from(rng.gen::<i64>());

      let expected_and = a.i64_and(b);
      let expected_or = a.i64_or(b);
      let expected_xor = a.i64_xor(b);

      let mut cs = TestConstraintSystem::<F>::new();
      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();

      let alloc_expected_and = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_and",
        || Ok(F::from(expected_and.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_or = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_or",
        || Ok(F::from(expected_or.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_xor = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_xor",
        || Ok(F::from(expected_xor.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();
      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let (and, xor, or) = tracing_texray::examine(tracing::info_span!("bitops"))
        .in_scope(|| super::bitops_64(cs.namespace(|| "bitops"), &alloc_a, &alloc_b).unwrap());

      cs.enforce(
        || "expected_and ==  and",
        |lc| lc + alloc_expected_and.get_variable(),
        |lc| lc + one_var,
        |lc| lc + and.get_variable(),
      );

      cs.enforce(
        || "expected_or ==  or",
        |lc| lc + alloc_expected_or.get_variable(),
        |lc| lc + one_var,
        |lc| lc + or.get_variable(),
      );

      cs.enforce(
        || "expected_xor ==  xor",
        |lc| lc + alloc_expected_xor.get_variable(),
        |lc| lc + one_var,
        |lc| lc + xor.get_variable(),
      );

      assert!(cs.is_satisfied());
    }
  }

  #[test]
  fn test_shift_rotate() {
    init_logger();
    let mut rng = StdRng::from_seed([113u8; 32]);
    let switch = F::one();

    for _ in 0..1_000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let by = UntypedValue::from(rng.gen::<u32>());

      let expected_shl = a.i64_shl(by);
      let expected_shr_u = a.i64_shr_u(by);
      let expected_shr_s = a.i64_shr_s(by);
      let expected_rotr = a.i64_rotr(by);
      let expected_rotl = a.i64_rotl(by);

      let mut cs = TestConstraintSystem::<F>::new();
      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();

      let alloc_expected_shl = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_shl",
        || Ok(F::from(expected_shl.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_shr_u = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_shr_u",
        || Ok(F::from(expected_shr_u.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_shr_s = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_shr_s",
        || Ok(F::from(expected_shr_s.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_rotr = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_rotr",
        || Ok(F::from(expected_rotr.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_expected_rotl = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected_rotl",
        || Ok(F::from(expected_rotl.to_bits())),
        switch,
      )
      .unwrap();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();

      let (shl, shr_u, shr_s, rotr, rotl) =
        tracing_texray::examine(tracing::info_span!("shift_rotate")).in_scope(|| {
          super::shift_rotate_64(
            cs.namespace(|| "shift_rotate"),
            &alloc_a,
            by.to_bits() as usize,
          )
          .unwrap()
        });

      cs.enforce(
        || "expected_shl ==  shl",
        |lc| lc + alloc_expected_shl.get_variable(),
        |lc| lc + one_var,
        |lc| lc + shl.get_variable(),
      );

      cs.enforce(
        || "expected_shr_u ==  shr_u",
        |lc| lc + alloc_expected_shr_u.get_variable(),
        |lc| lc + one_var,
        |lc| lc + shr_u.get_variable(),
      );

      cs.enforce(
        || "expected_shr_s ==  shr_s",
        |lc| lc + alloc_expected_shr_s.get_variable(),
        |lc| lc + one_var,
        |lc| lc + shr_s.get_variable(),
      );

      cs.enforce(
        || "expected_rotr ==  rotr",
        |lc| lc + alloc_expected_rotr.get_variable(),
        |lc| lc + one_var,
        |lc| lc + rotr.get_variable(),
      );

      cs.enforce(
        || "expected_rotl ==  rotl",
        |lc| lc + alloc_expected_rotl.get_variable(),
        |lc| lc + one_var,
        |lc| lc + rotl.get_variable(),
      );

      assert!(cs.is_satisfied());
    }
  }
}
