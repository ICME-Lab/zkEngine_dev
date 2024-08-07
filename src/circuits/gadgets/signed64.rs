//! This module provides a gadget for signed 64-bit integers.
use super::bits::{ge_u_bits, get_twos_complement, shl_bits, sub_bits};
use crate::circuits::supernova::helpers::conditionally_select;
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};

/// A signed 64-bit integer gadget.
pub struct Int64<F: PrimeField + PrimeFieldBits + PartialOrd> {
  /// The allocated number representing the integer
  pub alloc_num: AllocatedNum<F>,
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> Int64<F> {
  /// Allocate a `Int64` in the constraint system
  pub fn alloc<CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: Option<u64>,
  ) -> Result<Self, SynthesisError> {
    let alloc_num =
      AllocatedNum::alloc(cs.namespace(|| "alloc_num"), || Ok(F::from(value.unwrap())))?;
    Ok(Self { alloc_num })
  }

  /// Convert the `Int64` into bits in the constraint system
  pub fn convert_to_bits<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
  ) -> Result<Vec<Boolean>, SynthesisError> {
    let res = self
      .alloc_num
      .to_bits_le(cs.namespace(|| "alloc num bits"))?
      .into_iter()
      .take(64)
      .collect();
    Ok(res)
  }

  #[allow(dead_code)]
  /// Get the 64-bit value of the `Int64`
  pub fn get_64_bit_value(&self) -> Option<u64> {
    let element = self.alloc_num.get_value()?;
    let mut byte_array = [0u8; 8];
    byte_array.copy_from_slice(&element.to_repr().as_ref()[0..8]);
    Some(u64::from_le_bytes(byte_array))
  }

  /// Conditionally select between two `Int64` values
  pub fn conditionally_select<CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &Self,
    b: &Self,
    condition: Boolean,
  ) -> Result<Self, SynthesisError> {
    let res = conditionally_select(
      cs.namespace(|| "conditionally_select"),
      &a.alloc_num,
      &b.alloc_num,
      &condition,
    )?;
    Ok(Self { alloc_num: res })
  }

  /// Converts a little-endian byte order representation of bits into a
  /// `UInt64`.
  pub fn from_bits<CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits: &[Boolean],
  ) -> Result<Self, SynthesisError> {
    assert_eq!(bits.len(), 64);

    let new_bits = bits.to_vec();

    let mut value = Some(0u64);
    for b in new_bits.iter().rev() {
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

    let alloc_num =
      AllocatedNum::alloc(cs.namespace(|| "alloc num"), || Ok(F::from(value.unwrap())))?;

    Ok(Self { alloc_num })
  }

  /// Perform division of two `Int64` values
  pub fn div<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    is_neg: Boolean,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    // N / D pseudocode:
    //
    // if D = 0 then error(DivisionByZeroException) end
    //
    // positive = msb(N) == msb(D) -- if msb's equal, return positive result
    //
    // Q := 0                  -- Initialize quotient and remainder to zero
    // R := 0
    //
    // for i := n − 1 .. 0 do  -- Where n is number of bits in N
    //   R := R << 1           -- Left-shift R by 1 bit
    //   R(0) := N(i)          -- Set the least-significant bit of R equal to bit i of the numerator
    //   if R ≥ D then
    //     R := R − D
    //     Q(i) := 1
    //   end
    // end
    //
    // if positive then           -- positive result
    //    Q
    // else
    //    !Q                      -- negative result
    let dividend = self.convert_to_bits(cs.namespace(|| "dividend bits"))?;
    let divisor = other.convert_to_bits(cs.namespace(|| "divisor bits"))?;

    let mut quotient = Int64::alloc(cs.namespace(|| "quotient"), Some(0))?
      .convert_to_bits(cs.namespace(|| "quotient bits"))?;
    let mut remainder = Int64::alloc(cs.namespace(|| "remainder"), Some(0))?
      .convert_to_bits(cs.namespace(|| "remainder bits"))?;

    let true_bit = Boolean::Is(AllocatedBit::alloc(
      cs.namespace(|| "true bit"),
      Some(true),
    )?);

    for i in (0..64).rev() {
      let zero_bits = Int64::alloc(cs.namespace(|| format!("zero on iter {}", i)), Some(0))?
        .convert_to_bits(cs.namespace(|| format!("zero bits on iter {}", i)))?;
      remainder = shl_bits(
        cs.namespace(|| format!("rem << 1 on iter {}", i)),
        &remainder,
        1,
      )?;
      remainder[0] = dividend[i].clone();
      let remainder_sub_divisor_bits = sub_bits(
        cs.namespace(|| format!("remainder - divisor, {}", i)),
        &remainder,
        &divisor,
      )?;
      let remainder_sub_zero_bits = sub_bits(
        cs.namespace(|| format!("remainder - divisor (zero) iter: {}", i)),
        &remainder,
        &zero_bits,
      )?;

      let condition = ge_u_bits(
        cs.namespace(|| format!("ge_u on iter {}", i)),
        &remainder,
        &divisor,
      )?;

      let remainder_sub_divisor = Int64::from_bits(
        cs.namespace(|| format!("remainder sub divisor on iter {}", i)),
        &remainder_sub_divisor_bits,
      )?;

      let remainder_sub_zero = Int64::from_bits(
        cs.namespace(|| format!("remainder sub zero on iter {}", i)),
        &remainder_sub_zero_bits,
      )?;

      let remainder_num = Int64::conditionally_select(
        cs.namespace(|| format!("select remainder on iter {}", i)),
        &remainder_sub_divisor,
        &remainder_sub_zero,
        condition.clone(),
      )?;

      remainder =
        remainder_num.convert_to_bits(cs.namespace(|| format!("remainder on iter {}", i)))?;
      if *condition.get_value().get()? {
        quotient[i] = true_bit.clone();
      }
    }
    let remainder = Int64::from_bits(cs.namespace(|| "res remainder"), &remainder)?;

    let neg_quotient_bits = get_twos_complement(cs.namespace(|| "neg quotient bits"), &quotient)?;
    let neg_quotient = Int64::from_bits(cs.namespace(|| "neg quotient"), &neg_quotient_bits)?;

    let quotient_num = Int64::from_bits(cs.namespace(|| "quotient_num"), &quotient)?;

    cs.enforce(
      || "N - R = Q * D",
      |lc| lc + other.alloc_num.get_variable(),
      |lc| lc + quotient_num.alloc_num.get_variable(),
      |lc| lc + self.alloc_num.get_variable() - remainder.alloc_num.get_variable(),
    );

    let res = Int64::conditionally_select(
      cs.namespace(|| "select quotient"),
      &neg_quotient,
      &quotient_num,
      is_neg,
    )?;

    Ok(res)
  }

  /// Performs rem operation of two `Int64` values
  pub fn rem<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    is_neg: Boolean,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    // N / D pseudocode:
    //
    // if D = 0 then error(DivisionByZeroException) end
    //
    // positive = msb(N) == msb(D) -- if msb's equal, return positive result
    //
    // Q := 0                  -- Initialize quotient and remainder to zero
    // R := 0
    //
    // for i := n − 1 .. 0 do  -- Where n is number of bits in N
    //   R := R << 1           -- Left-shift R by 1 bit
    //   R(0) := N(i)          -- Set the least-significant bit of R equal to bit i of the numerator
    //   if R ≥ D then
    //     R := R − D
    //     Q(i) := 1
    //   end
    // end
    //
    // if positive then           -- positive result
    //    Q
    // else
    //    !Q                      -- negative result
    let dividend = self.convert_to_bits(cs.namespace(|| "dividend bits"))?;
    let divisor = other.convert_to_bits(cs.namespace(|| "divisor bits"))?;

    let mut quotient = Int64::alloc(cs.namespace(|| "quotient"), Some(0))?
      .convert_to_bits(cs.namespace(|| "quotient bits"))?;
    let mut remainder = Int64::alloc(cs.namespace(|| "remainder"), Some(0))?
      .convert_to_bits(cs.namespace(|| "remainder bits"))?;

    let true_bit = Boolean::Is(AllocatedBit::alloc(
      cs.namespace(|| "true bit"),
      Some(true),
    )?);

    for i in (0..64).rev() {
      let zero_bits = Int64::alloc(cs.namespace(|| format!("zero on iter {}", i)), Some(0))?
        .convert_to_bits(cs.namespace(|| format!("zero bits on iter {}", i)))?;
      remainder = shl_bits(
        cs.namespace(|| format!("rem << 1 on iter {}", i)),
        &remainder,
        1,
      )?;
      remainder[0] = dividend[i].clone();
      let remainder_sub_divisor_bits = sub_bits(
        cs.namespace(|| format!("remainder - divisor, {}", i)),
        &remainder,
        &divisor,
      )?;
      let remainder_sub_zero_bits = sub_bits(
        cs.namespace(|| format!("remainder - divisor (zero) iter: {}", i)),
        &remainder,
        &zero_bits,
      )?;

      let condition = ge_u_bits(
        cs.namespace(|| format!("ge_u on iter {}", i)),
        &remainder,
        &divisor,
      )?;

      let remainder_sub_divisor = Int64::from_bits(
        cs.namespace(|| format!("remainder sub divisor on iter {}", i)),
        &remainder_sub_divisor_bits,
      )?;

      let remainder_sub_zero = Int64::from_bits(
        cs.namespace(|| format!("remainder sub zero on iter {}", i)),
        &remainder_sub_zero_bits,
      )?;

      let remainder_num = Int64::conditionally_select(
        cs.namespace(|| format!("select remainder on iter {}", i)),
        &remainder_sub_divisor,
        &remainder_sub_zero,
        condition.clone(),
      )?;

      remainder =
        remainder_num.convert_to_bits(cs.namespace(|| format!("remainder on iter {}", i)))?;
      if *condition.get_value().get()? {
        quotient[i] = true_bit.clone();
      }
    }

    let quotient = Int64::from_bits(cs.namespace(|| "res quotient"), &quotient)?;
    let neg_remainder_bits =
      get_twos_complement(cs.namespace(|| "neg remainder bits"), &remainder)?;
    let neg_remainder = Int64::from_bits(cs.namespace(|| "neg remainder"), &neg_remainder_bits)?;

    let remainder_num = Int64::from_bits(cs.namespace(|| "remainder_num"), &remainder)?;

    cs.enforce(
      || "N - R = Q * D",
      |lc| lc + other.alloc_num.get_variable(),
      |lc| lc + quotient.alloc_num.get_variable(),
      |lc| lc + self.alloc_num.get_variable() - remainder_num.alloc_num.get_variable(),
    );

    let res = Int64::conditionally_select(
      cs.namespace(|| "select remainder"),
      &neg_remainder,
      &remainder_num,
      is_neg,
    )?;

    Ok(res)
  }

  /// Performs a less than comparison of two `Int64` values
  pub fn lt<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.convert_to_bits(cs.namespace(|| "a bits"))?;
    let b = &other.convert_to_bits(cs.namespace(|| "b bits"))?;

    let a_sign = a.last().unwrap().get_value().unwrap_or(false);
    let b_sign = b.last().unwrap().get_value().unwrap_or(false);

    if a_sign && !b_sign {
      return Int64::alloc(cs.namespace(|| "lt res"), Some(1));
    }
    if !a_sign && b_sign {
      return Int64::alloc(cs.namespace(|| "lt res"), Some(0));
    }

    for (a, b) in a.iter().zip(b.iter()).rev().skip(1) {
      let a = a.get_value().unwrap_or(false);
      let b = b.get_value().unwrap_or(false);
      if a && !b {
        return Int64::alloc(cs.namespace(|| "lt res"), Some(0));
      }
      if !a && b {
        return Int64::alloc(cs.namespace(|| "lt res"), Some(1));
      }
    }

    Int64::alloc(cs.namespace(|| "lt res"), Some(0))
  }

  /// Performs a greater than comparison of two `Int64` values
  pub fn gt<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.convert_to_bits(cs.namespace(|| "a bits"))?;
    let b = &other.convert_to_bits(cs.namespace(|| "b bits"))?;

    let a_sign = a.last().unwrap().get_value().unwrap_or(false);
    let b_sign = b.last().unwrap().get_value().unwrap_or(false);

    if a_sign && !b_sign {
      return Int64::alloc(cs.namespace(|| "ge res"), Some(0));
    }
    if !a_sign && b_sign {
      return Int64::alloc(cs.namespace(|| "ge res"), Some(1));
    }

    for (a, b) in a.iter().zip(b.iter()).rev().skip(1) {
      let a = a.get_value().unwrap_or(false);
      let b = b.get_value().unwrap_or(false);
      if a && !b {
        return Int64::alloc(cs.namespace(|| "ge res"), Some(1));
      }
      if !a && b {
        return Int64::alloc(cs.namespace(|| "ge res"), Some(0));
      }
    }

    Int64::alloc(cs.namespace(|| "ge res"), Some(0))
  }

  /// Performs a less than or equal to comparison of two `Int64` values
  pub fn le<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.convert_to_bits(cs.namespace(|| "a bits"))?;
    let b = &other.convert_to_bits(cs.namespace(|| "b bits"))?;

    let a_sign = a.last().unwrap().get_value().unwrap_or(false);
    let b_sign = b.last().unwrap().get_value().unwrap_or(false);

    if a_sign && !b_sign {
      return Int64::alloc(cs.namespace(|| "ge res"), Some(1));
    }
    if !a_sign && b_sign {
      return Int64::alloc(cs.namespace(|| "ge res"), Some(0));
    }

    for (a, b) in a.iter().zip(b.iter()).rev().skip(1) {
      let a = a.get_value().unwrap_or(false);
      let b = b.get_value().unwrap_or(false);
      if a && !b {
        return Int64::alloc(cs.namespace(|| "ge res"), Some(0));
      }
      if !a && b {
        return Int64::alloc(cs.namespace(|| "ge res"), Some(1));
      }
    }

    Int64::alloc(cs.namespace(|| "ge res"), Some(1))
  }

  /// Performs a greater than or equal to comparison of two `Int64` values
  pub fn ge<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.convert_to_bits(cs.namespace(|| "a bits"))?;
    let b = &other.convert_to_bits(cs.namespace(|| "b bits"))?;

    let a_sign = a.last().unwrap().get_value().unwrap_or(false);
    let b_sign = b.last().unwrap().get_value().unwrap_or(false);

    if a_sign && !b_sign {
      return Int64::alloc(cs.namespace(|| "ge res"), Some(0));
    }
    if !a_sign && b_sign {
      return Int64::alloc(cs.namespace(|| "ge res"), Some(1));
    }

    for (a, b) in a.iter().zip(b.iter()).rev().skip(1) {
      let a = a.get_value().unwrap_or(false);
      let b = b.get_value().unwrap_or(false);
      if a && !b {
        return Int64::alloc(cs.namespace(|| "ge res"), Some(1));
      }
      if !a && b {
        return Int64::alloc(cs.namespace(|| "ge res"), Some(0));
      }
    }

    Int64::alloc(cs.namespace(|| "ge res"), Some(1))
  }

  /// Perform a bitwise shift right operation on the `Int64`
  pub fn shr<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    by: usize,
  ) -> Result<Self, SynthesisError> {
    let bits = self.convert_to_bits(cs.namespace(|| "a bits"))?;

    // get the sign bit
    let sign_bit = *bits.last().get()?;

    let res_bits: Vec<Boolean> = bits
      .iter()
      .skip(by)
      .chain(Some(sign_bit).into_iter().cycle())
      .take(64)
      .cloned()
      .collect();

    let res = Int64::from_bits(cs.namespace(|| "res"), &res_bits)?;
    Ok(res)
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use halo2curves::bn256::Fr;
  use rand::{Rng, SeedableRng};
  use rand_xorshift::XorShiftRng;

  #[ignore]
  #[test]
  fn test_div() {
    let mut rng = XorShiftRng::seed_from_u64(42);
    for _ in 0..50 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();

      if b == 0 {
        continue;
      }
      let expected = a / b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let is_neg = Boolean::from(
        AllocatedBit::alloc(cs.namespace(|| "is neg"), Some((a < 0) ^ (b < 0))).unwrap(),
      );

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a.unsigned_abs())).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b.unsigned_abs())).unwrap();

      let res = a.div(cs.namespace(|| "div"), is_neg, &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
      assert!(cs.is_satisfied());
    }
  }

  #[ignore]
  #[test]
  fn test_div_32_bits() {
    let mut rng = XorShiftRng::seed_from_u64(42);
    for _ in 0..50 {
      let a = rng.gen::<i32>();
      let b = rng.gen::<i32>();

      if b == 0 {
        continue;
      }
      let expected = a / b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let is_neg = Boolean::from(
        AllocatedBit::alloc(cs.namespace(|| "is neg"), Some((a < 0) ^ (b < 0))).unwrap(),
      );

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a.unsigned_abs() as u64)).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b.unsigned_abs() as u64)).unwrap();

      let res = a.div(cs.namespace(|| "div"), is_neg, &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i32;
      assert_eq!(expected, res);
      assert!(cs.is_satisfied());
    }
  }

  #[ignore]
  #[test]
  fn test_rem() {
    let mut rng = XorShiftRng::seed_from_u64(42);
    for _ in 0..50 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();

      if b == 0 {
        continue;
      }
      let expected = a % b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let is_neg =
        Boolean::from(AllocatedBit::alloc(cs.namespace(|| "is neg"), Some(a < 0)).unwrap());

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a.unsigned_abs())).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b.unsigned_abs())).unwrap();

      let res = a.rem(cs.namespace(|| "rem"), is_neg, &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
      assert!(cs.is_satisfied());
    }
  }

  #[ignore]
  #[test]
  fn test_rem_32_bits() {
    let mut rng = XorShiftRng::seed_from_u64(42);
    for _ in 0..50 {
      let a = rng.gen::<i32>();
      let b = rng.gen::<i32>();

      if b == 0 {
        continue;
      }
      let expected = a % b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let is_neg =
        Boolean::from(AllocatedBit::alloc(cs.namespace(|| "is neg"), Some(a < 0)).unwrap());

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a.unsigned_abs() as u64)).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b.unsigned_abs() as u64)).unwrap();

      let res = a.rem(cs.namespace(|| "rem"), is_neg, &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i32;
      assert_eq!(expected, res);
      assert!(cs.is_satisfied());
    }
  }

  #[test]
  fn test_shr() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<usize>() % 64;
      let expected = a >> b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.shr(cs.namespace(|| "shr"), b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_shr_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i32>();
      let b = rng.gen::<usize>() % 32;
      let expected = a >> b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.shr(cs.namespace(|| "shr"), b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i32;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_ge() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();
      let expected = a >= b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.ge(cs.namespace(|| "ge"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() == 1;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_ge_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i32>();
      let b = rng.gen::<i32>();

      let expected = a >= b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.ge(cs.namespace(|| "ge"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() == 1;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_gt() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();

      let expected = a > b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.gt(cs.namespace(|| "gt"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() == 1;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_gt_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i32>();
      let b = rng.gen::<i32>();
      let expected = a > b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.gt(cs.namespace(|| "gt"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() == 1;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_lt() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x56, 0x3d, 0x31, 0x8d, 0x47, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();

      let expected = a < b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.lt(cs.namespace(|| "gt"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() == 1;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_le() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x56, 0x3d, 0x31, 0x8d, 0x47, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();

      let expected = a <= b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = Int64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = Int64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.le(cs.namespace(|| "gt"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() == 1;
      assert_eq!(expected, res);
    }
  }
}
