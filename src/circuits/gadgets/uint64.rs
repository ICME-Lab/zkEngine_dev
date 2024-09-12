//! This module provides a gadget for unsigned 64-bit integers.

use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};

use crate::circuits::supernova::helpers::{conditionally_select, fits_in_bits};

use super::bits::{ge_u_bits, shl_bits, sub_bits};

/// A 64-bit unsigned integer gadget.
pub struct UInt64<F: PrimeField + PrimeFieldBits + PartialOrd> {
  /// The allocated number in the constraint system representing the integer
  pub alloc_num: AllocatedNum<F>,
}

impl<F: PrimeField + PrimeFieldBits + PartialOrd> UInt64<F> {
  /// Allocate a `UInt64` in the constraint system
  pub fn alloc<CS: ConstraintSystem<F>>(
    mut cs: CS,
    value: Option<u64>,
  ) -> Result<Self, SynthesisError> {
    let alloc_num =
      AllocatedNum::alloc(cs.namespace(|| "alloc_num"), || Ok(F::from(value.unwrap())))?;
    Ok(Self { alloc_num })
  }

  #[allow(dead_code)]
  /// Get the 64-bit value of the `UInt64` value
  pub fn get_64_bit_value(&self) -> Option<u64> {
    let element = self.alloc_num.get_value()?;
    let mut byte_array = [0u8; 8];
    byte_array.copy_from_slice(&element.to_repr().as_ref()[0..8]);
    Some(u64::from_le_bytes(byte_array))
  }

  /// Convert the `UInt64` into bits in the constraint system
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

  /// Conditionally select between two `UInt64` values
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

  /// Performs addition of two `UInt64` values
  pub fn add<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.alloc_num;
    let b = &other.alloc_num;
    let res = AllocatedNum::alloc(cs.namespace(|| "sum"), || {
      Ok(*a.get_value().get()? + *b.get_value().get()?)
    })?;

    cs.enforce(
      || "a + b = c",
      |lc| lc + a.get_variable() + b.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + res.get_variable(),
    );

    Ok(Self { alloc_num: res })
  }

  /// Performs multiplication of two `UInt64` values
  pub fn mul<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.alloc_num;
    let b = &other.alloc_num;
    let res = AllocatedNum::alloc(cs.namespace(|| "res"), || {
      let a_value = a.get_value().unwrap_or(F::ZERO);
      let b_value = b.get_value().unwrap_or(F::ZERO);
      let result_value = a_value * b_value;

      Ok(result_value)
    })?;

    cs.enforce(
      || "res = a * b",
      |lc| lc + a.get_variable(),
      |lc| lc + b.get_variable(),
      |lc| lc + res.get_variable(),
    );

    Ok(Self { alloc_num: res })
  }

  /// Performs div operation on two `UInt64` values
  pub fn div<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    // N / D pseudocode:
    //
    // if D = 0 then error(DivisionByZeroException) end
    //
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
    //    Q
    let dividend = self.convert_to_bits(cs.namespace(|| "dividend bits"))?;
    let divisor = other.convert_to_bits(cs.namespace(|| "divisor bits"))?;
    let mut quotient = UInt64::alloc(cs.namespace(|| "quotient"), Some(0))?
      .convert_to_bits(cs.namespace(|| "quotient bits"))?;
    let mut remainder = UInt64::alloc(cs.namespace(|| "remainder"), Some(0))?
      .convert_to_bits(cs.namespace(|| "remainder bits"))?;

    let true_bit = Boolean::Is(AllocatedBit::alloc(
      cs.namespace(|| "true bit"),
      Some(true),
    )?);

    for i in (0..64).rev() {
      let zero_bits = UInt64::alloc(cs.namespace(|| format!("zero on iter {}", i)), Some(0))?
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
      let remainder_sub_divisor = UInt64::from_bits(
        cs.namespace(|| format!("remainder sub divisor on iter {}", i)),
        &remainder_sub_divisor_bits,
      )?;

      let remainder_sub_zero = UInt64::from_bits(
        cs.namespace(|| format!("remainder sub zero on iter {}", i)),
        &remainder_sub_zero_bits,
      )?;

      let remainder_num = UInt64::conditionally_select(
        cs.namespace(|| format!("select remainder on iter {}", i)),
        &remainder_sub_divisor,
        &remainder_sub_zero,
        condition.clone(),
      )?;

      remainder =
        remainder_num.convert_to_bits(cs.namespace(|| format!("remainder on iter {}", i)))?;
      if condition.get_value().unwrap_or(false) {
        quotient[i] = true_bit.clone();
      }
    }
    let res = UInt64::from_bits(cs.namespace(|| "res quotient"), &quotient)?;
    let remainder = UInt64::from_bits(cs.namespace(|| "res remainder"), &remainder)?;

    cs.enforce(
      || "N - R = Q * D",
      |lc| lc + other.alloc_num.get_variable(),
      |lc| lc + res.alloc_num.get_variable(),
      |lc| lc + self.alloc_num.get_variable() - remainder.alloc_num.get_variable(),
    );
    Ok(res)
  }

  /// Performs rem operation of two `UInt64` values
  pub fn rem<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    // N / D pseudocode:
    //
    // if D = 0 then error(DivisionByZeroException) end
    //
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
    //    Q
    let dividend = self.convert_to_bits(cs.namespace(|| "dividend bits"))?;
    let divisor = other.convert_to_bits(cs.namespace(|| "divisor bits"))?;

    let mut quotient = UInt64::alloc(cs.namespace(|| "quotient"), Some(0))?
      .convert_to_bits(cs.namespace(|| "quotient bits"))?;
    let mut remainder = UInt64::alloc(cs.namespace(|| "remainder"), Some(0))?
      .convert_to_bits(cs.namespace(|| "remainder bits"))?;

    let true_bit = Boolean::Is(AllocatedBit::alloc(
      cs.namespace(|| "true bit"),
      Some(true),
    )?);

    for i in (0..64).rev() {
      let zero_bits = UInt64::alloc(cs.namespace(|| format!("zero on iter {}", i)), Some(0))?
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

      let condition = &ge_u_bits(
        cs.namespace(|| format!("ge_u on iter {}", i)),
        &remainder,
        &divisor,
      )?;

      let remainder_sub_divisor = UInt64::from_bits(
        cs.namespace(|| format!("remainder sub divisor on iter {}", i)),
        &remainder_sub_divisor_bits,
      )?;

      let remainder_sub_zero = UInt64::from_bits(
        cs.namespace(|| format!("remainder sub zero on iter {}", i)),
        &remainder_sub_zero_bits,
      )?;

      let remainder_num = UInt64::conditionally_select(
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
    let res = UInt64::from_bits(cs.namespace(|| "res remainder"), &remainder)?;
    let quotient = UInt64::from_bits(cs.namespace(|| "res quotient"), &quotient)?;

    cs.enforce(
      || "N - R = Q * D",
      |lc| lc + other.alloc_num.get_variable(),
      |lc| lc + quotient.alloc_num.get_variable(),
      |lc| lc + self.alloc_num.get_variable() - res.alloc_num.get_variable(),
    );
    Ok(res)
  }

  /// Performs bitwise AND operation on two `UInt64` values
  pub fn and<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let bits = self.convert_to_bits(cs.namespace(|| "self bits"))?;
    let other_bits = other.convert_to_bits(cs.namespace(|| "other bits"))?;
    let res: Vec<Boolean> = bits
      .iter()
      .zip(other_bits.iter())
      .enumerate()
      .map(|(i, (a, b))| Boolean::and(cs.namespace(|| format!("and of bit {}", i)), a, b))
      .collect::<Result<_, _>>()?;

    let res = UInt64::from_bits(cs.namespace(|| "res"), &res)?;
    Ok(res)
  }

  /// Performs bitwise OR operation on two `UInt64` values
  pub fn or<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let bits = self.convert_to_bits(cs.namespace(|| "self bits"))?;
    let other_bits = other.convert_to_bits(cs.namespace(|| "other bits"))?;
    let res: Vec<Boolean> = bits
      .iter()
      .zip(other_bits.iter())
      .enumerate()
      .map(|(i, (a, b))| Boolean::or(cs.namespace(|| format!("and of bit {}", i)), a, b))
      .collect::<Result<_, _>>()?;

    let res = UInt64::from_bits(cs.namespace(|| "res"), &res)?;
    Ok(res)
  }

  /// Performs bitwise XOR operation on two `UInt64` values
  pub fn xor<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let bits = self.convert_to_bits(cs.namespace(|| "self bits"))?;
    let other_bits = other.convert_to_bits(cs.namespace(|| "other bits"))?;
    let res: Vec<Boolean> = bits
      .iter()
      .zip(other_bits.iter())
      .enumerate()
      .map(|(i, (a, b))| Boolean::xor(cs.namespace(|| format!("and of bit {}", i)), a, b))
      .collect::<Result<_, _>>()?;

    let res = UInt64::from_bits(cs.namespace(|| "res"), &res)?;
    Ok(res)
  }

  /// Performs bitwise shl operation on a `UInt64` value
  pub fn shl<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    by: usize,
  ) -> Result<Self, SynthesisError> {
    let bits = self.convert_to_bits(cs.namespace(|| "self bits"))?;
    let res_bits = shl_bits(cs.namespace(|| "shl bits"), &bits, by)?;

    let res = UInt64::from_bits(cs.namespace(|| "res"), &res_bits)?;
    Ok(res)
  }

  /// Performs bitwise shr operation on a `UInt64` value
  pub fn shr<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    by: usize,
  ) -> Result<Self, SynthesisError> {
    let bits = self.convert_to_bits(cs.namespace(|| "a bits"))?;
    let fill = Boolean::Is(AllocatedBit::alloc(
      cs.namespace(|| "fill bit"),
      Some(false),
    )?);
    let res_bits: Vec<Boolean> = bits
      .iter()
      .skip(by)
      .chain(Some(&fill).into_iter().cycle())
      .take(64)
      .cloned()
      .collect();

    let res = UInt64::from_bits(cs.namespace(|| "res"), &res_bits)?;
    Ok(res)
  }

  /// Performs bitwise rotl operation on a `UInt64` value
  pub fn rotl<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    by: usize,
  ) -> Result<Self, SynthesisError> {
    let by = by % 64; // added here for PP bug
    let bits = self.convert_to_bits(cs.namespace(|| "self bits"))?;
    let res_bits: Vec<Boolean> = bits
      .iter()
      .cycle()
      .skip(64 - by)
      .take(64)
      .cloned()
      .collect();

    let res = UInt64::from_bits(cs.namespace(|| "res"), &res_bits)?;
    Ok(res)
  }

  /// Performs bitwise rotl operation on a `UInt64` value using only its first 32 bits
  pub fn rotl_32_bit<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    by: usize,
  ) -> Result<Self, SynthesisError> {
    let by = by % 32; // added here for PP bug
    let bits = self.convert_to_bits(cs.namespace(|| "self bits"))?;
    let fill = Boolean::Is(AllocatedBit::alloc(
      cs.namespace(|| "fill bit"),
      Some(false),
    )?);
    let res_bits: Vec<Boolean> = bits
      .iter()
      .take(32)
      .cycle()
      .skip(32 - by)
      .take(32)
      .chain(Some(&fill).into_iter().cycle())
      .take(64)
      .cloned()
      .collect();

    let res = UInt64::from_bits(cs.namespace(|| "res"), &res_bits)?;
    Ok(res)
  }

  /// Performs bitwise rotr operation on a `UInt64` value
  pub fn rotr<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    by: usize,
  ) -> Result<Self, SynthesisError> {
    let by = by % 64; // added here for PP
    let bits = self.convert_to_bits(cs.namespace(|| "self bits"))?;
    let res_bits: Vec<Boolean> = bits.iter().cycle().skip(by).take(64).cloned().collect();

    let res = UInt64::from_bits(cs.namespace(|| "res"), &res_bits)?;
    Ok(res)
  }

  /// Performs bitwise rotr operation on a `UInt64` value using only its first 32 bits
  pub fn rotr_32_bit<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    by: usize,
  ) -> Result<Self, SynthesisError> {
    let by = by % 32; // added here for PP
    let fill = Boolean::Is(AllocatedBit::alloc(
      cs.namespace(|| "fill bit"),
      Some(false),
    )?);
    let bits = self.convert_to_bits(cs.namespace(|| "self bits"))?;
    let res_bits: Vec<Boolean> = bits
      .iter()
      .take(32)
      .cycle()
      .skip(by)
      .take(32)
      .chain(Some(&fill).into_iter().cycle())
      .take(64)
      .cloned()
      .collect();

    let res = UInt64::from_bits(cs.namespace(|| "res"), &res_bits)?;
    Ok(res)
  }

  /// Performs a equal comparison of two `UInt64` values
  pub fn eq<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.alloc_num;
    let b = &other.alloc_num;

    let res = AllocatedNum::alloc(cs.namespace(|| "res"), || {
      Ok(if a.get_value().get()? == b.get_value().get()? {
        F::ONE
      } else {
        F::ZERO
      })
    })?;

    cs.enforce(
      || "res = (a == b)",
      |lc| lc + a.get_variable() - b.get_variable(),
      |lc| lc - res.get_variable(),
      |lc| lc,
    );

    Ok(Self { alloc_num: res })
  }

  /// Performs a not equal comparison of two `UInt64` values
  pub fn ne<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.alloc_num;
    let b = &other.alloc_num;

    let not_equal = AllocatedNum::alloc(cs.namespace(|| "are_not_equal"), || {
      Ok(if a.get_value().unwrap() != b.get_value().unwrap() {
        F::ONE
      } else {
        F::ZERO
      })
    })?;

    cs.enforce(
      || "are_not_equal = (a != b)",
      |lc| lc + a.get_variable() - b.get_variable(),
      |lc| lc + not_equal.get_variable() - CS::one(),
      |lc| lc,
    );

    Ok(Self {
      alloc_num: not_equal,
    })
  }

  /// Performs a equal to zero comparison of a `UInt64` value
  pub fn eqz<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    let a = &self.alloc_num;

    let res = AllocatedNum::alloc(cs.namespace(|| "res"), || {
      Ok(if a.get_value().unwrap() == F::ZERO {
        F::ONE
      } else {
        F::ZERO
      })
    })?;

    cs.enforce(
      || "res = (a == 0)",
      |lc| lc + a.get_variable(),
      |lc| lc - res.get_variable(),
      |lc| lc,
    );

    Ok(Self { alloc_num: res })
  }

  /// Performs a less than comparison of two `UInt64` values
  pub fn lt<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.alloc_num;
    let b = &other.alloc_num;

    let range = AllocatedNum::alloc(cs.namespace(|| "range"), || Ok(F::from(u64::MAX)))?;
    // diff = (lhs - rhs) + (if lt { range } else { 0 });
    let diff = AllocatedNum::alloc(cs.namespace(|| "diff"), || {
      a.get_value()
        .zip(b.get_value())
        .zip(range.get_value())
        .map(|((a, b), range)| {
          let lt = a < b;
          (a - b) + (if lt { range } else { F::ZERO })
        })
        .ok_or(SynthesisError::AssignmentMissing)
    })?;

    fits_in_bits(&diff, cs.namespace(|| "diff fit in bits"), 64)?;

    let lt = AllocatedNum::alloc(cs.namespace(|| "lt"), || {
      a.get_value()
        .zip(b.get_value())
        .map(|(a, b)| F::from(u64::from(a < b)))
        .ok_or(SynthesisError::AssignmentMissing)
    })?;

    cs.enforce(
      || "lt is bit",
      |lc| lc + lt.get_variable(),
      |lc| lc + CS::one() - lt.get_variable(),
      |lc| lc,
    );

    cs.enforce(
      || "lt ⋅ range == diff - lhs + rhs",
      |lc| lc + lt.get_variable(),
      |lc| lc + range.get_variable(),
      |lc| lc + diff.get_variable() - a.get_variable() + b.get_variable(),
    );

    Ok(Self { alloc_num: lt })
  }

  /// Performs a greater than comparison of two `UInt64` values
  pub fn gt<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.alloc_num;
    let b = &other.alloc_num;

    let range = AllocatedNum::alloc(cs.namespace(|| "range"), || Ok(F::from(u64::MAX)))?;
    // diff = (lhs - rhs) + (if lt { range } else { 0 });
    let diff = AllocatedNum::alloc(cs.namespace(|| "diff"), || {
      a.get_value()
        .zip(b.get_value())
        .zip(range.get_value())
        .map(|((a, b), range)| {
          let gt = a > b;
          (b - a) + (if gt { range } else { F::ZERO })
        })
        .ok_or(SynthesisError::AssignmentMissing)
    })?;

    fits_in_bits(&diff, cs.namespace(|| "diff fit in bits"), 64)?;
    let gt = AllocatedNum::alloc(cs.namespace(|| "gt"), || {
      a.get_value()
        .zip(b.get_value())
        .map(|(a, b)| F::from(u64::from(a > b)))
        .ok_or(SynthesisError::AssignmentMissing)
    })?;

    cs.enforce(
      || "gt is bit",
      |lc| lc + gt.get_variable(),
      |lc| lc + CS::one() - gt.get_variable(),
      |lc| lc,
    );
    cs.enforce(
      || "gt ⋅ range == diff - lhs + rhs",
      |lc| lc + gt.get_variable(),
      |lc| lc + range.get_variable(),
      |lc| lc + diff.get_variable() - b.get_variable() + a.get_variable(),
    );

    Ok(Self { alloc_num: gt })
  }

  /// Performs a less than or equal to comparison of two `UInt64` values
  pub fn le<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.alloc_num;
    let b = &other.alloc_num;

    let range = AllocatedNum::alloc(cs.namespace(|| "range"), || Ok(F::from(u64::MAX)))?;
    // diff = (lhs - rhs) + (if lt { range } else { 0 });
    let diff = AllocatedNum::alloc(cs.namespace(|| "diff"), || {
      a.get_value()
        .zip(b.get_value())
        .zip(range.get_value())
        .map(|((a, b), range)| {
          let lt = a <= b;
          (a - b) + (if lt { range } else { F::ZERO })
        })
        .ok_or(SynthesisError::AssignmentMissing)
    })?;

    fits_in_bits(&diff, cs.namespace(|| "diff fit in bits"), 64)?;
    let le = AllocatedNum::alloc(cs.namespace(|| "le"), || {
      a.get_value()
        .zip(b.get_value())
        .map(|(a, b)| F::from(u64::from(a <= b)))
        .ok_or(SynthesisError::AssignmentMissing)
    })?;

    cs.enforce(
      || "le is bit",
      |lc| lc + le.get_variable(),
      |lc| lc + CS::one() - le.get_variable(),
      |lc| lc,
    );
    cs.enforce(
      || "le ⋅ range == diff - lhs + rhs",
      |lc| lc + le.get_variable(),
      |lc| lc + range.get_variable(),
      |lc| lc + diff.get_variable() - a.get_variable() + b.get_variable(),
    );

    Ok(Self { alloc_num: le })
  }

  /// Performs a greater than or equal to comparison of two `UInt64` values
  pub fn ge<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let a = &self.alloc_num;
    let b = &other.alloc_num;

    let range = AllocatedNum::alloc(cs.namespace(|| "range"), || Ok(F::from(u64::MAX)))?;
    // diff = (lhs - rhs) + (if lt { range } else { 0 });
    let diff = AllocatedNum::alloc(cs.namespace(|| "diff"), || {
      a.get_value()
        .zip(b.get_value())
        .zip(range.get_value())
        .map(|((a, b), range)| {
          let gt = a >= b;
          (b - a) + (if gt { range } else { F::ZERO })
        })
        .ok_or(SynthesisError::AssignmentMissing)
    })?;

    fits_in_bits(&diff, cs.namespace(|| "diff fit in bits"), 64)?;
    let ge = AllocatedNum::alloc(cs.namespace(|| "ge"), || {
      a.get_value()
        .zip(b.get_value())
        .map(|(a, b)| F::from(u64::from(a >= b)))
        .ok_or(SynthesisError::AssignmentMissing)
    })?;

    cs.enforce(
      || "ge is bit",
      |lc| lc + ge.get_variable(),
      |lc| lc + CS::one() - ge.get_variable(),
      |lc| lc,
    );
    cs.enforce(
      || "ge ⋅ range == diff - lhs + rhs",
      |lc| lc + ge.get_variable(),
      |lc| lc + range.get_variable(),
      |lc| lc + diff.get_variable() - b.get_variable() + a.get_variable(),
    );

    Ok(Self { alloc_num: ge })
  }

  /// Counts the number of leading zeros in a `UInt64` value
  pub fn clz<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    let a = &self.convert_to_bits(cs.namespace(|| "a bits"))?;

    let mut leading_zeros = 0;
    for bit in a.iter().rev() {
      if bit.get_value().unwrap_or(false) {
        break;
      }
      leading_zeros += 1;
    }
    let leading_zeros =
      UInt64::alloc(cs.namespace(|| "leading_zeros"), Some(leading_zeros as u64))?;

    Ok(leading_zeros)
  }

  /// Counts the number of leading zeros in a `UInt64` value using only its first 32 bits
  pub fn clz_32_bit<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    let a = &self.convert_to_bits(cs.namespace(|| "a bits"))?;

    let mut leading_zeros = 0;
    for bit in a.iter().take(32).rev() {
      if bit.get_value().unwrap_or(false) {
        break;
      }
      leading_zeros += 1;
    }
    let leading_zeros =
      UInt64::alloc(cs.namespace(|| "leading_zeros"), Some(leading_zeros as u64))?;
    Ok(leading_zeros)
  }

  /// Counts the number of trailing zeros in a `UInt64` value
  pub fn ctz<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    let a = &self.convert_to_bits(cs.namespace(|| "a bits"))?;

    let mut trailing_zeros = 0;
    for bit in a.iter() {
      if bit.get_value().unwrap_or(false) {
        break;
      }
      trailing_zeros += 1;
    }
    let trailing_zeros = UInt64::alloc(
      cs.namespace(|| "trailing_zeros"),
      Some(trailing_zeros as u64),
    )?;
    Ok(trailing_zeros)
  }

  /// Counts the number of trailing zeros in a `UInt64` value using only its first 32 bits
  pub fn ctz_32_bit<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    let a = &self.convert_to_bits(cs.namespace(|| "a bits"))?;
    let mut trailing_zeros = 0;
    for bit in a.iter().take(32) {
      if bit.get_value().unwrap_or(false) {
        break;
      }
      trailing_zeros += 1;
    }
    let trailing_zeros = UInt64::alloc(
      cs.namespace(|| "trailing_zeros"),
      Some(trailing_zeros as u64),
    )?;
    Ok(trailing_zeros)
  }

  /// Counts the number of ones in a `UInt64` value
  pub fn popcnt<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    let a = &self.convert_to_bits(cs.namespace(|| "a bits"))?;

    let mut ones = 0;
    for bit in a.iter() {
      if !bit.get_value().unwrap_or(false) {
        continue;
      }
      ones += 1;
    }
    let ones = UInt64::alloc(cs.namespace(|| "ones"), Some(ones as u64))?;
    Ok(ones)
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use bellpepper_core::{test_cs::TestConstraintSystem, Comparable};
  use nova::{provider::PallasEngine, traits::Engine};
  use rand::{Rng, SeedableRng};
  use rand_xorshift::XorShiftRng;

  type Fr = <PallasEngine as Engine>::Base;

  #[test]
  fn test_convert_to_bits() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let mut cs = TestConstraintSystem::<Fr>::new();
      let a_alloc = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let bits = a_alloc.convert_to_bits(cs.namespace(|| "bits")).unwrap();
      assert_eq!(bits.len(), 64);
      for (i, bit) in bits.iter().enumerate() {
        let bit = bit.get_value().unwrap();
        let expected = (a >> i) & 1;
        assert_eq!(expected as u64, bit as u64);
      }
    }
  }
  #[test]
  fn test_from_bits() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let mut cs = TestConstraintSystem::<Fr>::new();
      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let bits = a.convert_to_bits(cs.namespace(|| "bits")).unwrap();
      let b = UInt64::from_bits(cs.namespace(|| "b"), &bits).unwrap();
      assert_eq!(a.get_64_bit_value().unwrap(), b.get_64_bit_value().unwrap());
    }
  }
  // bin_ops
  #[test]
  fn test_add() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();
      let expected = a.wrapping_add(b);
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.add(cs.namespace(|| "add"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_sub() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();
      let expected = a.wrapping_sub(b);
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "-b"), Some(-b as u64)).unwrap();
      let res = a.add(cs.namespace(|| "sub"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_sub_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i32>();
      let b = rng.gen::<i32>();
      let expected = a.wrapping_sub(b);
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "-b"), Some(-b as u64)).unwrap();
      let res = a.add(cs.namespace(|| "sub 32"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i32;
      assert_eq!(expected, res);
    }
  }
  #[test]
  fn test_mul() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();
      let expected = a.wrapping_mul(b);
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.mul(cs.namespace(|| "mul"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
    }
  }

  #[ignore]
  #[test]
  fn test_div() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..50 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();

      if b == 0 {
        continue;
      }

      let expected = a / b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();

      let res = a.div(cs.namespace(|| "div"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
      assert!(cs.is_satisfied());
    }
  }

  #[ignore]
  #[test]
  fn test_rem() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..50 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();

      if b == 0 {
        continue;
      }

      let expected = a % b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();

      let res = a.rem(cs.namespace(|| "rem"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
      assert!(cs.is_satisfied());
    }
  }

  #[ignore]
  #[test]
  fn test_div_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..50 {
      let a = rng.gen::<u32>();
      let b = rng.gen::<u32>();

      if b == 0 {
        continue;
      }

      let expected = a / b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();

      let res = a.div(cs.namespace(|| "div"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as u32;
      assert_eq!(expected, res);
      assert!(cs.is_satisfied());
    }
  }

  #[ignore]
  #[test]
  fn test_rem_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..50 {
      let a = rng.gen::<u32>();
      let b = rng.gen::<u32>();

      if b == 0 {
        continue;
      }

      let expected = a % b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();

      let res = a.rem(cs.namespace(|| "rem"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as u32;
      assert_eq!(expected, res);
      assert!(cs.is_satisfied());
    }
  }

  // bin_bit_ops
  #[test]
  fn test_and() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();
      let expected = a & b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.and(cs.namespace(|| "add"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
    }
  }
  #[test]
  fn test_or() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();
      let expected = a | b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.or(cs.namespace(|| "or"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_xor() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<i64>();
      let expected = a ^ b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b as u64)).unwrap();
      let res = a.xor(cs.namespace(|| "xor"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
    }
  }

  //bin_shift_bit_ops
  #[test]
  fn test_shl() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i64>();
      let b = rng.gen::<usize>() % 64;
      let expected = a << b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.shl(cs.namespace(|| "shl"), b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i64;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_shl_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<i32>();
      let b = rng.gen::<usize>() % 32;
      let expected = a << b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.shl(cs.namespace(|| "shl"), b).unwrap();
      let res = res.get_64_bit_value().unwrap() as i32;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_shr() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<usize>() % 64;
      let expected = a >> b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let res = a.shr(cs.namespace(|| "shr"), b).unwrap();
      let res = res.get_64_bit_value().unwrap();
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
      let a = rng.gen::<u32>();
      let b = rng.gen::<usize>() % 32;
      let expected = a >> b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.shr(cs.namespace(|| "shr"), b).unwrap();
      let res = res.get_64_bit_value().unwrap() as u32;
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_rotl() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<usize>() % 64;
      let expected = a.rotate_left(b as u32);
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let res = a.rotl(cs.namespace(|| "rotl"), b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_rotl_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u32>();
      let b = rng.gen::<usize>() % 32;
      let expected = a.rotate_left(b as u32);
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.rotl_32_bit(cs.namespace(|| "rotl"), b).unwrap();
      let res = res.get_64_bit_value().unwrap() as u32;
      assert_eq!(expected, res);
    }
  }
  #[test]
  fn test_rotr() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<usize>() % 64;
      let expected = a.rotate_right(b as u32);
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let res = a.rotr(cs.namespace(|| "rotr"), b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_rotr_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u32>();
      let b = rng.gen::<usize>() % 32;
      let expected = a.rotate_right(b as u32);
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.rotr_32_bit(cs.namespace(|| "rotr"), b).unwrap();
      let res = res.get_64_bit_value().unwrap() as u32;
      assert_eq!(expected, res);
    }
  }

  // relops
  #[test]
  fn test_eq() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let mut b = rng.gen::<u64>();
      if b > u64::MAX / 2 {
        b = a;
      }
      let expected = a == b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();
      let res = a.eq(cs.namespace(|| "eq"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected as u64, res);
    }
  }

  #[test]
  fn test_eqz() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();

      let expected = a == 0;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let res = a.eqz(cs.namespace(|| "eqz")).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected as u64, res);
    }
  }

  #[test]
  fn test_ne() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let mut b = rng.gen::<u64>();
      if b > u64::MAX / 2 {
        b = a;
      }
      let expected = a != b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();
      let res = a.ne(cs.namespace(|| "ne"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected as u64, res);
    }
  }

  #[test]
  fn test_lt_u() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();

      let expected = a < b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();
      let res = a.lt(cs.namespace(|| "lt"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected as u64, res);
    }
  }

  #[test]
  fn test_gt_u() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();

      let expected = a > b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();
      let res = a.gt(cs.namespace(|| "gt"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected as u64, res);
    }
  }

  #[test]
  fn test_le_u() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();

      let expected = a <= b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();
      let res = a.le(cs.namespace(|| "le"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected as u64, res);
    }
  }

  #[test]
  fn test_ge_u() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();

      let expected = a >= b;
      let mut cs = TestConstraintSystem::<Fr>::new();

      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();
      let res = a.ge(cs.namespace(|| "ge"), &b).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected as u64, res);
    }
  }

  #[test]
  fn test_clz() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);

    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let expected = a.leading_zeros() as u64;

      let mut cs = TestConstraintSystem::<Fr>::new();
      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let res = a.clz(cs.namespace(|| "clz")).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_clz_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);

    for _ in 0..1000 {
      let a = rng.gen::<u32>();
      let expected = a.leading_zeros() as u64;

      let mut cs = TestConstraintSystem::<Fr>::new();
      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.clz_32_bit(cs.namespace(|| "clz")).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_ctz() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);

    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let expected = a.trailing_zeros() as u64;

      let mut cs = TestConstraintSystem::<Fr>::new();
      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let res = a.ctz(cs.namespace(|| "clz")).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_ctz_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);

    for _ in 0..10000 {
      let a = rng.gen::<u32>();
      let expected = a.trailing_zeros() as u64;

      let mut cs = TestConstraintSystem::<Fr>::new();
      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.ctz_32_bit(cs.namespace(|| "clz")).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_popcnt() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);

    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let expected = a.count_ones() as u64;

      let mut cs = TestConstraintSystem::<Fr>::new();
      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let res = a.popcnt(cs.namespace(|| "popcnt")).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_r1cs_popcnt() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);

    let a = rng.gen::<u64>();
    let expected = a.count_ones() as u64;

    let mut cs = TestConstraintSystem::<Fr>::new();
    let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
    let res = a.popcnt(cs.namespace(|| "popcnt")).unwrap();

    let r1cs = cs.constraints();
    println!("{:#?}", r1cs);
    let res = res.get_64_bit_value().unwrap();
    assert_eq!(expected, res);
  }

  #[test]
  fn test_popcnt_32_bit() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);

    for _ in 0..1000 {
      let a = rng.gen::<u32>();
      let expected = a.count_ones() as u64;

      let mut cs = TestConstraintSystem::<Fr>::new();
      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a as u64)).unwrap();
      let res = a.popcnt(cs.namespace(|| "clz")).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
    }
  }

  #[test]
  fn test_conditionally_select() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);

    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();
      let c = rng.gen::<bool>();

      let expected = if c { a } else { b };

      let mut cs = TestConstraintSystem::<Fr>::new();
      let a = UInt64::alloc(cs.namespace(|| "a"), Some(a)).unwrap();
      let b = UInt64::alloc(cs.namespace(|| "b"), Some(b)).unwrap();
      let c = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "c"), Some(c)).unwrap());
      let res = UInt64::conditionally_select(cs.namespace(|| "select"), &a, &b, c).unwrap();
      let res = res.get_64_bit_value().unwrap();
      assert_eq!(expected, res);
    }
  }
}
