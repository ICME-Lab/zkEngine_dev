//! Gadgets for bit operations.
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  ConstraintSystem, SynthesisError,
};
use ff::PrimeField;

/// Gadget to perform bitwise shl operation.
pub fn shl_bits<F: PrimeField, CS: ConstraintSystem<F>>(
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

/// Gadget to peform full adder operation on bits.
fn full_adder_bits<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  a: &Boolean,
  b: &Boolean,
  c: &Boolean,
) -> Result<(Boolean, Boolean), SynthesisError> {
  let sum_ab = Boolean::xor(cs.namespace(|| "a ^ b"), a, b)?;
  let res_sum = Boolean::xor(cs.namespace(|| "sum ^ c"), &sum_ab, c)?;
  let carry_ab = Boolean::and(cs.namespace(|| "a & b"), a, b)?;
  let carry_ac = Boolean::and(cs.namespace(|| "carry & (a ^ b)"), c, &sum_ab)?;
  let res_carry = Boolean::or(
    cs.namespace(|| "(a & b) | carry & (a ^ b)"),
    &carry_ab,
    &carry_ac,
  )?;
  Ok((res_sum, res_carry))
}

/// Gadget to add two bit vectors.
pub fn add_bits<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  a: &[Boolean],
  b: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
  let mut carry = Boolean::Is(AllocatedBit::alloc(
    cs.namespace(|| "carry bit"),
    Some(false),
  )?);
  let mut res_bits = Vec::with_capacity(64);
  for (i, (a, b)) in a.iter().zip(b.iter()).enumerate() {
    let (sum, carry_out) = full_adder_bits(
      cs.namespace(|| format!("full adder bits at {}", i)),
      a,
      b,
      &carry,
    )?;
    res_bits.push(sum);
    carry = carry_out;
  }
  Ok(res_bits)
}

/// Gadget to convert u64 into little-endian bit vector.
pub fn u64_into_bit_vec_le(value: Option<u64>) -> Result<Vec<Boolean>, SynthesisError> {
  let mut res_bits = Vec::with_capacity(64);
  let value = value.unwrap_or(0);
  for i in 0..64 {
    let bit = (value >> i) & 1 == 1;
    res_bits.push(Boolean::constant(bit));
  }
  Ok(res_bits)
}

/// Gadget to get two's complement of a bit vector.
pub fn get_twos_complement<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
  let mut res_bits = Vec::with_capacity(64);
  for (i, bit) in bits.iter().enumerate() {
    let value = bit.get_value().unwrap_or(false);
    res_bits.push(Boolean::Is(AllocatedBit::alloc(
      cs.namespace(|| format!("i: {} 2s comp bit", i)),
      Some(!value),
    )?));
  }
  let one_bits = u64_into_bit_vec_le(Some(1))?;
  res_bits = add_bits(cs.namespace(|| "add 1"), &res_bits, &one_bits)?;
  Ok(res_bits)
}

/// Gadget to subtract two bit vectors.
pub fn sub_bits<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  a: &[Boolean],
  b: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
  let b = get_twos_complement(cs.namespace(|| "twos complement"), b)?;
  let res_bits = add_bits(cs.namespace(|| "add"), a, &b)?;
  Ok(res_bits)
}

/// Gadget to perform greater than or equal to comparison on two bit vectors.
pub fn ge_u_bits<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  a: &[Boolean],
  b: &[Boolean],
) -> Result<Boolean, SynthesisError> {
  for (a, b) in a.iter().zip(b.iter()).rev() {
    let a = a.get_value().unwrap_or(false);
    let b = b.get_value().unwrap_or(false);
    if a && !b {
      return Ok(Boolean::Is(AllocatedBit::alloc(
        cs.namespace(|| "ge res"),
        Some(true),
      )?));
    }
    if !a && b {
      return Ok(Boolean::Is(AllocatedBit::alloc(
        cs.namespace(|| "ge res"),
        Some(false),
      )?));
    }
  }

  Ok(Boolean::Is(AllocatedBit::alloc(
    cs.namespace(|| "ge res"),
    Some(true),
  )?))
}

#[cfg(test)]
mod test {
  use super::*;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use halo2curves::bn256::Fr;
  use rand::{Rng, SeedableRng};
  use rand_xorshift::XorShiftRng;
  #[test]
  fn test_shl_bits() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let mut cs = TestConstraintSystem::<Fr>::new();
      let a = rng.gen::<u64>();
      let shift = rng.gen_range(0..64);
      let a_bits: Vec<_> = (0..64)
        .map(|i| Boolean::constant(a >> i & 1 == 1))
        .collect();
      let res = shl_bits(cs.namespace(|| "shl bits"), &a_bits, shift).unwrap();
      let mut expected = vec![Boolean::constant(false); 64];
      for i in 0..64 {
        if i + shift < 64 {
          expected[i + shift] = a_bits[i].clone();
        }
      }
      for i in 0..64 {
        assert_eq!(
          expected[i].get_value().unwrap(),
          res[i].get_value().unwrap()
        );
      }
    }
  }

  #[test]
  fn test_full_adder_bits() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<bool>();
      let b = rng.gen::<bool>();
      let c = rng.gen::<bool>();

      let a_const = Boolean::constant(a);
      let b_const = Boolean::constant(b);
      let c_const = Boolean::constant(c);

      let mut cs = TestConstraintSystem::<Fr>::new();
      let res = full_adder_bits(&mut cs, &a_const, &b_const, &c_const).unwrap();
      let expected_sum = (a ^ b) ^ c;
      let expected_carry = (a & b) | (c & (a ^ b));
      assert_eq!(expected_sum, res.0.get_value().unwrap());
      assert_eq!(expected_carry, res.1.get_value().unwrap());
    }
  }

  #[test]
  fn test_add_bits() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();
      let mut cs = TestConstraintSystem::<Fr>::new();
      let a_bits: Vec<_> = (0..64)
        .map(|i| Boolean::constant(a >> i & 1 == 1))
        .collect();
      let b_bits: Vec<_> = (0..64)
        .map(|i| Boolean::constant(b >> i & 1 == 1))
        .collect();
      let res = add_bits(&mut cs, &a_bits, &b_bits).unwrap();
      let expected = a.wrapping_add(b);
      for (i, res_bit) in res.iter().enumerate() {
        assert_eq!(
          (expected >> i & 1 == 1),
          res_bit.get_value().unwrap(),
          "i = {}",
          i
        );
      }
    }
  }

  #[test]
  fn test_u64_into_bit_vec_le() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let bits = u64_into_bit_vec_le(Some(a)).unwrap();
      for (i, bit) in bits.iter().enumerate() {
        assert_eq!((a >> i & 1 == 1), bit.get_value().unwrap(), "i = {}", i);
      }
    }
  }

  #[test]
  fn test_get_twos_complement() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let mut cs = TestConstraintSystem::<Fr>::new();
      let a_bits: Vec<_> = (0..64)
        .map(|i| Boolean::constant(a >> i & 1 == 1))
        .collect();
      let res = get_twos_complement(&mut cs, &a_bits).unwrap();
      let expected = (!a).wrapping_add(1);
      for (i, res_bit) in res.iter().enumerate() {
        assert_eq!(
          (expected >> i & 1 == 1),
          res_bit.get_value().unwrap(),
          "i = {}",
          i
        );
      }
    }
  }

  #[test]
  pub fn test_sub_bits() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();
      let mut cs = TestConstraintSystem::<Fr>::new();
      let a_bits: Vec<_> = (0..64)
        .map(|i| Boolean::constant(a >> i & 1 == 1))
        .collect();
      let b_bits: Vec<_> = (0..64)
        .map(|i| Boolean::constant(b >> i & 1 == 1))
        .collect();
      let res = sub_bits(&mut cs, &a_bits, &b_bits).unwrap();
      let expected = a.wrapping_sub(b);
      for (i, res_bit) in res.iter().enumerate() {
        assert_eq!(
          (expected >> i & 1 == 1),
          res_bit.get_value().unwrap(),
          "i = {}",
          i
        );
      }
    }
  }

  #[test]
  fn test_ge_u_bits() {
    let mut rng = XorShiftRng::from_seed([
      0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
      0xe5,
    ]);
    for _ in 0..1000 {
      let a = rng.gen::<u64>();
      let b = rng.gen::<u64>();
      let mut cs = TestConstraintSystem::<Fr>::new();
      let a_bits: Vec<_> = (0..64)
        .map(|i| Boolean::constant(a >> i & 1 == 1))
        .collect();
      let b_bits: Vec<_> = (0..64)
        .map(|i| Boolean::constant(b >> i & 1 == 1))
        .collect();
      let res = ge_u_bits(&mut cs, &a_bits, &b_bits).unwrap();
      assert_eq!(a >= b, res.get_value().unwrap());
    }
  }
}
