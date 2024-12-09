use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

fn add64<F, CS>(mut cs: CS, a: u64, b: u64) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let zero = F::ZERO;
  let O = F::from_u128(u64::MAX as u128 + 1);
  let ON: F = zero - O;

  let (c, of) = a.overflowing_add(b);
  let o = if of { ON } else { zero };

  // construct witness
  let a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(F::from(a)))?;
  let b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(F::from(b)))?;
  let c = AllocatedNum::alloc(cs.namespace(|| "c"), || Ok(F::from(c)))?;

  // note, this is "advice"
  let o = AllocatedNum::alloc(cs.namespace(|| "o"), || Ok(o))?;
  let O = AllocatedNum::alloc(cs.namespace(|| "O"), || Ok(O))?;

  // check o * (o + O) == 0
  cs.enforce(
    || "check o * (o + O) == 0",
    |lc| lc + o.get_variable(),
    |lc| lc + o.get_variable() + O.get_variable(),
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

fn add32<F, CS>(mut cs: CS, a: u32, b: u32) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let zero = F::ZERO;
  let O = F::from(0x100000000u64);
  let ON: F = zero - O;

  let (c, of) = a.overflowing_add(b);
  let o = if of { ON } else { zero };

  // construct witness
  let a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(F::from(a as u64)))?;
  let b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(F::from(b as u64)))?;
  let c = AllocatedNum::alloc(cs.namespace(|| "c"), || Ok(F::from(c as u64)))?;

  // note, this is "advice"
  let o = AllocatedNum::alloc(cs.namespace(|| "o"), || Ok(o))?;
  let O = AllocatedNum::alloc(cs.namespace(|| "O"), || Ok(O))?;

  // check o * (o + O) == 0
  cs.enforce(
    || "check o * (o + O) == 0",
    |lc| lc + o.get_variable(),
    |lc| lc + o.get_variable() + O.get_variable(),
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

#[cfg(test)]
mod tests {
  use bellpepper_core::{num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem};
  use ff::PrimeField;
  use nova::{provider::Bn256EngineIPA, traits::Engine};
  use rand::{rngs::StdRng, Rng, SeedableRng};
  use wasmi::core::UntypedValue;

  use crate::v1::wasm_snark::switchboard::sub_circuits::{add32, add64};

  type E = Bn256EngineIPA;
  type F = <E as Engine>::Scalar;

  /// Convert a field element to a u64
  pub fn field_element_to_u64<Scalar: PrimeField>(element: &Scalar) -> u64 {
    let mut byte_array = [0u8; 8];
    byte_array.copy_from_slice(&element.to_repr().as_ref()[0..8]);
    u64::from_le_bytes(byte_array)
  }

  /// Convert a field element to a u32
  pub fn field_element_to_u32<Scalar: PrimeField>(element: &Scalar) -> u32 {
    let mut byte_array = [0u8; 4];
    byte_array.copy_from_slice(&element.to_repr().as_ref()[0..4]);
    u32::from_le_bytes(byte_array)
  }

  #[test]
  fn test_add64() {
    let mut rng = StdRng::from_seed([100u8; 32]);

    for i in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = UntypedValue::from(rng.gen::<i64>());
      let expected = a.i64_add(b);

      let mut cs = TestConstraintSystem::<F>::new();

      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
      let alloc_expected = AllocatedNum::alloc(cs.namespace(|| "expected"), || {
        Ok(F::from(expected.to_bits()))
      })
      .unwrap();

      let c = add64(cs.namespace(|| "add32"), a.to_bits(), b.to_bits()).unwrap();

      cs.enforce(
        || "expected ==  c",
        |lc| lc + alloc_expected.get_variable(),
        |lc| lc + one_var,
        |lc| lc + c.get_variable(),
      );

      if !cs.is_satisfied() {
        println!("failed at iteration: {}", i);
        println!("a: {:?}", a);
        println!("b: {:?}", b);
        println!("c: {:#?}", c.get_value().unwrap());

        println!("expected: {:#?}", alloc_expected.get_value().unwrap());
      }

      assert!(cs.is_satisfied());
    }
  }

  #[test]
  fn test_add32() {
    let mut rng = StdRng::from_seed([100u8; 32]);

    for i in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i32>());
      let b = UntypedValue::from(rng.gen::<i32>());
      let expected = a.i32_add(b);

      let mut cs = TestConstraintSystem::<F>::new();

      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
      let alloc_expected = AllocatedNum::alloc(cs.namespace(|| "expected"), || {
        Ok(F::from(expected.to_bits()))
      })
      .unwrap();

      let c = add32(
        cs.namespace(|| "add32"),
        a.to_bits() as u32,
        b.to_bits() as u32,
      )
      .unwrap();

      cs.enforce(
        || "expected ==  c",
        |lc| lc + alloc_expected.get_variable(),
        |lc| lc + one_var,
        |lc| lc + c.get_variable(),
      );

      if !cs.is_satisfied() {
        println!("failed at iteration: {}", i);
        println!("a: {:?}", a);
        println!("b: {:?}", b);
        println!("c: {:#?}", c.get_value().unwrap());

        println!("expected: {:#?}", alloc_expected.get_value().unwrap());
      }

      assert!(cs.is_satisfied());
    }
  }
}
