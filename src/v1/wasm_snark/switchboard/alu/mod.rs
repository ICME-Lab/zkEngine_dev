use super::WASMTransitionCircuit as SwitchBoardCircuit;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

pub mod int32;
pub mod int64;

pub fn eq<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  switch: F,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  // Difference between `a` and `b`. This will be zero if `a` and `b` are equal.
  // result = (a == b)
  let res = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "a == b",
    || {
      let a_val = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
      let b_val = b.get_value().ok_or(SynthesisError::AssignmentMissing)?;
      if a_val == b_val {
        Ok(F::ONE)
      } else {
        Ok(F::ZERO)
      }
    },
    switch,
  )?;

  // result * (a - b) = 0
  // This means that at least one of result or a - b is zero.
  cs.enforce(
    || "result or diff is 0",
    |lc| lc + res.get_variable(),
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc,
  );

  // Inverse of `a - b`, if it exists, otherwise one.
  let q = cs.alloc(
    || "q",
    || {
      let a_val = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
      let b_val = b.get_value().ok_or(SynthesisError::AssignmentMissing)?;
      let tmp0 = a_val - b_val;
      let tmp1 = tmp0.invert();

      if tmp1.is_some().into() {
        Ok(tmp1.unwrap())
      } else {
        Ok(F::ONE)
      }
    },
  )?;

  let one = SwitchBoardCircuit::alloc_num(&mut cs, || "one", || Ok(F::ONE), switch)?;

  // (a - b + result) * q = 1.
  // This enforces that diff and result are not both 0.
  cs.enforce(
    || "(a - b + result) * q = 1",
    |lc| lc + a.get_variable() - b.get_variable() + res.get_variable(),
    |lc| lc + q,
    |lc| lc + one.get_variable(),
  );

  Ok(res)
}

/// Returns `1` if a == 0 else `0`
pub fn eqz<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  switch: F,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let zero = F::ZERO;
  let one = F::ONE;

  // result = (a == 0)
  let res = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "a == 0",
    || {
      let a_val = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
      if a_val == zero {
        Ok(one)
      } else {
        Ok(zero)
      }
    },
    switch,
  )?;

  // result * a = 0
  // This means that at least one of result or a is zero.
  cs.enforce(
    || "res or a is 0",
    |lc| lc + res.get_variable(),
    |lc| lc + a.get_variable(),
    |lc| lc,
  );

  // Inverse of `a`, if it exists, otherwise one.
  let q = cs.alloc(
    || "q",
    || {
      let a_val = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
      let tmp = a_val.invert();
      if tmp.is_some().into() {
        Ok(tmp.unwrap())
      } else {
        Ok(F::ONE)
      }
    },
  )?;

  let one = SwitchBoardCircuit::alloc_num(&mut cs, || "one", || Ok(F::ONE), switch)?;

  // (a + result) * q = 1.
  // This enforces that x and result are not both 0.
  cs.enforce(
    || "(a + res) * q = 1",
    |lc| lc + a.get_variable() + res.get_variable(),
    |lc| lc + q,
    |lc| lc + one.get_variable(),
  );

  Ok(res)
}

#[cfg(test)]
mod tests {
  use bellpepper_core::{test_cs::TestConstraintSystem, ConstraintSystem};
  use nova::{provider::Bn256EngineIPA, traits::Engine};
  use rand::{rngs::StdRng, Rng, SeedableRng};
  use wasmi::core::UntypedValue;

  use crate::v1::wasm_snark::switchboard::{
    alu::{eq, eqz},
    WASMTransitionCircuit as SwitchBoardCircuit,
  };

  type E = Bn256EngineIPA;
  type F = <E as Engine>::Scalar;

  #[test]
  fn test_eqz() {
    let mut rng = StdRng::from_seed([99u8; 32]);

    let switch = F::one();

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<bool>());
      let expected = a.i64_eqz();

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

      let c = eqz(cs.namespace(|| "eqz"), &alloc_a, switch).unwrap();

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
  fn test_eq() {
    let mut rng = StdRng::from_seed([99u8; 32]);

    let switch = F::one();

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = if rng.gen::<bool>() {
        UntypedValue::from(rng.gen::<i64>())
      } else {
        a
      };

      let expected = a.i64_eq(b);

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

      let c = eq(cs.namespace(|| "eq"), &alloc_a, &alloc_b, switch).unwrap();

      cs.enforce(
        || "expected ==  c",
        |lc| lc + alloc_expected.get_variable(),
        |lc| lc + one_var,
        |lc| lc + c.get_variable(),
      );

      assert!(cs.is_satisfied());
    }
  }
}
