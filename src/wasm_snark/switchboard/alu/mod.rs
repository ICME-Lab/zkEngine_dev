use super::WASMTransitionCircuit as SwitchBoardCircuit;
use ff::PrimeField;
use nova::frontend::{num::AllocatedNum, Boolean, ConstraintSystem, SynthesisError};

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

pub fn ne<F, CS>(
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
  // result = (a != b)
  let res = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "a != b",
    || {
      let a_val = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
      let b_val = b.get_value().ok_or(SynthesisError::AssignmentMissing)?;
      if a_val != b_val {
        Ok(F::ONE)
      } else {
        Ok(F::ZERO)
      }
    },
    switch,
  )?;

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

  // (a - b + result) * q = 1.
  // This enforces that diff and result are not both 0.
  cs.enforce(
    || "(a - b + result) * q = 1",
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc + q,
    |lc| lc + res.get_variable(),
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

/// Returns `1` if a == 0 else `0`
pub fn eqz_bit<F, CS>(mut cs: CS, a: &AllocatedNum<F>, switch: F) -> Result<Boolean, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let a_val = a.get_value();
  let is_zero = a_val.map(|val| val == F::ZERO);

  // result = (a == 0)
  let res = SwitchBoardCircuit::alloc_bit(&mut cs, || "res", is_zero, switch)?;

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

  Ok(Boolean::Is(res))
}

pub fn add<F, CS, B>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: B,
  b_bits: B,
  switch: F,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
  B: OverFlowTrait,
{
  let zero = F::ZERO;
  let range = F::from_u128(1_u128 << B::NUM_BITS);
  let neg_range: F = zero - range;
  let (c, overflow) = a_bits.of_add(b_bits);
  let o = if overflow { neg_range } else { zero };

  // construct witness
  let c = SwitchBoardCircuit::alloc_num(&mut cs, || "c", || Ok(F::from(c.into())), switch)?;

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

pub fn sub<F, CS, B>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: B,
  b_bits: B,
  switch: F,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
  B: OverFlowTrait,
{
  let range = F::from_u128(1_u128 << B::NUM_BITS);
  let (c, of) = a_bits.of_sub(b_bits);
  let c = SwitchBoardCircuit::alloc_num(&mut cs, || "c", || Ok(F::from(c.into())), switch)?;
  let of = SwitchBoardCircuit::alloc_bit(&mut cs, || "of", Some(of), switch)?;
  cs.enforce(
    || "a - b + (range * of) = c",
    |lc| lc + a.get_variable() - b.get_variable() + (range, of.get_variable()),
    |lc| lc + CS::one(),
    |lc| lc + c.get_variable(),
  );
  Ok(c)
}

pub fn mul<F, CS, B>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: B,
  b_bits: B,
  switch: F,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
  B: OverFlowTrait,
{
  // Get value WASM vm will spit out
  let c = a_bits.wrap_mul(b_bits);
  let c = SwitchBoardCircuit::alloc_num(&mut cs, || "c", || Ok(F::from(c.into())), switch)?;

  // Calculate the product value in 128 bits
  let a_128_bits: u128 = a_bits.into();
  let b_128_bits: u128 = b_bits.into();
  let c_128_bits = a_128_bits * b_128_bits;

  // Calculate the left overs (value to subtract from c_128 to get c)
  //
  // # Note
  //
  // This is advice
  let range = F::from_u128(1_u128 << B::NUM_BITS);

  let trunc = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "trunc",
    || Ok(F::from_u128(c_128_bits >> B::NUM_BITS)),
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

pub trait OverFlowTrait: Into<u64> + Into<u128> + Copy
where
  Self: Sized,
{
  const NUM_BITS: u32;

  fn of_add(&self, other: Self) -> (Self, bool);

  fn of_sub(&self, other: Self) -> (Self, bool);

  fn wrap_mul(&self, other: Self) -> Self;
}

macro_rules! impl_overflow_trait {
  ($($t:ty),*) => {
      $(
          impl OverFlowTrait for $t {
              const NUM_BITS: u32 = <$t>::BITS;

              fn of_add(&self, other: Self) -> (Self, bool) {
                  self.overflowing_add(other)
              }

              fn of_sub(&self, other: Self) -> (Self, bool) {
                  self.overflowing_sub(other)
              }

              fn wrap_mul(&self, other: Self) -> Self {
                  self.wrapping_mul(other)
              }

          }
      )*
  };
}

impl_overflow_trait!(u32, u64);

pub trait IntegerOps<F, CS>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  fn i64_add(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>;

  fn i32_add(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>;

  fn i64_sub(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>;

  fn i32_sub(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>;

  fn i64_mul(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>;

  fn i32_mul(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError>;
}

pub struct ALUGadget;

impl<F, CS> IntegerOps<F, CS> for ALUGadget
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  fn i64_add(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError> {
    add(cs.namespace(|| "i64_add"), a, b, a_bits, b_bits, switch)
  }

  fn i32_add(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError> {
    add(
      cs.namespace(|| "i32_add"),
      a,
      b,
      a_bits as u32,
      b_bits as u32,
      switch,
    )
  }

  fn i64_sub(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError> {
    sub(cs.namespace(|| "i64_sub"), a, b, a_bits, b_bits, switch)
  }

  fn i32_sub(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError> {
    sub(
      cs.namespace(|| "i32_sub"),
      a,
      b,
      a_bits as u32,
      b_bits as u32,
      switch,
    )
  }

  fn i64_mul(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError> {
    mul(cs.namespace(|| "i64_mul"), a, b, a_bits, b_bits, switch)
  }

  fn i32_mul(
    cs: &mut CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
    a_bits: u64,
    b_bits: u64,
    switch: F,
  ) -> Result<AllocatedNum<F>, SynthesisError> {
    mul(
      cs.namespace(|| "i32_mul"),
      a,
      b,
      a_bits as u32,
      b_bits as u32,
      switch,
    )
  }
}

#[cfg(test)]
mod tests {
  use nova::frontend::{test_cs::TestConstraintSystem, ConstraintSystem};
  use nova::{provider::Bn256EngineIPA, traits::Engine};
  use rand::{rngs::StdRng, Rng, SeedableRng};
  use wasmi::core::UntypedValue;

  use crate::wasm_snark::switchboard::{
    alu::{self, eq, eqz},
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

  #[test]
  fn test_ne() {
    let mut rng = StdRng::from_seed([99u8; 32]);

    let switch = F::zero();

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i64>());
      let b = if rng.gen::<bool>() {
        UntypedValue::from(rng.gen::<i64>())
      } else {
        a
      };

      let expected = a.i64_ne(b);

      let mut cs = TestConstraintSystem::<F>::new();

      let alloc_expected = SwitchBoardCircuit::alloc_num(
        &mut cs,
        || "expected",
        || Ok(F::from(expected.to_bits())),
        switch,
      )
      .unwrap();

      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();

      let alloc_a =
        SwitchBoardCircuit::alloc_num(&mut cs, || "a", || Ok(F::from(a.to_bits())), switch)
          .unwrap();
      let alloc_b =
        SwitchBoardCircuit::alloc_num(&mut cs, || "b", || Ok(F::from(b.to_bits())), switch)
          .unwrap();

      let c = alu::ne(cs.namespace(|| "ne"), &alloc_a, &alloc_b, switch).unwrap();

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
