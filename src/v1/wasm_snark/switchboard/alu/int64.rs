use crate::v1::wasm_snark::switchboard::WASMTransitionCircuit as SwitchBoardCircuit;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

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
  let range = SwitchBoardCircuit::alloc_num(&mut cs, || "O", || Ok(range), switch)?;

  // check o * (o + range) == 0
  cs.enforce(
    || "check o * (o + range) == 0",
    |lc| lc + o.get_variable(),
    |lc| lc + o.get_variable() + range.get_variable(),
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
  let range = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "range",
    || Ok(F::from_u128(1_u128 << 64)),
    switch,
  )?;
  let trunc = SwitchBoardCircuit::alloc_num(
    &mut cs,
    || "trunc",
    || Ok(F::from_u128(c_128_bits >> 64)),
    switch,
  )?;
  let left_overs = range.mul(cs.namespace(|| "left_overs"), &trunc)?;

  /*
   * Enforce c_128 is the product of a and b
   */
  let c_intermediate = a.mul(cs.namespace(|| "c_intermediate"), b)?;

  // c == c_128 - left_overs
  cs.enforce(
    || "c == c_128 - left_overs",
    |lc| lc + c.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + c_intermediate.get_variable() - left_overs.get_variable(),
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

  // a_31 + b_31 - 2 a_31 b_31 = ds  (XOR)
  cs.enforce(
    || "X_31 + Y_31 - 2 X_31 Y_31 = ds",
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

#[cfg(test)]
mod tests {

  use bellpepper_core::{test_cs::TestConstraintSystem, ConstraintSystem};
  use nova::{provider::Bn256EngineIPA, traits::Engine};
  use rand::{rngs::StdRng, Rng, SeedableRng};
  use wasmi::core::UntypedValue;

  use crate::v1::wasm_snark::switchboard::{
    alu::int64::sub64, WASMTransitionCircuit as SwitchBoardCircuit,
  };

  use super::{add64, mul64};

  type E = Bn256EngineIPA;
  type F = <E as Engine>::Scalar;

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
}
