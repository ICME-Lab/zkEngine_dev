use crate::v1::wasm_snark::switchboard::WASMTransitionCircuit as SwitchBoardCircuit;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

pub fn add32<F, CS>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  a_bits: u32,
  b_bits: u32,
  switch: F,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let zero = F::ZERO;
  let range = F::from(1u64 << 32);
  let ON: F = zero - range;

  let (c, of) = a_bits.overflowing_add(b_bits);
  let o = if of { ON } else { zero };

  // construct witness
  let c = SwitchBoardCircuit::alloc_num(&mut cs, || "c", || Ok(F::from(c as u64)), switch)?;

  // note, this is "advice"
  let o = SwitchBoardCircuit::alloc_num(&mut cs, || "o", || Ok(o), switch)?;
  let range = SwitchBoardCircuit::alloc_num(&mut cs, || "O", || Ok(range), switch)?;

  // check o * (o + O) == 0
  cs.enforce(
    || "check o * (o + O) == 0",
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

#[cfg(test)]
mod tests {

  use bellpepper_core::{num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem};
  use nova::{provider::Bn256EngineIPA, traits::Engine};
  use rand::{rngs::StdRng, Rng, SeedableRng};
  use wasmi::core::UntypedValue;

  use crate::v1::wasm_snark::switchboard::alu::int32::add32;

  type E = Bn256EngineIPA;
  type F = <E as Engine>::Scalar;

  #[test]
  fn test_add32() {
    let mut rng = StdRng::from_seed([100u8; 32]);

    let switch = F::one();

    for _ in 0..1000 {
      let a = UntypedValue::from(rng.gen::<i32>());
      let b = UntypedValue::from(rng.gen::<i32>());
      let expected = a.i32_add(b);

      let mut cs = TestConstraintSystem::<F>::new();

      let one_var = <TestConstraintSystem<F> as ConstraintSystem<F>>::one();
      let alloc_expected = AllocatedNum::alloc(cs.namespace(|| "expected"), || {
        Ok(F::from(expected.to_bits()))
      })
      .unwrap();

      let alloc_a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(F::from(a.to_bits()))).unwrap();
      let alloc_b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(F::from(b.to_bits()))).unwrap();

      let c = add32(
        cs.namespace(|| "add32"),
        &alloc_a,
        &alloc_b,
        a.to_bits() as u32,
        b.to_bits() as u32,
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
}
