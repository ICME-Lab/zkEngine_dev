use nova::frontend::gadgets::Assignment;
use nova::frontend::{
  num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use ff::PrimeField;

pub struct Num<F>
where
  F: PrimeField,
{
  value: Option<F>,
  lc: LinearCombination<F>,
}

impl<F> Num<F>
where
  F: PrimeField,
{
  pub fn alloc<CS, Func>(mut cs: CS, value: Func) -> Result<Self, SynthesisError>
  where
    CS: ConstraintSystem<F>,
    Func: FnOnce() -> Result<F, SynthesisError>,
  {
    let mut new_value = None;
    let new_var = cs.alloc(
      || "num",
      || {
        let tmp = value()?;
        new_value = Some(tmp);
        Ok(tmp)
      },
    )?;
    Ok(Self {
      value: new_value,
      lc: LinearCombination::zero() + new_var,
    })
  }

  pub fn fits_in_bits<CS>(&self, mut cs: CS, n_bits: usize) -> Result<(), SynthesisError>
  where
    CS: ConstraintSystem<F>,
  {
    // Allocate all but the first bit
    let bits: Vec<Variable> = (1..n_bits)
      .map(|i| {
        cs.alloc(
          || format!("bit {i}"),
          || {
            if *self.value.get()?.get_bit(i).get()? {
              Ok(F::ONE)
            } else {
              Ok(F::ZERO)
            }
          },
        )
      })
      .collect::<Result<_, _>>()?;
    for (i, v) in bits.iter().enumerate() {
      cs.enforce(
        || format!("{i} is bit"),
        |lc| lc + *v,
        |lc| lc + CS::one() - *v,
        |lc| lc,
      )
    }
    // Last bit
    cs.enforce(
      || "last bit",
      |mut lc| {
        let mut f = F::ONE;
        lc = lc + &self.lc;
        for v in bits.iter() {
          f = f.double();
          lc = lc - (f, *v);
        }
        lc
      },
      |mut lc| {
        lc = lc + CS::one();
        let mut f = F::ONE;
        lc = lc - &self.lc;
        for v in bits.iter() {
          f = f.double();
          lc = lc + (f, *v);
        }
        lc
      },
      |lc| lc,
    );
    Ok(())
  }

  pub fn as_allocated_num<CS: ConstraintSystem<F>>(
    &self,
    mut cs: CS,
  ) -> Result<AllocatedNum<F>, SynthesisError> {
    let new = AllocatedNum::alloc(cs.namespace(|| "alloc"), || Ok(*self.value.get()?))?;
    cs.enforce(
      || "eq",
      |lc| lc,
      |lc| lc,
      |lc| lc + new.get_variable() - &self.lc,
    );
    Ok(new)
  }
}

trait BitAccess {
  fn get_bit(&self, i: usize) -> Option<bool>;
}

impl<Scalar: PrimeField> BitAccess for Scalar {
  fn get_bit(&self, i: usize) -> Option<bool> {
    if i as u32 >= Scalar::NUM_BITS {
      return None;
    }

    let (byte_pos, bit_pos) = (i / 8, i % 8);
    let byte = self.to_repr().as_ref()[byte_pos];
    let bit = byte >> bit_pos & 1;
    Some(bit == 1)
  }
}
