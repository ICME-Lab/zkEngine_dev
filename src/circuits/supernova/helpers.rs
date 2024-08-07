//! Helper functions for opcode circuits
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use ff::PrimeField;
use itertools::Itertools;

/// Fetch the next rom index and pc
pub fn next_rom_index_and_pc<F: PrimeField, CS: ConstraintSystem<F>>(
  cs: &mut CS,
  rom_index: &AllocatedNum<F>,
  allocated_rom: &[AllocatedNum<F>],
  pc: &AllocatedNum<F>,
) -> Result<(AllocatedNum<F>, AllocatedNum<F>), SynthesisError> {
  // Compute a selector for the current rom_index in allocated_rom
  let current_rom_selector = get_selector_vec_from_index(
    cs.namespace(|| "rom selector"),
    rom_index,
    allocated_rom.len(),
  )?;

  // Enforce that allocated_rom[rom_index] = pc
  for (rom, bit) in allocated_rom.iter().zip_eq(current_rom_selector.iter()) {
    // if bit = 1, then rom = pc
    // bit * (rom - pc) = 0
    cs.enforce(
      || "enforce bit = 1 => rom = pc",
      |lc| lc + &bit.lc(CS::one(), F::ONE),
      |lc| lc + rom.get_variable() - pc.get_variable(),
      |lc| lc,
    );
  }

  // Get the index of the current rom, or the index of the invalid rom if no match
  let current_rom_index = current_rom_selector
    .iter()
    .position(|bit| bit.get_value().is_some_and(|v| v))
    .unwrap_or_default();
  let next_rom_index = current_rom_index + 1;

  let rom_index_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next rom index"), || {
    F::from(next_rom_index as u64)
  });
  cs.enforce(
    || " rom_index + 1 - next_rom_index_num = 0",
    |lc| lc,
    |lc| lc,
    |lc| lc + rom_index.get_variable() + CS::one() - rom_index_next.get_variable(),
  );

  // Allocate the next pc without checking.
  // The next iteration will check whether the next pc is valid.
  let pc_next = AllocatedNum::alloc_infallible(cs.namespace(|| "next pc"), || {
    allocated_rom
      .get(next_rom_index)
      .and_then(|v| v.get_value())
      .unwrap_or(-F::ONE)
  });

  Ok((rom_index_next, pc_next))
}

/// Compute a selector vector `s` of size `num_indices`, such that
/// `s[i] == 1` if i == `target_index` and 0 otherwise.
pub fn get_selector_vec_from_index<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  target_index: &AllocatedNum<F>,
  num_indices: usize,
) -> Result<Vec<Boolean>, SynthesisError> {
  assert_ne!(num_indices, 0);

  // Compute the selector vector non-deterministically
  let selector = (0..num_indices)
    .map(|idx| {
      // b <- idx == target_index
      Ok(Boolean::Is(AllocatedBit::alloc(
        cs.namespace(|| format!("allocate s_{:?}", idx)),
        target_index.get_value().map(|v| v == F::from(idx as u64)),
      )?))
    })
    .collect::<Result<Vec<Boolean>, SynthesisError>>()?;

  // Enforce ∑ selector[i] = 1
  {
    let selected_sum = selector.iter().fold(LinearCombination::zero(), |lc, bit| {
      lc + &bit.lc(CS::one(), F::ONE)
    });
    cs.enforce(
      || "exactly-one-selection",
      |_| selected_sum,
      |lc| lc + CS::one(),
      |lc| lc + CS::one(),
    );
  }

  // Enforce `target_index - ∑ i * selector[i] = 0``
  {
    let selected_value = selector
      .iter()
      .enumerate()
      .fold(LinearCombination::zero(), |lc, (i, bit)| {
        lc + &bit.lc(CS::one(), F::from(i as u64))
      });
    cs.enforce(
      || "target_index - ∑ i * selector[i] = 0",
      |lc| lc,
      |lc| lc,
      |lc| lc + target_index.get_variable() - &selected_value,
    );
  }

  Ok(selector)
}

/// If condition return a otherwise b
pub fn conditionally_select<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  a: &AllocatedNum<Scalar>,
  b: &AllocatedNum<Scalar>,
  condition: &Boolean,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? {
      Ok(*a.get_value().get()?)
    } else {
      Ok(*b.get_value().get()?)
    }
  })?;

  // a * condition + b*(1-condition) = c ->
  // a * condition - b*condition = c - b
  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable() - b.get_variable(),
    |_| condition.lc(CS::one(), Scalar::ONE),
    |lc| lc + c.get_variable() - b.get_variable(),
  );

  Ok(c)
}

/// Check if the number fits in n_bits
pub fn fits_in_bits<F: PrimeField, CS: ConstraintSystem<F>>(
  num: &AllocatedNum<F>,
  mut cs: CS,
  n_bits: usize,
) -> Result<(), SynthesisError> {
  let v = num.get_value();

  // Allocate all but the first bit.
  let bits: Vec<Variable> = (1..n_bits)
    .map(|i| {
      cs.alloc(
        || format!("bit {i}"),
        || {
          let r = if *v.grab()?.get_bit(i).grab()? {
            F::ONE
          } else {
            F::ZERO
          };
          Ok(r)
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
      lc = lc + num.get_variable();
      for v in bits.iter() {
        f = f.double();
        lc = lc - (f, *v);
      }
      lc
    },
    |mut lc| {
      lc = lc + CS::one();
      let mut f = F::ONE;
      lc = lc - num.get_variable();
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

/// Same as the above but Condition is an `AllocatedNum` that needs to be
/// 0 or 1. 1 => True, 0 => False
pub fn conditionally_select2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(*a.get_value().get()?)
    } else {
      Ok(*b.get_value().get()?)
    }
  })?;

  // a * condition + b*(1-condition) = c ->
  // a * condition - b*condition = c - b
  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc + condition.get_variable(),
    |lc| lc + c.get_variable() - b.get_variable(),
  );

  Ok(c)
}

trait OptionExt<T> {
  fn grab(&self) -> Result<&T, SynthesisError>;
  #[allow(dead_code)]
  fn grab_mut(&mut self) -> Result<&mut T, SynthesisError>;
}

impl<T> OptionExt<T> for Option<T> {
  fn grab(&self) -> Result<&T, SynthesisError> {
    self.as_ref().ok_or(SynthesisError::AssignmentMissing)
  }
  fn grab_mut(&mut self) -> Result<&mut T, SynthesisError> {
    self.as_mut().ok_or(SynthesisError::AssignmentMissing)
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

#[allow(dead_code)]
/// Convert a field element to a u64
pub fn field_element_to_u64<Scalar: PrimeField>(element: &Scalar) -> u64 {
  let mut byte_array = [0u8; 8];
  byte_array.copy_from_slice(&element.to_repr().as_ref()[0..8]);
  u64::from_le_bytes(byte_array)
}

/// Convert string to u128
pub fn string_to_u128(s: &str) -> u128 {
  let mut byte_array = [0u8; 16];
  byte_array.copy_from_slice(&s.as_bytes()[0..16]);
  u128::from_le_bytes(byte_array)
}
