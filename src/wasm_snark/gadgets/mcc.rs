use crate::wasm_snark::gadgets::int::{add, mul, sub};
use bellpepper::gadgets::Assignment;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

/// Does a read-solomon fingerprint on the (a,v,t) tuple and then subtracts's it
/// by alpha to compute a polynomials roots
///
/// Hash(gamma, alpha, a, v, t) → h
// 1. return (a + v · gamma + t · gamma^2 − alpha)
pub fn randomized_hash_func<F, CS>(
  mut cs: CS,
  addr: &AllocatedNum<F>,
  val: &AllocatedNum<F>,
  ts: &AllocatedNum<F>,
  gamma: &AllocatedNum<F>,
  alpha: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  // ts · gamma^2
  let gamma_squared = mul(cs.namespace(|| "gamma * gamma"), gamma, gamma)?;
  let ts_term = mul(cs.namespace(|| "ts * gamma_squared"), ts, &gamma_squared)?;

  // v · gamma
  let val_term = mul(cs.namespace(|| "val * gamma"), val, gamma)?;

  // addr + val_term
  let sum_addr_val_term = add(cs.namespace(|| "addr + val_term"), addr, &val_term)?;

  // addr + v · gamma + ts · gamma^2
  let fingerprint = add(
    cs.namespace(|| "addr + v · gamma + ts · gamma^2"),
    &sum_addr_val_term,
    &ts_term,
  )?;

  // (a + v · gamma + t · gamma^2 − alpha)
  sub(cs.namespace(|| "fingerprint - alpha"), &fingerprint, alpha)
}

/// Converts an addr, val, ts tuple `(usize, u64, u64)` to a `Vec<Scalar>`
pub fn alloc_avt_tuple<F, CS>(
  mut cs: CS,
  tuple: (usize, u64, u64),
) -> Result<(AllocatedNum<F>, AllocatedNum<F>, AllocatedNum<F>), SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let (addr, val, ts) = tuple;
  let addr = AllocatedNum::alloc(cs.namespace(|| "addr"), || Ok(F::from(addr as u64)))?;
  let val = AllocatedNum::alloc(cs.namespace(|| "val"), || Ok(F::from(val)))?;
  let ts = AllocatedNum::alloc(cs.namespace(|| "ts"), || Ok(F::from(ts)))?;

  Ok((addr, val, ts))
}

/// Calculate the inverse of an allocated number
///
/// We are guaranteed (by some  neglible soundness error) to have the hash != 0
pub fn countable_hash<F, CS>(
  mut cs: CS,
  hash: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let inverse = AllocatedNum::alloc(cs.namespace(|| "inverse"), || {
    let tmp = hash.get_value().get()?.invert();
    if tmp.is_some().into() {
      Ok(tmp.unwrap())
    } else {
      Ok(F::ONE)
    }
  })?;

  // Produce counting_element
  let counting_element = mul(cs.namespace(|| "count"), hash, &inverse)?;

  // Check counting_element = 1
  cs.enforce(
    || "counting_element = 1",
    |lc| lc + counting_element.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + CS::one(),
  );
  Ok(counting_element)
}
