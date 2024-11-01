use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

#[allow(dead_code)]
fn alloc_scalar_vec<F, CS>(mut cs: CS, z: &[F]) -> Result<Vec<AllocatedNum<F>>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  z.iter()
    .enumerate()
    .map(|(i, zi)| AllocatedNum::alloc(cs.namespace(|| format!("z{i}")), || Ok(*zi)))
    .collect()
}
