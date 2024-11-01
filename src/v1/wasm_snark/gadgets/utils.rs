use bellpepper_core::{num::AllocatedNum, ConstraintSystem};
use ff::PrimeField;

#[allow(dead_code)]
/// Allocate a variable that is set to zero
pub fn alloc_zero<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
) -> AllocatedNum<F> {
    let zero =
        AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || F::ZERO);
    cs.enforce(
        || "check zero is valid",
        |lc| lc,
        |lc| lc,
        |lc| lc + zero.get_variable(),
    );
    zero
}

/// Allocate a variable that is set to one
pub fn alloc_one<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
) -> AllocatedNum<F> {
    let one =
        AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || F::ONE);
    cs.enforce(
        || "check one is valid",
        |lc| lc + CS::one(),
        |lc| lc + CS::one(),
        |lc| lc + one.get_variable(),
    );

    one
}
