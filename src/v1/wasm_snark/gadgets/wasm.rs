use bellpepper_core::{boolean::AllocatedBit, num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use wasmi::Instruction;

use super::int::{add, mul, sub};

///  arithmetic logic unit (ALU)
///
/// A combinational digital circuit that performs arithmetic and bitwise
/// operations on integer binary numbers.
pub fn alu<CS, F>(
  mut cs: CS,
  X: &AllocatedNum<F>,
  Y: &AllocatedNum<F>,
  ZJ: &mut Vec<AllocatedNum<F>>,
) -> Result<(), SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  // I64Add
  alu_add(cs.namespace(|| "alu_add"), X, Y, ZJ)?;

  // I64Mul
  alu_mul(cs.namespace(|| "alu_mul"), X, Y, ZJ)?;

  // I64Sub
  alu_sub(cs.namespace(|| "alu_sub"), X, Y, ZJ)?;

  Ok(())
}

/// Assigns the result of the instruction execution as the immediate value
/// parsed when the instruction was decoded
pub fn imm_const_opc<CS, F>(
  mut cs: CS,
  Z: &AllocatedNum<F>,
  ZJ: &mut Vec<AllocatedNum<F>>,
) -> Result<(), SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let imm_const = AllocatedNum::alloc(cs.namespace(|| "imm_const"), || {
    Z.get_value().ok_or(SynthesisError::AssignmentMissing)
  })?;

  ZJ.push(imm_const);

  Ok(())
}

/// Adds the two argument values of the instruction and then pushes the result
/// to the vector which contains all the possible instruction result values
/// (which will later be constrianed to the correct result value)
pub fn alu_add<CS, F>(
  mut cs: CS,
  X: &AllocatedNum<F>,
  Y: &AllocatedNum<F>,
  ZJ: &mut Vec<AllocatedNum<F>>,
) -> Result<(), SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  ZJ.push(add(cs.namespace(|| "X+Y"), X, Y)?);
  Ok(())
}

/// Multiplies the two argument values
pub fn alu_mul<CS, F>(
  mut cs: CS,
  X: &AllocatedNum<F>,
  Y: &AllocatedNum<F>,
  ZJ: &mut Vec<AllocatedNum<F>>,
) -> Result<(), SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  ZJ.push(mul(cs.namespace(|| "X+Y"), X, Y)?);
  Ok(())
}

/// Subtracts the two argument values
pub fn alu_sub<CS, F>(
  mut cs: CS,
  X: &AllocatedNum<F>,
  Y: &AllocatedNum<F>,
  ZJ: &mut Vec<AllocatedNum<F>>,
) -> Result<(), SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  ZJ.push(sub(cs.namespace(|| "X+Y"), X, Y)?);
  Ok(())
}

/// Produce bits that are used to constraint the result of the instruction
/// execution
pub fn parse_J<CS, F>(mut cs: CS, vm_J: u64) -> Result<Vec<AllocatedBit>, SynthesisError>
where
  F: PrimeField,
  CS: ConstraintSystem<F>,
{
  let mut J_bits = Vec::new();
  for j in 0..Instruction::MAX_J {
    J_bits.push(AllocatedBit::alloc(
      cs.namespace(|| format!("J={j}")),
      Some(j == vm_J),
    )?);
  }

  Ok(J_bits)
}
