//! A batched ROM circuit that can be used to run 10 shards of a WASM program in parallel.
use crate::{
  circuits::{
    gadgets::{signed64::Int64, uint64::UInt64},
    supernova::helpers::next_rom_index_and_pc,
  },
  step_generator, wasm_circuit,
};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use core::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use nova::{
  supernova::{NonUniformCircuit, StepCircuit, TrivialSecondaryCircuit},
  traits::{CurveCycleEquipped, Dual, Engine},
};
use paste::paste;
use wasmi::{
  etable::step_info::{BinOp, BitOp, RelOp, ShiftOp, StepInfo, UnaryOp},
  mtable::VarType,
};

step_generator!(
  // CircuitName
  Batched
  // How many steps to run
  StepCircuit0,
  StepCircuit1,
  StepCircuit2,
  StepCircuit3,
  StepCircuit4,
  StepCircuit5,
  StepCircuit6,
  StepCircuit7,
  StepCircuit8,
  StepCircuit9,
  StepCircuit10
);
