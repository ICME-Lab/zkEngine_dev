//! Implements a Etable ROM to constraints the sequence of execution order for opcode, in the
//! Execution table (ETable)
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use core::marker::PhantomData;
use ff::{Field, PrimeField, PrimeFieldBits};
use nova::{
  supernova::{
    NonUniformCircuit, PublicParams, RecursiveSNARK, StepCircuit, TrivialSecondaryCircuit,
  },
  traits::{snark::default_ck_hint, CurveCycleEquipped, Dual, Engine},
};

use crate::errors::ProvingError;

use super::step_circuits::{
  control_ops::{BrCircuit, BrIfEqzCircuit, BrIfNezCircuit},
  integer::{
    bin_op::{
      AddCircuit, DivSignedCircuit, DivUnsignedCircuit, MulCircuit, RemSignedCircuit,
      RemUnSignedCircuit, SubCircuit,
    },
    bit_op::{AndCircuit, OrCircuit, XorCircuit},
    relational_op::{
      EqCircuit, EqzCircuit, GeSignedCircuit, GeUnsignedCircuit, GtSignedCircuit,
      GtUnsignedCircuit, LeSignedCircuit, LeUnsignedCircuit, LtCircuit, LtUnsignedCircuit,
      NeCircuit,
    },
    shift_op::{
      I32RotlCircuit, I32RotrCircuit, RotlCircuit, RotrCircuit, ShlCircuit, ShrSignedCircuit,
      ShrUnsignedCircuit,
    },
    unary_op::{ClzCircuit, CtzCircuit, I32ClzCircuit, I32CtzCircuit, PopCntCircuit},
  },
  parametric_ops::SelectCircuit,
};

//use std::time::Instant;

/// The Etable ROM to constraint the sequence of execution order for opcode, in the Execution table
pub struct EtableROM<E1> {
  /// Stores opcode index in sequence related to the ETable
  pub rom: Vec<usize>,
  tracer_values: Vec<(u64, u64, u64)>,
  /// Counter to keep track of the current opcode index, to see which tracer value to use for which
  /// opcode
  pub counter: i32,
  _p: PhantomData<E1>,
}

impl<E1> EtableROM<E1> {
  /// Create a new Etable ROM
  pub fn new(rom: Vec<usize>, tracer_values: Vec<(u64, u64, u64)>) -> Self {
    Self {
      rom,
      tracer_values,
      counter: 0,
      _p: Default::default(),
    }
  }
}

/// Circuit for the Etable ROM to match opcode index with the corresponding circuit
#[derive(Clone, Debug)]
pub enum OpcodeCircuits<F: PrimeField + PartialOrd + PrimeFieldBits> {
  /// i32.add, i64.add
  Add(AddCircuit<F>),
  /// i32.eqz, i64.eqz
  Eqz(EqzCircuit<F>),
  /// i32.eq, i64.eq
  Eq(EqCircuit<F>),
  /// i32.ne, i64.ne
  Ne(NeCircuit<F>),
  /// i32.lt_s, i64.lt_s
  Lt(LtCircuit<F>),
  /// i32.lt_u, i64.lt_u
  LtUnsigned(LtUnsignedCircuit<F>),
  /// i32.gt_s, i64.gt_s
  GtSigned(GtSignedCircuit<F>),
  /// i32.gt_u, i64.gt_u
  GtUnsigned(GtUnsignedCircuit<F>),
  /// i32.le_s, i64.le_s
  LeSigned(LeSignedCircuit<F>),
  /// i32.le_u, i64.le_u
  LeUnsigned(LeUnsignedCircuit<F>),
  /// i32.ge_s, i64.ge_s
  GeSigned(GeSignedCircuit<F>),
  /// i32.ge_u, i64.ge_u
  GeUnsigned(GeUnsignedCircuit<F>),
  /// i32.sub, i64.sub
  Sub(SubCircuit<F>),
  /// i32.mul, i64.mul
  Mul(MulCircuit<F>),
  /// i32.div_s, i64.div_s
  DivSigned(DivSignedCircuit<F>),
  /// i32.div_u, i64.div_u
  DivUnsigned(DivUnsignedCircuit<F>),
  /// i32.rem_s, i64.rem_s
  RemSigned(RemSignedCircuit<F>),
  /// i32.rem_u, i64.rem_u
  RemUnSigned(RemUnSignedCircuit<F>),
  /// i32.and, i64.and
  And(AndCircuit<F>),
  /// i32.or, i64.or
  Or(OrCircuit<F>),
  /// i32.xor, i64.xor
  Xor(XorCircuit<F>),
  /// i32.shl, i64.shl
  Shl(ShlCircuit<F>),
  /// i32.shr_s, i64.shr_s
  ShrSigned(ShrSignedCircuit<F>),
  /// i32.shr_u, i64.shr_u
  ShrUnsigned(ShrUnsignedCircuit<F>),
  /// i64.rotl
  Rotl(RotlCircuit<F>),
  /// i64.rotr
  Rotr(RotrCircuit<F>),
  /// i64.clz
  Clz(ClzCircuit<F>),
  /// i32.ctz, i64.ctz
  Ctz(CtzCircuit<F>),
  /// i32.popcnt, i64.popcnt
  PopCnt(PopCntCircuit<F>),
  /// select
  Select(SelectCircuit<F>),
  /// i32.clz
  I32Clz(I32ClzCircuit<F>),
  /// i32.ctz
  I32Ctz(I32CtzCircuit<F>),
  /// i32.rotl
  I32RotlCircuit(I32RotlCircuit<F>),
  /// i32.rotr
  I32RotrCircuit(I32RotrCircuit<F>),
  // Br
  Br(BrCircuit<F>),
  // BrIfNez
  BrIfNez(BrIfNezCircuit<F>),
  // BrIfEqz
  BrIfEqz(BrIfEqzCircuit<F>),
}

impl<F: PrimeField + PartialOrd + PrimeFieldBits> StepCircuit<F> for OpcodeCircuits<F> {
  fn arity(&self) -> usize {
    match self {
      Self::Add(x) => x.arity(),
      Self::Eqz(x) => x.arity(),
      Self::Eq(x) => x.arity(),
      Self::Ne(x) => x.arity(),
      Self::Lt(x) => x.arity(),
      Self::LtUnsigned(x) => x.arity(),
      Self::GtSigned(x) => x.arity(),
      Self::GtUnsigned(x) => x.arity(),
      Self::LeSigned(x) => x.arity(),
      Self::LeUnsigned(x) => x.arity(),
      Self::GeSigned(x) => x.arity(),
      Self::GeUnsigned(x) => x.arity(),
      Self::Sub(x) => x.arity(),
      Self::Mul(x) => x.arity(),
      Self::DivSigned(x) => x.arity(),
      Self::DivUnsigned(x) => x.arity(),
      Self::RemSigned(x) => x.arity(),
      Self::RemUnSigned(x) => x.arity(),
      Self::And(x) => x.arity(),
      Self::Or(x) => x.arity(),
      Self::Xor(x) => x.arity(),
      Self::Shl(x) => x.arity(),
      Self::ShrSigned(x) => x.arity(),
      Self::ShrUnsigned(x) => x.arity(),
      Self::Rotl(x) => x.arity(),
      Self::Rotr(x) => x.arity(),
      Self::Clz(x) => x.arity(),
      Self::Ctz(x) => x.arity(),
      Self::PopCnt(x) => x.arity(),
      Self::Select(x) => x.arity(),
      Self::I32Clz(x) => x.arity(),
      Self::I32Ctz(x) => x.arity(),
      Self::I32RotlCircuit(x) => x.arity(),
      Self::I32RotrCircuit(x) => x.arity(),
      Self::Br(x) => x.arity(),
      Self::BrIfNez(x) => x.arity(),
      Self::BrIfEqz(x) => x.arity(),
    }
  }

  fn circuit_index(&self) -> usize {
    match self {
      Self::Add(x) => x.circuit_index(),
      Self::Eqz(x) => x.circuit_index(),
      Self::Eq(x) => x.circuit_index(),
      Self::Ne(x) => x.circuit_index(),
      Self::Lt(x) => x.circuit_index(),
      Self::LtUnsigned(x) => x.circuit_index(),
      Self::GtSigned(x) => x.circuit_index(),
      Self::GtUnsigned(x) => x.circuit_index(),
      Self::LeSigned(x) => x.circuit_index(),
      Self::LeUnsigned(x) => x.circuit_index(),
      Self::GeSigned(x) => x.circuit_index(),
      Self::GeUnsigned(x) => x.circuit_index(),
      Self::Sub(x) => x.circuit_index(),
      Self::Mul(x) => x.circuit_index(),
      Self::DivSigned(x) => x.circuit_index(),
      Self::DivUnsigned(x) => x.circuit_index(),
      Self::RemSigned(x) => x.circuit_index(),
      Self::RemUnSigned(x) => x.circuit_index(),
      Self::And(x) => x.circuit_index(),
      Self::Or(x) => x.circuit_index(),
      Self::Xor(x) => x.circuit_index(),
      Self::Shl(x) => x.circuit_index(),
      Self::ShrSigned(x) => x.circuit_index(),
      Self::ShrUnsigned(x) => x.circuit_index(),
      Self::Rotl(x) => x.circuit_index(),
      Self::Rotr(x) => x.circuit_index(),
      Self::Clz(x) => x.circuit_index(),
      Self::Ctz(x) => x.circuit_index(),
      Self::PopCnt(x) => x.circuit_index(),
      Self::Select(x) => x.circuit_index(),
      Self::I32Clz(x) => x.circuit_index(),
      Self::I32Ctz(x) => x.circuit_index(),
      Self::I32RotlCircuit(x) => x.circuit_index(),
      Self::I32RotrCircuit(x) => x.circuit_index(),
      Self::Br(x) => x.circuit_index(),
      Self::BrIfNez(x) => x.circuit_index(),
      Self::BrIfEqz(x) => x.circuit_index(),
    }
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F>>,
    z: &[AllocatedNum<F>],
  ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
    match self {
      Self::Add(x) => x.synthesize(cs, pc, z),
      Self::Eqz(x) => x.synthesize(cs, pc, z),
      Self::Eq(x) => x.synthesize(cs, pc, z),
      Self::Ne(x) => x.synthesize(cs, pc, z),
      Self::Lt(x) => x.synthesize(cs, pc, z),
      Self::LtUnsigned(x) => x.synthesize(cs, pc, z),
      Self::GtSigned(x) => x.synthesize(cs, pc, z),
      Self::GtUnsigned(x) => x.synthesize(cs, pc, z),
      Self::LeSigned(x) => x.synthesize(cs, pc, z),
      Self::LeUnsigned(x) => x.synthesize(cs, pc, z),
      Self::GeSigned(x) => x.synthesize(cs, pc, z),
      Self::GeUnsigned(x) => x.synthesize(cs, pc, z),
      Self::Sub(x) => x.synthesize(cs, pc, z),
      Self::Mul(x) => x.synthesize(cs, pc, z),
      Self::DivSigned(x) => x.synthesize(cs, pc, z),
      Self::DivUnsigned(x) => x.synthesize(cs, pc, z),
      Self::RemSigned(x) => x.synthesize(cs, pc, z),
      Self::RemUnSigned(x) => x.synthesize(cs, pc, z),
      Self::And(x) => x.synthesize(cs, pc, z),
      Self::Or(x) => x.synthesize(cs, pc, z),
      Self::Xor(x) => x.synthesize(cs, pc, z),
      Self::Shl(x) => x.synthesize(cs, pc, z),
      Self::ShrSigned(x) => x.synthesize(cs, pc, z),
      Self::ShrUnsigned(x) => x.synthesize(cs, pc, z),
      Self::Rotl(x) => x.synthesize(cs, pc, z),
      Self::Rotr(x) => x.synthesize(cs, pc, z),
      Self::Clz(x) => x.synthesize(cs, pc, z),
      Self::Ctz(x) => x.synthesize(cs, pc, z),
      Self::PopCnt(x) => x.synthesize(cs, pc, z),
      Self::Select(x) => x.synthesize(cs, pc, z),
      Self::I32Clz(x) => x.synthesize(cs, pc, z),
      Self::I32Ctz(x) => x.synthesize(cs, pc, z),
      Self::I32RotlCircuit(x) => x.synthesize(cs, pc, z),
      Self::I32RotrCircuit(x) => x.synthesize(cs, pc, z),
      Self::Br(x) => x.synthesize(cs, pc, z),
      Self::BrIfNez(x) => x.synthesize(cs, pc, z),
      Self::BrIfEqz(x) => x.synthesize(cs, pc, z),
    }
  }
}

impl<E1> NonUniformCircuit<E1> for EtableROM<E1>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd,
{
  type C1 = OpcodeCircuits<E1::Scalar>;
  type C2 = TrivialSecondaryCircuit<<Dual<E1> as Engine>::Scalar>;

  fn num_circuits(&self) -> usize {
    37
  }

  fn primary_circuit(&self, circuit_index: usize) -> OpcodeCircuits<E1::Scalar> {
    let (a, b, _) = self.tracer_values[self.counter as usize];

    let mut fixed_rom = vec![];
    fixed_rom.extend(
      self
        .rom
        .iter()
        .map(|opcode| <E1 as Engine>::Scalar::from(*opcode as u64)),
    );

    match circuit_index {
      0 => OpcodeCircuits::Add(AddCircuit::new(circuit_index, fixed_rom, (a, b))),
      1 => OpcodeCircuits::Eqz(EqzCircuit::new(circuit_index, fixed_rom, (a, b))),
      2 => OpcodeCircuits::Eq(EqCircuit::new(circuit_index, fixed_rom, (a, b))),
      3 => OpcodeCircuits::Ne(NeCircuit::new(circuit_index, fixed_rom, (a, b))),
      4 => OpcodeCircuits::Lt(LtCircuit::new(circuit_index, fixed_rom, (a, b))),
      5 => OpcodeCircuits::LtUnsigned(LtUnsignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      6 => OpcodeCircuits::GtSigned(GtSignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      7 => OpcodeCircuits::GtUnsigned(GtUnsignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      8 => OpcodeCircuits::LeSigned(LeSignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      9 => OpcodeCircuits::LeUnsigned(LeUnsignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      10 => OpcodeCircuits::GeSigned(GeSignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      11 => OpcodeCircuits::GeUnsigned(GeUnsignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      12 => OpcodeCircuits::Sub(SubCircuit::new(circuit_index, fixed_rom, (a, b))),
      13 => OpcodeCircuits::Mul(MulCircuit::new(circuit_index, fixed_rom, (a, b))),
      14 => OpcodeCircuits::DivSigned(DivSignedCircuit::new(
        circuit_index,
        fixed_rom,
        self.tracer_values[self.counter as usize],
      )),
      15 => OpcodeCircuits::DivUnsigned(DivUnsignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      16 => OpcodeCircuits::RemSigned(RemSignedCircuit::new(
        circuit_index,
        fixed_rom,
        self.tracer_values[self.counter as usize],
      )),
      17 => OpcodeCircuits::RemUnSigned(RemUnSignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      18 => OpcodeCircuits::And(AndCircuit::new(circuit_index, fixed_rom, (a, b))),
      19 => OpcodeCircuits::Or(OrCircuit::new(circuit_index, fixed_rom, (a, b))),
      20 => OpcodeCircuits::Xor(XorCircuit::new(circuit_index, fixed_rom, (a, b))),
      21 => OpcodeCircuits::Shl(ShlCircuit::new(circuit_index, fixed_rom, (a, b))),
      22 => OpcodeCircuits::ShrSigned(ShrSignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      23 => OpcodeCircuits::ShrUnsigned(ShrUnsignedCircuit::new(circuit_index, fixed_rom, (a, b))),
      24 => OpcodeCircuits::Rotl(RotlCircuit::new(circuit_index, fixed_rom, (a, b))),
      25 => OpcodeCircuits::Rotr(RotrCircuit::new(circuit_index, fixed_rom, (a, b))),
      26 => OpcodeCircuits::Clz(ClzCircuit::new(circuit_index, fixed_rom, (a, b))),
      27 => OpcodeCircuits::Ctz(CtzCircuit::new(circuit_index, fixed_rom, (a, b))),
      28 => OpcodeCircuits::PopCnt(PopCntCircuit::new(circuit_index, fixed_rom, (a, b))),
      29 => OpcodeCircuits::Select(SelectCircuit::new(
        circuit_index,
        fixed_rom,
        self.tracer_values[self.counter as usize],
      )),
      30 => OpcodeCircuits::I32Clz(I32ClzCircuit::new(circuit_index, fixed_rom, (a, b))),
      31 => OpcodeCircuits::I32Ctz(I32CtzCircuit::new(circuit_index, fixed_rom, (a, b))),
      32 => OpcodeCircuits::I32RotlCircuit(I32RotlCircuit::new(circuit_index, fixed_rom, (a, b))),
      33 => OpcodeCircuits::I32RotrCircuit(I32RotrCircuit::new(circuit_index, fixed_rom, (a, b))),
      34 => OpcodeCircuits::Br(BrCircuit::new(circuit_index, fixed_rom, a)),
      35 => OpcodeCircuits::BrIfNez(BrIfNezCircuit::new(circuit_index, fixed_rom, (a, b))),
      36 => OpcodeCircuits::BrIfEqz(BrIfEqzCircuit::new(circuit_index, fixed_rom, (a, b))),
      _ => panic!("unsupported primary circuit index: {}", circuit_index),
    }
  }

  fn secondary_circuit(&self) -> Self::C2 {
    Default::default()
  }

  fn initial_circuit_index(&self) -> usize {
    self.rom[0]
  }
}

/// Prove execution of a WASM using NIVC
pub fn wasm_nivc<E1>(
  rom: Vec<usize>,
  tracer_values: Vec<(u64, u64, u64)>,
  _overwrite_pp: bool,
  should_stop: impl Fn() -> bool,
) -> Result<(), ProvingError>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd,
{
  //let total_time = Instant::now();
  let mut test_rom = EtableROM::<E1>::new(rom, tracer_values.to_vec());

  let pp = PublicParams::setup(&test_rom, &*default_ck_hint(), &*default_ck_hint());

  // extend z0_primary/secondary with rom content
  let mut z0_primary = vec![<E1 as Engine>::Scalar::ONE];
  z0_primary.push(<E1 as Engine>::Scalar::ZERO); // rom_index = 0
  let z0_secondary = vec![<Dual<E1> as Engine>::Scalar::ONE];

  let mut recursive_snark_option: Option<RecursiveSNARK<E1>> = None;

  let last_index = test_rom.rom.len() - 1;
  tracing::info!("Starting NIVC");

  //let time = Instant::now();
  for (i, &op_code) in test_rom.rom.iter().enumerate() {
    if i % 10 == 0 && should_stop() {
      return Err(ProvingError::Interrupted);
    }

    let op_code_err = format!("index:{}, failed to run on opcode {:?}", i, op_code);
    let circuit_primary = test_rom.primary_circuit(op_code);
    tracing::debug!("index:{}, opcode:{}", i, op_code);
    let circuit_secondary = test_rom.secondary_circuit();

    let mut recursive_snark = recursive_snark_option.unwrap_or_else(|| {
      RecursiveSNARK::new(
        &pp,
        &test_rom,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
      )
      .expect(&op_code_err)
    });

    recursive_snark
      .prove_step(&pp, &circuit_primary, &circuit_secondary)
      .expect(&op_code_err);

    if i == last_index {
      recursive_snark
        .verify(&pp, &z0_primary, &z0_secondary)
        .expect(&op_code_err);
    }
    test_rom.counter += 1;
    recursive_snark_option = Some(recursive_snark)
  }
  //tracing::info!("NIVC done in {:?}", time.elapsed());
  //let total_elapsed_time = total_time.elapsed();

  //tracing::info!("The full run took {:?}", total_elapsed_time);

  assert!(recursive_snark_option.is_some());
  Ok(())
}
