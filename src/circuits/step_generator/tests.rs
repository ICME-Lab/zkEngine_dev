use std::path::PathBuf;

use crate::{
  args::{WASMArgsBuilder, WASMCtx},
  circuits::{
    gadgets::{signed64::Int64, uint64::UInt64},
    supernova::helpers::next_rom_index_and_pc,
  },
  traits::args::ZKWASMContext,
};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use core::marker::PhantomData;
use ff::{Field, PrimeField, PrimeFieldBits};
use nova::{
  supernova::{
    NonUniformCircuit, PublicParams, RecursiveSNARK, StepCircuit, TrivialSecondaryCircuit,
  },
  traits::{snark::default_ck_hint, CurveCycleEquipped, Dual, Engine},
};
use paste::paste;
use std::time::Instant;
use wasmi::{
  etable::step_info::{BinOp, BitOp, RelOp, ShiftOp, StepInfo, UnaryOp},
  mtable::VarType,
};

#[test]
fn test_wasm_circuit() -> anyhow::Result<()> {
  type E1 = nova::provider::PallasEngine;
  step_generator!(Test StepCircuit0, StepCircuit1, StepCircuit2, StepCircuit3, StepCircuit4);
  let file_path = PathBuf::from("wasm/complete_int_opcodes.wat");

  let wasm_args = WASMArgsBuilder::default()
    .file_path(file_path)
    .invoke(Some(String::from("test")))
    .func_args(Vec::new())
    .build();

  let mut wasm_ctx = WASMCtx::new_from_file(wasm_args)?;
  let (etable, _) = wasm_ctx.build_execution_trace()?;
  println!("amount of opcodes {:?}", etable.entries().len());
  let etable_entries = etable.entries().clone();

  let mut execution_trace = Vec::new();
  let mut rom = Vec::new();
  for (i, entries) in etable_entries.chunks(100_000).enumerate() {
    execution_trace.push(
      entries
        .iter()
        .map(|entry| entry.step_info.clone())
        .collect::<Vec<_>>(),
    );
    rom.push(i);
  }
  println!("number of steps to run after batching: {}", rom.len());
  // nivc_bls_precompile::<PallasEngine, VestaEngine>(rom, execution_trace);
  let test_rom = TestROM::<E1>::new(rom, execution_trace.to_vec());
  let pp = PublicParams::setup(&test_rom, &*default_ck_hint(), &*default_ck_hint());
  let mut z0_primary = vec![<E1 as Engine>::Scalar::ONE];
  z0_primary.push(<E1 as Engine>::Scalar::ZERO); // rom_index = 0
  z0_primary.extend(
    test_rom
      .rom
      .iter()
      .map(|opcode| <E1 as Engine>::Scalar::from(*opcode as u64)),
  );
  let z0_secondary = vec![<Dual<E1> as Engine>::Scalar::ONE];

  let mut recursive_snark_option: Option<RecursiveSNARK<E1>> = None;

  let last_index = test_rom.rom.len() - 1;
  let time = Instant::now();
  println!("starting NIVC");
  for (i, &op_code) in test_rom.rom.iter().enumerate() {
    let op_code_err = format!("index:{}, failed to run on opcode {:?}", i, op_code);
    println!("index:{}, opcode:{}", i, op_code);
    let circuit_primary = test_rom.primary_circuit(op_code);
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
    recursive_snark_option = Some(recursive_snark)
  }

  let total_elapsed_time = time.elapsed();

  println!("NIVC run took {:?}", total_elapsed_time);

  assert!(recursive_snark_option.is_some());
  Ok(())
}
