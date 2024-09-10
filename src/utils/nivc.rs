//! Utility functions to run NIVC

//use std::time::Instant;

use crate::{circuits::supernova::batched_rom::BatchedROM, utils::save};
use ff::Field;
use nova::{
  supernova::{snark::CompressedSNARK, NonUniformCircuit, PublicParams, RecursiveSNARK},
  traits::{
    snark::{default_ck_hint, BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
    CurveCycleEquipped, Dual, Engine as NovaEngine,
  },
};
use wasmi::{
  etable::{
    step_info::{BinOp, BitOp, RelOp, ShiftOp, StepInfo, UnaryOp},
    ETable,
  },
  mtable::{AccessType, LocationType, MemoryTableEntry, VarType},
};

// TODO: Refactor
/// Build's ROM for NIVC
pub fn build_rom(execution_trace: &[StepInfo]) -> (Vec<usize>, Vec<(u64, u64, u64)>) {
  let mut rom: Vec<usize> = Vec::new();
  let placeholder = 0;
  let mut tracer_values: Vec<(u64, u64, u64)> = Vec::new();

  for step in execution_trace {
    match *step {
      StepInfo::I32BinOp {
        class, left, right, ..
      } => match class {
        BinOp::Add => {
          rom.push(0);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BinOp::Sub => {
          rom.push(12);
          tracer_values.push((left as u64, -right as u64, 0));
        }
        BinOp::Mul => {
          rom.push(13);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BinOp::SignedDiv => {
          rom.push(14);
          tracer_values.push((
            left.unsigned_abs() as u64,
            right.unsigned_abs() as u64,
            u64::from((left < 0) ^ (right < 0)),
          ));
        }
        BinOp::UnsignedDiv => {
          rom.push(15);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BinOp::SignedRem => {
          rom.push(16);
          tracer_values.push((
            left.unsigned_abs() as u64,
            right.unsigned_abs() as u64,
            u64::from(left < 0),
          ));
        }
        BinOp::UnsignedRem => {
          rom.push(17);
          tracer_values.push((left as u64, right as u64, 0));
        }
        _ => {}
      },
      StepInfo::I32BinBitOp {
        class, left, right, ..
      } => match class {
        BitOp::And => {
          rom.push(18);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BitOp::Or => {
          rom.push(19);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BitOp::Xor => {
          rom.push(20);
          tracer_values.push((left as u64, right as u64, 0));
        }
      },
      StepInfo::I32BinShiftOp {
        class, left, right, ..
      } => match class {
        ShiftOp::Shl => {
          rom.push(21);
          tracer_values.push((left as u64, (right % 32) as u64, 0));
        }
        ShiftOp::SignedShr => {
          rom.push(22);
          tracer_values.push((left as u64, (right % 32) as u64, 0));
        }
        ShiftOp::UnsignedShr => {
          rom.push(23);
          tracer_values.push((left as u64, (right % 32) as u64, 0));
        }
        ShiftOp::Rotl => {
          rom.push(32);
          tracer_values.push((left as u64, (right % 32) as u64, 0));
        }
        ShiftOp::Rotr => {
          rom.push(33);
          tracer_values.push((left as u64, (right % 32) as u64, 0));
        }
      },
      StepInfo::UnaryOp {
        class,
        vtype,
        operand,
        ..
      } => match vtype {
        VarType::I32 => match class {
          UnaryOp::Clz => {
            rom.push(30);
            tracer_values.push((operand, placeholder, placeholder));
          }
          UnaryOp::Ctz => {
            rom.push(31);
            tracer_values.push((operand, placeholder, placeholder));
          }
          UnaryOp::Popcnt => {
            rom.push(28);
            tracer_values.push((operand, placeholder, placeholder));
          }
          _ => {}
        },
        VarType::I64 => match class {
          UnaryOp::Clz => {
            rom.push(26);
            tracer_values.push((operand, placeholder, placeholder));
          }
          UnaryOp::Ctz => {
            rom.push(27);
            tracer_values.push((operand, placeholder, placeholder));
          }
          UnaryOp::Popcnt => {
            rom.push(28);
            tracer_values.push((operand, placeholder, placeholder));
          }
          _ => {}
        },
        _ => {}
      },
      StepInfo::CompZ { value, .. } => {
        rom.push(1);
        tracer_values.push((0, value, 0));
      }
      StepInfo::I32Comp {
        class, left, right, ..
      } => match class {
        RelOp::Eq => {
          rom.push(2);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::Ne => {
          rom.push(3);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::SignedLt => {
          rom.push(4);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::UnsignedLt => {
          rom.push(5);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::SignedGt => {
          rom.push(6);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::UnsignedGt => {
          rom.push(7);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::SignedLe => {
          rom.push(8);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::UnsignedLe => {
          rom.push(9);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::SignedGe => {
          rom.push(10);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::UnsignedGe => {
          rom.push(11);
          tracer_values.push((left as u64, right as u64, 0));
        }
        _ => {}
      },
      StepInfo::I64BinOp {
        class, left, right, ..
      } => match class {
        BinOp::Add => {
          rom.push(0);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BinOp::Sub => {
          rom.push(12);
          tracer_values.push((left as u64, -right as u64, 0));
        }
        BinOp::Mul => {
          rom.push(13);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BinOp::SignedDiv => {
          rom.push(14);
          tracer_values.push((
            left.unsigned_abs(),
            right.unsigned_abs(),
            u64::from((left < 0) ^ (right < 0)),
          ));
        }
        BinOp::UnsignedDiv => {
          rom.push(15);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BinOp::SignedRem => {
          rom.push(16);
          tracer_values.push((
            left.unsigned_abs(),
            right.unsigned_abs(),
            u64::from(left < 0),
          ));
        }
        BinOp::UnsignedRem => {
          rom.push(17);
          tracer_values.push((left as u64, right as u64, 0));
        }
        _ => {}
      },
      StepInfo::I64BinBitOp {
        class, left, right, ..
      } => match class {
        BitOp::And => {
          rom.push(18);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BitOp::Or => {
          rom.push(19);
          tracer_values.push((left as u64, right as u64, 0));
        }
        BitOp::Xor => {
          rom.push(20);
          tracer_values.push((left as u64, right as u64, 0));
        }
      },
      StepInfo::I64BinShiftOp {
        class, left, right, ..
      } => match class {
        ShiftOp::Shl => {
          rom.push(21);
          tracer_values.push((left as u64, (right % 64) as u64, 0));
        }
        ShiftOp::SignedShr => {
          rom.push(22);
          tracer_values.push((left as u64, (right % 64) as u64, placeholder));
        }
        ShiftOp::UnsignedShr => {
          rom.push(23);
          tracer_values.push((left as u64, (right % 64) as u64, 0));
        }
        ShiftOp::Rotl => {
          rom.push(24);
          tracer_values.push((left as u64, (right % 64) as u64, 0));
        }
        ShiftOp::Rotr => {
          rom.push(25);
          tracer_values.push((left as u64, (right % 64) as u64, 0));
        }
      },
      StepInfo::I64Comp {
        class, left, right, ..
      } => match class {
        RelOp::Eq => {
          rom.push(2);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::Ne => {
          rom.push(3);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::SignedLt => {
          rom.push(4);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::UnsignedLt => {
          rom.push(5);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::SignedGt => {
          rom.push(6);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::UnsignedGt => {
          rom.push(7);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::SignedLe => {
          rom.push(8);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::UnsignedLe => {
          rom.push(9);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::SignedGe => {
          rom.push(10);
          tracer_values.push((left as u64, right as u64, 0));
        }
        RelOp::UnsignedGe => {
          rom.push(11);
          tracer_values.push((left as u64, right as u64, 0));
        }
        _ => {}
      },

      StepInfo::Select {
        val1, val2, cond, ..
      } => {
        rom.push(29);
        tracer_values.push((val1, val2, cond));
      }
      StepInfo::Br { offset } => {
        rom.push(34);
        tracer_values.push((offset, placeholder, placeholder));
      }
      StepInfo::BrIfNez { condition, offset } => {
        rom.push(35);
        tracer_values.push((condition, offset, placeholder));
      }
      StepInfo::BrIfEqz { condition, offset } => {
        rom.push(36);
        tracer_values.push((condition, offset, placeholder));
      }
      StepInfo::BrAdjust { offset } => {
        rom.push(34);
        tracer_values.push((offset, placeholder, placeholder));
      }
      _ => {}
    }
  }

  (rom, tracer_values)
}

/// Util function to batch execution trace into exactly 10 steps
pub fn batch_execution_trace(etable: &ETable) -> anyhow::Result<(Vec<Vec<StepInfo>>, Vec<usize>)> {
  let mut batched_execution_trace = Vec::with_capacity(10);
  let mut rom = Vec::new();
  let step_size = etable.entries().len() / 10;
  let mut start = 0;
  let mut end = step_size;
  for i in 0..10 {
    if i == 9 {
      end = etable.entries().len();
    }

    let execution_trace = etable.entries()[start..end]
      .iter()
      .map(|entry| entry.step_info.clone())
      .collect::<Vec<_>>();

    batched_execution_trace.push(execution_trace);
    rom.push(i);
    start = end;
    end += step_size;
  }

  tracing::trace!("number of steps to run after batching: {}", rom.len());
  Ok((batched_execution_trace, rom))
}

/// Util function to batch memory trace into exactly 10 steps
pub fn batch_memory_trace(
  memory_trace: Vec<MemoryTableEntry>,
  last_addr: usize,
) -> anyhow::Result<Vec<Vec<MemoryTableEntry>>> {
  let mut batched_memory_trace = Vec::with_capacity(10);

  let step_size = memory_trace.len() / 9;
  let remainder = memory_trace.len() % 9;
  let mut start = 0;
  let mut end = step_size;
  for i in 0..10 {
    if i == 9 {
      let mut memory_trace = memory_trace[start..].to_owned();
      let dummy_step_len = step_size - remainder;

      for _ in 0..dummy_step_len {
        memory_trace.push(MemoryTableEntry {
          eid: Default::default(),
          addr: last_addr,
          value: 0,
          atype: AccessType::Read,
          emid: Default::default(),
          is_mutable: false,
          ltype: LocationType::Stack,
        })
      }

      batched_memory_trace.push(memory_trace);
      break;
    }

    let memory_trace = memory_trace[start..end].to_owned();
    batched_memory_trace.push(memory_trace);
    start = end;
    end += step_size;
  }
  tracing::trace!("number of steps to run after batching: 10");
  Ok(batched_memory_trace)
}

/// Proves WASM by creating large step-circuits that can take in many opcodes instead of the vanilla
/// approach which can only take one opcode per circuit step
pub fn batched_wasm_nivc<E1, S1, S2>(etable: &ETable, save_pp: bool) -> anyhow::Result<String>
where
  E1: CurveCycleEquipped,
  <E1 as NovaEngine>::Scalar: PartialOrd,
  S1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  // Batch execution trace in batched
  let (execution_trace, rom) = batch_execution_trace(etable)?;

  // Build large step circuits

  let test_rom = BatchedROM::<E1>::new(rom, execution_trace.to_vec());

  // Produce PP
  //let time = Instant::now();
  tracing::info!("Producing pp..");
  let pp = PublicParams::setup(&test_rom, &*default_ck_hint(), &*default_ck_hint());
  //tracing::info!("pp produced in {:?}", time.elapsed());

  if save_pp {
    save::save_pp(&pp, "public_params.json")?;
  }

  // Build z0
  let mut z0_primary = vec![<E1 as NovaEngine>::Scalar::ONE];
  z0_primary.push(<E1 as NovaEngine>::Scalar::ZERO); // rom_index = 0
  z0_primary.extend(
    test_rom
      .rom
      .iter()
      .map(|opcode| <E1 as NovaEngine>::Scalar::from(*opcode as u64)),
  );
  let z0_secondary = vec![<Dual<E1> as NovaEngine>::Scalar::ONE];

  let mut recursive_snark_option: Option<RecursiveSNARK<E1>> = None;

  let last_index = test_rom.rom.len() - 1;

  // Run NIVC
  //let time = Instant::now();
  tracing::info!("starting NIVC");
  for (i, &op_code) in test_rom.rom.iter().enumerate() {
    let op_code_err = format!("index:{}, failed to run on opcode {:?}", i, op_code);
    tracing::debug!("index:{}, opcode:{}", i, op_code);

    // Get circuit from rom[index]
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

    // Verify snark on last index
    if i == last_index {
      //let time = Instant::now();
      recursive_snark
        .verify(&pp, &z0_primary, &z0_secondary)
        .expect(&op_code_err);
      //tracing::info!("time to verify snark {:?}", time.elapsed())
    }

    recursive_snark_option = Some(recursive_snark)
  }

  //let total_elapsed_time = time.elapsed();

  //tracing::info!("NIVC run took {:?}", total_elapsed_time);

  assert!(recursive_snark_option.is_some());

  // Add CompressedSNARK check
  let recursive_snark = recursive_snark_option.unwrap();

  //let time = Instant::now();
  let (prover_key, verifier_key) = CompressedSNARK::<E1, S1, S2>::setup(&pp)?;
  //tracing::info!("CompressedSNARK setup done in {:?}", time.elapsed());

  tracing::info!("Proving CompressedSNARK..");
  //let time = Instant::now();
  let compressed_snark = CompressedSNARK::prove(&pp, &prover_key, &recursive_snark)?;
  //tracing::info!("CompressedSNARK prove time: {:?}", time.elapsed());

  //let time = Instant::now();
  compressed_snark.verify(&pp, &verifier_key, &z0_primary, &z0_secondary)?;
  //tracing::info!("CompressedSNARK verify time: {:?}", time.elapsed());

  Ok(serde_json::to_string(&compressed_snark)?) // return the compressed SNARK
}
