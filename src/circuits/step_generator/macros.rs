//! This module contains the macros used to create large circuit steps with the step_generator!
//! macro.

/// Builds a general WASM circuit that can take in an execution trace and run each opcode in trace
/// in one circuit.
#[macro_export]
macro_rules! wasm_circuit {
  ($name: ident) => {
    /// The general WASM circuit that will run the execution trace.
    #[derive(Clone, Debug)]
    pub struct $name<F: PrimeField + PartialOrd> {
      circuit_index: usize,
      _p: PhantomData<F>,
      execution_trace: Vec<StepInfo>,
      rom_size: usize,
    }

    impl<F: PrimeField + PartialOrd> $name<F> {
      /// Create a new general WASM circuit that will run the execution trace.
      pub fn new(execution_trace: Vec<StepInfo>, circuit_index: usize, rom_size: usize) -> Self {
        Self {
          _p: PhantomData::default(),
          execution_trace,
          circuit_index,
          rom_size,
        }
      }
    }

    impl<F: PrimeField + PartialOrd + PrimeFieldBits> StepCircuit<F> for $name<F> {
      fn arity(&self) -> usize {
        2 + self.rom_size
      }
      fn circuit_index(&self) -> usize {
        self.circuit_index
      }

      fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        pc: Option<&AllocatedNum<F>>,
        z: &[AllocatedNum<F>],
      ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
        let rom_index = &z[1];
        let allocated_rom = &z[2..];

        let (rom_index_next, pc_next) = next_rom_index_and_pc(
          &mut cs.namespace(|| "next and rom_index and pc"),
          rom_index,
          allocated_rom,
          pc.ok_or(SynthesisError::AssignmentMissing)?,
        )?;

        for step in self.execution_trace.iter() {
          match step {
            StepInfo::CompZ { value, .. } => {
              let value = *value;
              let value = UInt64::alloc(cs.namespace(|| "a"), Some(value as u64))?;
              value.eqz(cs.namespace(|| "eqz"))?;
            }
            StepInfo::I32Comp {
              class, left, right, ..
            } => {
              let (left, right) = (*left, *right);
              match class {
                RelOp::Eq => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.eq(cs.namespace(|| "eq"), &other)?;
                }
                RelOp::Ne => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.ne(cs.namespace(|| "ne"), &other)?;
                }
                RelOp::UnsignedLe => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.le(cs.namespace(|| "le_u"), &other)?;
                }
                RelOp::UnsignedLt => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.lt(cs.namespace(|| "lt_u"), &other)?;
                }
                RelOp::UnsignedGe => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.ge(cs.namespace(|| "ge_u"), &other)?;
                }
                RelOp::UnsignedGt => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.gt(cs.namespace(|| "gt_s"), &other)?;
                }
                RelOp::SignedLe => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.le(cs.namespace(|| "le_s"), &other)?;
                }
                RelOp::SignedLt => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.lt(cs.namespace(|| "lt_s"), &other)?;
                }
                RelOp::SignedGe => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.ge(cs.namespace(|| "ge_s"), &other)?;
                }
                RelOp::SignedGt => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.gt(cs.namespace(|| "gt_s"), &other)?;
                }
                _ => {}
              }
            }
            StepInfo::I32BinOp {
              class, left, right, ..
            } => {
              let (left, right) = (*left, *right);
              match class {
                BinOp::Add => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.add(cs.namespace(|| "add"), &other)?;
                }
                BinOp::Sub => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "-b"), Some((-right) as u64))?;
                  value.add(cs.namespace(|| "sub"), &other)?;
                }
                BinOp::Mul => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.mul(cs.namespace(|| "mul"), &other)?;
                }
                BinOp::UnsignedDiv => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.div(cs.namespace(|| "div_u"), &other)?;
                }
                BinOp::UnsignedRem => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.rem(cs.namespace(|| "rem_u"), &other)?;
                }
                BinOp::SignedDiv => {
                  let is_neg = Boolean::from(
                    AllocatedBit::alloc(cs.namespace(|| "is neg"), Some((left < 0) ^ (right < 0)))
                      .unwrap(),
                  );
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left.unsigned_abs() as u64))?;
                  let other =
                    Int64::alloc(cs.namespace(|| "b"), Some(right.unsigned_abs() as u64))?;
                  value.div(cs.namespace(|| "div_s"), is_neg, &other)?;
                }
                BinOp::SignedRem => {
                  let is_neg = Boolean::from(
                    AllocatedBit::alloc(cs.namespace(|| "is neg"), Some(left < 0)).unwrap(),
                  );
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left.unsigned_abs() as u64))?;
                  let other =
                    Int64::alloc(cs.namespace(|| "b"), Some(right.unsigned_abs() as u64))?;
                  value.rem(cs.namespace(|| "rem_s"), is_neg, &other)?;
                }
                _ => {}
              }
            }
            StepInfo::I32BinBitOp {
              class, left, right, ..
            } => {
              let (left, right) = (*left, *right);
              match class {
                BitOp::And => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.and(cs.namespace(|| "a & b"), &other)?;
                }
                BitOp::Or => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.or(cs.namespace(|| "a | b"), &other)?;
                }
                BitOp::Xor => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.xor(cs.namespace(|| "a ^ b"), &other)?;
                }
              }
            }
            StepInfo::I32BinShiftOp {
              class, left, right, ..
            } => {
              let (left, right) = (*left, *right as usize);
              match class {
                ShiftOp::Shl => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.shl(cs.namespace(|| "shl"), &right % 32)?;
                }
                ShiftOp::UnsignedShr => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.shr(cs.namespace(|| "shr_u"), &right % 32)?;
                }
                ShiftOp::SignedShr => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.shr(cs.namespace(|| "shr_s"), &right % 32)?;
                }
                ShiftOp::Rotl => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.rotl(cs.namespace(|| "rotl"), &right % 32)?;
                }
                ShiftOp::Rotr => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.rotr(cs.namespace(|| "rotr"), &right % 32)?;
                }
              }
            }
            StepInfo::UnaryOp {
              class,
              vtype,
              operand,
              ..
            } => match vtype {
              VarType::I32 => match class {
                UnaryOp::Ctz => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(*operand as u64))?;
                  value.ctz_32_bit(cs.namespace(|| "ctz"))?;
                }
                UnaryOp::Clz => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(*operand as u64))?;
                  value.clz_32_bit(cs.namespace(|| "clz"))?;
                }
                UnaryOp::Popcnt => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(*operand as u64))?;
                  value.popcnt(cs.namespace(|| "popcnt"))?;
                }
                _ => {}
              },
              VarType::I64 => match class {
                UnaryOp::Ctz => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(*operand as u64))?;
                  value.ctz(cs.namespace(|| "ctz"))?;
                }
                UnaryOp::Clz => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(*operand as u64))?;
                  value.clz(cs.namespace(|| "clz"))?;
                }
                UnaryOp::Popcnt => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(*operand as u64))?;
                  value.popcnt(cs.namespace(|| "popcnt"))?;
                }
                _ => {}
              },
              _ => {}
            },
            StepInfo::I64BinOp {
              class, left, right, ..
            } => {
              let (left, right) = (*left, *right);
              match class {
                BinOp::Add => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.add(cs.namespace(|| "add"), &other)?;
                }
                BinOp::Sub => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "-b"), Some((-right) as u64))?;
                  value.add(cs.namespace(|| "sub"), &other)?;
                }
                BinOp::Mul => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.mul(cs.namespace(|| "mul"), &other)?;
                }
                BinOp::UnsignedDiv => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.div(cs.namespace(|| "div_u"), &other)?;
                }
                BinOp::UnsignedRem => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.rem(cs.namespace(|| "rem_u"), &other)?;
                }
                BinOp::SignedDiv => {
                  let is_neg = Boolean::from(
                    AllocatedBit::alloc(cs.namespace(|| "is neg"), Some((left < 0) ^ (right < 0)))
                      .unwrap(),
                  );
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left.unsigned_abs()))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right.unsigned_abs()))?;
                  value.div(cs.namespace(|| "div_s"), is_neg, &other)?;
                }
                BinOp::SignedRem => {
                  let is_neg = Boolean::from(
                    AllocatedBit::alloc(cs.namespace(|| "is neg"), Some(left < 0)).unwrap(),
                  );
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left.unsigned_abs()))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right.unsigned_abs()))?;
                  value.rem(cs.namespace(|| "rem_s"), is_neg, &other)?;
                }
                _ => {}
              }
            }
            StepInfo::I64Comp {
              class, left, right, ..
            } => {
              let (left, right) = (*left, *right);
              match class {
                RelOp::Eq => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.eq(cs.namespace(|| "eq"), &other)?;
                }
                RelOp::Ne => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.ne(cs.namespace(|| "ne"), &other)?;
                }
                RelOp::UnsignedLe => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.le(cs.namespace(|| "le_u"), &other)?;
                }
                RelOp::UnsignedLt => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.lt(cs.namespace(|| "lt_u"), &other)?;
                }
                RelOp::UnsignedGe => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.ge(cs.namespace(|| "ge_u"), &other)?;
                }
                RelOp::UnsignedGt => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.gt(cs.namespace(|| "gt_s"), &other)?;
                }
                RelOp::SignedLe => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.le(cs.namespace(|| "le_s"), &other)?;
                }
                RelOp::SignedLt => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.lt(cs.namespace(|| "lt_s"), &other)?;
                }
                RelOp::SignedGe => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.ge(cs.namespace(|| "ge_s"), &other)?;
                }
                RelOp::SignedGt => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = Int64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.gt(cs.namespace(|| "gt_s"), &other)?;
                }
                _ => {}
              }
            }
            StepInfo::I64BinBitOp {
              class, left, right, ..
            } => {
              let (left, right) = (*left, *right);
              match class {
                BitOp::And => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.and(cs.namespace(|| "a & b"), &other)?;
                }
                BitOp::Or => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.or(cs.namespace(|| "a | b"), &other)?;
                }
                BitOp::Xor => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  let other = UInt64::alloc(cs.namespace(|| "b"), Some(right as u64))?;
                  value.xor(cs.namespace(|| "a ^ b"), &other)?;
                }
              }
            }
            StepInfo::I64BinShiftOp {
              class, left, right, ..
            } => {
              let (left, right) = (*left, *right as usize);
              match class {
                ShiftOp::Shl => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.shl(cs.namespace(|| "shl"), &right % 64)?;
                }
                ShiftOp::UnsignedShr => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.shr(cs.namespace(|| "shr_u"), &right % 64)?;
                }
                ShiftOp::SignedShr => {
                  let value = Int64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.shr(cs.namespace(|| "shr"), &right % 64)?;
                }
                ShiftOp::Rotl => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.rotl(cs.namespace(|| "rotl"), &right % 64)?;
                }
                ShiftOp::Rotr => {
                  let value = UInt64::alloc(cs.namespace(|| "a"), Some(left as u64))?;
                  value.rotr(cs.namespace(|| "rotr"), &right % 64)?;
                }
              }
            }
            _ => {}
          }
        }

        let res = AllocatedNum::alloc(cs.namespace(|| "res unique"), || Ok(F::from(0)))?;
        let mut z_next = vec![res];
        z_next.push(rom_index_next);
        z_next.extend(z[2..].iter().cloned());
        Ok((Some(pc_next), z_next))
      }
    }
  };
}

/// Macro to build large step-circuits
#[macro_export]
macro_rules! step_generator {
  ($circuit_name:ident $($x:ident),*) => {
      $(
          paste! {
            wasm_circuit!([<$circuit_name $x>]);
          }
      )*

      paste! {
        /// Enum used to help build the ROM
          #[derive(Clone)]
          pub enum [<$circuit_name Circuit>]<F: PrimeField + PartialOrd + PrimeFieldBits> {
              $(
                  /// Unique general wasm step-circuit corresponding to the step index
                  $x([<$circuit_name $x>]<F>),
              )*
          }
      }

      paste! {
          impl<F: PrimeField + PartialOrd + PrimeFieldBits> StepCircuit<F> for [<$circuit_name Circuit>]<F> {
              fn arity(&self) -> usize {
                  match self {
                      $(
                        [<$circuit_name Circuit>]::$x(circuit) => circuit.arity(),
                      )*
                  }
              }
              fn circuit_index(&self) -> usize {
                  match self {
                      $(
                        [<$circuit_name Circuit>]::$x(circuit) => circuit.circuit_index(),
                      )*
                  }
              }
              fn synthesize<CS: ConstraintSystem<F>>(
                  &self,
                  cs: &mut CS,
                  pc: Option<&AllocatedNum<F>>,
                  z: &[AllocatedNum<F>],
              ) -> Result<(Option<AllocatedNum<F>>, Vec<AllocatedNum<F>>), SynthesisError> {
                  match self {
                      $(
                        [<$circuit_name Circuit>]::$x(circuit) => circuit.synthesize(cs, pc, z),
                      )*
                  }
              }
          }
      }

      paste! {
        /// The general WASM step circuit used in the step generator.
        pub struct [<$circuit_name ROM>]<E1> {
          /// The ROM that contains the circuit indices built by the step-generator.
          pub rom: Vec<usize>,
          /// The full execution trace that will be batched and run by the general wasm circuits.
          pub execution_trace: Vec<Vec<StepInfo>>,
          _p: PhantomData<E1>,
        }

        impl<E1> [<$circuit_name ROM>]<E1> {
          /// Create a new ROM circuit that will run the batched execution trace.
          pub fn new(rom: Vec<usize>, execution_trace: Vec<Vec<StepInfo>>) -> Self {
            Self {
              rom,
              execution_trace,
              _p: Default::default(),
            }
          }
        }
        impl<E1> NonUniformCircuit<E1> for [<$circuit_name ROM>]<E1>
        where
          E1: CurveCycleEquipped,
          <E1 as Engine>::Scalar: PartialOrd,
        {
          type C1 = [<$circuit_name Circuit>]<E1::Scalar>;
          type C2 = TrivialSecondaryCircuit<<Dual<E1> as Engine>::Scalar>;

          fn num_circuits(&self) -> usize {
            self.rom.len()
          }

          fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
            match circuit_index {
              $(
                ${index()} => [<$circuit_name Circuit>]::$x([<$circuit_name $x>]::new(
                  self.execution_trace[${index()}].clone(),
                  circuit_index,
                  self.rom.len(),
                )),
              )*
              _ => panic!("Invalid circuit index"),
            }
          }

          fn secondary_circuit(&self) -> Self::C2 {
            Default::default()
          }

          fn initial_circuit_index(&self) -> usize {
            self.rom[0]
          }
        }
      }
  };
}
