mod circuit;
use std::{borrow::Cow, cell::OnceCell, marker::PhantomData, time::Instant};

use anyhow::anyhow;
use circuit::MCCCircuit;
use ff::Field;

use nova::{
  errors::NovaError,
  gadgets::lookup::{Lookup, LookupTraceBuilder},
  traits::{
    circuit::TrivialCircuit, commitment::CommitmentEngineTrait, snark::RelaxedR1CSSNARKTrait,
    CurveCycleEquipped, Dual, Engine, ROConstants, ROConstantsCircuit,
  },
  CompressedSNARK, ProverKey, RecursiveSNARK, VerifierKey,
};
use serde::{Deserialize, Serialize};
use wasmi::mtable::MTable;

use crate::{
  errors::ProofError,
  traits::{prover::Prover, snark::RecursiveSNARKTrait},
  utils::memory::create_lookup_table,
};
use nova::PublicParams as NovaPublicParams;

/// Inner circuit instance
pub type IC1<E1> = MCCCircuit<E1>;

/// Steps of circuits to prove
pub type C1<E1> = Vec<IC1<E1>>;

/// Type alias for a Trivial Test Circuit with G2 scalar field elements.
pub type C2<E1> = TrivialCircuit<<Dual<E1> as Engine>::Scalar>;
type CommitmentKey<E> = <<E as Engine>::CE as CommitmentEngineTrait<E>>::CommitmentKey;

type KeyPair<E1, S1, S2> = (ProverKey<E1, S1, S2>, VerifierKey<E1, S1, S2>);

/// A struct that contains public parameters for the Nova proving system.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MCCPublicParams<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  /// Public parameters for the Nova proving system.
  pub pp: NovaPublicParams<E1>,
  /// Prover and verifier key for final proof compression
  #[serde(skip)]
  pk_and_vk: OnceCell<KeyPair<E1, S1, S2>>,
}

// this avoids dipping into the pk/vk
impl<E1, S1, S2> std::fmt::Debug for MCCPublicParams<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("PublicParams")
      .field("pp", &self.pp)
      .finish()
  }
}

impl<E1, S1, S2> MCCPublicParams<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  /// provides a reference to a ProverKey suitable for producing a CompressedProof
  pub fn pk(&self) -> &ProverKey<E1, S1, S2> {
    let (pk, _vk) = self
      .pk_and_vk
      .get_or_init(|| CompressedSNARK::<E1, S1, S2>::setup(&self.pp).unwrap());
    pk
  }

  /// provides a reference to a VerifierKey suitable for verifying a CompressedProof
  pub fn vk(&self) -> &VerifierKey<E1, S1, S2> {
    let (_pk, vk) = self
      .pk_and_vk
      .get_or_init(|| CompressedSNARK::<E1, S1, S2>::setup(&self.pp).unwrap());
    vk
  }
}

impl<E1, S1, S2> From<NovaPublicParams<E1>> for MCCPublicParams<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  fn from(pp: NovaPublicParams<E1>) -> MCCPublicParams<E1, S1, S2> {
    MCCPublicParams {
      pp,
      pk_and_vk: OnceCell::new(),
    }
  }
}

/// Generates the public parameters for the Nova proving system.
pub fn public_params<E1, S1, S2>(
  circuit_primary: IC1<E1>,
  circuit_secondary: C2<E1>,
) -> anyhow::Result<MCCPublicParams<E1, S1, S2>>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: Ord,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  let commitment_size_hint1 = <S1 as RelaxedR1CSSNARKTrait<E1>>::ck_floor();
  let commitment_size_hint2 = <S2 as RelaxedR1CSSNARKTrait<Dual<E1>>>::ck_floor();

  let time = Instant::now();
  tracing::info!("producing PP...");
  let pp = nova::PublicParams::setup(
    &circuit_primary,
    &circuit_secondary,
    &*commitment_size_hint1,
    &*commitment_size_hint2,
  )?;

  tracing::info!("producing PP took: {:?}", time.elapsed());

  Ok(MCCPublicParams {
    pp,
    pk_and_vk: OnceCell::new(),
  })
}

/// An enum representing the two types of proofs that can be generated and verified.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub enum MCCProof<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  /// A proof for the intermediate steps of a recursive computation along with
  /// the number of steps used for verification
  Recursive(Box<RecursiveSNARK<E1>>, usize, Vec<E1::Scalar>),
  /// A proof for the final step of a recursive computation along with the number
  /// of steps used for verification
  Compressed(Box<CompressedSNARK<E1, S1, S2>>, usize),
}

impl<E1, S1, S2> RecursiveSNARKTrait<E1, C1<E1>> for MCCProof<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: Ord,
  S1: RelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  type PublicParams = MCCPublicParams<E1, S1, S2>;
  type BaseRecursiveSNARK = RecursiveSNARK<E1>;
  type ErrorType = NovaError;

  fn prove_recursively(
    pp: &MCCPublicParams<E1, S1, S2>,
    z0: &[<E1 as Engine>::Scalar],
    init: Option<RecursiveSNARK<E1>>,
    steps: C1<E1>,
  ) -> Result<Self, ProofError> {
    let num_steps = steps.len();

    let secondary_circuit = TrivialCircuit::default();
    let mut recursive_snark_option = init;

    let prove_step = |i: usize, step: &IC1<E1>, rs: &mut Option<RecursiveSNARK<E1>>| {
      let mut recursive_snark = rs.take().unwrap_or_else(|| {
        RecursiveSNARK::new(&pp.pp, step, &secondary_circuit, z0, &Self::z0_secondary())
          .expect("failed to construct initial recursive SNARK")
      });
      tracing::debug!("prove_step {i}");
      recursive_snark
        .prove_step(&pp.pp, step, &secondary_circuit)
        .unwrap();
      *rs = Some(recursive_snark);
    };

    for (i, step) in steps.iter().enumerate() {
      prove_step(i, step, &mut recursive_snark_option);
    }

    let (zi, _) = recursive_snark_option.as_ref().unwrap().verify(
      &pp.pp,
      num_steps,
      z0,
      &Self::z0_secondary(),
    )?;

    Ok(Self::Recursive(
      Box::new(recursive_snark_option.expect("RecursiveSNARK missing")),
      num_steps,
      zi,
    ))
  }

  fn compress(&self, pp: &MCCPublicParams<E1, S1, S2>) -> Result<Cow<'_, Self>, ProofError> {
    tracing::info!("compressing MCC IVC proof...");
    match self {
      Self::Recursive(recursive_snark, num_steps, _) => Ok(Cow::Owned(Self::Compressed(
        Box::new(CompressedSNARK::<_, S1, S2>::prove(
          &pp.pp,
          pp.pk(),
          recursive_snark,
        )?),
        *num_steps,
      ))),
      Self::Compressed(..) => Ok(Cow::Borrowed(self)),
    }
  }

  fn verify(
    &self,
    pp: &Self::PublicParams,
    z0: &[<E1 as Engine>::Scalar],
    zi: &[<E1 as Engine>::Scalar],
  ) -> Result<bool, Self::ErrorType> {
    let (z0_primary, zi_primary) = (z0, zi);
    let z0_secondary = Self::z0_secondary();
    let zi_secondary = &z0_secondary;

    let (zi_primary_verified, zi_secondary_verified) = match self {
      Self::Recursive(p, num_steps, _) => {
        p.verify(&pp.pp, *num_steps, z0_primary, &z0_secondary)?
      }
      Self::Compressed(p, num_steps) => p.verify(pp.vk(), *num_steps, z0_primary, &z0_secondary)?,
    };

    Ok(zi_primary == zi_primary_verified && zi_secondary == &zi_secondary_verified)
  }

  fn zi_primary(&self) -> anyhow::Result<&[<E1 as Engine>::Scalar]> {
    match self {
      Self::Recursive(_, _, zi) => Ok(zi),
      _ => Err(anyhow!("zi not found")),
    }
  }
}

#[derive(Clone, Debug)]
pub struct MCCProver<E1, S1, S2> {
  _e1: PhantomData<E1>,
  _s1: PhantomData<S1>,
  _s2: PhantomData<S2>,
}

impl<E1, S1, S2> MCCProver<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: Ord,
  S1: RelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  pub fn mcc_inputs(mtable: MTable) -> C1<E1> {
    let (init_table, memory_trace, _) = create_lookup_table(mtable);
    let initial_intermediate_gamma = <E1 as Engine>::Scalar::from(1);
    let mut intermediate_gamma = initial_intermediate_gamma;

    let mut lookup = init_table;
    let num_steps = memory_trace.len();

    let ro_consts = ROConstants::<Dual<E1>>::default();

    // simulate folding step lookup io
    let mut primary_circuits = Vec::with_capacity(num_steps + 1);
    for m_entry in memory_trace.into_iter() {
      let mut lookup_trace_builder = LookupTraceBuilder::<E1>::new(&mut lookup);

      // Map the actual memory address to address in the lookup table
      let scalar_addr = <E1 as Engine>::Scalar::from(m_entry.addr as u64);
      let scalar_val = <E1 as Engine>::Scalar::from(m_entry.value);

      lookup_trace_builder.read(scalar_addr);
      lookup_trace_builder.write(scalar_addr, scalar_val);

      let res = lookup_trace_builder.snapshot::<Dual<E1>>(ro_consts.clone(), intermediate_gamma);
      intermediate_gamma = res.0;
      let (_, lookup_trace) = res;
      primary_circuits.push(MCCCircuit::new(lookup_trace, m_entry));
    }

    primary_circuits
  }
}

impl<E1, S1, S2> Prover<E1> for MCCProver<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: Ord,
  S1: RelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  type Frames = C1<E1>;
  type PublicParams = MCCPublicParams<E1, S1, S2>;
  type RecursiveSNARK = MCCProof<E1, S1, S2>;
}
