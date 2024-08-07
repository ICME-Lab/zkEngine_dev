use std::{borrow::Cow, cell::OnceCell, marker::PhantomData, time::Instant};

use anyhow::anyhow;
use nova::{
  supernova::{
    error::SuperNovaError,
    snark::{CompressedSNARK, ProverKey, VerifierKey},
    RecursiveSNARK,
  },
  traits::{
    snark::{default_ck_hint, BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
    CurveCycleEquipped, Dual, Engine,
  },
};
use serde::{Deserialize, Serialize};

use crate::{
  circuits::supernova::etable_rom::{EtableROM, OpcodeCircuits},
  errors::ProofError,
  traits::{prover::Prover, snark::RecursiveSNARKTrait},
};

use nova::supernova::{NonUniformCircuit, PublicParams as SuperNovaPublicParams};

type IC1<E1> = OpcodeCircuits<<E1 as Engine>::Scalar>;
type C1<E1> = EtableROM<E1>;

type KeyPair<E1, S1, S2> = (ProverKey<E1, S1, S2>, VerifierKey<E1, S1, S2>);

/// A struct that contains public parameters for the SuperNova proving system.
pub struct ExecutionPublicParams<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  /// Public params for SuperNova.
  pub pp: SuperNovaPublicParams<E1>,
  /// Prover key and Verifier key for SuperNova
  // TODO: mark as #[serde(skip)] when serializing
  pub pk_and_vk: OnceCell<KeyPair<E1, S1, S2>>,
}

impl<E1, S1, S2> ExecutionPublicParams<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E1>,
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

impl<E1, S1, S2> From<SuperNovaPublicParams<E1>> for ExecutionPublicParams<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  fn from(pp: SuperNovaPublicParams<E1>) -> ExecutionPublicParams<E1, S1, S2> {
    ExecutionPublicParams {
      pp,
      pk_and_vk: OnceCell::new(),
    }
  }
}

pub fn super_nova_public_params<E1, S1, S2>(
  nc: &C1<E1>,
) -> anyhow::Result<ExecutionPublicParams<E1, S1, S2>>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd,
  S1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  let time = Instant::now();
  tracing::info!("producing PP...");
  let pp = SuperNovaPublicParams::setup(nc, &*default_ck_hint(), &*default_ck_hint());
  tracing::info!("producing PP took: {:?}", time.elapsed());
  Ok(ExecutionPublicParams {
    pp,
    pk_and_vk: OnceCell::new(),
  })
}

/// An enum representing the two types of proofs that can be generated and verified.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "")]
pub enum ExecutionProof<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  /// A proof for the intermediate steps of a recursive computation
  Recursive(Box<RecursiveSNARK<E1>>, usize, Vec<<E1 as Engine>::Scalar>),
  /// A proof for the final step of a recursive computation
  Compressed(Box<CompressedSNARK<E1, S1, S2>>),
}

impl<E1, S1, S2> RecursiveSNARKTrait<E1, C1<E1>> for ExecutionProof<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd,
  S1: BatchedRelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  type PublicParams = ExecutionPublicParams<E1, S1, S2>;
  type BaseRecursiveSNARK = RecursiveSNARK<E1>;
  type ErrorType = SuperNovaError;

  fn prove_recursively(
    pp: &ExecutionPublicParams<E1, S1, S2>,
    z0: &[<E1 as Engine>::Scalar],
    init: Option<RecursiveSNARK<E1>>,
    mut steps: C1<E1>,
  ) -> Result<Self, ProofError> {
    let num_steps = steps.rom.len();
    let secondary_circuit = steps.secondary_circuit();
    let mut recursive_snark_option = init;

    let prove_step =
      |i: usize, opcode: IC1<E1>, rs: &mut Option<RecursiveSNARK<E1>>, nc: &C1<E1>| {
        tracing::debug!("Proving step {i}");
        tracing::trace!("index: {i}, opcode: {:#?}", opcode);
        let mut recursive_snark = rs.take().unwrap_or_else(|| {
          RecursiveSNARK::new(
            &pp.pp,
            nc,
            &opcode,
            &secondary_circuit,
            z0,
            &Self::z0_secondary(),
          )
          .expect("failed to construct initial recursive SNARK")
        });
        recursive_snark
          .prove_step(&pp.pp, &opcode, &secondary_circuit)
          .unwrap();
        *rs = Some(recursive_snark);
      };

    for (i, opcode) in steps.rom.iter().enumerate() {
      let opcode = steps.primary_circuit(*opcode);
      prove_step(i, opcode, &mut recursive_snark_option, &steps);
      steps.counter += 1;
    }

    let (zi, _) =
      recursive_snark_option
        .as_ref()
        .unwrap()
        .verify(&pp.pp, z0, &Self::z0_secondary())?;

    Ok(Self::Recursive(
      Box::new(recursive_snark_option.expect("RecursiveSNARK missing")),
      num_steps,
      zi,
    ))
  }

  fn compress(&self, pp: &ExecutionPublicParams<E1, S1, S2>) -> Result<Cow<'_, Self>, ProofError> {
    tracing::info!("compressing NIVC proof...");
    match &self {
      Self::Recursive(recursive_snark, _, _) => {
        let snark = CompressedSNARK::<_, S1, S2>::prove(&pp.pp, pp.pk(), recursive_snark)?;
        Ok(Cow::Owned(Self::Compressed(Box::new(snark))))
      }
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
      Self::Recursive(p, _, _) => p.verify(&pp.pp, z0_primary, &z0_secondary)?,
      Self::Compressed(p) => p.verify(&pp.pp, pp.vk(), z0_primary, &z0_secondary)?,
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
pub struct ExecutionProver<E1, S1, S2> {
  _e1: PhantomData<E1>,
  _s1: PhantomData<S1>,
  _s2: PhantomData<S2>,
}

impl<E1, S1, S2> Prover<E1> for ExecutionProver<E1, S1, S2>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd,
  S1: BatchedRelaxedR1CSSNARKTrait<E1> + Clone,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>> + Clone,
{
  type Frames = C1<E1>;
  type PublicParams = ExecutionPublicParams<E1, S1, S2>;
  type RecursiveSNARK = ExecutionProof<E1, S1, S2>;
}
