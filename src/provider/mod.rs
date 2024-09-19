//! This module implements zkEngines's traits using several different combinations
use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan,
  traits::Dual,
};

use crate::{
  run::{batched, default},
  traits::be_engine::BackendEngine,
};

/// Implements the Pallas Vesta Curve Cycle Engine
pub struct PastaEngine;

impl BackendEngine for PastaEngine {
  type E1 = PallasEngine;
  type EE1 = ipa_pc::EvaluationEngine<Self::E1>;
  type EE2 = ipa_pc::EvaluationEngine<Dual<Self::E1>>;
  type BS1 = spartan::batched::BatchedRelaxedR1CSSNARK<Self::E1, Self::EE1>;
  type BS2 = spartan::batched::BatchedRelaxedR1CSSNARK<Dual<Self::E1>, Self::EE2>;
  type S1 = spartan::snark::RelaxedR1CSSNARK<Self::E1, Self::EE1>;
  type S2 = spartan::snark::RelaxedR1CSSNARK<Dual<Self::E1>, Self::EE2>;
}

/// Implements the backend needed for aggregating SNARKS
pub struct AggregationEngine;

impl BackendEngine for AggregationEngine {
  type E1 = PallasEngine;
  type EE1 = ipa_pc::EvaluationEngine<Self::E1>;
  type EE2 = ipa_pc::EvaluationEngine<Dual<Self::E1>>;
  type BS1 =
    spartan::verify_circuit::ipa_prover_poseidon::batched::BatchedRelaxedR1CSSNARK<Self::E1>;
  type BS2 =
    spartan::verify_circuit::ipa_prover_poseidon::batched::BatchedRelaxedR1CSSNARK<Dual<Self::E1>>;
  type S1 = spartan::snark::RelaxedR1CSSNARK<Self::E1, Self::EE1>;
  type S2 = spartan::snark::RelaxedR1CSSNARK<Dual<Self::E1>, Self::EE2>;
}

/// Backend Engine used for testing
pub type E = PastaEngine;

/// The default zkEngine type alias.
pub type WasmSNARK = default::WasmSNARK<E>;

/// The Batched zkEngine type alias.
pub type BatchedWasmSNARK = batched::WasmSNARK<E>;
