//! This module defines the backend trait for zkEngine.
use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan,
  traits::{
    evaluation::EvaluationEngineTrait,
    snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
    CurveCycleEquipped, Dual, Engine,
  },
};

/// Defines the backend engine for proving
pub trait BackendEngine {
  /// The Curve Cycle used for proving
  type E1: CurveCycleEquipped;

  /// Primary PCS
  type EE1: EvaluationEngineTrait<Self::E1>;

  /// Secondary PCS
  type EE2: EvaluationEngineTrait<Dual<Self::E1>>;

  /// Final Spartan SNARK used at the end of NIVC
  type BS1: BatchedRelaxedR1CSSNARKTrait<Self::E1> + Clone;

  /// Final primary Spartan SNARK used at the end of IVC
  type S1: RelaxedR1CSSNARKTrait<Self::E1> + Clone;

  /// Final secondary Spartan SNARK used at the end of (N)IVC
  type S2: RelaxedR1CSSNARKTrait<Dual<Self::E1>> + Clone;
}

/// Implements the Pallas Vesta Curve Cycle Engine
pub struct PastaEngine;

impl BackendEngine for PastaEngine {
  type E1 = PallasEngine;
  type EE1 = ipa_pc::EvaluationEngine<Self::E1>;
  type EE2 = ipa_pc::EvaluationEngine<Dual<Self::E1>>;
  type BS1 = spartan::batched::BatchedRelaxedR1CSSNARK<Self::E1, Self::EE1>;
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
  type S1 = spartan::snark::RelaxedR1CSSNARK<Self::E1, Self::EE1>;
  type S2 = spartan::snark::RelaxedR1CSSNARK<Dual<Self::E1>, Self::EE2>;
}
