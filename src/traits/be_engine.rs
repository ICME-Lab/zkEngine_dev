//! This module defines the backend trait for zkEngine.
use nova::traits::{
  evaluation::EvaluationEngineTrait,
  snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
  CurveCycleEquipped, Dual,
};

/// Defines the backend engine for proving
pub trait BackendEngine {
  /// The Curve Cycle used for proving
  type E1: CurveCycleEquipped;

  /// Primary PCS
  type EE1: EvaluationEngineTrait<Self::E1>;

  /// Secondary PCS
  type EE2: EvaluationEngineTrait<Dual<Self::E1>>;

  /// Final primary Spartan SNARK used at the end of NIVC
  type BS1: BatchedRelaxedR1CSSNARKTrait<Self::E1> + Clone;

  /// Final secondary Spartan SNARK used at the end of NIVC
  type BS2: BatchedRelaxedR1CSSNARKTrait<Dual<Self::E1>> + Clone;

  /// Final primary Spartan SNARK used at the end of IVC
  type S1: RelaxedR1CSSNARKTrait<Self::E1> + Clone;

  /// Final secondary Spartan SNARK used at the end of (N)IVC
  type S2: RelaxedR1CSSNARKTrait<Dual<Self::E1>> + Clone;
}
