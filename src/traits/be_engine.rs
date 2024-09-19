use nova::{
  provider::{ipa_pc, PallasEngine},
  spartan,
  traits::{
    evaluation::EvaluationEngineTrait,
    snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
    CurveCycleEquipped, Dual,
  },
};

pub trait BackendEngine {
  type E1: CurveCycleEquipped;
  type EE1: EvaluationEngineTrait<Self::E1>;
  type EE2: EvaluationEngineTrait<Dual<Self::E1>>;
  type BS1: BatchedRelaxedR1CSSNARKTrait<Self::E1>;
  type S1: RelaxedR1CSSNARKTrait<Self::E1>;
  type S2: RelaxedR1CSSNARKTrait<Dual<Self::E1>>;
}

pub struct PastaEngine;

impl BackendEngine for PastaEngine {
  type E1 = PallasEngine;
  type EE1 = ipa_pc::EvaluationEngine<Self::E1>;
  type EE2 = ipa_pc::EvaluationEngine<Dual<Self::E1>>;
  type BS1 = spartan::batched::BatchedRelaxedR1CSSNARK<Self::E1, Self::EE1>;
  type S1 = spartan::snark::RelaxedR1CSSNARK<Self::E1, Self::EE1>;
  type S2 = spartan::snark::RelaxedR1CSSNARK<Dual<Self::E1>, Self::EE2>;
}
