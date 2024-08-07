use nova::traits::CurveCycleEquipped;

pub trait PublicValuesTrait<E1: CurveCycleEquipped> {
  type PublicParams;

  fn public_params(&self) -> &Self::PublicParams;
  fn public_inputs(&self) -> &[E1::Scalar];
  fn public_outputs(&self) -> &[E1::Scalar];
}

pub trait ZKVMPublicValues<E1: CurveCycleEquipped> {
  type MCCPublicParams;
  type ExecutionPublicParams;
  type MCCPublicValues: PublicValuesTrait<E1, PublicParams = Self::MCCPublicParams>;
  type ExecutionPublicValues: PublicValuesTrait<E1, PublicParams = Self::ExecutionPublicParams>;

  fn mcc(&self) -> &Self::MCCPublicValues;
  fn execution(&self) -> &Self::ExecutionPublicValues;
}
