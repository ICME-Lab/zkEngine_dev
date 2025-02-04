use super::{
  avt_tuple_to_scalar_vec,
  gadgets::{
    int::{add, enforce_equal, enforce_lt_32, mul},
    mcc::{alloc_avt_tuple, randomized_hash_func},
    utils::alloc_one,
  },
  MEMORY_OPS_PER_STEP,
};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use itertools::Itertools;
use nova::nebula::{audit_rs::AuditStepCircuit, rs::StepCircuit};

pub mod multiset_ops;
#[cfg(test)]
mod tests;

/// Circuit to compute multiset hashes of (RS, WS)
#[derive(Clone, Debug)]
pub struct OpsCircuit {
  RS: Vec<(usize, u64, u64)>, // Vec<(a, v, t)>
  WS: Vec<(usize, u64, u64)>, // Vec<(a, v, t)>
}

impl<F> StepCircuit<F> for OpsCircuit
where
  F: PrimeField + PartialOrd,
{
  fn arity(&self) -> usize {
    5
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let (gamma, alpha, mut gts, mut h_rs, mut h_ws) = {
      (
        z[0].clone(),
        z[1].clone(),
        z[2].clone(),
        z[3].clone(),
        z[4].clone(),
      )
    };
    let one = alloc_one(cs.namespace(|| "one"));

    // 1. assert |RS| = |WS|
    let RS_len = AllocatedNum::alloc(cs.namespace(|| "RS.len()"), || {
      Ok(F::from(self.RS.len() as u64))
    })?;
    let WS_len = AllocatedNum::alloc(cs.namespace(|| "WS.len()"), || {
      Ok(F::from(self.WS.len() as u64))
    })?;
    enforce_equal(cs, || " assert |RS| = |WS|", &RS_len, &WS_len);

    // 2. for i in 0..|RS|
    for (i, (rs, ws)) in self.RS.iter().zip_eq(self.WS.iter()).enumerate() {
      // (a) (a,v,rt) ← RS[i]
      let (r_addr, r_val, r_ts) = alloc_avt_tuple(cs.namespace(|| format!("rs{i}")), *rs)?;

      // (b) (a′,v′,wt) ← WS[i]
      let (w_addr, w_val, w_ts) = alloc_avt_tuple(cs.namespace(|| format!("ws{i}")), *ws)?;

      // (c) gts ← gts + 1
      gts = add(cs.namespace(|| format!("{i},  gts ← gts + 1")), &gts, &one)?;

      // (d) assert rt < ts
      enforce_lt_32(cs.namespace(|| "enforce_lt_32"), &r_ts, &gts)?;

      // (e) assert wt = ts
      enforce_equal(cs, || format!("{i} assert wt = ts"), &w_ts, &gts);

      // (f) h_RS ← h_RS · Hash(gamma, alpha, a, v, rt)
      //
      // Get Hash(gamma, alpha, a, v, rt)
      let hash_rs = randomized_hash_func(
        cs.namespace(|| format!("{i}, Hash(gamma, alpha, a, v, rt)")),
        &r_addr,
        &r_val,
        &r_ts,
        &gamma,
        &alpha,
      )?;
      h_rs = mul(
        cs.namespace(|| format!("{i}, update h_rs")),
        &h_rs,
        &hash_rs,
      )?;

      // (g) h_WS ← h_WS · Hash(gamma, alpha, a′, v′, wt)
      let hash_ws = randomized_hash_func(
        cs.namespace(|| format!("{i}, Hash(gamma, alpha, wa, wv, wt)")),
        &w_addr,
        &w_val,
        &w_ts,
        &gamma,
        &alpha,
      )?;

      h_ws = mul(
        cs.namespace(|| format!("{i}, update h_ws")),
        &h_ws,
        &hash_ws,
      )?;
    }

    Ok(vec![gamma, alpha, gts, h_rs, h_ws])
  }

  fn non_deterministic_advice(&self) -> Vec<F> {
    self
      .RS
      .iter()
      .zip_eq(self.WS.iter())
      .flat_map(|(rs, ws)| {
        avt_tuple_to_scalar_vec::<F>(*rs)
          .into_iter()
          .chain(avt_tuple_to_scalar_vec::<F>(*ws))
      })
      .collect()
  }
}

impl OpsCircuit {
  /// Create a new instance of OpsCircuit for computing multiset hashes of
  /// (RS, WS)
  pub fn new(RS: Vec<(usize, u64, u64)>, WS: Vec<(usize, u64, u64)>) -> Self {
    OpsCircuit { RS, WS }
  }
}

impl Default for OpsCircuit {
  fn default() -> Self {
    OpsCircuit {
      RS: vec![(0, 0, 0); MEMORY_OPS_PER_STEP / 2],
      WS: vec![(0, 0, 0); MEMORY_OPS_PER_STEP / 2],
    }
  }
}

/// Circuit to compute multiset hashes of (IS, FS)
#[derive(Clone, Debug)]
pub struct ScanCircuit {
  IS: Vec<(usize, u64, u64)>, // Vec<(a, v, t)>
  FS: Vec<(usize, u64, u64)>, // Vec<(a, v, t)>
}

impl<F> AuditStepCircuit<F> for ScanCircuit
where
  F: PrimeField,
{
  fn arity(&self) -> usize {
    4
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let (gamma, alpha, mut h_is, mut h_fs) =
      { (z[0].clone(), z[1].clone(), z[2].clone(), z[3].clone()) };

    // 1. assert |IS| = |FS|
    let IS_len = AllocatedNum::alloc(cs.namespace(|| "IS.len()"), || {
      Ok(F::from(self.IS.len() as u64))
    })?;
    let FS_len = AllocatedNum::alloc(cs.namespace(|| "FS.len()"), || {
      Ok(F::from(self.FS.len() as u64))
    })?;
    enforce_equal(cs, || " assert |IS| = |FS|", &IS_len, &FS_len);

    // 2. for i in 0..|IS|
    for (i, (is, fs)) in self.IS.iter().zip_eq(self.FS.iter()).enumerate() {
      // (a) (a,v,it)←IS[i]
      let (i_addr, i_val, i_ts) = alloc_avt_tuple(cs.namespace(|| format!("is{i}")), *is)?;

      // (b) (a′,v′,ft) ← FS[i]
      let (f_addr, f_val, f_ts) = alloc_avt_tuple(cs.namespace(|| format!("fs{i}")), *fs)?;

      // (c) assert a=a′
      cs.enforce(
        || "a == a_prime",
        |lc| lc + i_addr.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + f_addr.get_variable(),
      );

      // (d) h_IS ← h_IS · Hash(gamma, alpha, a, v, it)

      // Get Hash(gamma, alpha, a, v, it)
      let hash_is = randomized_hash_func(
        cs.namespace(|| format!("{i}, Hash(gamma, alpha, a, v, it)")),
        &i_addr,
        &i_val,
        &i_ts,
        &gamma,
        &alpha,
      )?;

      h_is = mul(
        cs.namespace(|| format!("{i}, update h_is")),
        &h_is,
        &hash_is,
      )?;

      // (e) h_FS ← h_FS · Hash(gamma, alpha, a′, v′, ft)
      let hash_fs = randomized_hash_func(
        cs.namespace(|| format!("{i}, Hash(gamma, alpha, fa, fv, ft)")),
        &f_addr,
        &f_val,
        &f_ts,
        &gamma,
        &alpha,
      )?;

      h_fs = mul(
        cs.namespace(|| format!("{i}, update h_fs")),
        &h_fs,
        &hash_fs,
      )?;
    }

    Ok(vec![gamma, alpha, h_is, h_fs])
  }

  fn IS_advice(&self) -> Vec<F> {
    self
      .IS
      .iter()
      .flat_map(|is| avt_tuple_to_scalar_vec::<F>(*is))
      .collect()
  }

  fn FS_advice(&self) -> Vec<F> {
    self
      .FS
      .iter()
      .flat_map(|fs| avt_tuple_to_scalar_vec::<F>(*fs))
      .collect()
  }
}

impl ScanCircuit {
  /// Create a new instance of ScanCircuit for computing multiset hashes of
  /// (IS, FS)
  pub fn new(IS: Vec<(usize, u64, u64)>, FS: Vec<(usize, u64, u64)>) -> Self {
    ScanCircuit { IS, FS }
  }
}

impl ScanCircuit {
  /// Create a empty instance of [`ScanCircuit`]
  pub fn empty(step_size: usize) -> Self {
    ScanCircuit {
      IS: vec![(0, 0, 0); step_size],
      FS: vec![(0, 0, 0); step_size],
    }
  }
}

#[derive(Clone, Debug)]
/// BatchedWasmTransitionCircuit
pub struct BatchedOpsCircuit {
  circuits: Vec<OpsCircuit>,
}

impl<F> StepCircuit<F> for BatchedOpsCircuit
where
  F: PrimeField + PartialOrd,
{
  fn arity(&self) -> usize {
    5
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let mut z = z.to_vec();

    for circuit in self.circuits.iter() {
      z = circuit.synthesize(cs, &z)?;
    }

    Ok(z)
  }

  fn non_deterministic_advice(&self) -> Vec<F> {
    self
      .circuits
      .iter()
      .flat_map(|circuit| circuit.non_deterministic_advice())
      .collect()
  }
}

impl BatchedOpsCircuit {
  /// Create an empty instance of [`BatchedOpsCircuit`]
  pub fn empty(step_size: usize) -> Self {
    Self {
      circuits: vec![OpsCircuit::default(); step_size],
    }
  }

  /// Create a new instance of [`BatchedOpsCircuit`]
  pub fn new(circuits: Vec<OpsCircuit>) -> Self {
    Self { circuits }
  }
}
