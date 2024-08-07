//! This module contains utilities to save data structures to disk
use std::{fs::File, io::Write};

use nova::{
  supernova::{snark::CompressedSNARK, PublicParams},
  traits::{
    snark::{BatchedRelaxedR1CSSNARKTrait, RelaxedR1CSSNARKTrait},
    CurveCycleEquipped, Dual, Engine,
  },
};

use std::{io::Read, path::Path};

/// Save public parameters to a file on disk
pub fn save_pp<E1>(pp: &PublicParams<E1>, file: &str) -> anyhow::Result<()>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd,
  PublicParams<E1>: serde::Serialize,
{
  let mut f = File::create(file)?;
  let json_string = serde_json::to_string(&pp)?;
  f.write_all(json_string.as_bytes())?;
  f.sync_all()?;
  Ok(())
}

/// Load public parameters from a file on disk
pub fn load_pp<E1>(file: &Path) -> anyhow::Result<PublicParams<E1>>
where
  E1: CurveCycleEquipped,
  <E1 as Engine>::Scalar: PartialOrd,
  PublicParams<E1>: serde::de::DeserializeOwned,
{
  let mut f = File::open(file)?;
  let mut json_string = String::new();
  f.read_to_string(&mut json_string)?;
  let pp = serde_json::from_str(&json_string)?;
  Ok(pp)
}

/// Load a `T` from a file on disk
pub fn load_from_disk<T>(file: &Path) -> anyhow::Result<T>
where
  T: serde::de::DeserializeOwned,
{
  let mut f = File::open(file)?;
  let mut json_string = String::new();
  f.read_to_string(&mut json_string)?;
  let t = serde_json::from_str(&json_string)?;
  Ok(t)
}

/// Save `String` to a file on disk
pub fn save_string(json_string: String, file: &str) -> anyhow::Result<()> {
  let mut f = File::create(file)?;
  f.write_all(json_string.as_bytes())?;
  f.sync_all().map_err(From::from)
}

/// Load CompressedSNARK from a file on disk
pub fn load_compressed_snark<E1, S1, S2>(file: &Path) -> anyhow::Result<CompressedSNARK<E1, S1, S2>>
where
  E1: CurveCycleEquipped,
  S1: BatchedRelaxedR1CSSNARKTrait<E1>,
  S2: RelaxedR1CSSNARKTrait<Dual<E1>>,
{
  let mut f = File::open(file)?;
  let mut json_string = String::new();
  f.read_to_string(&mut json_string)?;
  let snark = serde_json::from_str(&json_string)?;
  Ok(snark)
}
