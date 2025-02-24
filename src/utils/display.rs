//! Display utilities for pretty-printing types and values.
#![allow(dead_code)]
use std::fmt::{self, Display};
use wasmi::{core::ValueType, FuncType, Value};

/// [`Display`]-wrapper type for [`ValueType`].
pub struct DisplayValueType<'a>(&'a ValueType);

impl<'a> From<&'a ValueType> for DisplayValueType<'a> {
  fn from(value_type: &'a ValueType) -> Self {
    Self(value_type)
  }
}

impl Display for DisplayValueType<'_> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self.0 {
      ValueType::I32 => write!(f, "i32"),
      ValueType::I64 => write!(f, "i64"),
      ValueType::F32 => write!(f, "f32"),
      ValueType::F64 => write!(f, "f64"),
      ValueType::FuncRef => write!(f, "funcref"),
      ValueType::ExternRef => write!(f, "externref"),
    }
  }
}

/// [`Display`]-wrapper type for [`Value`].
pub struct DisplayValue<'a>(&'a Value);

impl<'a> From<&'a Value> for DisplayValue<'a> {
  fn from(value: &'a Value) -> Self {
    Self(value)
  }
}

impl fmt::Display for DisplayValue<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match &self.0 {
      Value::I32(value) => write!(f, "{value}"),
      Value::I64(value) => write!(f, "{value}"),
      Value::F32(value) => write!(f, "{value}"),
      Value::F64(value) => write!(f, "{value}"),
      Value::FuncRef(value) => panic!("cannot display funcref values but found {value:?}"),
      Value::ExternRef(value) => {
        panic!("cannot display externref values but found {value:?}")
      }
    }
  }
}

/// [`Display`]-wrapper type around [`FuncType`].
pub struct DisplayFuncType<'a> {
  name: Option<&'a str>,
  func_type: &'a FuncType,
}

impl<'a> DisplayFuncType<'a> {
  /// Creates a named [`DisplayFuncType`] for the given [`FuncType`].
  pub fn new(name: &'a str, func_type: &'a FuncType) -> Self {
    Self {
      name: Some(name),
      func_type,
    }
  }
}

impl<'a> From<&'a FuncType> for DisplayFuncType<'a> {
  fn from(func_type: &'a FuncType) -> Self {
    Self {
      name: None,
      func_type,
    }
  }
}

impl fmt::Display for DisplayFuncType<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if let Some(name) = self.name {
      write!(f, "fn {name}(")?;
    } else {
      write!(f, "fn(")?;
    }
    let params = self.func_type.params();
    let results = self.func_type.results();
    write!(
      f,
      "{}",
      DisplaySequence::new(", ", params.iter().map(DisplayValueType::from))
    )?;
    write!(f, ")")?;
    if !results.is_empty() {
      write!(f, " -> ")?;
      if results.len() == 1 {
        write!(f, "{}", DisplayValueType::from(&results[0]))?;
      } else {
        write!(
          f,
          "({})",
          DisplaySequence::new(", ", results.iter().map(DisplayValueType::from))
        )?;
      }
    }
    Ok(())
  }
}

/// [`Display`]-wrapper for generic sequences with separators.
#[derive(Debug)]
pub struct DisplaySequence<'a, T> {
  /// The sequence to display.
  sequence: Box<[T]>,
  /// The separator between the displayed sequence items.
  separator: &'a str,
}

impl<'a, T> DisplaySequence<'a, T> {
  /// Creates a new [`DisplaySequence`] for the given `separator` and `sequence` iterator.
  pub fn new<I>(separator: &'a str, sequence: I) -> Self
  where
    I: IntoIterator<Item = T>,
  {
    let sequence = sequence.into_iter().collect();
    Self {
      sequence,
      separator,
    }
  }
}

impl<T> Display for DisplaySequence<'_, T>
where
  T: Display,
{
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let separator = self.separator;
    if let Some((first, rest)) = self.sequence.split_first() {
      write!(f, "{first}")?;
      for param in rest {
        write!(f, "{separator}{param}")?;
      }
    }
    Ok(())
  }
}
