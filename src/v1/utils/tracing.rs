use crate::v1::{error::ZKWASMError, wasm_ctx::ZKWASMCtx};
use std::{cell::RefCell, rc::Rc, time::Instant};

use super::macros::{start_timer, stop_timer};

/// Get inner value of [`Rc<RefCell<T>>`]
///
/// # Panics
///
/// Panics if [`Rc`] is not the sole owner of the underlying data,
pub fn unwrap_rc_refcell<T>(last_elem: Rc<RefCell<T>>) -> T {
  let inner: RefCell<T> = Rc::try_unwrap(last_elem)
    .unwrap_or_else(|_| panic!("The last_elem was shared, failed to unwrap"));
  inner.into_inner()
}

#[allow(dead_code)]
/// Get estimations of the WASM execution trace size
pub fn estimate_wasm(program: impl ZKWASMCtx) -> Result<(), ZKWASMError> {
  let execution_timer = start_timer!("Running WASM");
  let _ = program.execution_trace()?;
  stop_timer!(execution_timer);
  Ok(())
}

/// Split vector and return Vec's
pub fn split_vector<T>(mut vec: Vec<T>, split_index: usize) -> (Vec<T>, Vec<T>) {
  let second_part = vec.split_off(split_index);
  (vec, second_part)
}
