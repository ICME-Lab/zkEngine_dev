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

/// Get estimations of the WASM execution trace size
pub fn estimate_wasm(program: impl ZKWASMCtx) -> Result<(), ZKWASMError> {
  let execution_timer = start_timer!("Running WASM");
  let (execution_trace, _, IS_stack_len, IS_mem_len) = program.execution_trace()?;
  stop_timer!(execution_timer);

  tracing::info!("stack len: {}", IS_stack_len);
  tracing::info!("IS_mem.len: {}", IS_mem_len);

  tracing::info!("Execution trace len: {:?}", execution_trace.len());
  Ok(())
}
