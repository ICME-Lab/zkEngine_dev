//! Logging utilities

/// Initializes the logger with the default environment filter.
pub fn init_logger() {
  let _ = tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .try_init();
}
