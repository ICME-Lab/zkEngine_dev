//! Macros for logging and timing

// Macro to start the timer
macro_rules! start_timer {
  ($msg:expr) => {{
    tracing::info!("{}...", $msg);
    (Instant::now(), $msg)
  }};
}

// Macro to stop the timer
macro_rules! stop_timer {
  ($timer:expr) => {{
    let (start, msg) = $timer;
    tracing::info!("{} took {:?}", msg, start.elapsed());
  }};
}

pub(crate) use start_timer;
pub(crate) use stop_timer;
