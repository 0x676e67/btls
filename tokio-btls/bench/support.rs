//! Shared dimensions, adapters and lifecycle helpers for the TLS read and write targets.

mod aead;
mod allocator;
mod case;
mod client;
mod memory;
mod runner;
mod runtime;
mod server;

pub use case::{BenchTarget, Clock, Direction, Transport};
pub use runner::{bench, criterion};

/// Error type used while preparing or cleaning up a benchmark case.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
