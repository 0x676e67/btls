//! Benchmarks TLS client reads over loopback TCP in wall time.

mod support;

use criterion::{criterion_group, criterion_main, Criterion};
use support::{BenchTarget, Clock, Direction, Transport};

/// Target dimensions for the loopback TCP read benchmark.
const TARGET: BenchTarget = BenchTarget {
    direction: Direction::Read,
    transport: Transport::Tcp,
    clock: Clock::Wall,
};

/// Runs the full body matrix for this target.
///
/// Panics if a case fails to configure, execute, or verify its data.
fn benchmark(c: &mut Criterion) {
    support::bench(c, TARGET).expect("failed to run loopback TCP read benchmark");
}

criterion_group!(
    name = benches;
    config = support::criterion();
    targets = benchmark
);
criterion_main!(benches);
