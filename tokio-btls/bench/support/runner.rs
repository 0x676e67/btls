//! Criterion configuration and body-matrix orchestration.

use std::time::Duration;

use criterion::{Criterion, Throughput};

use super::{
    aead::bench_aead,
    case::BODY_CASES,
    client::{bench_clients, ClientBenchCase},
    BenchTarget, BoxError, Transport,
};

/// Set to check only a lower bound of the ciphertext length, for a tokio-btls without vectored
/// sealing (before #219), whose chunked writes seal one record per slice.
const RELAXED_FRAMING: &str = "TOKIO_BTLS_BENCH_RELAXED_FRAMING";

/// Set to reverse the backend order within each body kind for paired runs.
const REVERSE_ORDER: &str = "TOKIO_BTLS_BENCH_REVERSE_ORDER";

/// Builds the Criterion configuration shared by every target.
pub fn criterion() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(3))
}

/// Runs the complete body matrix for one benchmark target.
///
/// Returns any throughput conversion, server, client, or data check error from setup.
pub fn bench(criterion: &mut Criterion, target: BenchTarget) -> Result<(), BoxError> {
    const OS: &str = std::env::consts::OS;
    const ARCH: &str = std::env::consts::ARCH;

    let system = sysinfo::System::new_all();
    let cpu_model = system
        .cpus()
        .first()
        .map_or("n/a", |cpu| cpu.brand().trim());
    let exact_framing = std::env::var_os(RELAXED_FRAMING).is_none();
    let reverse_order = std::env::var_os(REVERSE_ORDER).is_some();

    for &body_case in BODY_CASES {
        let mut group = criterion.benchmark_group(format!(
            "{cpu_model}/{OS}_{ARCH}/{}/{}/{}/{}KB",
            target.direction,
            target.transport,
            target.clock,
            body_case.len / 1024,
        ));
        group.throughput(Throughput::Bytes(u64::try_from(body_case.len)?));

        bench_clients(
            &mut group,
            ClientBenchCase::new(target, body_case, exact_framing),
            reverse_order,
        )?;
        if let Transport::Memory = target.transport {
            bench_aead(&mut group, target, body_case.bytes(), reverse_order)?;
        }
        group.finish();
    }

    Ok(())
}
