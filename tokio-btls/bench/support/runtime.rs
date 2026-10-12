//! Async runtime construction for benchmark clients and the loopback server.

/// Builds the single-thread Tokio runtime every client and server thread uses.
///
/// A client's TLS stack, runtime and syscalls then all run on the thread that the CPU clock reads.
pub(super) fn tokio_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
