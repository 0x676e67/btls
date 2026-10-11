//! Target dimensions, clocks and the body matrix shared by every benchmark.

use std::{
    fmt,
    sync::LazyLock,
    time::{Duration, Instant},
};

use cpu_time::ThreadTime;

/// Selects the direction, transport and clock for one benchmark target.
#[derive(Clone, Copy, Debug)]
pub struct BenchTarget {
    pub direction: Direction,
    pub transport: Transport,
    pub clock: Clock,
}

/// Stream operation the measured client performs.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum Direction {
    /// The client reads bodies a tokio-btls server sends.
    Read,
    /// The client writes bodies a tokio-btls server receives.
    Write,
}

// ===== impl Direction =====

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
        })
    }
}

/// Transport under the measured client stream.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum Transport {
    /// In-process pipe; a tokio-btls server on the same task works between timed batches.
    Memory,
    /// Loopback TCP to a server on its own thread, one per connection.
    Tcp,
}

// ===== impl Transport =====

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Memory => "memory",
            Self::Tcp => "tcp",
        })
    }
}

/// Clock a measured duration is read from.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum Clock {
    /// Elapsed wall time. A TCP server streams bodies for as long as the connection lasts.
    Wall,
    /// CPU time of the benchmark thread, which runs the client and its runtime. A TCP server
    /// moves bodies only between timed batches, so the client never waits for it or wakes it.
    Cpu,
}

/// A measurement started on one [`Clock`].
pub(crate) enum Stopwatch {
    Wall(Instant),
    Cpu(ThreadTime),
}

// ===== impl Clock =====

impl Clock {
    /// Starts a measurement on this clock.
    pub(crate) fn start(self) -> Stopwatch {
        match self {
            Self::Wall => Stopwatch::Wall(Instant::now()),
            Self::Cpu => Stopwatch::Cpu(ThreadTime::now()),
        }
    }
}

impl fmt::Display for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Wall => "wall_time",
            Self::Cpu => "cpu_time",
        })
    }
}

// ===== impl Stopwatch =====

impl Stopwatch {
    /// Time on the clock since the measurement started.
    pub(crate) fn elapsed(&self) -> Duration {
        match self {
            Self::Wall(start) => start.elapsed(),
            Self::Cpu(start) => start.elapsed(),
        }
    }
}

/// Whether a stream carries TLS records or the bare body.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Tls {
    Enabled,
    Disabled,
}

// ===== impl Tls =====

impl Tls {
    /// Bytes on the wire for `len` bytes of body that start on a record boundary.
    pub(crate) const fn wire_len(self, len: usize) -> usize {
        match self {
            Self::Enabled => len + len.div_ceil(MAX_RECORD) * RECORD_OVERHEAD,
            Self::Disabled => len,
        }
    }
}

/// Body length and the slice or buffer size of its `chunked` kind.
#[derive(Clone, Copy, Debug)]
pub struct BodyCase {
    pub len: usize,
    pub chunk_size: usize,
}

// ===== impl BodyCase =====

impl BodyCase {
    /// The body's bytes: one pattern with a prime period, cut to size, so a slice or record out
    /// of place changes them.
    pub(crate) fn bytes(self) -> &'static [u8] {
        static PATTERN: LazyLock<Box<[u8]>> = LazyLock::new(|| {
            let max_len = BODY_CASES.iter().map(|body_case| body_case.len).max();
            (0..=250u8).cycle().take(max_len.unwrap_or(0)).collect()
        });
        &PATTERN[..self.len]
    }
}

/// How the client hands a body to the stream or takes it back.
#[derive(Clone, Copy, Debug)]
pub enum BodyKind {
    /// Write: one `write_all`. Read: into one buffer as long as the body.
    Full,
    /// Write: `chunk_size` slices through `write_vectored`. Read: into a `chunk_size` buffer.
    Chunked,
}

// ===== impl BodyKind =====

impl BodyKind {
    /// Body kinds registered for every stack.
    pub(crate) const ALL: [Self; 2] = [Self::Full, Self::Chunked];
}

impl fmt::Display for BodyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Full => "full",
            Self::Chunked => "chunked",
        })
    }
}

const KIB: usize = 1024;

/// Largest plaintext in one TLS record.
pub(crate) const MAX_RECORD: usize = 16 * KIB;

/// Bytes a TLS 1.3 AES-GCM record adds: a 5-byte header, the inner content type and a 16-byte tag
/// ([RFC 8446 §5.2](https://www.rfc-editor.org/rfc/rfc8446#section-5.2)).
const RECORD_OVERHEAD: usize = 22;

/// Body bytes a batch moves between two clock reads: whole bodies, at least one. Over TCP a
/// larger body moves in parts of this size, so a batch always fits the socket buffers.
pub(crate) const BATCH_LEN: usize = 128 * KIB;

/// Most slices in one chunked write; they live in a stack array.
pub(crate) const MAX_SLICES: usize = 16;

/// Body sizes measured by every target, each split into 16 chunks.
///
/// The x4 ladder crosses the record size (16 KiB), tokio-btls's 64 KiB seal budget and rustls's
/// 64 KiB send limit, and extends to a 4 MiB working set.
pub(crate) const BODY_CASES: &[BodyCase] = &[
    BodyCase {
        len: KIB,
        chunk_size: 64,
    },
    BodyCase {
        len: 16 * KIB,
        chunk_size: KIB,
    },
    BodyCase {
        len: 64 * KIB,
        chunk_size: 4 * KIB,
    },
    BodyCase {
        len: 256 * KIB,
        chunk_size: 16 * KIB,
    },
    BodyCase {
        len: 1024 * KIB,
        chunk_size: 64 * KIB,
    },
    BodyCase {
        len: 4096 * KIB,
        chunk_size: 256 * KIB,
    },
];

// Every body has bytes, every chunked write fits the slice array, and a TCP part of a body
// starts on a record boundary.
const _: () = {
    assert!(BATCH_LEN.is_multiple_of(MAX_RECORD));
    let mut i = 0;
    while i < BODY_CASES.len() {
        let body_case = BODY_CASES[i];
        assert!(body_case.len > 0 && body_case.chunk_size > 0);
        assert!(body_case.len.div_ceil(body_case.chunk_size) <= MAX_SLICES);
        i += 1;
    }
};
