# Vectored write benchmark: tokio-btls vs tokio-rustls

Compares the vectored write path of `tokio-btls` (branch `demo/tokio-btls-vectored-write`, 53594cc, BoringSSL)
with `tokio-rustls` 0.26.6 + `rustls` 0.23.45 (aws-lc-rs). Both negotiate TLS 1.3 with AES-128-GCM.

Measured on a 4 vCPU cloud VM over loopback. Tables show the median of 5 runs for TCP and 7 runs for null mode.
Raw output is in [`results/`](results). [`results/baseline/`](results/baseline) holds the raw output and callgrind
counts of the write path before `SSL_seal_app_data`, measured on a faster VM.

## Running

```sh
cargo build --release
./target/release/vbench [tcp|null|null-partial|both] [case-filter] [runs]
VB_IMPL=btls|rustls VB_SCALE=N ./target/release/vbench ...   # one impl / N times less data
```

- The writer under test is the TLS server. The reader is always the same tokio-btls client on its own thread,
  so only the write path differs.
- `tcp` mode uses loopback TCP through a counting `AsyncFd` transport. It counts every `write`/`writev`
  syscall and every EAGAIN exactly.
- `null` mode makes the transport discard ciphertext after the handshake, so it measures TLS CPU only.
- `null-partial` mode discards too, but takes at most 16 KiB per poll and returns `Pending` on every other
  poll, so backpressure is deterministic.
- Record counts are derived from ciphertext overhead, at 22 B per TLS 1.3 record.
- "transport polls/msg" counts every `write`/`writev` call on the transport, including those that return
  `Pending` (counted in "transport Pending/MiB").
- "Rust allocs" counts the writer thread's global allocator. It includes one Vec per message made by the
  harness.
- "C allocs" counts the writer thread's other `malloc` calls (glibc only): BoringSSL's per-record write
  buffer and `OPENSSL_malloc`, or AWS-LC's.
- For callgrind, `--toggle-collect='*poll_tls_write*'` collects only the TLS write calls, for example
  `VB_IMPL=btls VB_SCALE=16 valgrind --tool=callgrind --toggle-collect='*poll_tls_write*' ./target/release/vbench null 1x100B 1`.

## Summary

- **Syscalls are a tie.** Both stacks make one `write`/`writev` per ~64 KiB call and merge buffered
  records under backpressure. The one exception favors btls. An input slightly over 64 KiB, such as four h2
  DATA frames, costs rustls two TLS calls and twice the syscalls (32 vs 16 per MiB). This is because rustls
  caps the plaintext it accepts at 64 KiB per call.
- **Large aligned writes cost about the same CPU**, roughly 212–228 ns/KiB on both. Each stack makes one extra
  memcpy per byte: rustls copies plaintext into a Vec per record, and btls copies ciphertext into `out_buf`
  for every record except the last one of a call.
- **btls loses on fixed per-record cost.** A 100 B write takes 44% more CPU (4525 vs 3132 ns/KiB), and batches
  of small slices take 8–23% more. Callgrind places about 90% of the instructions per write inside
  BoringSSL's `SSL_write`, which sweeps the error queue, mallocs and frees the write buffer per record, and
  makes a BIO round trip. The tokio-btls wrapper itself costs about 316 instructions per call, against about
  527 for tokio-rustls.
- **btls emits extra tiny records for `[9 B header, 16 KiB payload]` shapes**: 128 vs 80 records/MiB. That
  costs 16% more writer CPU in null mode and a few percent more on the reader.
- **On real TCP, throughput gaps mostly fall within run-to-run noise** (±15–20% on this VM). rustls came out
  ahead in most large-write runs, and btls writer CPU was 10–20% higher there.

## CPU cost of the write path (null transport)

Lower is better. "b / r" columns list btls first, then rustls.

| Shape per call | btls ns/KiB | rustls ns/KiB | btls Δ | records/MiB b / r | transport calls/MiB b / r | Rust allocs/MiB b / r |
|---|---:|---:|---:|---:|---:|---:|
| 1×100B | 4525 | 3132 | +44% | 10487 / 10486 | 10486 / 10486 | 10486 / 20972 |
| 64×64B | 426 | 346 | +23% | 256 / 256 | 256 / 256 | 512 / 768 |
| 512×32B | 399 | 371 | +8% | 64 / 64 | 64 / 64 | 128 / 192 |
| 16×1KiB | 243 | 220 | +10% | 64 / 64 | 64 / 64 | 128 / 192 |
| 4×(9B+16KiB) | 253 | 218 | +16% | 128 / 80 | 16 / 32 | 32 / 112 |
| 4×16KiB | 212 | 216 | −2% | 64 / 64 | 16 / 16 | 32 / 96 |
| 2×64KiB | 220 | 228 | −4% | 64 / 64 | 16 / 16 | 24 / 80 |
| 1×256KiB | 212 | 223 | −5% | 64 / 64 | 16 / 16 | 20 / 68 |

## Loopback TCP

No EAGAIN occurred in any run, because the reader kept up. Batching under load came from tokio's coop
budget, which applied to both stacks equally. Writer CPU includes the kernel copy.

| Shape per call | MiB/s b / r | writer ns/KiB b / r | reader ns/KiB b / r | syscalls/MiB b / r | iovs per writev b / r |
|---|---:|---:|---:|---:|---:|
| 1×100B | 108 / 92 | 9019 / 10399 | 6116 / 6368 | 2024 / 2048 | 2 / 49.7 |
| 64×64B | 387 / 451 | 2398 / 2123 | 1785 / 1634 | 229 / 231 | 2 / 2.0 |
| 512×32B | 676 / 786 | 1428 / 1214 | 790 / 671 | 62.5 / 63 | 2 / 1.1 |
| 16×1KiB | 1257 / 1411 | 768 / 680 | 659 / 679 | 62.5 / 63 | 2 / 1.1 |
| 4×(9B+16KiB) | 1273 / 1403 | 739 / 652 | 639 / 617 | 16 / 32 | 2 / 2.5 |
| 4×16KiB | 1267 / 1303 | 755 / 689 | 630 / 574 | 16 / 16 | 2 / 4 |
| 2×64KiB | 1245 / 1562 | 755 / 619 | 593 / 560 | 16 / 16 | 2 / 4 |
| 1×256KiB | 1274 / 1512 | 756 / 643 | 544 / 515 | 16 / 16 | 2 / 4 |

Repeat runs of the same case swung by up to ±20%. For example, 16×1KiB btls ran at 839, 966, 1248 and
871 MiB/s. Read the throughput column as a tendency only. The counters are deterministic.

## How each stack writes

**tokio-btls**

- `is_write_vectored` returns true. Each call seals at most ~64 KiB of ciphertext into `out_buf`, plus one
  final record of up to 16 KiB.
- `pack_record` copies small adjacent slices into a single record. A slice of 8 KiB or more is sealed in
  place with no plaintext copy, even when that leaves a small record in front of it.
- Every record is one `SSL_write` call (`ENABLE_PARTIAL_WRITE`). BoringSSL mallocs and frees its write
  buffer for each record and clears the error queue on every call.
- Records before the last one are copied into `out_buf`. The last record goes out directly with
  `writev([out_buf, record])`, so a single record of up to 16 KiB is sent with no extra copy.
- Under backpressure, sealed bytes are reported as written and kept in the buffer.

**tokio-rustls / rustls**

- Each call makes one `writer().write_vectored()`. It allocates a `Vec<&[u8]>` of the slices and chunks them
  as if they were one flat buffer, so every record is full.
- Accepted plaintext is capped by the 64 KiB `sendable_tls` limit, with no second pass in the same call.
  A 65,572 B input needs two calls and two syscalls, and the second one carries a 36 B record.
- Each record is a new Vec. The plaintext is copied into it and encrypted in place.
- `write_tls` gathers up to 64 record Vecs into one `writev`, with no ciphertext copy.

## Improvement ideas for tokio-btls

1. **Gather sealing in BoringSSL.** This is the largest win. BoringSSL already seals through
   `EVP_AEAD_CTX_sealv` with an iovec list (`aead_aes_gcm_tls13_sealv` shows up in the profile). A small btls
   patch could add an `SSL_write` variant that takes `CRYPTO_IOVEC`s and passes them through to
   `SealScatter`. That would remove the `record` copy for small slices and resolve the header vs payload
   trade-off, giving full records with no plaintext copy.
2. **Seal several records per `SSL_write` into caller memory.** The fixed cost per record (error-queue sweep,
   write-buffer malloc/free, BIO round trip) is what loses the small-write cases. One fix is a patch that
   keeps the write buffer allocated. Another is letting one call seal up to N records straight into
   `out_buf`, which would also remove the ciphertext copy into `out_buf`.
3. **Fill records after tiny heads.** In a measured experiment, `pack_record` was allowed to fill past a large
   next slice when the record so far was under 1 KiB. On 4×(9B+16KiB), records dropped from 128 to 80 per
   MiB and reader CPU fell 6–16% over three runs (580/623/567 vs 617/717/672 ns/KiB). Writer CPU in null
   mode rose from 253 to 277 ns/KiB, because every byte is now copied, as rustls does. Idea 1 gets the
   same benefit without the copy.
4. **Stop polling a transport that just returned Pending.** With small writes, btls polls the transport 2.6
   times per message (drain, write-through, drain) against 1.0 for rustls: 27,457 vs 10,662 calls per MiB.
   The extra polls all return Pending, so they are cheap, but a per-call "transport pending" flag would skip
   them.
5. **Keep the "one record past the cap" rule.** It already spares btls the two-call split that rustls pays on
   inputs slightly over 64 KiB.
