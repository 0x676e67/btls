# Vectored write benchmark: tokio-btls vs tokio-rustls

Compares the vectored write path of `tokio-btls` (BoringSSL) with `tokio-rustls` 0.26.6 + `rustls` 0.23.45
(aws-lc-rs). Both negotiate TLS 1.3 with AES-128-GCM. "Before" is tokio-btls at `b4a667b`, which makes one
`SSL_write` per record. "After" is `3a490de`, which seals with `SSL_seal_app_data` (patch 0012).

Measured on a 4 vCPU cloud VM with VAES and AVX-512, over loopback. Before, after and rustls runs are
interleaved. Each table cell is the median of the round medians: 5 rounds of 7 runs pinned to one core for
null mode, 3 such rounds for `null-partial`, and 2 rounds of 5 unpinned runs for TCP. Raw output, callgrind
counts and the tuning sweep are in [`results/`](results). [`results/baseline/`](results/baseline) holds the
write path before the switch, measured on the same VM.

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

- **btls now costs less CPU than rustls on every shape except the smallest.** Sealing into caller memory
  cut btls writer CPU by 9–27% in null mode. btls is now 4–29% below rustls, except 1×100B (+15%, down
  from +57%) and 64×64B (+3%, down from +14%).
- **No per-record overhead in BoringSSL.** btls makes no C allocation per record (C allocs/MiB 64 → 0 on
  the large shapes) and no `SSL_write` call after the handshake. Callgrind counts 699 fewer instructions
  per 100 B write (3,518 → 2,819, against 2,448 for rustls) and 54,000–67,000 fewer per 64 KiB call
  (about 156,000, against about 221,000 for rustls).
- **Full records across slices.** `[9 B header, 16 KiB payload]` shapes now make 80 records/MiB, as
  rustls does, down from 128. Small-slice shapes need half the Rust allocations, because the packing
  scratch Vec is gone.
- **Syscalls stay a tie, except for h2.** Both stacks make one transport write per ~64 KiB call. btls still
  takes inputs slightly over 64 KiB in one call, while rustls needs two calls and twice the syscalls (32 vs
  16 per MiB). After the handshake every btls transport write is a plain `write`, with no `writev`.
- **On real TCP, btls writer CPU fell on every row**, by 6–27%. It is below rustls on every shape except
  h2 (473 vs 420 ns/KiB). Reader CPU fell by up to 21% (1×256KiB: +0.4%). 1×100B polls the transport
  once per message, down from 2.62. Round medians swing by up to 21% on this VM, so read the TCP ratios
  as tendencies.

## CPU cost of the write path (null transport)

Lower is better. "a / r" columns list btls after, then rustls.

| Shape per call | btls before ns/KiB | btls after ns/KiB | rustls ns/KiB | after vs before | after vs rustls | records/MiB a / r | transport calls/MiB a / r | Rust allocs/MiB a / r |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1×100B | 4167 | 3058 | 2648 | −27% | +15% | 10487 / 10486 | 10486 / 10486 | 10486 / 20972 |
| 64×64B | 276 | 250 | 243 | −9% | +3% | 256 / 256 | 256 / 256 | 256 / 768 |
| 512×32B | 297 | 256 | 274 | −14% | −7% | 64 / 64 | 64 / 64 | 64 / 192 |
| 16×1KiB | 121 | 101 | 111 | −17% | −9% | 64 / 64 | 64 / 64 | 64 / 192 |
| 4×(9B+16KiB) | 129 | 97 | 124 | −25% | −22% | 80 / 80 | 16 / 32 | 32 / 112 |
| 4×16KiB | 107 | 86 | 121 | −20% | −29% | 64 / 64 | 16 / 16 | 32 / 96 |
| 2×64KiB | 111 | 87 | 121 | −22% | −28% | 64 / 64 | 16 / 16 | 24 / 80 |
| 1×256KiB | 111 | 87 | 120 | −22% | −28% | 64 / 64 | 16 / 16 | 20 / 68 |
| 8×2KiB | 115 | 99 | 107 | −14% | −7% | 64 / 64 | 64 / 64 | 64 / 192 |
| 4×4KiB | 115 | 94 | 106 | −18% | −11% | 64 / 64 | 64 / 64 | 64 / 192 |
| 10000B+7000B | 127 | 111 | 116 | −13% | −4% | 123 / 123 | 62 / 62 | 123 / 247 |

Before, btls made 128 records/MiB on 4×(9B+16KiB) and twice the Rust allocations on 64×64B, 512×32B,
16×1KiB, 8×2KiB and 4×4KiB. Its other counters were the same. It also made one C allocation per record;
after, it makes none (0.1/MiB on 1×100B, from the handshake).

### With backpressure (`null-partial`)

| Shape per call | btls before ns/KiB | btls after ns/KiB | rustls ns/KiB | after vs before | TLS calls/msg b / a / r | transport calls/MiB b / a / r |
|---|---:|---:|---:|---:|---:|---:|
| 1×100B | 4549 | 3577 | 2691 | −21% | 1 / 1 / 1 | 20972 / 20972 / 10486 |
| 64×64B | 304 | 279 | 248 | −8% | 1 / 1 / 1 | 512 / 512 / 256 |
| 512×32B | 330 | 286 | 279 | −13% | 1 / 1 / 1 | 256 / 128 / 128 |
| 16×1KiB | 175 | 150 | 135 | −14% | 1 / 1 / 1 | 256 / 128 / 128 |
| 4×(9B+16KiB) | 197 | 126 | 136 | −36% | 2 / 4 / 4 | 128 / 128 / 128 |
| 4×16KiB | 190 | 128 | 136 | −33% | 2 / 3 / 4 | 128 / 128 / 128 |
| 2×64KiB | 191 | 124 | 134 | −35% | 4 / 7 / 8 | 128 / 128 / 128 |
| 1×256KiB | 187 | 119 | 130 | −36% | 8 / 15 / 16 | 128 / 128 / 128 |
| 8×2KiB | 175 | 150 | 129 | −14% | 1 / 1 / 1 | 256 / 128 / 128 |
| 4×4KiB | 180 | 129 | 129 | −28% | 1 / 1 / 1 | 256 / 128 / 128 |
| 10000B+7000B | 146 | 135 | 137 | −8% | 1 / 1 / 1 | 247 / 128 / 128 |

A call that finds the transport blocked no longer polls it again. Large writes therefore take more TLS
calls, as rustls's do, and 16 KiB writes make half the transport calls. Partial writes also advance an
offset instead of shifting the buffer.

## Loopback TCP

No EAGAIN occurred in any run, because the reader kept up. Batching under load came from tokio's coop
budget, which applied to both stacks equally. Writer CPU includes the kernel copy. "b / a / r" columns list
btls before, btls after, then rustls.

| Shape per call | MiB/s b / a / r | writer ns/KiB b / a / r | reader ns/KiB b / a / r | syscalls/MiB a / r | transport polls/msg b / a / r |
|---|---:|---:|---:|---:|---:|
| 1×100B | 127 / 157 / 127 | 7658 / 6176 / 7678 | 5631 / 4434 / 4753 | 2024 / 2048 | 2.62 / 1.00 / 1.02 |
| 64×64B | 591 / 640 / 583 | 1654 / 1525 / 1674 | 1180 / 1084 / 1143 | 229 / 231 | 1.23 / 1.01 / 1.02 |
| 512×32B | 1042 / 1168 / 1072 | 936 / 836 / 912 | 535 / 494 / 514 | 62.5 / 63 | 1.07 / 1.02 / 1.02 |
| 16×1KiB | 1638 / 1783 / 1502 | 595 / 548 / 656 | 465 / 447 / 466 | 62.5 / 63 | 1.07 / 1.02 / 1.02 |
| 4×(9B+16KiB) | 1944 / 2070 / 2327 | 502 / 473 / 420 | 399 / 363 / 376 | 16 / 32 | 1.02 / 1.02 / 2.03 |
| 4×16KiB | 1924 / 2098 / 2046 | 504 / 465 / 477 | 367 / 363 / 354 | 16 / 16 | 1.02 / 1.02 / 1.02 |
| 2×64KiB | 1794 / 2090 / 2052 | 544 / 467 / 476 | 380 / 357 / 362 | 16 / 16 | 2.05 / 2.03 / 2.03 |
| 1×256KiB | 1781 / 2090 / 2054 | 548 / 467 / 475 | 372 / 373 / 362 | 16 / 16 | 4.09 / 4.06 / 4.06 |
| 8×2KiB | 1693 / 1837 / 1680 | 577 / 532 / 582 | 462 / 439 / 448 | 62.5 / 63 | 1.07 / 1.02 / 1.02 |
| 4×4KiB | 1682 / 2118 / 1656 | 580 / 461 / 590 | 472 / 414 / 456 | 62.5 / 63 | 1.07 / 1.02 / 1.02 |
| 10000B+7000B | 1628 / 2239 / 1625 | 600 / 436 / 596 | 471 / 414 / 478 | 60.3 / 60.7 | 1.07 / 1.02 / 1.02 |

btls syscalls/MiB did not change. Round medians of one row swung by up to 21%; for example, the two h2
rounds of btls after were 17% apart. Read the throughput column as a tendency only. The counters are
deterministic.

## How each stack writes

**tokio-btls**

- `is_write_vectored` returns true. A call first retries buffered ciphertext. If the transport returns
  `Pending`, the call does not poll it again.
- A write of up to 16 KiB with nothing buffered is sealed by one `SSL_seal_app_data` call into a 17 KiB
  stack buffer and sent with one `write`. Records that do not fit there (small send fragments, a large
  ticket flight) are buffered, and the rest of the write follows them in the same transport write.
- Larger writes, and writes behind buffered records, are sealed straight into `out_buf`'s spare capacity.
  Sealing stops at about 64 KiB of ciphertext but takes a final tail of up to 16 KiB in the same call. Then
  `out_buf` is drained with one `write`.
- BoringSSL fills every record across slice boundaries. With AES-GCM, pieces of 4 KiB or more are
  encrypted where they are; shorter ones are copied into the record. There is no per-record `malloc`, no
  BIO round trip, and the error queue is cleared only when it holds an error.
- Under backpressure, sealed bytes are reported as written and kept in the buffer. Partial writes advance
  an offset into it.
- States that `SSL_seal_app_data` declines, such as a handshake in progress or a FIPS build, fall back to
  one `SSL_write` per record. Small slices are packed into records no larger than the send fragment.

**tokio-rustls / rustls**

- Each call makes one `writer().write_vectored()`. It allocates a `Vec<&[u8]>` of the slices and chunks them
  as if they were one flat buffer, so every record is full.
- Accepted plaintext is capped by the 64 KiB `sendable_tls` limit, with no second pass in the same call.
  A 65,572 B input needs two calls and two syscalls, and the second one carries a 36 B record.
- Each record is a new Vec. The plaintext is copied into it and encrypted in place.
- `write_tls` gathers up to 64 record Vecs into one `writev`, with no ciphertext copy.

## Improvement ideas for tokio-btls

1. **Gather sealing in BoringSSL.** Done: patch 0012 seals through `EVP_AEAD_CTX_sealv` with pieces of 4 KiB
   or more left in place. A sweep of 1, 2 and 8 KiB found no better threshold.
2. **Seal several records per call into caller memory.** Done: `SSL_seal_app_data` seals a whole call into
   the stack buffer or `out_buf`. It removes the per-record `malloc`, the BIO round trip and the ciphertext
   copy into `out_buf`.
3. **Fill records after tiny heads.** Done through idea 1, without the plaintext copy: 4×(9B+16KiB) makes 80
   records/MiB, and its TCP reader CPU fell 9%.
4. **Stop polling a transport that just returned Pending.** Done: TCP 1×100B polls 1.00 times per message,
   against 2.62 before and 1.02 for rustls.
5. **Keep the "one record past the cap" rule.** Kept. It still spares btls the two-call split that rustls
   pays on inputs slightly over 64 KiB.
6. **Trim the per-call fixed cost.** 1×100B still costs 15% more CPU than rustls: 2,819 instructions per
   call against 2,448. Patch 0012 could look up the protocol version and seal overhead once per call.
