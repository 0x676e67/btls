# Raw results

The README tables come from these runs. "old" is the write path at `b4a667b`, one `SSL_write` per record.
"new" is the `SSL_seal_app_data` write path at `3a490de`. Both binaries are built from this harness, and
"rustls" runs from the new binary.

- **Machine.** A 4 vCPU KVM guest on an Intel Xeon at 2.1 GHz (family 6, model 207) with VAES,
  VPCLMULQDQ and AVX-512. Linux 6.18, glibc 2.39, rustc 1.97.0, release profile, otherwise idle.
- **Runs.** Each round runs old, new and rustls in turn. A table cell is the median of the per-round
  medians.
  - [`null.md`](null.md): `VB_IMPL=<impl> taskset -c 2 vbench null '' 7`, 5 rounds;
  - [`null-partial.md`](null-partial.md): the same in `null-partial` mode, 3 rounds;
  - [`tcp.md`](tcp.md): `VB_IMPL=<impl> vbench tcp '' 5`, unpinned, 2 rounds.
- **Noise.** The round medians of a row spread by up to 9% in null mode, by up to 32% in `null-partial`
  (old, large shapes) and by up to 21% in TCP mode. The null and `null-partial` counters are identical
  in every round.
- **Drift.** The null rustls medians are within ±4.3% of [`baseline/`](baseline), which was measured on
  the same machine before the switch.

## Callgrind

`VB_IMPL=<impl> VB_SCALE=16 valgrind --tool=callgrind --toggle-collect='*poll_tls_write*' vbench null <case> 1`
(valgrind 3.22). "Ir per call" counts only the TLS write calls. Valgrind hides AVX-512 and VAES, so both
libraries run their AES-NI/AVX GCM code here. The new path calls no `SSL_write` and makes no `malloc` from
`SSLBuffer::EnsureCap` while writing.

| case | old Ir per call | new Ir per call | change | rustls Ir per call | old `SSL_write` calls | new `SSL_write` calls |
|---|---:|---:|---:|---:|---:|---:|
| 1x100B | 3,518 | 2,819 | −699 | 2,448 | 10486 | 0 |
| 64x64B | 16,984 | 16,162 | −822 | 16,181 | 1024 | 0 |
| 512x32B | 71,012 | 66,523 | −4,489 | 72,330 | 256 | 0 |
| 16x1KiB | 43,527 | 42,271 | −1,256 | 42,374 | 1024 | 0 |
| h2 4x(9B+16KiB) | 222,516 | 160,630 | −61,886 | 112,086 (2 calls per message) | 4096 | 0 |
| 4x16KiB | 210,459 | 156,198 | −54,261 | 221,374 | 2048 | 0 |
| 2x64KiB | 218,733 | 156,179 | −62,554 | 221,247 | 2048 | 0 |
| 1x256KiB | 222,815 | 156,207 | −66,608 | 221,108 | 2048 | 0 |
| 8x2KiB | 42,929 | 41,591 | −1,338 | 41,600 | 1024 | 0 |
| 4x4KiB | 42,631 | 40,583 | −2,048 | 41,269 | 1024 | 0 |
| 10000B+7000B | 55,578 | 43,945 | −11,633 | 53,367 | 1974 | 0 |

## Tuning sweep

[`sweep.md`](sweep.md) holds the raw output: btls only, null mode, pinned, 5 interleaved rounds of 7 runs.
The variants are:

- `g1024`, `g2048` and `g8192`: patch 0012's `kSealGatherMin` (4096 in `new`);
- `s8k`: `SEAL_STACK_LEN = 8 KiB`, with the stack path limited to writes that fit it.

Writer ns/KiB:

| case | new | g1024 | g2048 | g8192 | s8k |
|---|---:|---:|---:|---:|---:|
| 1x100B | 3055 | −0.4% | +1.3% | −0.5% | −0.2% |
| 64x64B | 250 | +1.2% | +0.8% | +0.0% | +2.4% |
| 512x32B | 255 | +0.0% | +1.6% | +0.4% | +7.1% |
| 16x1KiB | 104 | +8.7% | +0.0% | −1.0% | +5.8% |
| h2 4x(9B+16KiB) | 95 | +0.0% | +0.0% | −1.1% | −1.1% |
| 4x16KiB | 87 | +0.0% | +0.0% | +0.0% | +0.0% |
| 2x64KiB | 87 | +1.1% | −1.1% | +1.1% | −1.1% |
| 1x256KiB | 86 | +0.0% | +0.0% | +0.0% | −1.2% |
| 8x2KiB | 98 | +2.0% | +3.1% | +1.0% | +8.2% |
| 4x4KiB | 94 | +0.0% | +1.1% | +6.4% | +11.7% |
| 10000B+7000B | 111 | −0.9% | +1.8% | +2.7% | −0.9% |

- No other threshold is 2% better on two rows. Gathering 1 KiB pieces costs 16x1KiB 8.7%, and copying
  4 KiB pieces costs 4x4KiB 6.4%. 4 KiB stays.
- An 8 KiB stack buffer saves nothing on 1x100B or 64x64B. It sends the 16 KiB shapes through `out_buf`,
  which costs 6–12% and doubles their Rust allocations (64 → 128 per MiB). 17 KiB stays.
