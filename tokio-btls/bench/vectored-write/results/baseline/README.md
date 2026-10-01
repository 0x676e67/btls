# Baseline before `SSL_seal_app_data`

These numbers show the write path at `10fbd67`, measured with this harness. Patch 0012 is applied there,
but tokio-btls does not call it yet. They are the reference for the switch to the sealing API.

- **Machine.** A 4 vCPU KVM guest on an Intel Xeon at 2.1 GHz (family 6, model 207) with VAES,
  VPCLMULQDQ and AVX-512. Linux 6.18, glibc 2.39, rustc 1.97.0, release profile, otherwise idle.
- **Runs.** Each row is the median of its runs:
  - [`null.md`](null.md): `vbench null '' 7`;
  - [`null-partial.md`](null-partial.md): `vbench null-partial '' 7`;
  - [`tcp.md`](tcp.md): `vbench tcp '' 5`.
- **Comparison with the README.** The null-mode counters match its raw output in [`../`](..) exactly, and
  the TCP counters to within 0.1. This VM is faster, so the ns/KiB figures are lower: 4x16KiB takes
  110 ns/KiB here against 212 there.
- **Session tickets.** btls sends its TLS 1.3 session tickets with the first write. Their ~380 bytes count
  as about 17 records per run in btls's rows: 1.1 records/MiB on 1x100B, and more at a higher `VB_SCALE`.

## Callgrind

Each row comes from
`VB_IMPL=<impl> VB_SCALE=16 valgrind --tool=callgrind --toggle-collect='*poll_tls_write*' vbench null <case> 1`
(valgrind 3.22).

- **Ir per call** counts only the TLS write calls.
- **Call counts** come from `callgrind_annotate --tree=caller` and cover the whole run, so `EnsureCap`'s 9
  handshake mallocs are included.
- **Crypto code path.** Valgrind hides AVX-512 and VAES, so both libraries run their AES-NI/AVX GCM code
  here.

| case | btls TLS calls | btls Ir per call | rustls TLS calls | rustls Ir per call | btls `SSL_write` calls | btls `EnsureCap` mallocs |
|---|---:|---:|---:|---:|---:|---:|
| 1x100B | 10486 | 3,533 | 10486 | 2,448 | 10486 | 10495 |
| 64x64B | 1024 | 16,999 | 1024 | 16,181 | 1024 | 1033 |
| 512x32B | 256 | 71,027 | 256 | 72,330 | 256 | 265 |
| 16x1KiB | 1024 | 43,542 | 1024 | 42,374 | 1024 | 1033 |
| h2 4x(9B+16KiB) | 512 | 222,636 | 1024 | 112,094 | 4096 | 4105 |
| 4x16KiB | 512 | 210,519 | 512 | 221,379 | 2048 | 2057 |
| 2x64KiB | 512 | 218,793 | 512 | 221,247 | 2048 | 2057 |
| 1x256KiB | 512 | 222,875 | 512 | 221,076 | 2048 | 2057 |
| 8x2KiB | 1024 | 42,944 | 1024 | 41,600 | 1024 | 1033 |
| 4x4KiB | 1024 | 42,646 | 1024 | 41,269 | 1024 | 1033 |
| 10000B+7000B | 987 | 55,608 | 987 | 53,367 | 1974 | 1983 |
