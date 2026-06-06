# Low-level bindings to BoringSSL

[BoringSSL](https://boringssl.googlesource.com/boringssl) is Google's fork of OpenSSL for Chrome/Chromium and Android.

This crate builds the BoringSSL library (or optionally links a pre-built version) and generates FFI bindings for it.
It supports [FIPS-compatible builds of BoringSSL](https://boringssl.googlesource.com/boringssl/+/master/crypto/fipsmodule/FIPS.md),
as well as [Post-Quantum crypto](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
and [Raw Public Key](https://docs.rs/btls/latest/btls/ssl/struct.SslRef.html#method.peer_pubkey) extensions.

To use BoringSSL from Rust, prefer the [higher-level safe API](https://docs.rs/btls).

## Speeding up the build

Compiling BoringSSL from source is by far the most expensive part of building
this crate. The build script applies two accelerations automatically:
       
- **Ninja generator.** When [`ninja`](https://ninja-build.org/) is found on 
  it is used instead of the default `make` generator. Ninja has lower
  configure overhead and schedules the compile better. An explicit
  `CMAKE_GENERATOR` is always respected, and Windows generator selection is left
  untouched.

- **Compiler caching.** `RUSTC_WRAPPER` only caches `rustc`, so the ~370
  BoringSSL translation units are recompiled on every clean build even when
  [`sccache`](https://github.com/mozilla/sccache) or
  [`ccache`](https://ccache.dev/) is configured.  
  If `RUSTC_WRAPPER`/`RUSTC_WORKSPACE_WRAPPER` points at `sccache` or
  `ccache` it is reused as-is; otherwise set `BORING_BSSL_COMPILER_LAUNCHER`
  explicitly:

  ```sh
  # Reuse an existing sccache automatically:
  export RUSTC_WRAPPER=sccache

  # ...or point the BoringSSL build at a cache explicitly:
  export BORING_BSSL_COMPILER_LAUNCHER=sccache
  ```

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.
