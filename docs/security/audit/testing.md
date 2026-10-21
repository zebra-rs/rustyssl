# Building and testing rustyssl

Everything runs from the repository root with the pinned toolchain (`rust-toolchain.toml`,
stable 1.99). README.md's "Commands" section lists each command and the tools it needs; this is
the short path for an auditor.

## Build

```sh
cargo build --workspace                 # every crate
cargo xtask ref-openssl                 # the reference OpenSSL 3.6.5 into target/ref/ (verified download)
cargo xtask dist                        # libcrypto.so.3/libssl.so.3 (macOS: .3.dylib) and bin/openssl into target/dist/
```

Linking an application against rustyssl: build it against OpenSSL 3's headers as usual and point
the loader at `target/dist/lib` (`LD_LIBRARY_PATH`, or `DYLD_LIBRARY_PATH` on macOS).

## The gates CI runs (about an hour on a laptop)

```sh
bash scripts/gates.sh                   # all of the below, one summary line per gate
```

| Gate | What it checks |
|---|---|
| `cargo fmt`, `cargo clippy -D warnings` | style; the lints that enforce the security rules (unsafe documentation, no lossy casts, no `unwrap`/indexing in parsers) |
| `cargo test --workspace` | unit, property and known-answer tests |
| `cargo xtask codegen`, `coverage` | generated code is current; every export has a C conformance test |
| `cargo xtask unsafe-audit` | the unsafe budget per module, `forbid(unsafe_code)` elsewhere, the panic guard on every export |
| `cargo xtask test-c` | 272 C programs, compiled against OpenSSL's headers, run on the reference and on rustyssl: output must match |
| `cargo xtask test-apps` | the `openssl` tool's 4 342 command lines, ours and upstream's, on both libraries |
| `cargo xtask test-openssl-suite` | upstream's `evp_test` data files and BN/EC/RSA programs on rustyssl |
| `cargo xtask test-wycheproof` | Wycheproof's vectors (61 339 tests) on both libraries |
| `cargo xtask test-differential --random 1000` | a probe corpus and random API sessions, reference vs rustyssl |
| `cargo xtask abi-check` | symbols, versions, signatures, struct layouts and constants against the reference build |
| `cargo deny check`, `cargo vet --locked` | advisories, licenses, sources; audited dependencies |
| `cargo +nightly miri test -p rustyssl-capi` | the FFI layer's tests under Miri, on the host and on x86_64 Linux |

## Longer suites

```sh
cargo xtask test-openssl-suite --all [--cli ours]   # upstream's whole test/recipes tree: 4334/4334 eligible on macOS
cargo xtask test-openssl-suite --ssl                # libssl's upstream test programs
cargo xtask test-interop [--peer gnutls|quic]       # TLS/DTLS/QUIC against the reference and GnuTLS
cargo xtask test-bogo                               # BoringSSL's TLS test runner
cargo xtask test-tlsfuzzer [--timing]               # tlsfuzzer's scripts against s_server
cargo xtask test-timing                             # dudect constant-time checks and Marvin's RSA split
cargo xtask test-consumers                          # rust-openssl, ruby/openssl, pyca/cryptography, Node.js, ngtcp2, curl-h3
cargo xtask test-quic-interop                       # quic-interop-runner's core cases against quiche, ngtcp2, quic-go
cargo xtask test-providers                          # oqs-provider, pkcs11-provider, tpm2-openssl
```

## Fuzzing

```sh
cargo +nightly fuzz list                            # 108 targets (fuzz/fuzz_targets/)
cargo +nightly fuzz run <target>
```

ClusterFuzzLite runs them on every pull request and daily (`oss-fuzz/README.md`).
