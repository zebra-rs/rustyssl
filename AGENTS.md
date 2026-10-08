# AGENTS.md — rustssl

## Mission

rustssl is a **memory-safe Rust reimplementation of OpenSSL** (libcrypto + libssl) that
works as a **drop-in binary replacement**. An application built against OpenSSL must run
unchanged with rustssl's libraries in its place, with no recompile and no source changes.

Why it exists: **security**. OpenSSL's history of memory-safety and parsing CVEs
(Heartbleed, ASN.1 and X.509 parser bugs, the punycode overflow, and others) comes mostly
from C. rustssl removes that class of bug and keeps the exact C API/ABI, so adopting it
costs users nothing.

Priority order when goals conflict:
1. **Security and correctness**
2. **ABI and behavioral compatibility** with OpenSSL
3. Performance

Plans: [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) (phased steps) and
[docs/TEST_PLAN.md](docs/TEST_PLAN.md) (verification strategy). Keep both current: mark
steps done and record decisions as they're made.

## Compatibility target

| Milestone | ABI | Libraries |
|---|---|---|
| Primary | **OpenSSL 3.x**: 3.5 LTS symbol set first, then the 3.6 additions | `libcrypto.so.3`, `libssl.so.3` (macOS: `lib*.3.dylib`) |
| Later | **OpenSSL 4.0** (ENGINE API removed, ECH added, etc.) | `libcrypto.so.4`, `libssl.so.4` from the same core |

Size of the surface (OpenSSL 3.6): about 6,200 public libcrypto functions and about 650
libssl functions, plus 20–40 exported data symbols. The exact list is `util/libcrypto.num`
and `util/libssl.num`.

**Sources of truth** are vendored under `abi/openssl-<ver>/` by `cargo xtask vendor` (see
`abi/README.md`): the public headers, the `.num` files, `objects.txt`, the error tables, and
the man pages (OpenSSL 3+ is Apache-2.0; keep its copyright). `configuration.h` differs per
target and lives under `config/<target>/`; for example, `RC4_INT` changes the `RC4_KEY` layout
between x86_64 and aarch64 Linux, so layouts and bindings are per target. The man pages (`doc/man3/*.pod`) are the
behavioral spec. When the docs are silent or ambiguous, **the reference OpenSSL build's
actual behavior is the spec**. Test it, don't guess.

"Compatible" means all of the following:
- The same exported symbols with the same **ELF symbol versions** (`OPENSSL_3.0.0` …
  `OPENSSL_3.6.0`), the same sonames, and the same macOS install names.
- The same function signatures, and the same `#[repr(C)]` layout for every struct that's
  public in the headers (`ASN1_STRING`, `ASN1_TYPE`, `X509_ALGOR`, `GENERAL_NAME`,
  `OSSL_PARAM`, `OSSL_DISPATCH`, `CRYPTO_EX_DATA`, `X509V3_CTX`, the `ASN1_ITEM`
  templates, and so on).
- The same semantics for `*_ctrl()` command numbers. Many public "functions" are header
  macros that expand to `SSL_CTX_ctrl(ctx, CMD, larg, parg)` and similar calls.
- The same return conventions (`1`/`0`/`-1`/`<=0`/`NULL`), the same NULL-argument
  behavior (`X509_free(NULL)` is a no-op, for example), and the same ownership rules
  (`get0`/`get1`/`set0`/`set1`/`push0`/`push1`, `*_up_ref`).
- The same error-queue entries (`ERR_LIB_*` and reason codes) wherever applications can
  observe them, plus exact `X509_V_ERR_*` verify results and exact `SSL_get_error()` state
  transitions.
- **Byte-identical output** from print, encode, and PEM functions (`X509_print_ex`,
  `ERR_error_string_n`, `i2d_*`, `PEM_write_*`, and others). Applications and test suites
  diff these.
- The same config-file semantics (`openssl.cnf`, `OPENSSL_CONF`, provider and
  `ssl_conf` sections). Distro crypto policies depend on them.
- The same thread-safety guarantees as OpenSSL 3 (a shared `SSL_CTX` is safe across
  threads, and so on).

**Default feature set = OpenSSL's default `./Configure` build, plus
`enable-ec_nistp_64_gcc_128`.** Debian and Homebrew turn that option on, and it only adds
API (`EC_GFp_nistp{224,256,521}_method`), so binaries built there must load on rustssl. The
options live in `CONFIGURE_OPTIONS` in `xtask/src/vendor.rs`. Whatever upstream disables by
default (SSLv3, weak SSL ciphers, MD2, RC5, …) stays disabled. Legacy algorithms (MD4, RC4,
DES, Blowfish, …) are available only through the `legacy` provider. There is no FIPS
provider.

**Deviations** are allowed only for security reasons (for example, when no compatible
behavior is safe). Each one is recorded in `docs/DEVIATIONS.md` with its rationale and a
test.

## Architecture

Planned workspace layout (built in Phase 0):

```
abi/openssl-3.5/      vendored headers (+ config/<target>/), *.num, objects, err tables, man pages
crates/
  rustssl-abi/        generated per target from abi/: types, layouts, enums, every macro constant. No logic.
  rustssl-asn1/       DER/BER reader and writer, ASN.1 universal types, OID/NID registry, base64, PEM framing
  rustssl-crypto/     algorithm facade + backend traits, DRBG/RNG, BIGNUM, built-in provider algorithms
  rustssl-pki/        X.509/CRL/CSR, path validation, PKCS#7/#8/#12, CMS, OCSP, TS, CT
  rustssl-tls/        sans-IO TLS 1.0–1.3 + DTLS: record layer, handshake state machines, cipher-string parser
  rustssl-quic/       (later phase) QUIC transport for the SSL QUIC API
  rustssl-capi/       THE FFI LAYER: every extern "C" export, handle tables, BIO, callbacks,
                      OSSL_PARAM, ex_data, ERR queue, CRYPTO_malloc, the ASN1_ITEM template engine
libs/
  libcrypto/          static archive, linked into libcrypto.so.3 by `cargo xtask dist`; contains the WHOLE implementation
  libssl/             static archive of generated forwarders, linked into libssl.so.3; no implementation of its own
xtask/                codegen, version scripts, symbol coverage, ABI checks, reference-OpenSSL builds, test drivers
tests/                c/ (C conformance), differential/, interop/, consumers/, cve/
fuzz/                 cargo-fuzz targets
docs/                 plans, DEVIATIONS.md, DEPENDENCIES.md
```

Key design decisions:
- **One implementation, two ABI facades** ([ADR 0001](docs/adr/0001-library-layout.md)).
  All code and state live in libcrypto: objects, the allocator, the global state, and the
  TLS code, which libcrypto exports to libssl only, as `rustssl_private_<function>` in its
  `RUSTSSL_PRIVATE` version node. libssl exports exactly OpenSSL's libssl functions, each a
  generated one-branch forwarder to its private twin, and contains no Rust runtime. This
  keeps objects such as an `X509*` shared safely between the libraries. For static linking,
  `libcrypto.a` carries everything and `libssl.a` holds only the forwarders. Validated on
  macOS, glibc, and musl.
- **Cargo builds each facade as a static archive; `cargo xtask dist` links the shared
  libraries** from them with the C compiler. rustc gives every cdylib its own anonymous
  version script, which GNU ld refuses to combine with OpenSSL's named version nodes, so
  `cargo build` alone never produces the shipped `.so`/`.dylib`.
- **The core crates are safe, idiomatic Rust and sans-IO.** They know nothing about C
  pointers, BIOs, or callbacks. `rustssl-capi` adapts them to the C model.
- **There are two kinds of C-visible objects.**
  1. **Opaque handles** (`SSL_CTX`, `SSL`, `X509`, `EVP_PKEY`, `EVP_MD_CTX`, …) point to
     Rust-owned objects. Their refcounts map onto `*_up_ref` and `*_free`, and interior
     mutability matches OpenSSL's mutate-after-share patterns.
  2. **Public-layout structs** (`ASN1_STRING`, `GENERAL_NAME`, …) are `#[repr(C)]`
     mirrors from `rustssl-abi`. They're allocated with `CRYPTO_malloc` and populated by
     the ASN1_ITEM template engine. That engine also interprets **application-defined**
     `ASN1_SEQUENCE(...)` templates; built-in opaque types are exposed to it as
     `ASN1_ITYPE_EXTERN` items.
- **`get0` pointers stay valid for the parent's lifetime.** Sub-objects that can be
  borrowed (`X509_get_subject_name`, for example) live at stable heap addresses and are
  never moved or reallocated while the parent is alive.
- **Crypto primitives** come from vetted pure-Rust crates (RustCrypto and similar) behind
  backend traits in `rustssl-crypto`, so each one can be replaced. **Protocol and parsing
  code is our own**: ASN.1, X.509, PEM, PKCS#*, CMS, TLS, DTLS, and QUIC. That's where
  OpenSSL's CVEs concentrated.
- **The provider architecture is real.** `OSSL_LIB_CTX`, `EVP_*_fetch`, `OSSL_PARAM`,
  and the built-in `default`/`base`/`legacy`/`null` providers are all implemented. A
  later phase adds loading **third-party C providers** (`OSSL_provider_init` plus the
  core dispatch upcalls).

## Security rules (non-negotiable)

1. **`unsafe` only in `rustssl-capi`** and the `libs/*` shims. Every other crate has
   `#![forbid(unsafe_code)]`. Each `unsafe` block needs a `// SAFETY:` comment, enforced
   by `clippy::undocumented_unsafe_blocks = "deny"`.
2. **Treat the FFI boundary as hostile input.** Turn raw pointer and length pairs into
   slices exactly once, at the boundary, after checking them. Never truncate with `as`
   between `int`, `size_t`, and `long`; use `try_from` and fail like OpenSSL does.
   Handle NULL exactly as OpenSSL documents.
3. **No panics across FFI.** Every export goes through the `ffi_export!` wrapper. It
   catches unwinds, pushes an ERR entry, and returns the function's failure value. Core
   code must never panic on attacker-controlled input: deny `unwrap_used`, `expect_used`,
   and `indexing_slicing` in parser and protocol crates, and use checked arithmetic for
   every length and offset. Fuzzers treat any panic as a bug.
4. **Constant-time handling of secrets.** No branches or table indexes that depend on
   secret data. Use `subtle`, compare MACs and tags in constant time, and keep RSA
   PKCS#1 v1.5 (implicit rejection, Marvin) and CBC padding checks constant-time. Zeroize
   secrets on drop.
5. **Strict, bounded parsing.** Cap recursion depth, element counts, and sizes. Accept
   lenient encodings only where OpenSSL compatibility demands it, and document each case.
6. **Allocator discipline.** Memory that C callers free with `OPENSSL_free` must come
   from `CRYPTO_malloc`, which honors `CRYPTO_set_mem_functions`. Never free C memory with
   the Rust allocator, and never free Rust memory with `CRYPTO_free`.
7. **Callbacks are re-entrant.** Never hold a lock while invoking a C callback. Callbacks
   may call any API on the same object; for example, the SNI callback can call
   `SSL_set_SSL_CTX`.
8. **Dependencies are pure Rust only.** No C or asm build scripts, `cc`, or `*-sys`
   crates; `core::arch` intrinsics are fine. Every dependency is checked by `cargo vet`
   and `cargo deny` (advisories, licenses, bans) and recorded in `docs/DEPENDENCIES.md`
   (purpose, audit status, constant-time claims). Verify per crate, don't assume. For
   example, RustCrypto `rsa` carries RUSTSEC-2023-0071 (Marvin), so RSA private-key
   operations must use a constant-time path.
9. **Port behavior, not code.** OpenSSL's C source and man pages are the spec; don't
   transliterate the C. Reproduce an OpenSSL quirk only when compatibility requires it,
   and document it.
10. **Fail closed.** An export that isn't implemented yet is a generated stub that names the
    function on stderr and **aborts** the process. Returning an error isn't safe without
    knowing each function's conventions: a stub `CRYPTO_memcmp` returning 0 would say two
    buffers are equal, `SSL_get_verify_result` returning 0 means `X509_V_OK`, and
    `AES_set_encrypt_key` returns 0 on success. An implemented function never reports
    success for work it didn't do. Functions OpenSSL 3 documents as no-ops are implemented
    as no-ops, not left as stubs.
11. **Every relevant historical OpenSSL CVE gets a regression test** in `tests/cve/`.

## Code generation (never hand-type ABI facts)

Generate these from `abi/`, through `rustssl-abi` (bindgen) or `cargo xtask codegen`:
NIDs and OIDs (`objects.txt`), `ERR_LIB_*` and reason codes plus their strings, `*_ctrl`
command numbers, every `#define` constant, public struct layouts, the export list, and
the linker version scripts (from `*.num`). If a value you need isn't generated, extend the
generator. Don't paste the number.

## Commands

Working now: `cargo build`, `test`, `clippy`, `fmt`, `deny`, `vet`, and `fuzz`, and the
xtask commands `vendor`, `codegen`, `dist`, `ref-openssl`, `abi-check`, `test-c`,
`test-differential`, `coverage`, and `usage-scan`.
The other `cargo xtask` commands arrive later and fail with a message until then. Update this
section when they change. CI (`.github/workflows/ci.yml`) runs the gates on every push.

Tools each command needs:
- **`vendor` and `ref-openssl`:** `curl`, `gpg`/`gpgv`, `tar`, `make`, and a full `perl`
  (Debian's `perl`, not just `perl-base`).
- **`codegen`:** `clang` and bindgen 0.73.2 exactly
  (`cargo install bindgen-cli --version 0.73.2 --locked`).
- **`coverage`:** `clang`, a C compiler (`$CC`), and `nm`.
- **`usage-scan`:** `curl`, `xz`, and `zstd`, plus about 5 GB of downloads for a full scan
  (only the per-package results are kept, under `target/`).
- **`dist`, `test-c`, and `test-differential`:** a C compiler (`$CC`), `ar`, and `nm`; on
  Alpine also `llvm-libunwind-dev`.
- **`abi-check`:** what `dist` and `ref-openssl` need, plus `pkg-config`, and on macOS `otool`
  (from the Xcode command-line tools).
- **The supply-chain and fuzzing gates:** `cargo install --locked cargo-deny@0.20.2
  cargo-vet@0.10.2 cargo-fuzz`. Use these exact versions, the ones CI pins: another
  cargo-vet formats `supply-chain/` differently, and CI then fails.

`cargo xtask codegen` writes:

| Output | Contents |
|---|---|
| `crates/rustssl-abi/src/generated/` | types, layouts, enums, and every macro constant, per target |
| `libs/<lib>/exports/` | ELF version scripts (Linux) and exported-symbol lists (macOS), per target |
| `crates/rustssl-capi/src/generated/<lib>_stubs.rs` | an aborting stub for every export that isn't implemented yet |
| `crates/rustssl-capi/src/generated/err_reasons.rs` | the reason-string table |
| `crates/rustssl-asn1/src/generated/objects.rs` | the NID/name/OID table and the signature-algorithm cross-reference |

```sh
cargo build --workspace                      # build everything
cargo test --workspace                       # Rust unit, property, and KAT tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check && cargo vet                # supply-chain gates
cargo xtask vendor 3.5.9                     # fetch, verify (PGP + SHA-256), and vendor a release into abi/
cargo xtask codegen                          # regenerate bindings, export lists, stubs, error and object tables
cargo xtask dist                             # build lib{crypto,ssl}.so.3 with soname + symbol versions into target/dist/
cargo xtask ref-openssl [3.5.9]              # build the reference OpenSSL (default: the vendored version) into target/ref/
cargo xtask abi-check [check...]             # L3: exports+versions, metadata, signatures, layouts, constants, linking, headers
cargo xtask coverage [--list PREFIX...]      # implemented exports per library and header -> docs/coverage.md
cargo xtask usage-scan [--jobs N] [--limit N]  # rank exports by how many distro packages import them -> docs/symbol-usage.md
cargo xtask test-c                           # tests/c/*.c, each run on the reference and on target/dist; output must match
cargo xtask test-differential [--random N] [--seed S]  # probe corpus + N random sessions, reference vs ours
cargo xtask test-openssl-suite               # upstream OpenSSL test suite against our libraries
cargo xtask test-consumers <name>            # curl/nginx/openssh/python/... test suites with our libraries
cargo +nightly miri test -p rustssl-capi     # the unsafe FFI layer under Miri
cargo +nightly fuzz run <target>             # fuzzing (fuzz/ is its own workspace; `cargo +nightly fuzz list`)
```

The toolchain is stable Rust, pinned in `rust-toolchain.toml` (at least 1.99). Rust
1.99 supports defining C-variadic functions (`...`, `VaList::next_arg`), which
`BIO_printf`, `ERR_add_error_data`, and `ERR_raise_data` need, so no C shim is required.

## How to work in this repo

- **For each API family:** read the man pages and headers in `abi/`, then write the tests
  first (KAT, differential against the reference OpenSSL, and a C conformance test
  compiled against the official headers). Then implement the safe core, then the `capi`
  exports, then update the coverage status. Within a phase, go in `docs/symbol-usage.md`
  order: the functions the most distribution packages import come first.
- **To implement an export,** write it in `rustssl-capi` (any `extern "C" fn` outside
  `src/generated/`) and re-run `cargo xtask codegen`, which then drops its stub. A libssl
  function is written as `rustssl_private_<name>`; never implement anything in
  `libs/libssl`, whose forwarders are generated. Codegen also asserts the function's
  signature against the header's prototype at compile time (`generated/signatures.rs`). Use
  `ffi_export!` (`rustssl-capi/src/ffi.rs`) and give each export a `# Safety` section. Handles use `handle_type!`, C memory comes from
  `mem`, and errors go through `err::raise`. It counts as **implemented** only once it has a
  conformance test: a TAP program in `tests/c/` that passes, unchanged, against the reference
  and rustssl (`tests/c/buf_mem.c` is the model). Then run `cargo xtask coverage` and commit
  `docs/coverage.md`. CI fails if that file is stale, or if an export is defined but no test
  in `tests/c/` calls it.
- **Where the reference is the oracle,** add commands to the differential probe
  (`tests/differential/probe.c`), a corpus file, and random generation in
  `xtask/src/test_differential.rs`. **Parsers of untrusted input** get a fuzz target in
  `fuzz/fuzz_targets/` (`buf_mem.rs` is the model-based example).
- Commit one API family or step at a time, and keep the diffs reviewable.
- When OpenSSL's behavior is unclear, run it against the reference build
  (`target/ref/`), whose verified source is in `target/ref/openssl-<version>/src/`. Behavior
  matters more than intent, and it can differ by platform (measure macOS and Linux).
- Mark progress in `docs/IMPLEMENTATION_PLAN.md`, and record each new deviation in
  `docs/DEVIATIONS.md`.
- Edition 2024. Errors in core crates are typed (`thiserror`-style enums), and capi maps
  them to ERR codes in one place per crate.
- License: Apache-2.0 (`LICENSE.txt`), matching OpenSSL 3. Every crate sets
  `license = "Apache-2.0"`. Vendored files keep their upstream headers.
