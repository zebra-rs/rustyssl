# rustyssl Implementation Plan

Baseline: **OpenSSL 3.5 LTS ABI → 3.6 additions → OpenSSL 4.0 ABI.**
See [README.md](../README.md) for the rules and architecture, and [TEST_PLAN.md](TEST_PLAN.md)
for how each step is verified.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done. Update this file as you work.

The project was called rustssl until 2026-10-07; it was renamed because that name is taken on
crates.io. Everything changed with it: the crates (`rustyssl-*`), libssl's private symbols
(`rustyssl_private_*` in the `RUSTYSSL_PRIVATE` version node), the build variables
(`RUSTYSSL_OPENSSLDIR`, `RUSTYSSL_ENGINESDIR`, `RUSTYSSL_MODULESDIR`), and the build metadata
in the version text (`+rustyssl.<version>`).

---

## Strategy

1. **Foundations first.** ABI scaffolding, code generation, the reference OpenSSL build, and
   the test harnesses exist before any feature work. That makes every later step measurable
   (coverage %, conformance pass rate, consumer pass rate).
2. **Bottom-up by dependency:** runtime → ASN.1 → EVP → public keys → X.509 → TLS.
3. **A vertical slice early.** Inside Phases 3–7, implement the *slice set* first so that
   milestone **M2** (curl and nginx doing TLS 1.3 on our libraries) lands before breadth work.
   This exercises the risky architecture (two ABI facades, the handle model, BIO adapters,
   C callbacks) while changing it is still cheap.
   *Slice set:* SHA-256/384, HMAC, HKDF, AES-GCM, ChaCha20-Poly1305, X25519, X25519MLKEM768,
   ECDSA P-256/P-384, RSA PKCS#1/PSS sign and verify, X.509 parsing plus chain and hostname
   verification, PEM loading of certificates and keys, and a TLS 1.3 client and server.
4. **Breadth by API family**, ordered by real-world usage (step 0.10), until `cargo xtask
   coverage` reports 100% of `util/libcrypto.num` and `util/libssl.num`.
5. **The per-family loop:** spec (man pages and headers) → tests (KAT, C conformance,
   differential) → safe core implementation → `capi` exports → coverage update → commit.

## Milestones

| ID | Name | Definition of done |
|---|---|---|
| M0 | **Links** | A C program compiled against the official 3.5 headers links and runs against our libs. Every `.num` symbol is exported with the right version, unimplemented ones as fail-closed stubs. |
| M1 | **libcrypto basics** | EVP digests, MACs, ciphers, KDFs, and RAND pass KATs and differential tests. Upstream `openssl dgst`/`enc`/`rand`/`speed`, built against our libs, work. |
| M2 | **Vertical slice** | curl fetches HTTPS (TLS 1.3) from public sites and from the reference `s_server`. nginx serves TLS 1.3 to the reference `s_client` and to browsers. |
| M3 | **OpenSSH** | OpenSSH builds against our libcrypto and passes its regression suite. |
| M4 | **Mainstream TLS** | TLS 1.2 and 1.3 complete for common configurations. nginx-tests SSL, the curl TLS tests, and CPython `test_ssl`/`test_hashlib` match the reference results. |
| M5 | **Full libssl** | 100% of `libssl.num` (3.5) is implemented, including DTLS. The BoGo and tlsfuzzer targets are met. |
| M6 | **Full libcrypto** | 100% of `libcrypto.num` (3.5, then 3.6) is implemented. The upstream OpenSSL test suite passes at least 98% of the tests eligible to run against our libs. |
| M7 | **1.0 (3.x ABI)** | Drop-in replacement validated in distro container images, an external security audit is done, and performance targets are met. |
| M8 | **4.0 ABI** | `libcrypto.so.4` and `libssl.so.4` are built from the same core and pass the full test plan against the 4.0 reference. |

---

## Phase 0: Foundations and ABI scaffolding → M0

- [x] **0.1 Workspace.** Convert the root `Cargo.toml` into a workspace and remove the
  placeholder `src/lib.rs`. Create the crate skeletons from README.md, `rust-toolchain.toml`
  (stable, at least 1.99), and workspace lints: `forbid(unsafe_code)` everywhere except
  `rustyssl-capi` and `libs/*`, plus the clippy set from the security rules. Add `rustfmt.toml`,
  `license = "Apache-2.0"` in the workspace package metadata, and a `NOTICE` that carries
  OpenSSL's attribution for the vendored files. (`LICENSE.txt` already exists.)
  *Done.* The workspace has every `crates/*` from README.md except `rustyssl-quic` (deferred
  to Phase 10), plus `libs/libcrypto` (cdylib + staticlib), `libs/libssl` (cdylib), and
  `xtask`. The lints live in `[workspace.lints]` plus crate-level attributes, with test
  exemptions in `clippy.toml`. The release profile keeps `overflow-checks = true`.
- [x] **0.2 Vendor the ABI.** Add `cargo xtask vendor 3.5.<patch>`: download the pinned
  release tarball and verify its SHA-256 and PGP signature. Run `./Configure` with default
  options so that the **generated** headers exist (in 3.x many public headers come from
  `*.h.in`: `ssl.h`, `x509.h`, `asn1.h`, `crypto.h`, `opensslv.h`, `configuration.h`, …).
  Copy into `abi/openssl-3.5/`:
  `include/openssl/*.h`, `util/libcrypto.num`, `util/libssl.num`,
  `crypto/objects/objects.txt` + `obj_mac.num`, `crypto/err/openssl.txt`, `doc/man3`,
  `doc/man7`. Record the version and checksums in `abi/openssl-3.5/VERSION`.
  *Done* with OpenSSL **3.5.9** (`cargo xtask vendor 3.5.9`). Notes:
  - Trust: the signature must verify against `xtask/keys/openssl-pubkeys.asc` (from
    openssl-library.org) and chain to the published anchor `B146…2D40`. The SHA-256 must match
    the published checksum and any pin in `VERSION.toml` (which replaces the planned
    `VERSION`).
  - `configuration.h` is **per target**: `RC4_INT` is `unsigned int` on x86_64 and macOS but
    `unsigned char` on aarch64 Linux, which changes `RC4_KEY`'s size, and macOS adds
    `OPENSSL_SYS_MACOSX` and `OPENSSL_NO_AFALGENG`. It's vendored as
    `config/{linux-x86_64,linux-aarch64,darwin64-arm64}/openssl/configuration.h`. The tool
    fails if any other file differs between targets.
  - Also vendored: `obj_xref.txt` (needed by `OBJ_find_sigid_algs` in 2.1) and OpenSSL's
    `LICENSE.txt`. The generated `.pod` files come from `make build_generated_pods`.
  - The same command handles 3.6 and 4.0 (`abi/openssl-3.6/`, `abi/openssl-4.0/`).
- [x] **0.3 `rustyssl-abi`.** Generate it with bindgen from the vendored headers, **once per
  target** (see the `configuration.h` note in 0.2), selected with
  `cfg(target_arch, target_os)`. The output is committed so users don't need libclang. It
  holds opaque type declarations, every public struct and union with `#[repr(C)]`, and all
  constants. Generate layout assertions too.
  *Done* (`cargo xtask codegen`, output in `crates/rustyssl-abi/src/generated/`). Notes:
  - **Headers are parsed without a target sysroot**, using clang's freestanding headers plus
    generated stand-ins for the few libc headers OpenSSL includes. Each libc type is an
    *incomplete* struct there, so a public struct embedding one by value fails the parse.
    In Rust these types come from the `libc` crate, so glibc vs. musl is handled for free.
  - **Constants come from clang, not bindgen.** bindgen guesses Rust types and misses casts,
    `sizeof`, and function-like macros (`SSL_OP_BIT(n)`). xtask instead probes every
    object-like macro as an integer constant expression and as a string literal, then reads
    the values and C types from LLVM IR. Per target that's about 8,290 integer and 3,454
    string constants. Location-dependent macros (`OPENSSL_LINE`, …) are excluded.
  - Enums become constants (`--default-enum-style consts`). Extern data symbols and function
    prototypes are left out here; abi-check (L3) gets the prototypes.
  - **Verified** against real C compilers with real libc headers (Apple clang with the macOS
    SDK; gcc 14.2 with glibc 2.41 in Debian containers for x86_64 and aarch64). Every integer
    and string constant and every nameable struct size and alignment matches on all three
    targets. `RC4_KEY` is 1032 bytes on x86_64 and macOS but 258 on aarch64 Linux, as
    expected. That one-off check should become L3 items 4 and 5 in `cargo xtask abi-check`.
  - `rust-toolchain.toml` lists the three Rust targets, so codegen can `cargo check` each
    one, which evaluates the layout assertions. Regenerating gives byte-identical output.
- [x] **0.4 Code generators** (`cargo xtask codegen`):
  - Linux version scripts (`OPENSSL_3.0.0` … `OPENSSL_3.6.0` plus `RUSTYSSL_PRIVATE`) and
    macOS exported-symbol lists, from the `.num` files. Honor the `EXIST`/`NOEXIST` and
    feature columns exactly as the default build resolves them.
  - NID, short-name, long-name, and OID tables from `objects.txt`.
  - `ERR_LIB_*` codes, reason codes, and reason strings from `openssl.txt`.
  - A **fail-closed stub** for every export, built from the header prototype, to be replaced
    family by family.

  *Done.* Each output was checked against OpenSSL's own generated artifacts. Notes:
  - **Export lists.** `vendor` now saves what OpenSSL's `util/mkdef.pl` resolves for each
    target (`abi/.../config/<target>/lib{crypto,ssl}.ld`), so EXIST/NOEXIST and feature
    conditions are resolved by OpenSSL itself. The 3.5 set is **5,873 libcrypto and 603
    libssl** functions (5,876 in libcrypto once 0.6 adds `enable-ec_nistp_64_gcc_128`), identical on all three targets. There are 9 version nodes, including
    patch-level ones (`OPENSSL_3.0.3`, `3.0.8`, `3.0.9`) and up to `OPENSSL_3.5.0`; no data
    symbols are exported. The generated scripts match mkdef's output exactly. The
    `RUSTYSSL_PRIVATE` node exports the glob `rustyssl_private_*`, a placeholder until 0.6
    settles the names.
  - **Stubs abort** instead of returning an error (see rule 10 in README.md). There's one
    per export: 6,476, generated from bindgen prototypes parsed with `syn`. `va_list`
    parameters become `VaList`. All three targets must produce identical stubs, and they
    compile on each. A C program linked to the built `libcrypto.dylib` gets the message and
    SIGABRT. 26 exports are declared only in internal headers (`DSO_*`, `conf_ssl_*`,
    `OPENSSL_DIR_*`, …), so six of those are now vendored, and `rustyssl-abi` includes their
    types. The wrapper also puts headers first when another header declares extra
    functions only after them (`cms.h` declares the `PEM_*_CMS` functions only if `pem.h`
    came first).
  - **Error strings.** Three sources are cross-checked: `openssl.txt` (names and codes), the
    headers (codes, as `rustyssl-abi` constants), and the C string tables `*_err.c`, which
    are now vendored. Upstream, 3 BIO texts in `bio_err.c` differ from `openssl.txt`, and
    the C text wins because it's what OpenSSL prints. Separately,
    `BIO_R_PEER_ADDR_NOT_AVAILABLE` is 114 in `openssl.txt` but 151 in the header, and the
    header wins. The result is 1,821 reasons, matching the compiled tables exactly; 25
    (SM2, PROP) take their codes from `openssl.txt` alone.
  - **Object table:** 1,478 NIDs (up to 1,486) and 68 signature-algorithm rows. It matches
    OpenSSL's `obj_dat.h` exactly for all 1,487 slots, including `obj_dat.pl`'s quirks: the
    single-arc roots get no encoding, a bare alias (`ac_auditEntity`) is named `"NULL"`
    with no OID, and `NID_x` aliases are ignored.
- [x] **0.5 Library facades.** `libs/libcrypto` (`crate-type = ["cdylib", "staticlib"]`,
  lib name `crypto`) and `libs/libssl`. Their `build.rs` passes the soname or install_name,
  the version script, and on macOS the current and compatibility versions.
  `cargo xtask dist` lays out `target/dist/{lib,include,lib/pkgconfig}`, including
  `libcrypto.pc`, `libssl.pc`, and `openssl.pc`.

  *Done, with a different mechanism from the one planned:*
  - **No `build.rs`; dist links the shared libraries.** A cdylib can't carry OpenSSL's
    version nodes. rustc gives every cdylib an anonymous version script, and GNU ld rejects
    a second, named one: "anonymous version tag cannot be combined with other version
    tags" (reproduced on Linux). So both facades are `staticlib` only, and
    `cargo xtask dist` links `libcrypto.so.3`/`libssl.so.3` (macOS: `lib*.3.dylib`) from
    the archives with `cc`, adding the system libraries rustc reports.
    - **Linux:** whole archive, `--version-script`, soname, `--no-undefined-version`,
      `--no-undefined`, GC, strip.
    - **macOS:** `-force_load`, `-exported_symbols_list`, an absolute install name,
      compatibility and current version 3.0.0 (as in OpenSSL's dylibs), dead-strip.
  - **libssl defines its own exports.** Its 603 stubs moved from `rustyssl-capi` into
    `libs/libssl` (they become forwarders in 0.6), and libssl links against libcrypto
    (`NEEDED libcrypto.so.3`), as OpenSSL's does.
  - **dist also installs** the headers (with the host's `configuration.h`), the `.a`
    archives, the dev symlinks, and pkg-config files modeled on OpenSSL's. These use
    `${pcfiledir}` so the tree is relocatable, and report version 3.5.9.
  - **Verified on macOS arm64 and on Linux aarch64 and x86_64 (Docker):**
    - **Exports:** each library exports exactly its list (5,873 / 603). On Linux every
      symbol carries exactly its version node from the map.
    - **Builds:** a C program built through pkg-config runs and hits a stub.
    - **Drop-in:** binaries built against **real OpenSSL** (Homebrew 3.6.5; Debian 3.5.7)
      run on our libraries and reach our stubs, so versioned symbols and dyld
      compatibility versions resolve.
  - **Differences from OpenSSL's libraries:** Rust's std adds `libiconv` (macOS) and
    `ld-linux` (Linux) dependencies. `libssl.a` carries its own copy of std, so static
    linking of both archives is item 4 of 0.6.
- [x] **0.6 Architecture spike: "one implementation, two facades".** Prove on Linux
  (glibc and musl) and macOS that:
  1. libssl's `SSL_*` exports forward into libcrypto's `RUSTYSSL_PRIVATE` entry points.
  2. A binary **linked against real OpenSSL** resolves every versioned symbol against our libs.
  3. macOS two-level-namespace binding resolves correctly.
  4. `-lssl -lcrypto` static linking works and doesn't duplicate Rust `std` symbols.
  5. Forwarding overhead is negligible.

  OpenSSL 3.5 exports no data symbols (the `.num` files list only functions), so there's
  nothing to test there.

  *Done:* see [ADR 0001](adr/0001-library-layout.md) for the decision and evidence.
  - **Design.** libssl's exports are generated one-branch forwarders to libcrypto's
    `rustyssl_private_<name>`, which hold the stubs (and later the implementations).
    `dist` builds libssl from the crate's forwarder objects alone and verifies they
    reference nothing else, so libssl carries no Rust runtime: `libssl.a` shrank from
    19 MB to 95 KB.
  - **Proof, on macOS arm64, glibc aarch64/x86_64, and musl aarch64:**
    - **Real-OpenSSL binaries:** programs linked against Homebrew 3.6.5, Debian 3.5.7, and
      Alpine's OpenSSL, referencing every function they share with us (6,476 / 6,459 /
      6,402), load on our libraries with all symbols bound at launch (items 2 and 3).
    - **Static linking:** `libssl.a` + `libcrypto.a` link a program that references all
      6,476 functions (item 4).
    - **Overhead:** forwarding costs about 0.2 ns per call (item 5).
  - **Decided: vendor with `enable-ec_nistp_64_gcc_128`.** Debian and Homebrew build with
    that option and export `EC_GFp_nistp{224,256,521}_method`, which OpenSSL's default
    build doesn't. With the option, libcrypto exports 5,876 functions, and binaries linked
    against Homebrew and Debian resolve all 6,479 and 6,462 functions they share with us.
    Everything else distributions differ in, we export as a superset (Debian drops
    IDEA/MDC2; Alpine also drops GF2m, compression, and SEED). The exception is Debian's
    `SSL_test_functions` (`enable-unit-test`), an internal test hook left out on purpose.
- [x] **0.7 FFI primitives** in `rustyssl-capi`:
  - the `ffi_export!` wrapper (catches unwinds, pushes an ERR entry, returns the failure
    value);
  - the opaque handle model (Arc-backed, with `*_up_ref`/`*_free` and stable interior
    addresses for `get0`);
  - `CRYPTO_malloc`-backed allocation helpers;
  - checked int/size conversions;
  - the C-variadic export pattern.

  Prove them out on `BUF_MEM`.

  *Done.* Modules in `crates/rustyssl-capi/src/`:
  - **`ffi.rs`:** `guard` and `ffi_export!`. A panic becomes `ERR_R_INTERNAL_ERROR` for the
    export's library, plus its failure value. Also the checked conversions (`length`,
    `to_c_int`, `bytes`, `bytes_or_c_str` for the "-1 means NUL-terminated" convention), and
    the documented C-variadic pattern: the exported `...` function moves its argument list
    into a guarded helper shared with the `v` variant.
  - **`handle.rs`:** each handle is an `Arc` with a per-type tag in front.
    - `get`/`up_ref`/`free` follow OpenSSL's rules, and the object stays put, so `get0`
      pointers to its fields stay valid.
    - A valid handle of the **wrong type** is rejected instead of being reinterpreted.
    - It's used by tests only until the first opaque type arrives in Phase 1.
  - **`mem.rs`:** `alloc`/`zalloc`/`realloc`/`clear_realloc`/`free`/`clear_free`/`cleanse`
    with `CRYPTO_*` semantics. Zero bytes gives null with no error; a failure raises
    `ERR_R_MALLOC_FAILURE`. The exports and `CRYPTO_set_mem_functions` come in 1.1.
  - **`err.rs`:** the per-thread queue `raise` writes to, holding `ERR_NUM_ERRORS - 1`
    entries (to be confirmed in 1.4).
  - **`buffer.rs`:** all six `buffer.h` exports are implemented. The C test
    `tests/c/buf_mem.c` (26 checks) passes against the reference and rustyssl, with
    identical output: Homebrew 3.6.5 on macOS and Debian 3.5.7 on Linux, the same binary
    run against both. Where OpenSSL crashes (null buffer), rustyssl fails cleanly.
  - **Checks:** the `rustyssl-capi` tests pass under Miri
    (`cargo +nightly miri test -p rustyssl-capi`). Codegen's implemented-function scan now
    skips comments; doc examples had been hiding the `BIO_printf` stubs.
- [x] **0.8 Test infrastructure** (details in TEST_PLAN.md):
  - `cargo xtask ref-openssl 3.5`, which builds the reference into `target/ref/`;
  - the C conformance harness in `tests/c`, with dual runs (reference and ours). The first
    test, `tests/c/buf_mem.c` (TAP output), is already there and has been dual-run by hand
    (0.7);
  - Miri on the `rustyssl-capi` tests;
  - the differential probe skeleton;
  - fuzz scaffolding;
  - CI on Linux x86_64 and aarch64 and macOS arm64;
  - `deny.toml` and the `supply-chain/` config for `cargo vet`.

  *Done.*
  - **`cargo xtask ref-openssl [version]`** builds the vendored release (3.5.9 by
    default) into `target/ref/openssl-<version>/`. It uses the same verified download as
    `vendor` (signature, then the pinned SHA-256), the same Configure options as our build
    (`enable-ec_nistp_64_gcc_128`), and `-g`, with a cleared environment. A stamp file
    makes a rebuild with the same version, target, and options a no-op. A first build
    takes about 40 s on an M-series Mac. Linux needs the full `perl` package: Debian's
    slim images ship only `perl-base`, which lacks `FindBin`.
  - **`cargo xtask test-c`** builds the reference and `dist`, then compiles each
    `tests/c/*.c` once with `-Wall -Wextra -Werror` against our headers and the reference
    libraries. It runs each binary twice by switching the loader path, with a 120 s
    timeout. A test passes only if both runs pass every TAP check and their output is
    identical. `buf_mem`: 26 checks, identical on macOS arm64 and on Linux aarch64 (Debian
    trixie in Docker).
  - **`cargo xtask test-differential`** feeds the same command script to
    `tests/differential/probe.c` on the reference and on rustyssl and compares output line
    by line: the reference is the oracle. The inputs are the hand-written corpus in
    `tests/differential/corpus/` plus `--random N` generated sessions (default 200). The
    seed is printed, and `--seed` replays it. Results: 500 sessions on macOS (about 13,000
    lines) and 1,000 on Linux (25,367 lines), all identical. The corpus never grows a
    buffer to exactly the size limit, because that allocates 2 GB.
  - **Fuzzing:** `fuzz/` is its own workspace, because libFuzzer is C++ (see
    DEPENDENCIES.md). The first target, `buf_mem`, checks `BUF_MEM_grow`/`_grow_clean`
    against a `Vec` model: 958k runs in 31 s under ASan, no findings.
  - **Supply chain:** `deny.toml` covers advisories, licenses, sources, and a build-script
    allowlist (libc, proc-macro2, quote). `cargo vet` imports four organizations' audits;
    `quote` is audited, and 12 crates are exemptions to burn down before 1.0. CI pins
    cargo-deny 0.20.2 and cargo-vet 0.10.2. The first run on `main` installed the newest
    *prebuilt* cargo-vet, 0.10.0, which formats `imports.lock` differently and failed.
  - **CI** (`.github/workflows/ci.yml`; actionlint clean). On every push and PR, Linux
    x86_64 runs fmt, clippy, the tests, `test-c`, and `test-differential --random 1000`,
    plus separate Miri, supply-chain, and codegen jobs. The codegen job regenerates
    everything with Ubuntu's clang and fails on any diff; codegen is byte-identical
    between Apple clang 21 and Debian clang 19. The weekly cron and manual runs add Linux
    aarch64, macOS arm64, and 5 minutes of fuzzing per target. Those are deferred because
    the repository is private: macOS minutes count 10x, and arm64 Linux runners may not be
    available on the current plan. The reference build is cached per OS and arch.
- [x] **0.9 Coverage report.** `cargo xtask coverage` prints implemented/stubbed counts per
  API family (by prefix and header). CI keeps `docs/coverage.md` up to date.

  *Done.* `cargo xtask coverage` writes `docs/coverage.md`: totals per library, a table per
  header, and the implemented exports with the tests that call them. `--list PREFIX...`
  prints the status of every export with that prefix: implemented, untested, or stub.
  Starting point: 6 of 6,479 exports (all of `buffer.h`).
  - **Implemented** means `rustyssl-capi` defines the export and a `tests/c` program calls
    it, which is README.md's rule made mechanical. Calls come from the undefined symbols of
    each test compiled to an object, not from its source text. So a call through a macro
    (`BIO_get_mem_data` → `BIO_ctrl`) or an inline wrapper (`sk_X509_num` →
    `OPENSSL_sk_num`) credits the function that's actually linked; this was checked by
    hand.
  - **An export that's defined but that no test calls fails the command,** and so fails CI.
    It would otherwise ship untested.
  - **Headers:** each export is listed under the first header that declares it, found from
    the line markers in clang's preprocessed headers. That puts macro-generated
    declarations where the macro is invoked (`d2i_X509` in `x509.h`) and gives `internal/`
    headers for the internal APIs libcrypto exports. The counts agree with the generated
    stubs (5,870 + 603).
  - **The prefix view** is `--list`, not a table in the report. Families by leading
    token cut across headers (`d2i_`, `EVP_`), so headers group better.
  - The report is the same on every host: the export lists and headers are read for a
    fixed target, and the macOS and Linux outputs are byte-identical. CI's codegen job runs
    `coverage` after `codegen` and fails on any diff.
- [x] **0.10 Usage-driven prioritization.** `cargo xtask usage-scan` downloads the
  Debian/Ubuntu/Fedora packages that depend on `libssl3`/`libcrypto3` (treat them as untrusted
  data: parse the ELF only, never execute it), collects their imported versioned symbols,
  and writes `docs/symbol-usage.md`, a ranking of how many packages import each function.
  Breadth phases use it to choose order.

  *Done.* Scanned: Debian 13 (OpenSSL 3.5.7), Ubuntu 26.04 LTS (3.5.5), and Fedora 44
  (3.5.5), amd64, which are the current releases on the 3.5 series. Ubuntu 24.04's OpenSSL
  3.0 would add nothing newer.
  - **How it works:**
    - The packages to scan come from each distribution's index: Debian `Depends` on
      `libssl3t64`, Fedora requiring `libssl.so.3`/`libcrypto.so.3`.
    - Each package is downloaded over HTTPS only and checked against the index's SHA-256.
    - Safe-Rust parsers read it in memory: `ar`, tar, cpio, the RPM header, and ELF
      (`.dynsym`, `.gnu.version`, `.gnu.version_r`). `xz`/`zstd` only decompress. Nothing
      from a package touches the disk or runs.
    - An import counts when its version needs `libssl.so.3` or `libcrypto.so.3`.
    - Results are cached per SHA-256 and the package is deleted.
  - **Cost:** the full scan downloads about 5 GB and took 11 minutes with 8 jobs. A rerun
    from the 17 MB cache takes 16 s and writes an identical report.
  - **Validation:**
    - Debian's `/usr/bin/openssl` gives the same 1,623 imports as `objdump -T`, name and
      version node. Each lands in the right library (225 libssl, 1,398 libcrypto, all in
      the matching export list).
    - The ELF reader survives every truncation and every single-byte corruption of a test
      file.
  - **Results:**
    - 2,920 packages; all scanned, and 2,814 import OpenSSL directly.
    - 3,957 of our 6,479 exports are imported somewhere, and 2,522 never are.
    - The head is the TLS client/server and digest basics: `SSL_CTX_new`, `ERR_get_error`,
      `SSL_new`, `X509_free`, ….
    - The tail is long. Implementing the top 100 functions fully serves 108 packages
      (4%), the top 1,000 serves 41%, and the top 2,000 serves 68%. Usage orders the work,
      but nearly every imported function is needed by someone.
  - **Open decision: Fedora's ABI extras.** 7 Fedora packages import functions the
    upstream 3.5 ABI doesn't have, so they wouldn't load on rustyssl. Fedora's libcrypto
    (checked) has three extras:
    - MD2 (`EVP_md2`, `MD2_*`; ipmitool, perl-Net-SSLeay, qca), which upstream disables by
      default and README.md keeps disabled;
    - SCTP (`BIO_new_dgram_sctp`; Fedora's own `openssl` CLI);
    - an extra `OPENSSL_3.1.0` version node for `EVP_MD_CTX_dup` and `EVP_CIPHER_CTX_dup`
      (dpdk). This is the default version Fedora binaries bind to; upstream exports them
      only at `OPENSSL_3.2.0`.

    Supporting Fedora binaries means a per-distribution export profile. That's decided in
    12.3.
- [x] **0.11 ABI check.** `cargo xtask abi-check` automates TEST_PLAN L3. It turns the
  one-off checks from 0.3 and 0.6 into a gate that runs in CI on every PR: Linux x86_64 on
  each push, and the weekly run adds Linux aarch64 and macOS arm64. It checks the built
  `target/dist` libraries against `abi/` and fails on any difference:
  1. **Symbol set and versions.**
     - Each library's dynamic exports equal its export list from the vendored mkdef `.ld`
       files, and each symbol carries its version node.
     - libcrypto also exports `rustyssl_private_*`, exactly one per libssl function, under
       `RUSTYSSL_PRIVATE`. Nothing else is exported, including no Rust runtime symbols.
     - Linux symbols are read from the ELF version tables, extending `usage_scan/elf.rs`'s
       reader to defined symbols and `.gnu.version_d`. macOS uses `nm` and the export list.
  2. **Library metadata:**
     - the soname or install name;
     - `NEEDED` entries: libssl needs libcrypto, and neither needs anything beyond libc,
       libm, libpthread, libdl and the unwinder;
     - the version definitions and their parent chain;
     - macOS compatibility and current versions 3.0.0.
  3. **Signatures.** Every hand-written `extern "C"` export in `rustyssl-capi` (outside
     `generated/`), including the `rustyssl_private_*` definitions of libssl functions, must
     match the bindgen prototype exactly: parameter and return types, pointer constness,
     and variadics. The generated stubs and forwarders match by construction.
  4. **Layouts.** A generated C program, compiled with the official headers, prints
     `sizeof`, `alignof`, and `offsetof` for every public struct and union. The values must
     equal `rustyssl-abi`'s layout for the host target.
  5. **Constants.** The C compiler evaluates every integer and string macro constant with
     the real libc headers, and each value must equal `rustyssl-abi`'s.
  6. **Binary compatibility.** A program that references every exported function is linked
     against the reference OpenSSL with immediate binding (`-z now`; `-bind_at_load` on
     macOS). It's then loaded against our libraries, so every versioned symbol must resolve.
  7. **Static linking:** that program also links against `libssl.a` and `libcrypto.a` and
     runs.
  8. **Headers and pkg-config.** Each installed header compiles on its own, and
     `pkg-config --cflags --libs openssl` (and the `libssl`/`libcrypto` files) builds the
     program.

  Items 4 and 5 already ran by hand in 0.3 (all three targets, real compilers). Items 1, 2,
  6, and 7 ran in the 0.6 spike against Homebrew and Debian binaries. Each item reports
  every mismatch, not just the first.

  *Done.* All eight checks pass on macOS arm64 and on Linux aarch64 (Debian trixie in
  Docker). A run takes about 6 s once the libraries are built. `cargo xtask abi-check
  <check>...` runs only the named checks. CI runs it in the `test` job.
  - **Symbols:**
    - libcrypto exports 5,876 functions plus 603 `rustyssl_private_*`; libssl exports 603.
    - On Linux every symbol is at its node and none is a non-default version. The ELF
      reader from 0.10 now also reads `.gnu.version_d` and `.dynamic`. It skips the absolute
      symbols the linker defines for version nodes.
    - The reference is checked against the same lists. On Linux it exports exactly them,
      which validates the vendored mkdef output against a real build. On macOS it also
      exports 4,498 internal symbols: OpenSSL doesn't restrict exports there.
  - **Metadata:** the sonames, the version definitions, and their parents match the
    reference's. The macOS install-name leaf and compatibility and current versions 3.0.0
    match too, and only system libraries are needed.
    - **Fixed:** our macOS libcrypto also loaded `/usr/lib/libiconv.2.dylib`, which the
      reference doesn't. Rust's std names it but nothing calls it, so `dist` now links with
      `-dead_strip_dylibs`.
  - **Signatures:** instead of parsing `ffi_export!` bodies with `syn`, codegen writes
    `rustyssl-capi/src/generated/signatures.rs`. It assigns each hand-written export to a
    function pointer of the header prototype's type, so the compiler checks the signature
    exactly, on every target codegen checks. That covers `*const`/`*mut`, widths,
    variadics, and `VaList` through a higher-ranked lifetime. abi-check confirms every
    hand-written export has an assertion. A deliberate constness mismatch fails the build.
  - **Layouts:** 910 sizes, alignments, and field offsets (macOS) match `gcc`/Apple clang
    with the real libc. Records bindgen can't give C names to (anonymous ones and bitfield
    storage) are skipped. bindgen's `parent_child` names for nested records map back to
    their C tags (the `lh_*_dummy` unions).
  - **Constants:** 8,401 integer (8,400 on Linux) and 3,454 string constants match. Integers
    are checked for value, size, and signedness.
  - **Binary and static:** a program referencing all 6,479 public functions is linked
    against the reference with `-z now`/`-bind_at_load`. It loads on rustyssl's libraries,
    and `dladdr` shows ours were used. It also links statically against `libssl.a` and
    `libcrypto.a` and runs.
  - **Headers:** the 142 installed headers are byte-identical to the reference's, and
    each compiles on its own. The pkg-config versions match, and a program built with
    `pkg-config --cflags --libs openssl` runs.

**Exit:** M0. The ABI checks are green (symbol set and versions, signatures, layouts).
*Reached on 2026-10-07: every Phase 0 step is done, and `cargo xtask abi-check` is green on
macOS arm64 and Linux aarch64.*

## Phase 1: libcrypto runtime core

Everything else depends on this phase.

- [x] **1.1 Memory:**
  (The internal allocator exists in `rustyssl-capi/src/mem.rs` since 0.7; this step exports
  it, adds the `CRYPTO_set_mem_functions` hooks, and confirms its edge cases against the
  reference.)
  - `CRYPTO_malloc`, `zalloc`, `realloc`, `clear_realloc`, `free`, `clear_free`
  - `CRYPTO_set_mem_functions` / `CRYPTO_get_mem_functions`
  - `OPENSSL_cleanse`, `CRYPTO_memcmp`
  - the secure heap (`CRYPTO_secure_*`: mmap, mlock, guard pages, `MADV_DONTDUMP`)
  - `CRYPTO_mem_debug_*`, as no-ops (matching the default build)

  *Done:* 21 exports. With `BUF_MEM`, that's 27 of libcrypto's 5,876.
  - **Debug functions:** the `CRYPTO_mem_debug_*` and `CRYPTO_mem_leaks*` functions exist
    only with `crypto-mdebug`, which the default build doesn't enable. They aren't in the
    ABI, so there's nothing to implement.
  - **The source is now kept:** `cargo xtask ref-openssl` saves the verified, unbuilt
    source in `target/ref/openssl-<version>/src/`, the C spec for each family. Behavior
    that varies by platform was measured on the reference, macOS and Linux.
  - **Allocator (`mem.rs`):**
    - Every allocation, rustyssl's own included, goes through the functions installed with
      `CRYPTO_set_mem_functions`. Our own pass the file `"rustyssl"` and the Rust line.
    - Customization closes at the first allocation by the default allocator, as in OpenSSL.
      `CRYPTO_get_mem_functions` reports the defaults as `CRYPTO_malloc`/`_realloc`/`_free`,
      and passing those back restores them.
    - A failing `CRYPTO_realloc` raises no error, unlike `CRYPTO_malloc` (as in OpenSSL).
    - `CRYPTO_aligned_alloc` follows each platform's build: `posix_memalign` on Linux;
      over-allocate and round on macOS, alignment-0 and odd-alignment quirks included.
    - `CRYPTO_memcmp` returns exactly 0 or 1, like OpenSSL's x86_64 and arm64 assembly
      (the C fallback returns the OR of the differences), and uses `subtle` (new
      dependency, BSD-3-Clause, now allowed by `deny.toml`).
    - `OPENSSL_cleanse` uses volatile byte and word stores.
  - **Secure heap (`secure.rs`, `secure/buddy.rs`):**
    - The buddy allocator is safe Rust over arena offsets. It reproduces OpenSSL's
      placement exactly: LIFO lists, splitting toward the upper half, and buddy merging.
    - Its free lists live beside the arena, never in it, so blocks are zero because frees
      clear them.
    - The arena code does what OpenSSL's `sh_init` does: `mmap`, guard pages, `mlock` (or
      `mlock2` with `MLOCK_ONFAULT`), and `MADV_DONTDUMP`. So it returns 1 or 2 in the
      same cases.
    - Misuse aborts, as `OPENSSL_assert` does: a pointer that isn't a block start, a
      double free, or a size that isn't a power of two.
    - Secure `BUF_MEM` data now lives in the secure heap, as in OpenSSL.
  - **Tests:**
    - `tests/c/crypto_mem.c` (80 checks), `crypto_mem_hooks.c` (24, counting every call to
      an installed allocator, `BUF_MEM`'s included), and `crypto_secure_heap.c` (30).
    - The secure-heap test traces 300 random operations, with block offsets from the arena
      start. Placements, sizes, usage, and failures are identical to the reference's on
      macOS arm64 and Linux aarch64.
    - Rust tests cover cleanse ranges, `memcmp`, the overflow case, and a randomized buddy
      run (disjoint, aligned blocks that merge back). Miri passes.
  - **Deviations:** five, all where OpenSSL corrupts memory, crashes, or recurses forever.
    They're the first entries in the new `docs/DEVIATIONS.md`, each with a test (two as
    single-process integration tests).
- [x] **1.2 Init, version, info:**
  - `OPENSSL_init_crypto`, with every `OPENSSL_INIT_*` flag
  - `OPENSSL_cleanup`, `OPENSSL_atexit`
  - `OpenSSL_version*`, `OPENSSL_version_{major,minor,patch,pre_release,build_metadata}`,
    `OPENSSL_info`
  - fork handling

  Decide the version-string policy: the numbers report the targeted 3.5.x and the text names
  rustyssl. Record it in `DEVIATIONS.md` if it differs from upstream.

  *Done:* 23 exports, now 50 of libcrypto's 5,876.
  - **Version policy** (`version.rs`; `DEVIATIONS.md` explains why):
    - The numbers (`OpenSSL_version_num`, `OPENSSL_version_major`/`_minor`/`_patch`,
      `OPENSSL_VERSION_STRING`) and the release date are the vendored 3.5.9's.
    - rustyssl names itself in the build metadata, which OpenSSL's man page reserves "for
      other parties, such as `+fips`": `OpenSSL 3.5.9+rustyssl.0.1.0 29 Sep 2026`.
  - **Build information:**
    - `cargo xtask vendor` now records each target's `PLATFORM`, `OPENSSLDIR`,
      `ENGINESDIR`, `MODULESDIR`, and `DSO_EXTENSION` from OpenSSL's Makefile in
      `config/<target>/build.toml`, and codegen turns them into `rustyssl_abi::build`.
      x86_64 Linux gets `lib64`, as upstream's default build does.
    - Packagers override the directories with `RUSTYSSL_OPENSSLDIR`/`_ENGINESDIR`/
      `_MODULESDIR` at build time; that's for 12.3.
    - `CPUINFO` is `N/A`, since rustyssl has no `OPENSSL_ia32cap`-steered assembly. The
      compiler and build date say rustc and "reproducible build".
  - **Initialization** (`init.rs`), following `crypto/init.c`:
    - `OPENSSL_init_crypto(0, NULL)` does nothing.
    - Each subsystem is set up once, and between a flag and its `NO_` twin, the first one
      asked for wins.
    - `atexit(OPENSSL_cleanup)` is registered unless `OPENSSL_INIT_NO_ATEXIT` comes first.
      The library pins itself, and each handler's library, with
      `dlopen(RTLD_NOLOAD | RTLD_NODELETE)`, so exit never jumps into unmapped code.
    - `OPENSSL_cleanup` runs the `OPENSSL_atexit` handlers newest first, without holding a
      lock. After it, init fails with `ERR_R_INIT_FAIL`.
    - The settings object is the first real handle type.
    - `OPENSSL_fork_*`, `OPENSSL_init`, and `OPENSSL_isservice` are no-ops, as in
      OpenSSL 3.
    - `OPENSSL_issetugid` follows OpenSSL per platform: `getauxval(AT_SECURE)` on glibc,
      ID comparison elsewhere.
    - `OPENSSL_die` prints OpenSSL's exact line and aborts.
  - **Configuration:** `OPENSSL_INIT_LOAD_CONFIG` finds the file as OpenSSL does (the
    settings' file, else `$OPENSSL_CONF` unless set-user-ID, else
    `<OPENSSLDIR>/openssl.cnf`).
    - A missing file gives OpenSSL's result for the flags.
    - An existing file aborts until 6.1.
    - The dual-run test found an OpenSSL quirk, now reproduced. A thread's first load
      leaves a never-cleared "loading" mark (`in_init_config_local`). So later loads on that
      thread succeed even after a failed one, while other threads and
      `OPENSSL_INIT_NO_LOAD_CONFIG` get the failure.
  - **Still to come, aborting until then (rule 10):**
    - `OPENSSL_INIT_ADD_ALL_CIPHERS`/`_DIGESTS` (the name tables, 3.3 and 3.4);
    - `OPENSSL_INIT_ASYNC` (6.11);
    - `OPENSSL_INIT_ENGINE_*` (9.3);
    - loading a configuration file (3.12 and 6.1).

    `OPENSSL_INIT_BASE_ONLY` lives in an internal header, so applications can't name it,
    and it isn't supported. `OPENSSL_thread_stop` waits for 1.3, and ERR's per-thread state
    at cleanup for 1.4.
  - **Tests:**
    - `tests/c/crypto_version.c` (25 checks): version and info relationships that hold for
      every build, and `OPENSSL_die` in a forked child.
    - `crypto_init.c` (16): flag precedence, handler order, and init after cleanup.
    - `crypto_init_config.c` (3, with the exit handler run by `atexit`).
    - `crypto_init_config_strict.c` (5, including another thread).
    - All are identical to the reference on macOS. Rust unit tests cover the
      rustyssl-specific strings and the new deviations.
- [x] **1.3 Threads:** `CRYPTO_THREAD_*` locks, run-once, and thread-local storage;
  `CRYPTO_atomic_*`; `OSSL_set_max_threads` and the thread pool.

  *Done:* 24 exports, now 74 of libcrypto's 5,876 (`threads.rs`).
  - **pthread wrappers:** `crypto.h` defines `CRYPTO_ONCE`, `CRYPTO_THREAD_LOCAL`, and
    `CRYPTO_THREAD_ID` as `pthread_once_t`, `pthread_key_t`, and `pthread_t`, which live in
    the application's storage (`CRYPTO_ONCE_STATIC_INIT` is `PTHREAD_ONCE_INIT`). So
    run-once, thread-local storage (cleanup at thread exit included), and thread IDs are
    exact wrappers around the pthread calls OpenSSL makes.
  - **Locks:** a `CRYPTO_RWLOCK` is a `pthread_rwlock_t` from the C allocator, as
    OpenSSL's is, so readers share it and an installed allocator sees the allocation. The
    hooks test now counts it.
  - **Atomics:** they're lock-free on every supported target, so they ignore the lock
    (it may be null), with OpenSSL's memory orders (acquire-release, acquire for loads,
    release for stores) and wrapping arithmetic. Only a misaligned value falls back to
    the lock, as OpenSSL's does when `__atomic_is_lock_free` says no.
  - **Thread pool:**
    - `OSSL_get_thread_support_flags` reports both flags, as the default build does.
    - `OSSL_set_max_threads`/`OSSL_get_max_threads` kept the default context's limit
      until library contexts existed; 3.1b moved it into each context.
    - Argon2 uses the limit (3.6).
  - **Thread stop:** `OPENSSL_thread_stop` frees the thread's error queue, and
    `OPENSSL_cleanup` calls it, as OpenSSL's does. `OPENSSL_thread_stop_ex(ctx)` has no
    per-context state to free until the random generators (3.7).
  - **Deviation:** null pointers fail instead of crashing (`DEVIATIONS.md`).
  - **Tests:** `tests/c/crypto_threads.c` (27 checks) gives the same output as the
    reference on macOS. It covers:
    - 8 threads × 20,000 increments under a write lock, and with `CRYPTO_atomic_add`/`_add64`
      and no lock;
    - run-once across threads;
    - per-thread values and their exit cleanup;
    - thread IDs, and the pool setting.
- [x] **1.4 Error queue (all of `ERR_*`):**
  - a thread-local queue with marks
  - `ERR_raise`, `ERR_raise_data`, `ERR_set_debug`, `ERR_set_error` (variadic)
  - the get/peek variants (`_all`, `_data`, `_last`)
  - `ERR_error_string(_n)`, byte-exact
  - `ERR_print_errors_fp` / `ERR_print_errors_cb`
  - application-defined libraries (`ERR_get_next_error_library`, `ERR_load_strings`)
  - `ERR_add_error_data` / `ERR_add_error_vdata`

  *Done:* 79 exports, now 153 of libcrypto's 5,876, and libssl's `ERR_load_SSL_strings`
  (`err.rs`, `err/strings.rs`).
  - **The queue is OpenSSL's `ERR_STATE`:** the public `struct err_state_st`, a 16-slot ring
    that holds 15 errors and drops the oldest when full. The deprecated `ERR_get_state` hands
    it to applications, so its contents are OpenSSL's slot for slot: C memory for the state,
    for copies of each error's file and function names, and for its data. The differential
    probe compares the whole ring after random sessions. Ring positions an application wrote
    out of range are wrapped, never trusted. The application's allocator may call back in,
    so no reference to the state is held across an allocation.
  - **Lifetime:** a thread's state is created on first use, which also loads libcrypto's
    strings (unless `OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS` came first). It's freed at thread
    exit (a thread-local destructor) or `OPENSSL_thread_stop`. After `OPENSSL_cleanup` there
    is none, and the functions do nothing. Getting the state leaves `errno` alone.
    `init::base()` stands for OpenSSL's `OPENSSL_INIT_BASE_ONLY`: it makes `OPENSSL_cleanup`
    active and closes `CRYPTO_set_mem_functions`, as OpenSSL's lock allocations do.
  - **Raising from Rust:** `err::raise` records the Rust file and line (`#[track_caller]`)
    and the export's name; a panic caught by `ffi_export!` records the export's own location.
    `CRYPTO_malloc` and `CRYPTO_secure_malloc` failures name the caller's file and line and
    no function, and the error state's own allocation names none, so a failure there can't
    recurse.
  - **Strings:**
    - Codegen now parses every C table in order (`ERR_str_libraries` and `ERR_str_reasons`
      from `err.c`, `<LIB>_str_reasons` from `*_err.c`). It reads the load order from the
      vendored `crypto/err/err_all.c`, with its `#ifndef OPENSSL_NO_*` guards evaluated
      against each target's `configuration.h` (`generated/err_strings.rs`).
    - Order matters because a table whose first entry is already known isn't loaded.
    - Loading any table first reloads the library names and common reasons, as OpenSSL does.
    - SSL's table loads on `OPENSSL_INIT_LOAD_SSL_STRINGS`. The encoder and decoder tables
      are never loaded, as in 3.5. Applications' strings are kept by pointer.
  - **Formatting:**
    - `ERR_error_string_n` is OpenSSL's, including the switch to the short form `err:...`
      when the long one fills the buffer exactly.
    - System errors use `strerror` text the way each platform's OpenSSL build gets it. glibc
      defines `_POSIX_C_SOURCE`, so OpenSSL calls the XSI `strerror_r`, and an unknown number
      prints `reason(N)`. On macOS it falls back to `strerror`, which prints
      `Unknown error: N`. The differential probe found this; both are reproduced.
    - `ERR_print_errors_cb` prefixes each line with the thread ID's bytes in hex, as
      OpenSSL does.
  - **Saving:** `OSSL_ERR_STATE_new/save/save_to_mark/restore/free` follow OpenSSL's moves
    and copies.
  - **Later (step 1.6):** `ERR_set_error`/`ERR_vset_error` with a format (`ERR_raise_data`
    with text) needed the printf engine and aborted until step 1.6b; `ERR_print_errors` and
    `ERR_add_error_mem_bio` needed BIOs (step 1.6a).
  - **Deviations (`DEVIATIONS.md`):**
    - `ERR_add_error_txt` with a piece too long for one error: OpenSSL loops forever.
    - Restoring the thread's own state into itself: OpenSSL loops forever.
    - Null arguments that crash OpenSSL.
  - **Tests:** identical output to the reference on macOS and Linux aarch64:
    - `tests/c/err_queue.c` (96 checks): reading, data, text splitting, the ring, marks,
      strings, application libraries, printing, saving, threads, allocation failures;
    - `tests/c/err_strings.c` (12 checks, its own process): when tables load and when they
      don't;
    - the differential probe: an `err.txt` corpus, plus random sessions (raise, mark, pop,
      data, text, save and restore, `ERR_error_string_n` on random codes and lengths) that
      end with the whole `ERR_STATE`. 6,000 random sessions were identical on macOS.
- [x] **1.5 Containers and utilities:**
  - `OPENSSL_sk_*`, including the comparator and sort quirks
  - `OPENSSL_LH_*`
  - `BUF_MEM` (done in Phase 0)
  - the string helpers (`OPENSSL_strdup`, `strlcpy`, `hexstr2buf`, `buf2hexstr`,
    `strcasecmp`, …)
  - `OPENSSL_DIR_read`
  - `ex_data` (`CRYPTO_get_ex_new_index`, `new_ex_data`, `dup`, `free`, `set`, `get`, with
    per-class index spaces)

  *Done:* 67 exports, now 220 of libcrypto's 5,876 (`stack.rs`, `lhash.rs`, `ex_data.rs`,
  `string.rs`, `dir.rs`).
  - **Stacks:**
    - A stack is a Rust object behind a handle, and no lock is held while the application's
      comparator, copy, or free function runs (they work on a copy of the elements).
    - In 3.5, finding on an unsorted stack is a linear search with the comparator. It no
      longer sorts the stack as 1.1.1 did, so the plan's old example was out of date.
    - On a sorted stack, finding is OpenSSL's binary search, with the same probes, so
      `OPENSSL_sk_find_ex` lands where OpenSSL's does.
    - Sorting calls the C library's `qsort`, so equal elements end up in the same order as
      with OpenSSL on the same system.
    - Quirks kept: `OPENSSL_sk_find_all` on an unsorted stack adds to the caller's count;
      `OPENSSL_sk_dup(NULL)` returns an empty stack; `OPENSSL_sk_set` out of range raises
      with the data `i=<n>`.
  - **Hash tables:**
    - OpenSSL's linear hashing is ported step for step (bucket choice, splits, merges, chain
      order), since `doall`'s order is visible.
    - Nodes live in a slab under generation-checked references, and no lock is held during
      callbacks. A `doall` callback may delete the item it visits, as OpenSSL's session cache
      does; one that deletes the next item stops that chain where OpenSSL would read freed
      memory.
    - `OPENSSL_LH_strhash` reproduces the per-platform effect of `char`'s signedness.
    - The `FILE` statistics functions print OpenSSL 3.1+'s text. The `_bio` variants wait
      for 1.6.
  - **`ex_data`:**
    - Index 0 is reserved in each class, and the values are an ordinary `STACK_OF(void)` in
      the public `CRYPTO_EX_DATA`.
    - Free callbacks run in the order libc `qsort` leaves equal priorities. That isn't index
      order on macOS with 13 entries, and the test checks it.
    - Freed indexes keep do-nothing callbacks, as OpenSSL's dummies.
    - The quirks of `CRYPTO_set_ex_data(-1, NULL)` (succeeds, leaving an error) and of
      `CRYPTO_dup_ex_data` for a class without indexes are kept.
  - **Strings:**
    - Copies come from `CRYPTO_malloc` with the caller's file and line.
    - `OPENSSL_strcasecmp`/`strncasecmp` fold only ASCII and return differences of C
      `char`s, which are signed or not depending on the platform.
    - `OPENSSL_strtoul` is libc's `strtoul` with OpenSSL's checks.
    - The hex codec matches OpenSSL, including that a separator above 0x7f never matches
      where `char` is signed.
    - `err::raise_with_text` attaches preformatted error data exactly as `ERR_vset_error`
      does, buffer sizes included; 1.6's printf engine will reuse it.
  - **Directories:** `OPENSSL_DIR_read` wraps `opendir`/`readdir` with OpenSSL's `errno`
    conventions.
  - **Deviations (`DEVIATIONS.md`):**
    - `doall` on a table without thunks (OpenSSL calls a null thunk);
    - a `doall` callback deleting the next item;
    - `OPENSSL_DIR_end` leaving the context dangling;
    - null arguments that crash OpenSSL.
  - **Tests:** identical output to the reference on macOS and Linux aarch64:
    - `tests/c/stack.c` (48 checks), `lhash.c` (23, with `doall` orders and statistics
      compared), `ex_data.c` (27), `crypto_str.c` (41), `crypto_dir.c` (9);
    - differential: a `containers.txt` corpus, plus random stack, hash-table, hex, and
      `strtoul` sessions, 10,000 of them identical on macOS;
    - fuzz targets `stack` and `lhash`, model-based, and `hex`, against a model decoder
      with a round trip.
- [x] **1.6 BIO core**, in five sub-steps, each its own PR (about 200 exports in all; those that
  need later phases are listed at the end):
  - [x] **1.6a The BIO object and the simple types:**
    - the BIO object and chains
    - `read`/`write`/`gets`/`puts` and their `_ex` variants
    - the `BIO_ctrl` protocol
    - callbacks (`BIO_set_callback_ex` and the old-style one)
    - `BIO_meth_*`, for application-defined BIOs
    - ex_data
    - the mem (including read-only), secmem, null, file, and fd BIOs, and the null filter
    - `ERR_print_errors`, `ERR_add_error_mem_bio`, and the `OPENSSL_LH_*_bio` statistics

    *Done:* 99 exports, now 319 of libcrypto's 5,876 (`bio.rs`, `bio/`).
    - **Methods are tables of C functions,** built-in ones included. Applications build their
      own methods out of `BIO_meth_get_*(BIO_s_mem())`, so every built-in function is a real C
      function taking a `BIO *`, and the plain `read`/`write` go through OpenSSL's converters.
      The internal ones are written with `ffi_callback!`, the unexported twin of
      `ffi_export!`.
    - **The BIO object:**
      - The fields are atomics, so misuse from two threads isn't a data race on the Rust
        side.
      - No lock is held while a method or callback runs.
      - Each call holds a reference through `Handle::hold`, new in this step, so a callback
        that frees the BIO can't free it under the call. `BIO_free`'s count is separate from
        that.
      - The core is OpenSSL's `bio_lib.c`: errors and return values, the callbacks before
        and after (the old-style one with its length and count conversions), and the byte
        counts.
    - **The memory BIO** keeps OpenSSL's state in C memory: the public `BUF_MEM` that
      `BIO_get_mem_ptr` hands out, plus a read position. So applications that edit the buffer
      see what OpenSSL gives them, including the move of unread data on a write, seeks within
      the buffer, and the EOF return. A positive EOF return reads "bytes" that were never
      written, as in OpenSSL.
    - **The file and fd BIOs** are OpenSSL's Unix paths over stdio and descriptors. Failures
      raise the system error with the call in the data (`calling fopen(name, mode)`, through
      the new `err::raise_with_bytes`), then the BIO error.
    - **Quirks kept:**
      - The null filter refuses `BIO_CTRL_DUP`, so `BIO_dup_chain` fails on a chain with
        one.
      - `BIO_free_all` stops after a BIO with another reference.
      - `BIO_set_next` doesn't link back.
    - **Deviations (`DEVIATIONS.md`):**
      - null BIOs and methods;
      - built-in methods, which OpenSSL keeps read-only;
      - `BIO_indent` with a negative limit;
      - a file BIO without a `FILE`;
      - `BIO_set_mem_buf(NULL)`.
    - **Tests:** identical output to the reference on macOS and Linux aarch64:
      - `tests/c/bio_mem.c` (62 checks), `bio_meth.c` (37, with the callback traces
        compared), `bio_file.c` (31), `err_bio.c` (6), and an addition to `lhash.c`;
      - differential: a `bio.txt` corpus, plus random memory BIO sessions, 9,000 sessions
        identical on macOS and 3,000 on Linux;
      - a model-based `bio_mem` fuzz target (4 million runs clean). It caught a mistake in
        its own model: `BIO_write` of 0 bytes doesn't reach the BIO.
  - [x] **1.6b printf and formatting:**
    - `BIO_printf`, `BIO_snprintf`, `BIO_vprintf`, `BIO_vsnprintf`: byte-exact with the
      reference
    - `ERR_set_error`/`ERR_vset_error` with a format (they aborted until now)
    - `BIO_dump*`, `BIO_hex_string`, `BIO_debug_callback(_ex)`

    *Done:* 13 exports, now 332 of libcrypto's 5,876 (`bio/print.rs`, `bio/dump.rs`,
    `bio/debug.rs`).
    - **OpenSSL's printf is its own,** not the C library's, so `bio/print.rs` ports its
      behavior rather than calling `vsnprintf`. The differences from C that applications can
      see are kept:
      - negative `*` widths and precisions are ignored;
      - `0` pads even with `-` or a precision;
      - `%f`/`%e`/`%g` print at most 9 decimals, round half up on the scaled fraction, fail at
        2^64, print `?` for the sign of infinities and NaNs, leave 10.0 as the mantissa of
        `%e`, and drop the leading digit of a 20-digit integer part;
      - `%hhd` prints `d`; `%w` skips a character; `%L` reads a `double`, as OpenSSL is built
        without `long double`;
      - `BIO_snprintf` returns -1 on truncation and stops reading arguments once the buffer is
        full; `BIO_printf` fails past about 2 GiB of output.
      The arithmetic wraps where C's does, and `f64` is the `double` OpenSSL computes in, so
      the digits match bit for bit.
    - **One formatter, two kinds of arguments:** a C `va_list` (`VaList`, through the
      C-variadic definitions of Rust 1.99, with no C shim), or a slice of `Arg`s from Rust.
      The dump and debug functions use the latter, so their output, truncation, and sequence
      of `BIO_write` calls are OpenSSL's by construction.
    - **The error queue** formats `ERR_set_error`'s data into the reused, grown, and shrunk
      buffer as `ERR_vset_error` does; output that doesn't fit leaves the data empty.
    - **Deviations (`DEVIATIONS.md`):** null formats and `%n` targets, a final `%w`, and null
      arguments to the dump, hex, and debug functions.
    - **Tests:** identical output to the reference on macOS and Linux aarch64:
      - `tests/c/bio_print.c` (45 checks, the expected strings taken from the reference) and
        `bio_dump.c` (25, including the debug callback's traces for memory and fd BIOs and its
        255-byte cut);
      - differential: `printf` and `bioprintf` probe commands with typed arguments (dispatched
        by type signature, so every call is a real, well-typed C call on each ABI), a
        `printf.txt` corpus, and random formats in which the generator follows OpenSSL's
        parsing to know which arguments each conversion takes. 90,000 sessions identical on
        macOS and 40,000 on Linux;
      - Miri over the formatter's unit tests, including C-variadic calls, for macOS and Linux
        x86_64;
      - a `bio_printf` fuzz target (6 million runs clean) checking that `BIO_snprintf` stays
        in its buffer and agrees with `BIO_printf`.
  - [x] **1.6c Filters and pairs:**
    - buffer, linebuffer, readbuffer, prefix
    - the BIO pair (`BIO_s_bio`, `BIO_new_bio_pair`, `BIO_nread`/`nwrite`)
    - *Moved out:*
      - base64 to step 2.6, where the plan already had it beside its `EVP_Encode*` codec;
      - `BIO_f_nbio_test` to step 3.7, as it needs `RAND_priv_bytes`;
      - `BIO_s_dgram_pair`, `BIO_new_bio_dgram_pair`, and `BIO_s_dgram_mem` to 1.6e, as they
        carry peer addresses (`BIO_ADDR`).

    *Done:* 13 exports, now 345 of libcrypto's 5,876 (`bio/buffer.rs`, `bio/prefix.rs`,
    `bio/pair.rs`, `bio/state.rs`).
    - **Ports of OpenSSL's `bf_buff.c`, `bf_lbuf.c`, `bf_readbuff.c`, `bf_prefix.c`, and
      `bss_bio.c`.** What applications see is kept, quirks included:
      - how each write is split and when it reaches the next BIO;
      - partial writes and retries, and what is counted when the next BIO fails (a line
        buffer counts bytes it then drops);
      - a buffer's size only grows past 4 KiB, and `BIO_set_buffer_read_data` keeps it;
      - a read buffer refuses writes with 0 and passes no controls on;
      - `BIO_dup_chain` copies a pair end unpaired but with `init` set.
    - **State (`bio/state.rs`):** these types' private state is Rust, an `Arc<Mutex<T>>` in a
      typed slot of the BIO object, downcast to the type that asks for it. The BIO's `ptr`
      is set to its address, as OpenSSL sets it to its context, but nothing reads through
      it, so `BIO_set_data` can't make the state be misread.
      - A call clones the `Arc` before calling the next BIO, so a callback that frees the
        filter can't free the state under it.
      - Buffers are taken out of the state across such calls, and no lock is held across
        them.
      - An application method built from `BIO_meth_get_*(BIO_f_buffer())` with another
        create function has no state of that type, so its functions do nothing.
      - A first version told state apart by comparing create functions' addresses, which
        Rust doesn't guarantee to be unique: Miri gives a function different addresses, and
        caught it.
    - **The pair's ring buffers are C memory** (`OPENSSL_malloc`, as in OpenSSL), because
      `BIO_nread`/`BIO_nwrite` hand out pointers into them. Each end holds a counted
      reference to its peer, BIO and state, dropped on unpairing. So freeing an end, or
      misusing a pair from two threads, never reaches freed memory. Only one end's lock is
      held at a time.
    - **`Held` handles are now `Send`/`Sync`** (when the object is), so the pair can store
      one.
    - **Deviations (`DEVIATIONS.md`):**
      - a buffer filter's `BIO_gets` of size 0;
      - negative or null preloads and peeks;
      - read buffer reads past `INT_MAX`;
      - pairing with a non-pair BIO;
      - unpaired ends with `init` set;
      - null arguments to the pair functions and the prefix filter;
      - methods mixing these functions with another create function.
    - **Tests:** identical output to the reference:
      - `tests/c/bio_filter.c` (40 checks, through a scripted BIO that logs every write the
        filters pass on) and `bio_pair.c` (27);
      - differential: new `bionew` kinds (each filter in front of memory, a read buffer over
        a fixed text, and a pair with small buffers, with `biopeer`, `bionread`,
        `bionwrite`, and pair and buffer controls), a `bio_filters.txt` corpus, and random
        sessions;
      - a model-based `bio_pair` fuzz target (pair traffic against queues, and filter output
        against what was written).
  - [x] **1.6d Addresses, sockets, and the socket and accept BIOs:**
    - `BIO_ADDR`, `BIO_ADDRINFO`, `BIO_lookup(_ex)`, `BIO_parse_hostserv`
    - the socket helpers (`BIO_socket`, `BIO_connect`, `BIO_bind`, `BIO_listen`,
      `BIO_accept_ex`, `BIO_sock_*`, `BIO_socket_wait`, `BIO_socket_nbio`,
      `BIO_socket_ioctl`, ...), the deprecated ones (`BIO_get_host_ip`, `BIO_get_port`,
      `BIO_accept`, `BIO_get_accept_socket`, `BIO_gethostbyname`), `BIO_wait`,
      `BIO_do_connect_retry`, and `OSSL_sleep`
    - the socket and accept BIOs

    *Done:* 48 exports, now 393 of libcrypto's 5,876 (`bio/addr.rs`, `bio/sock.rs`,
    `bio/accept.rs`, `sleep.rs`).
    - **Split from 1.6e,** which holds the datagram BIOs and the connect BIO (whose
      `SOCK_DGRAM` mode wraps a datagram BIO). This step is everything below them.
    - **`BIO_ADDR`** is OpenSSL's union of the IPv4, IPv6, and Unix-domain socket addresses,
      from `OPENSSL_zalloc`. **`BIO_ADDRINFO` is the C library's `struct addrinfo`,** freed
      with `freeaddrinfo`, except for Unix-domain lookups, which build one entry as OpenSSL
      does. `BIO_ADDRINFO_address` hands out the entry's `sockaddr`, so a `BIO_ADDR` pointer
      may point at no more than its family's address. Nothing reads more of one than that
      family's size, and field pointers come from `offset_of!`, with one access per unsafe
      block.
    - **Lookups follow OpenSSL's `getaddrinfo` use:**
      - `AI_ADDRCONFIG` for `AF_UNSPEC` with a host, and a retry as `AI_NUMERICHOST`;
      - `AI_PASSIVE` for servers;
      - errors with `gai_strerror`'s text, or the system error for `EAI_SYSTEM`.
    - **The socket helpers** raise OpenSSL's errors, the system error with `calling
      socket()` and the like, then the BIO reason. TCP Fast Open follows OpenSSL's paths:
      `TCP_FASTOPEN_CONNECT` and `TCP_FASTOPEN` on Linux; on macOS the
      `net.inet.tcp.fastopen` sysctl, `connectx`, and `TCP_FASTOPEN`. The socket BIO keeps
      the Fast Open peer (`BIO_C_SET_CONNECT`) that OpenSSL keeps, though on these
      platforms it never sends to it.
    - **The accept BIO's** state machine calls `BIO_push` on itself, which runs its own
      control function, so its state's lock is never held across a call out. The cached
      names (`BIO_get_accept_name`, `BIO_get_peer_name`, ...) are `OPENSSL_malloc` strings
      the state owns, at stable addresses until replaced.
    - **Deviations (`DEVIATIONS.md`):**
      - null addresses, specs, results, and descriptors;
      - a Unix path that fills its field without a NUL;
      - an accept BIO freed with `BIO_NOCLOSE`, whose state is freed rather than leaked.
    - **Tests:** identical output to the reference:
      - `tests/c/bio_addr.c` (31 checks; numeric hosts and the local services database, so
        nothing depends on the network);
      - `tests/c/bio_sock.c` (49), over loopback: the helpers, socket BIOs, the accept BIO
        with and without a chain, non-blocking accepts, `BIO_wait`, and the deprecated
        functions. Ports are ephemeral, so only their relations are checked. The TCP Fast
        Open result is printed, as it depends on the machine, and compared too;
      - differential: `hostserv` and `addr` probe commands, an `addr.txt` corpus, and random
        specs and raw addresses. 60,000 sessions identical on macOS and 40,000 on Linux
        aarch64, where the C tests also passed (built with GCC);
      - Miri for macOS and Linux x86_64 (the socket test is skipped there);
      - a `bio_addr` fuzz target: `BIO_parse_hostserv` against a model of its rules, and raw
        addresses round-tripped through `BIO_ADDR`, about 12 million runs. It found that
        macOS's `getnameinfo` refuses some multicast-scoped IPv6 addresses, which OpenSSL
        reports identically; the target's model was too strict.
  - [x] **1.6e Datagrams and the connect BIO:**
    - the datagram BIO (`BIO_s_datagram`, `BIO_new_dgram`, `BIO_dgram_non_fatal_error`,
      `BIO_err_is_non_fatal`): peers, MTU queries, timeouts, local addresses, and
      `sendmmsg`/`recvmmsg`
    - the connect BIO (`BIO_s_connect`, `BIO_new_connect`), stream and datagram
    - the datagram pair and memory BIOs (`BIO_s_dgram_pair`, `BIO_new_bio_dgram_pair`,
      `BIO_s_dgram_mem`), moved from 1.6c

    *Done:* 9 exports, now 402 of libcrypto's 5,876 (`bio/dgram.rs`, `bio/dgram_pair.rs`,
    `bio/connect.rs`). This completes the BIOs of the default build that don't wait for later
    phases.
    - **The datagram BIO follows what OpenSSL compiles in per platform,** checked by compiling a
      probe of the socket macros on each (with OpenSSL's `_GNU_SOURCE`, and on macOS
      `__APPLE_USE_RFC_3542`, which `internal/sockets.h` defines):
      - **Linux:** batches of up to 64 through `sendmmsg`/`recvmmsg`; `IP_MTU`/`IPV6_MTU`
        queries; `IP_MTU_DISCOVER` for discovery and for IPv4's don't-fragment; a 40-byte
        control buffer.
      - **macOS:** one message per call through `sendmsg`/`recvmsg`; no MTU queries;
        `IP_DONTFRAG`; a 64-byte control buffer.
      - **Both:** destination addresses from `IP_PKTINFO` and `IPV6_RECVPKTINFO`;
        `IPV6_DONTFRAG`; DTLS's receive timeout adjusted to the next timer, in OpenSSL's
        nanosecond ticks from `gettimeofday`.
      SCTP is off in OpenSSL's default build.
    - **The datagram pair stores datagrams as OpenSSL does,** a header (length, source and
      destination `BIO_ADDR`) then the payload, in an `OPENSSL_malloc` ring. So the buffer
      sizes applications see, which depend on `sizeof(BIO_ADDR)`, match on each platform, and
      allocation failures leave the same errors. A memory BIO grows its ring by 8/5.
    - **The connect BIO** calls the application's info callback after each state with no lock
      held, and in datagram mode forwards reads, writes, and messages to a datagram BIO on its
      socket.
    - **Quirks kept:**
      - `BIO_get_conn_ip_family` and `BIO_get_conn_mode` pass a null pointer, which the control
        refuses, so they return 0.
      - An info callback that returns 0 ends the state machine before `BIO_R_CONNECT_ERROR` is
        raised.
      - A connect BIO's read of a null buffer returns the state machine's result.
      - The non-blocking connect check polls with no wait, so a pending connect spins until it
        finishes, as in OpenSSL.
      - A datagram BIO marked connected writes with `write`.
      - No truncation fails a short read without a retry.
    - **Deviations (`DEVIATIONS.md`):**
      - negative counts and null arguments to the peer and timeout controls;
      - the datagram pair's double free of its local address;
      - null out-pointers to `BIO_new_bio_dgram_pair`;
      - a connect BIO freed with `BIO_NOCLOSE` (as for accept);
      - only a family's bytes of the addresses written into a datagram's header.
    - **Tests:** identical output to the reference:
      - `tests/c/bio_dgram.c` (28 checks, over loopback UDP, with the platform's MTU and
        don't-fragment results printed and compared);
      - `tests/c/bio_dgram_pair.c` (28, with the default and grown buffer sizes printed). It
        clears the local address before unpairing, as the reference would otherwise
        double-free it;
      - `tests/c/bio_connect.c` (26, against an accept BIO, with the info callback's states
        printed and compared);
      - differential: datagram memory BIOs and pairs as new `bionew` kinds, with no-truncation,
        MTU, and buffer-size controls; 80,000 sessions identical on macOS;
      - a model-based `bio_dgram_pair` fuzz target (2.5 million runs). It found two mistakes in
        its own model, both instructive: `BIO_write` of 0 bytes stops at the generic layer,
        but `BIO_read` of 0 bytes reaches the BIO and reads (truncates) a datagram.

  Later phases: the md and cipher filters (`BIO_f_md`, `BIO_f_cipher`, `BIO_f_reliable`,
  Phase 3); the ASN.1, CMS, PKCS#7, and NDEF BIOs; and the provider core BIO
  (`BIO_s_core`, `BIO_new_from_core_bio`).
- [x] **1.7 Tracing:** `OSSL_trace_*` with the default build's behavior (tracing disabled).

  *Done:* 10 exports, now 412 of libcrypto's 5,876 (`trace.rs`). This completes phase 1's
  steps, and its exit criteria hold: the C conformance tests pass identically on both
  libraries, the printf corpus is byte-identical, and the printf and BIO fuzzers run clean.
  - **As OpenSSL's default build (`OPENSSL_NO_TRACE`):**
    - nothing can be attached: `OSSL_trace_set_channel`, `_set_callback`, `_set_prefix`, and
      `_set_suffix` return 0, and the channel stays the caller's;
    - no category is enabled, `OSSL_trace_begin` returns NULL, and `OSSL_trace_end` does nothing;
    - the header's `OSSL_TRACE*` macros compile to nothing in applications, so they never call
      in.
  - **What still works:**
    - the category names map to numbers and back, ignoring ASCII case. The table takes each
      name from its generated `OSSL_TRACE_CATEGORY_*` constant's identifier, and a
      compile-time check ties its length to `OSSL_TRACE_CATEGORY_NUM`;
    - `OSSL_trace_string` formats through the same `BIO_printf` path. So a NUL in text ends
      the output, NULL text prints the start of `<NULL>`, empty text returns 0, and a NULL BIO
      returns 0 with no error, all as OpenSSL does.
  - **Deviations (`DEVIATIONS.md`):** `OSSL_trace_string` overflows OpenSSL's 81-byte buffer
    when asked to mask more than 80 bytes in full; rustyssl masks them all. NULL data to mask,
    and sizes over `INT_MAX`, fail with -1.
  - **Tests:** identical output to the reference:
    - `tests/c/trace.c` (25 checks, with every category's name and each formatted string
      printed escaped);
    - differential: `tracecat` and `tracestr` commands, a `trace.txt` corpus, and random
      strings of up to 120 bytes around the limit mixing control characters, NULs, and high
      bytes; 80,000 sessions identical on macOS. The probe never asks the reference to mask
      more than 80 bytes in full.
  - No fuzz target: `OSSL_trace_string` parses nothing, and the differential sessions cover
    its inputs.

**Exit:** C conformance tests for ERR, BIO, stack, lhash, ex_data, and memory pass on both
the reference and ours. The printf corpus is byte-identical to the reference. The printf and
BIO fuzzers run clean (the base64 fuzzer comes with the codec, step 2.6).

## Phase 2: ASN.1, objects, encodings

- [x] **2.1 OBJ:**
  - the generated NID table (`rustyssl_asn1::objects`, from 0.4), plus
    `OBJ_create`/`OBJ_add_object` for runtime OIDs
  - `OBJ_txt2obj`/`OBJ_obj2txt` (byte-exact, including large arcs)
  - `OBJ_find_sigid_algs`, `OBJ_add_sigid`
  - the `OBJ_NAME_*` alias registry

  *Done:* 37 exports, now 449 of libcrypto's 5,876: every `OBJ_*` function, the
  `ASN1_OBJECT` functions, `a2d_ASN1_OBJECT`, `i2t_ASN1_OBJECT`, and `i2a_ASN1_OBJECT`
  (`capi/src/objects.rs`, `objects/name.rs`, `objects/sigid.rs`; the safe core is
  `rustyssl_asn1::objects` and `rustyssl_asn1::oid`). `d2i_`/`i2d_ASN1_OBJECT` come with the
  DER engine (2.2) and `ASN1_OBJECT_it` with the template engine (2.4).
  - **Lookups are OpenSSL's binary searches, step for step.** Three objects are named `"NULL"`
    and two share the OID 1.3 (`ORG` and `identified-organization`), so which one a search
    finds depends on the probe sequence. The indexes are rebuilt the way `obj_dat.pl` builds
    them (Perl's stable sort over ascending NIDs; for OIDs, shorter first, then bytewise), which
    reproduces the reference's `sn_objs`, `ln_objs`, and `obj_objs` exactly. The OID index also
    holds the 7 objects whose OID OpenSSL doesn't encode (single arcs and bare aliases): they
    never match but shift the midpoints, so the generator now records `indexed` for each
    object. The signature cross-reference leaves out algorithms without a digest, as
    `objxref.pl` does; the rest have no ties.
  - **Built-in objects** have OpenSSL's `ASN1_OBJECT` layout at fixed addresses and are shared;
    `ASN1_OBJECT_free` and `OBJ_dup` treat non-dynamic objects as OpenSSL does. Objects added
    at run time are kept by NID, OID, and names (a newer one replaces an older one per key) and
    never freed; NIDs are handed out from 1487, the first past the table.
  - **Text conversions** are ports of `a2d_ASN1_OBJECT` and `OBJ_obj2txt` with their
    leniencies: spaces separate arcs too, empty arcs are 0, a trailing separator is dropped,
    `"12"` is no OID without an error, and `""` fails with `ASN1_R_FIRST_NUM_TOO_LARGE` (the
    NUL is read as the first number). Arcs of any size are exact (a small bignum in
    `rustyssl_asn1::oid`); text is limited to RFC 2578's 586 content octets, as in OpenSSL.
    `OBJ_obj2txt` writes a prefix of the text when it fails partway, as OpenSSL's does.
  - **`OBJ_create_objects`** reads 512-byte lines into one buffer, as OpenSSL does, so a line
    without a long name after one with uses what was left in the buffer (a quirk kept: it
    usually fails with `OBJ_R_OID_EXISTS` and stops).
  - **The name registry** is one of our `OPENSSL_LH_*` tables with OpenSSL's hash
    (`ossl_lh_strcasehash`, with the platform's `char` signedness), so `OBJ_NAME_do_all`
    visits in OpenSSL's order; `OBJ_NAME_do_all_sorted` sorts with the C library's `qsort`. No
    lock is held while an application's hash, comparison, free, or visiting function runs.
  - **Added signature algorithms** live on two of our stacks, sorted with `qsort` and searched
    as OpenSSL's are, including the comparator that lets an algorithm without a digest match any.
  - **Configuration:** OpenSSL loads the configuration file before it first consults added
    objects, and a missing file leaves heap buffers in the error queue's slots (the `fopen`
    error's text, raised and then dropped). `OPENSSL_init_crypto`'s configuration step now
    follows `CONF_modules_load_file_ex` and `def_load` (mark, `BIO_new_file`,
    `CONF_R_NO_SUCH_FILE`, pop or keep), so the error queue matches. The test drivers point
    both libraries at the same missing `OPENSSL_CONF`, since the text names the path.
  - **Deviations (`DEVIATIONS.md`):** NULL strings to the name lookups, `OBJ_txt2obj`, and
    `a2d_ASN1_OBJECT`; a negative `OBJ_obj2txt` length; NULL objects to `OBJ_cmp`; a NULL
    `OBJ_bsearch_` comparator; `OBJ_add_object` of a built-in object; searches after
    `OBJ_sigid_free`; and the name registry's NULL free functions, negative types, and reuse
    after `OBJ_NAME_cleanup(-1)`. In each, OpenSSL crashes.
  - **Tests:**
    - `tests/c/objects.c` (60 checks), identical on both libraries. It prints every lookup's
      result, texts, encodings, `i2a` output, the first new NID, binary-search positions, the
      signature table's choices, and the registry's visiting orders, so all are compared;
    - differential: `objtxt`, `objder`, and `objname` probe commands with random dotted texts
      (known prefixes, large arcs, odd separators), names, and content octets; 80,000 sessions
      identical on macOS;
    - a fuzz target, `oid` (6.4 million runs): text through `a2d_ASN1_OBJECT` and
      `OBJ_txt2obj`, and content through `OBJ_obj2txt`, must round-trip, failing only where
      OpenSSL's rules say.
- [x] **2.2 DER/BER engine** (`rustyssl-asn1`):
  - safe and zero-copy, with bounded depth and size
  - indefinite-length BER (needed for PKCS#7, CMS, and PKCS#12)
  - strict DER, plus a documented list of the leniencies OpenSSL accepts
  - `ASN1_get_object`/`ASN1_put_object`

  *Done:* 8 exports, now 457 of libcrypto's 5,876: `ASN1_get_object`, `ASN1_put_object`,
  `ASN1_put_eoc`, `ASN1_object_size`, `ASN1_check_infinite_end`,
  `ASN1_const_check_infinite_end`, and (from 2.1) `d2i_ASN1_OBJECT`/`i2d_ASN1_OBJECT`
  (`capi/src/asn1.rs`, `objects.rs`; the safe core is `rustyssl_asn1::der`).
  - **The header reader accepts what OpenSSL's does,** documented in `rustyssl_asn1::der`:
    long-form lengths however small, with leading zero octets (up to 127); high-tag form for
    any tag number, with any number of leading `0x80` octets; the indefinite length on
    constructed elements. It reports the same results, errors, and partial outputs: a length
    past `omax` is `ASN1_R_TOO_LONG` with the header returned; the tag and class (and length)
    are stored before a later fault. `der::is_der` checks a header is in DER's single form,
    for callers that want strictness.
  - **Bounds:** a header has no length limit in OpenSSL (leading `0x80` octets), and callers
    pass `omax` values larger than their buffers (`LONG_MAX`), so the reader fetches one
    octet at a time and never past the header, and no slice of `omax` octets is made.
    `der::element` reads whole elements zero-copy; nested indefinite-length content is
    skipped with a counter, as OpenSSL's `asn1_find_end` does, so depth costs no stack (tested
    at 100,000 levels). The template engine's `asn1_check_tlen`/`asn1_collect` come with it
    (2.4).
  - **The writer** reproduces `ASN1_put_object`'s C arithmetic: negative tags and lengths are
    written as their low bits, any nonzero `constructed` sets the bit, 2 is indefinite.
  - **`d2i_ASN1_OBJECT`** takes any class and the constructed bit, as OpenSSL does, and
    `c2i` (now also behind `OBJ_txt2obj`) reuses a dynamic `*a`, keeping its NID and dropping
    its names.
  - **Deviation (`DEVIATIONS.md`):** NULL pointers to these functions.
  - **Tests:**
    - `tests/c/asn1_header.c` (15 checks, with every read's result, outputs, octets used, and
      errors printed), identical on both libraries;
    - differential: `asnhdr`, `asnput`, and `d2iobj` probe commands with random headers in
      every form OpenSSL reads, cut short and claimed long; 80,000 sessions identical on
      macOS;
    - a `der` fuzz target (15 million runs): exact-size input to `ASN1_get_object`, headers
      round-tripped through `ASN1_put_object`, objects through `i2d`/`d2i`, and the element
      reader.
- [x] **2.3 Universal types** (public-layout `ASN1_STRING` family), in six sub-steps, each its
  own PR. The `d2i_`/`i2d_`/`_it` functions of these types, and the `new`/`free` of those
  built from templates (`ASN1_TIME`, `ASN1_PRINTABLE`, `DIRECTORYSTRING`, ...), come from the
  template engine (2.4).
  - [x] **2.3a `ASN1_STRING` and the string types' `new`/`free`:**
    `ASN1_STRING_new`/`type_new`/`free`/`clear_free`/`set`/`set0`/`copy`/`dup`/`cmp` and
    the accessors; the 14 types whose `new`/`free` are plain functions
    (`IMPLEMENT_ASN1_STRING_FUNCTIONS`); `ASN1_OCTET_STRING_dup`/`cmp`/`set`.

    *Done:* 48 exports, now 502 of libcrypto's 5,876 (`capi/src/asn1/string.rs`).
    - **The struct is the application's** (`length`, `type`, `data`, `flags`), so its fields
      are taken as they are, as OpenSSL takes them. `ASN1_STRING_set` keeps a NUL after the
      data, reuses the buffer only when the new length is below the old one (an equal length
      is reallocated), sizes without copying for NULL data, and fails with
      `ASN1_R_TOO_LARGE` past `INT_MAX` - 1 octets. `ASN1_STRING_FLAG_NDEF` strings don't
      own their data and `ASN1_STRING_FLAG_EMBED` ones are part of another structure;
      `ASN1_STRING_copy` keeps the destination's `EMBED` flag. `ASN1_STRING_cmp` orders by
      length, then octets, then type.
    - **Deviations (`DEVIATIONS.md`):** NULL strings to the setters, comparison, and
      accessors; `ASN1_STRING_clear_free` with a negative length.
    - **Tests:** `tests/c/asn1_string.c` (19 checks), identical on both libraries. Nothing here
      parses input, so there's no probe command or fuzz target.
  - [x] **2.3b INTEGER and ENUMERATED:** `get`/`set` for `long`, `int64`, and `uint64`,
    negative values, `cmp`, `dup`. The `BIGNUM` conversions wait for `BIGNUM` (Phase 4).

    *Done:* 17 exports, now 519 of libcrypto's 5,876: the 10 getters and setters,
    `ASN1_INTEGER_cmp`/`dup`, `i2a_`/`a2i_ASN1_INTEGER` and `_ENUMERATED`, and
    `d2i_ASN1_UINTEGER` (`capi/src/asn1/integer.rs`). `ASN1_INTEGER_to_BN`,
    `BN_to_ASN1_INTEGER` (and the ENUMERATED ones) and `i2s_`/`s2i_ASN1_INTEGER` wait for
    `BIGNUM`.
    - **Values are magnitudes as stored**, with `V_ASN1_NEG` in the type: leading zero octets
      count toward the 8 a 64-bit value allows; the setters write the shortest magnitude (one
      zero octet for 0). The getters check the type, then (unsigned) the sign, then the size,
      raising what OpenSSL raises (`ASN1_R_WRONG_INTEGER_TYPE`, `ILLEGAL_NEGATIVE_VALUE`,
      `TOO_LARGE`, `TOO_SMALL`); `ASN1_INTEGER_get` gives -1 on failure and 0 for NULL;
      `ASN1_ENUMERATED_get` gives `0xffffffff` past 8 octets.
    - **`i2a_ASN1_INTEGER`** writes uppercase hex with a backslash and newline every 35
      octets. **`a2i_ASN1_INTEGER`** is a port, quirks included: a leading `00` is dropped on
      the first line only; on a continued line the character before the backslash is dropped
      too, so `i2a`'s own continued output reads as an odd number of characters; it writes NULs
      into the caller's buffer; it doesn't free the string's earlier data; the result is always
      an INTEGER. **`d2i_ASN1_UINTEGER`** takes any class and drops one leading zero.
    - **Deviation (`DEVIATIONS.md`):** NULL integers, outputs, and buffers.
    - **Tests:**
      - `tests/c/asn1_integer.c` (10 checks, with every value's octets, getter results, texts,
        and errors printed), identical on both libraries;
      - differential: `asnint`, `asnset`, and `a2iint` probe commands. They found two
        orderings this needed: the unsigned getter refuses a negative value before checking
        its size, and `00\` on the first line is an odd count (-1), not a short line. Both are
        in the C test now; 120,000 sessions identical on macOS;
      - an `a2i_integer` fuzz target (9 million runs): arbitrary text and buffer sizes, and
        values round-tripped through `i2a_ASN1_INTEGER`.
  - [x] **2.3c BIT STRING, OCTET STRING, BOOLEAN, NULL:** bits, unused bits and flags.

    *Done:* 7 exports, now 526 of libcrypto's 5,876: `ASN1_BIT_STRING_set`/`set_bit`/
    `get_bit`/`check`/`num_asc`/`set_asc`/`name_print` (`capi/src/asn1/bit_string.rs`). The
    OCTET STRING functions came with 2.3a; BOOLEAN and NULL have only template functions
    (`ASN1_NULL_new`/`free`, the `_it` items), which come with 2.4, as does the content
    encoding of the unused-bits octet.
    - **As in OpenSSL:** bit 0 is the first octet's most significant bit; setting a bit past
      the end grows the string with zero octets (clearing one there does nothing); every change
      drops trailing zero octets and the stored unused-bits count (`ASN1_STRING_FLAG_BITS_LEFT`
      and its 3 bits), leaving the other flags; `ASN1_BIT_STRING_check` allows no bits past
      the flags given; `name_print` writes the long names of the set bits after `%*s`
      indentation (negative widths included).
    - **Deviation (`DEVIATIONS.md`):** a negative length to `set_bit`; NULL flags to `check`;
      NULL names to `num_asc`.
    - **Tests:** `tests/c/asn1_bit_string.c` (17 checks, with the octets and flags after each
      change printed), identical on both libraries; an `asnbit` probe command with random
      octets, bits, values, and flags (80,000 sessions identical on macOS). Nothing here
      parses input, so there's no fuzz target.
  - [x] **2.3d Character strings:** `ASN1_mbstring_copy`/`ncopy`, `ASN1_STRING_TABLE`, the
    default mask, `ASN1_STRING_to_UTF8`, `ASN1_STRING_print_ex` (RFC 2253 flags),
    `ASN1_PRINTABLE_type`.

    *Done:* 19 exports, now 545 of libcrypto's 5,876: those, `ASN1_STRING_print_ex_fp`,
    `ASN1_STRING_print`, `ASN1_UNIVERSALSTRING_to_string`, `UTF8_getc`/`UTF8_putc`,
    `ASN1_tag2bit`, and `ASN1_tag2str` (brought forward from 2.5, as `print_ex` names types)
    (`capi/src/asn1/text.rs`; the safe core is `rustyssl_asn1::text`). `X509_NAME_print_ex`
    comes with X.509.
    - **Conversions are ports of `ASN1_mbstring_ncopy`:** the same checks in the same order
      (lengths, UTF-8 validity, `minsize`/`maxsize` with their `minsize=N` error data, the
      character check per type), the same choice of type from the mask (other types in the
      mask counting as UTF-8, an empty string keeping the mask as given), the same reuse of
      `*out`, and a BMPString or UniversalString past `INT_MAX` octets refused before it is made.
    - **`ASN1_STRING_print_ex` is a port of `do_print_ex`:** OpenSSL's `char_type` table,
      computed from `charmap.pl`'s rules over the public flag constants; RFC 2253 escapes
      (first and last characters too), quoting with `ESC_QUOTE`, `\XX` for control and
      high characters, `\UXXXX` and `\WXXXXXXXX` for wide ones, type names, UTF-8 conversion,
      and hex dumps. The output goes out in OpenSSL's writes, so a failing BIO stops at the
      same point; no BIO only counts. Dumping DER (`ASN1_STRFLGS_DUMP_DER`, which RFC 2253 output
      uses for unknown types) encodes the string as `i2d_ASN1_TYPE` would: BIT STRING and
      INTEGER content converted (`rustyssl_asn1::text::bit_string_content`, `integer_content`,
      ready for the template engine), SEQUENCE and SET as they are, types past 30 in high-tag
      form.
    - **The string table** is OpenSSL's built-in one (two bounds, `ub_serial_number` and
      `ub_rfc822_mailbox`, are `tbl_standard.h`'s own, not in the public headers) and the
      entries applications add, found first; lookups load the configuration first, as
      OpenSSL's do.
    - **Deviations (`DEVIATIONS.md`):** dumping the DER of a string typed BOOLEAN or OBJECT,
      where OpenSSL reads the string as another structure and prints part of a heap address
      (so the probe's generator leaves those two types out); NULL arguments.
    - **Tests:**
      - `tests/c/asn1_text.c` (17 checks, 250 printed lines: every conversion and printout
        escaped, with errors and their data), identical on both libraries;
      - differential: `asntext` (strings of many types, valid and malformed text, random
        flag combinations, printed to a BIO and counted, and converted to UTF-8) and `asnmb`
        (random forms, masks, and limits); 120,000 sessions identical on macOS;
      - an `asn1_text` fuzz target (3.6 million runs): counts match output, and conversions
        round-trip through UTF-8.
  - [x] **2.3e Times:** UTCTIME, GENERALIZEDTIME, and TIME (parse, compare, diff, print
    formats), the `OPENSSL_gmtime*` family.

    *Done:* 27 exports, now 572 of libcrypto's 5,876 (`capi/src/asn1/time.rs`; the safe core
    is `rustyssl_asn1::time`). `ASN1_TIME_new`/`free`/`dup` and the typed `_dup` functions are
    built from templates and come with 2.4.
    - **The parser is a port of `ossl_asn1_time_to_tm`:** the minimum lengths (so a UTCTIME
      leaves out its seconds only before a `+hhmm` offset), field limits and days per month,
      fractions in a GENERALIZEDTIME only, offsets up to 12 hours folded in only when a `tm` is
      wanted (a check doesn't apply them), and the strict RFC 5280 form under
      `ASN1_STRING_FLAG_X509_TIME`. The weekday and day of the year are computed before an
      offset moves the date, as there.
    - **The date arithmetic** (`OPENSSL_gmtime_adj`/`_diff`, Julian days) keeps C's `int` and
      `long` arithmetic, wrapping where C would; results outside 1900 to 9999 fail.
    - **Writing** goes into 20 octets as `BIO_snprintf` does, so a year too long to fit leaves
      the string with length -1, as in OpenSSL. `ASN1_TIME_set_string_X509` copies the
      `ASN1_STRING_FLAG_X509_TIME` flag into the result, as there.
    - **Deviation (`DEVIATIONS.md`):** NULL arguments.
    - **Tests:**
      - `tests/c/asn1_time.c` (15 checks; parsed fields, normal forms, both printouts, X.509
        conversions, and the arithmetic at fixed times printed, nothing clock-dependent but
        relations), identical on both libraries;
      - differential: `asntime` (text near the valid forms, strict or not) and `asntimet`
        (times and offsets around the edges of both types and of 9999); 80,000 sessions
        identical on macOS;
      - an `asn1_time` fuzz target (15.6 million runs): valid times normalize to the same time,
        and comparisons agree with differences.
  - [x] **2.3f `ASN1_TYPE`:** `get`/`set`, `set1`, `cmp`, the `get_octetstring` and
    `get_int_octetstring` helpers.

    *Done:* 6 exports, now 578 of libcrypto's 5,876: `ASN1_TYPE_get`/`set`/`set1`/`cmp`/
    `set_octetstring`/`get_octetstring` (`capi/src/asn1/any.rs`). `ASN1_TYPE_new`/`free`,
    `ASN1_TYPE_pack_sequence`/`unpack_sequence`, and the `int_octetstring` pair (which pack a
    SEQUENCE through a template) come with 2.4.
    - **As in OpenSSL:** `ASN1_TYPE_get` counts BOOLEAN and NULL as holding a value; setting
      frees the old value as `ossl_asn1_primitive_free` does (objects with
      `ASN1_OBJECT_free`, a nested ANY recursively, strings even if marked embedded, BOOLEAN
      and NULL not at all); a BOOLEAN is 0xff or 0; `ASN1_TYPE_set1` copies objects and
      strings (a built-in object stays shared); `ASN1_TYPE_cmp` gives -1 for NULL or different
      types and compares BOOLEANs by subtraction.
    - **Deviation (`DEVIATIONS.md`):** NULL `ASN1_TYPE`s.
    - **Tests:** `tests/c/asn1_type.c` (22 checks), identical on both libraries. Nothing here
      parses input, so there's no probe command or fuzz target.

  *Step 2.3 done:* 121 exports over the six sub-steps, now 578 of libcrypto's 5,876.
- [ ] **2.4 ASN1_ITEM template engine** (in `capi`; this is the most security-sensitive unsafe
  code):
  - interprets `ASN1_ITEM`, `ASN1_TEMPLATE`, and `ASN1_AUX` tables, including callbacks,
    SEQUENCE, CHOICE, SET OF, EXPLICIT/IMPLICIT tagging, ADB, EMBED, REFCOUNT, ENCODING
    cache, EXTERN, MSTRING, and COMPAT
  - the `ASN1_item_*` API
  - built-in types exposed as `ASN1_ITYPE_EXTERN` items
  - **generated** `d2i_`/`i2d_`/`_new`/`_free`/`_dup`/`_it` functions for every type declared
    with `DECLARE_ASN1_*` in the headers

  In three sub-steps, each its own PR. The types of later phases (X.509, PKCS#7, ...) get their
  items and functions with those phases, as `BIGNUM_it`/`CBIGNUM_it` do with `BIGNUM`;
  `ASN1_item_sign`/`verify`/`digest` come with EVP (Phase 3).
  - [x] **2.4a The engine, allocation, and encoding:** reading items, templates, ADB tables,
    and aux data; `ASN1_item_new`/`new_ex`/`ex_new`/`free`/`ex_free`, `ASN1_item_i2d`/
    `ex_i2d`/`ndef_i2d` (aux callbacks, CHOICE, ADB, EMBED, REFCOUNT, the ENCODING cache, SET OF
    sorting, NDEF); the universal items (the string types, `ASN1_NULL`, the BOOLEANs, `ASN1_OBJECT`,
    `ASN1_ANY`, `ASN1_SEQUENCE`, the MSTRINGs, `ASN1_SEQUENCE_ANY`/`ASN1_SET_ANY`,
    `ASN1_OCTET_STRING_NDEF`, `INT32` to `ZUINT64`, `LONG`/`ZLONG`) and their `new`/`free`/`i2d_`
    functions.

    *Done:* 80 exports, in `capi/src/asn1/tpl/` (`new`, `free`, `encode`, `items`, `ints`), each
    step a port of `tasn_new.c`, `tasn_fre.c`, and `tasn_enc.c` in OpenSSL's order, so aux
    callbacks run at the same points and as often (`ASN1_OP_I2D_PRE` in both passes,
    `_POST` only when writing). Decisions:
    - Output goes through a cursor that knows the buffer's end when rustyssl allocated it; a
      second pass that writes more than the first measured is dropped and fails
      (docs/DEVIATIONS.md). A caller's buffer has no known size and is written as in C.
    - A SET OF is encoded into a scratch `Vec` and sorted with a stable sort. The DER is the
      same as OpenSSL's `qsort`; only the order of equal elements in an `ASN1_TFLG_SET_ORDER`
      stack could differ, and equal elements encode identically.
    - The universal items' sizes are OpenSSL's: 0 for `IMPLEMENT_ASN1_TYPE` items (not the
      struct size), `sizeof(ASN1_STRING)` for MSTRINGs, flags for `INTxx` and the default for
      `LONG`. `INTxx` and `LONG` get `c2i` with 2.4b and `print` with 2.5 (it moved there
      with `ASN1_item_print`); until then their tables have no such functions.
    - The ENCODING cache is read and freed here but only filled by decoding (2.4b).

    Tests: `tests/c/asn1_template.c` defines application types with the `asn1t.h` macros
    (optional, tagged, embedded, SET OF / SET ORDER / SEQUENCE OF fields, a CHOICE, ANY DEFINED
    BY, a reference count, an NDEF SEQUENCE, a traced aux callback) and compares encodings and
    callback traces; the probe's `asnany` encodes random SEQUENCE OF and SET OF ANY. Encoding
    parses no input, so there's no fuzz target yet; decoding gets one.
  - [x] **2.4b Decoding:** `ASN1_item_d2i`/`d2i_ex`/`ex_d2i` (tag checks, indefinite-length
    collection, OPTIONAL and DEFAULT, CHOICE, ADB, the depth limit, the ENCODING cache) and the
    universal types' `d2i_` functions, fuzzed hard.

    *Done:* 25 exports (`ASN1_item_d2i`, `_d2i_ex`, `_ex_d2i`, and the universal `d2i_`
    functions), in `capi/src/asn1/tpl/decode.rs`, a port of `tasn_dec.c` in OpenSSL's order:
    the same callbacks, the same error queue (reasons and the `Field=, Type=` data), the same
    nesting limits (30 constructed levels, 5 for constructed strings). Decisions:
    - The caller's pointer and length become one slice at the boundary, and every read is
      bounded by it. An extern item's function gets a pointer into it, as in C; one that moves
      past its input is refused (docs/DEVIATIONS.md).
    - The header cache (`ASN1_TLC`) is kept as OpenSSL keeps it, because which errors bad
      input raises depends on it. Its layout is OpenSSL's private one; applications only pass on
      the pointer they were given. A cached header is used only where it fits the input.
    - Content parsing that needs no C structures (INTEGER and BIT STRING content, end-of-contents
      octets) is in `rustyssl_asn1::content`.
    - Collected constructed strings go into a `CRYPTO_malloc` block a string takes over (or an
      item's `c2i` may), as OpenSSL's `BUF_MEM` does.
    - `INTxx`/`LONG` items got their `c2i` functions; their `print` comes with 2.5.

    Tests: `tests/c/asn1_d2i.c` (84 checks) decodes DER and BER with the universal items and
    with application types (optional, tagged, SET OF, CHOICE, ADB, the ENCODING cache, traced
    callbacks, nesting), malformed input included, and compares the error queues. The probe's
    `asnd2i` decodes random BER with 14 items (one an application type with a CHOICE, ADB, and
    itself), comparing results and errors with the reference. The `asn1_d2i` fuzz target decodes
    arbitrary input with those items, re-encodes what decodes, and checks the encoding is
    stable. The fuzzer showed OpenSSL can write what it can't read back (an ANY of universal tag
    0 encodes as `00 00`, an end-of-contents); rustyssl does the same.
  - [x] **2.4c The rest of the item API:** `ASN1_item_dup`, `ASN1_item_pack`/`unpack`, the BIO
    and FILE variants, the universal `_dup` functions, `ASN1_TYPE_pack_sequence`/
    `unpack_sequence`, and the `int_octetstring` pair.

    *Done:* 23 exports, in `capi/src/asn1/tpl/util.rs` and `io.rs`: `ASN1_item_dup` and
    `ASN1_dup`, the three time `_dup`s, `ASN1_item_pack`/`unpack`/`unpack_ex`,
    `ASN1_TYPE_pack_sequence`/`unpack_sequence`, `ASN1_TYPE_set_int_octetstring`/`get`, and
    the BIO and FILE functions (`ASN1_item_d2i_bio`/`_ex`/`_fp`/`_fp_ex`,
    `ASN1_item_i2d_bio`/`_fp`/`_mem_bio`, `ASN1_d2i_bio`/`_fp`, `ASN1_i2d_bio`/`_fp`).
    Decisions:
    - `ASN1_item_print` and `ASN1_PCTX` moved to 2.5: printing a SEQUENCE, SET, or
      non-universal ANY needs `ASN1_parse_dump`, and INTEGERs print through the decimal
      conversion of `i2s_ASN1_INTEGER`.
    - `asn1_d2i_read_bio` is ported over a real `BUF_MEM`, so its growth and errors are
      OpenSSL's, with every look at the buffer bounded by its length: header octets not read
      yet count as the zeros the buffer was grown with, as they are in C. A clean end of input
      before an element queues no error, so loops over concatenated elements end quietly.
    - `ASN1_TYPE_set_int_octetstring(NULL, ...)` frees the `ASN1_TYPE` it makes, which OpenSSL
      leaks.

    Tests: `tests/c/asn1_item_io.c` (62 checks): dup with callback traces (`DUP_PRE`, the
    library-context queries, `DUP_POST` with the original), packing, the int/octet pair, and
    reading streams of DER and BER through a memory BIO and through one giving an octet per
    read (high tag numbers, long lengths, 40,000-octet content read in chunks, truncation,
    impossible lengths), and FILE round trips. The probe's `asnbio` reads random element
    streams through a BIO, and the `asn1_d2i_bio` fuzz target checks each element read from a
    BIO decodes the same in place.
- [x] **2.5 Utilities**, in three sub-steps, each its own PR. `ASN1_generate_nconf`/`_v3` (the
  string → DER mini-language) move to 6.1, as they read their SEQUENCE and SET sections through
  NCONF and an `X509V3_CTX` (`X509V3_get_section`, Phase 5); `ASN1_bn_print` moves to 4.1 with
  BIGNUM.
  - [x] **2.5a `ASN1_parse` and `ASN1_parse_dump`** (byte-exact `asn1parse` output).

    *Done:* 2 exports, in `capi/src/asn1/parse.rs`, a port of `asn1_parse.c`: one slice of the
    caller's input, each element read within its parent, nesting stopped at 128 levels
    ("BAD RECURSION DEPTH"), and the line prefix written through a prefix BIO pushed onto the
    caller's (or the caller's own, its indent restored), so the listing is OpenSSL's byte for
    byte. Contents are decoded with the same `d2i_` functions, so their errors queue as in
    OpenSSL. Tests: `tests/c/asn1_parse.c` (19 checks) lists every kind of element with each
    dump setting, malformed input, nesting past the limit, and a BIO that already has a prefix;
    the probe's `asnparse` lists random BER (corpus `asn1_parse.txt`); the `asn1_parse` fuzz
    target runs arbitrary input under ASan.
  - [x] **2.5b `ASN1_item_print`** and the `ASN1_PCTX` functions (moved from 2.4c), with the
    `INTxx`/`LONG` items' `print`, and the `i2s_`/`s2i_ASN1_INTEGER`, `_ENUMERATED`,
    `_ENUMERATED_TABLE`, and `_OCTET_STRING` conversions it prints INTEGERs with (decimal
    below 128 bits, hex above), done on octet strings rather than through BIGNUM.

    *Done:* 19 exports: `ASN1_item_print` (`capi/src/asn1/tpl/print.rs`, a port of
    `tasn_prn.c`), the 12 `ASN1_PCTX` functions, and the six X509V3 conversions in a new
    `capi/src/x509v3.rs`, over `rustyssl_asn1::number` (`bignum_to_string`'s text, and
    `s2i_ASN1_INTEGER`'s parse with `BN_dec2bn`/`BN_hex2bn`'s rules: a sign in either place,
    nothing after the digits). Formatted output goes through `BIO_printf` with OpenSSL's format
    strings. Quirks kept: an ENUMERATED field fails the print (it goes through
    `i2s_ASN1_INTEGER`), OIDs are cut to 79 characters, an extern item without a print function
    writes only its indent, and a LONG of 0 at the top prints `<ABSENT>`. Tests:
    `tests/c/asn1_print.c` (21 checks) prints an application type under each context flag;
    the probe's `asns2i` converts random number text, and `asnd2i` now prints what it decodes;
    the `asn1_d2i` fuzz target prints every value it decodes.
  - [x] **2.5c `i2a_ASN1_STRING`/`a2i_ASN1_STRING`** and `ASN1_buf_print` (`ASN1_tag2str` came
    with 2.3d, and the INTEGER helpers with 2.3b).

    *Done:* 3 exports, in `capi/src/asn1/hex.rs`. `a2i_ASN1_STRING` reads its lines as
    OpenSSL's does, unlike `a2i_ASN1_INTEGER`'s: a line is cut only at its last character if
    that isn't a hex digit (scanning back to the second), so junk before it is an error
    (`ASN1_R_NON_HEX_CHARACTERS`), and a trailing backslash takes the digit before it, so what
    `i2a_ASN1_STRING` writes over several lines doesn't read back; the test pins that. Tests:
    `tests/c/asn1_hex.c` (23 checks); the probe's `a2istr` (random lines, beside `a2iint`); the
    `a2i_integer` fuzz target runs both readers.

  *Step 2.5 done:* 24 exports over the three sub-steps, now 730 of libcrypto's 5,876.
- [x] **2.6 Base64 and PEM framing**, in three sub-steps, each its own PR. The typed PEM
  functions arrive with their types.
  - [x] **2.6a The codec:** `EVP_Encode*`/`EVP_Decode*`, including the exact line-handling
    quirks, `EVP_EncodeBlock`/`EVP_DecodeBlock`, and the `EVP_ENCODE_CTX` functions.

    *Done:* 12 exports, in `capi/src/evp/encode.rs` over `rustyssl_asn1::base64`, a port of
    `encode.c` as a state machine on OpenSSL's context layout (any bit pattern a valid state):
    both alphabets (SRP's for later), the NUL written after encoded lines, the octets reported
    on a decoding error, groups held until a line has a multiple of 4, an empty update as the
    end and a negative one as not. `EVP_DecodeFinal` counts padding by comparing decoded values
    with `'='`, as OpenSSL does, though the API can't reach that (it only ever holds a count
    that isn't a multiple of 4). Tests: `tests/c/evp_encode.c` (11 checks, every chunk size);
    the probe's `b64enc`/`b64dec` (corpus `base64.txt`, random streams); the `base64` fuzz
    target round-trips arbitrary data with output buffers of exactly the documented room.
  - [x] **2.6b `BIO_f_base64`.**

    *Done:* 1 export, in `capi/src/bio/base64.rs`, a port of `bio_b64.c` over the 2.6a codec:
    lines of 64 (or none with `BIO_FLAGS_BASE64_NO_NL`, in groups of 3 written through
    `EVP_EncodeBlock`) finished by `BIO_flush`; reading that skips lines until one decodes,
    an overlong line first included, and stops on retries as OpenSSL does. The filter's state is
    taken out of its lock while the next BIO is called. OpenSSL's surprises are kept: PEM-style
    text with a non-base64 line before the data fails, and a junk line that happens to decode
    is the start. Tests:
    `tests/c/bio_base64.c` (every write size, both modes, ten decodings in four chunk sizes,
    retries, controls); the probe's `b64bio` (random streams both ways); the `bio_base64` fuzz
    target round-trips arbitrary data through the filter and reads arbitrary text.
  - [x] **2.6c PEM framing:** `PEM_read_bio`/`PEM_write_bio`/`PEM_read_bio_ex`/
    `PEM_bytes_read_bio`, plus `Proc-Type`/`DEK-Info` header handling.

    *Done:* 7 exports (`PEM_read_bio_ex`, `PEM_read_bio`, `PEM_read`, `PEM_write_bio`,
    `PEM_write`, `PEM_proc_type`, `PEM_dek_info`), in `capi/src/pem.rs` over
    `rustyssl_asn1::pem`, a line-driven port of `get_name`, `sanitize_line`, and
    `get_header_and_data`: lines of up to 254 characters with partial lines tracked, a UTF-8
    BOM dropped, C-string semantics (a NUL ends what a line compares and copies), the header up
    to a blank line, the 64-character rule after one, and the three reading flags. With
    `PEM_FLAG_EAY_COMPATIBLE`, trailing characters are compared with `' '` as a C `char`, so
    octets from 0x80 are trimmed where `char` is signed (macOS, x86_64) and kept where it isn't
    (Linux aarch64), as OpenSSL does on each. Reading the rest moves on with what it needs:
    encrypted PEM (`PEM_get_EVP_CIPHER_INFO`, `PEM_do_header`) and `PEM_ASN1_write*` (which
    may encrypt) to 3.4; `PEM_bytes_read_bio`/`_secmem` and `PEM_ASN1_read*`, whose name
    matching consults the `EVP_PKEY` ASN.1 methods, to 4.2; `PEM_Sign*` to 3.3;
    `PEM_def_callback` to 6.2; `PEM_write_bio_ASN1_stream` to 6.3. Tests: `tests/c/pem.c`
    (twenty texts under each flag, long lines, NULs, BOM, headers, files, and the header
    helpers); the probe's `pemread` (corpus `pem.txt`, random PEM-like text); the `pem` fuzz
    target reads arbitrary text and round-trips arbitrary data.

  *Step 2.6 done:* 20 exports over the three sub-steps, now 750 of libcrypto's 5,876.

**Exit:** d2i → i2d round trips and print output are identical to the reference on the
corpora (OpenSSL fuzz corpora, CT certificates). The DER, template, PEM, and base64 fuzzers
have run for at least 24 CPU-hours with no findings.

## Phase 3: Provider core, EVP symmetric, RAND → M1

- [x] **3.1 Library contexts, params, and providers**, in five sub-steps, each its own PR:
  - [x] **3.1a `OSSL_PARAM`:** all types, the `*_ptr` semantics, the modified flags,
    `OSSL_PARAM_dup`/`merge`/`free`, and `OSSL_PARAM_BLD`.

    *Done:* 74 exports. The conversions are a port of `params.c` in
    `rustyssl_crypto::params`: the 4- and 8-octet fast paths, `copy_integer` for other sizes
    (sign-extended or zero-padded, and narrowed only when the dropped octets are padding and
    the sign is kept), the real checks against 53 mantissa bits, and each function's own
    `return_size` and error on every path, quirks included (`set_int32` of a negative number
    into an unsigned parameter is a type error; `set_uint32` leaves `return_size` 4 when a
    signed 4-octet parameter overflows). Setters return the octets to store, and
    `capi/src/params.rs` writes them, so no reference to a caller's buffer is made. Strings,
    pointers, `locate`, the constructors, and the modified flags are in the same file.
    `params/dup.rs` lays copies out as OpenSSL does (the array, then each parameter's data in
    8-octet units, secure-heap data copied to a secure block that the
    `OSSL_PARAM_ALLOCATED_END` terminator records), and merges with a stable sort by key without
    case. `params/build.rs` is the builder, an opaque handle that keeps the caller's keys and
    strings until `OSSL_PARAM_BLD_to_param`, with the same layout. Tests:
    `tests/c/params.c` (35 checks, 9,364 lines: every setter into four types, eight sizes, and
    NULL data; every getter over those; strings, pointers, dup, merge, the builder, and the
    secure heap, layouts included); the probe's `paramset`/`paramget`/`paramstr`/`parammerge`
    (corpus `params.txt`, random sessions); the `params` fuzz target checks that every value
    read stores back to the same octets and every value stored reads back, with buffers of
    exactly `data_size`. Moved to 4.1: `OSSL_PARAM_get_BN`, `OSSL_PARAM_set_BN`,
    `OSSL_PARAM_BLD_push_BN`, `OSSL_PARAM_BLD_push_BN_pad`, `OSSL_PARAM_allocate_from_text`
    (its numbers are BIGNUMs), and `OSSL_PARAM_print_to_bio` (it prints them).
  - [x] **3.1b `OSSL_LIB_CTX`** (default and child contexts); move `OSSL_set_max_threads`'s
    limit, kept for the default context since 1.3, into each context.

    *Done:* 6 new exports (`OSSL_LIB_CTX_new`, `_free`, `_get0_global_default`,
    `_set0_default`, `_get_conf_diagnostics`, `_set_conf_diagnostics`), and
    `OSSL_set_max_threads`/`OSSL_get_max_threads` moved into `capi/src/libctx.rs`. A context
    is an opaque handle. The global default is made on first use and never freed. Each thread
    may set its own default, which NULL then means everywhere. Freeing NULL or the thread's
    default does nothing, as in OpenSSL. A thread's default is held with its own reference, so
    a context freed by another thread stays valid while it's a default (it would dangle in
    OpenSSL). Each context keeps its thread limit, its configuration diagnostics flag, and its
    own application-data registry: `CRYPTO_get_ex_new_index` and `CRYPTO_free_ex_index` use
    the thread's default, and an object's data uses the context in its `CRYPTO_EX_DATA` (NULL
    through the public API), as OpenSSL's do. Tests: `tests/c/lib_ctx.c` (25 checks: defaults
    across threads, freeing defaults, per-context settings, and indexes per context); the
    probe's `ctx*` commands (corpus `lib_ctx.txt`, random sessions). There is no fuzz target:
    nothing here parses input. Moved: `OSSL_LIB_CTX_new_from_dispatch` and
    `OSSL_LIB_CTX_new_child` to 3.1d (they take a provider's core dispatch table),
    `OSSL_LIB_CTX_get_data` to 3.1e (it returns the stores that step makes), and
    `OSSL_LIB_CTX_load_config` to 3.12.
  - [x] **3.1c The property-query parser and matcher.**

    *Done:* `rustyssl_crypto::property` is a port of `crypto/property/`:
    - **Numbering:** each context numbers names and values in the order it first sees them,
      after the predefined names (`provider` … `structure`) and the values `yes` and `no`.
    - **Parsers:** definitions (unknown plain names refused) and queries (unknown plain names
      kept as number 0, unparsable values kept as missing, values added only on request),
      with OpenSSL's errors and their data text (`HERE-->…`, ``Duplicated name `<NULL>'``).
      The 99-character name and 999-character value limits are kept.
    - **Matching and merging:** match counts (a missing property compares as `no`), merging,
      and the `fips` check.
    - **Canonical text:** names from the highest number down, quoted where needed.

    The four exports, in `capi/src/property.rs`:
    - `EVP_set_default_properties` and `EVP_get1_default_properties`;
    - `EVP_default_properties_enable_fips` (merged into the default) and
      `EVP_default_properties_is_fips_enabled`.

    Each context keeps its strings and default query, and the configuration loads first, as
    in OpenSSL. A query that parses but has no canonical text (`fips=`) is refused with
    `ERR_R_INTERNAL_ERROR`.

    The `PROP_R_*` codes come from an internal header, so codegen now emits named constants
    for internal reasons (from `openssl.txt`) instead of bare numbers.

    Tests:
    - `tests/c/properties.c`: 13 checks, covering 31 valid and 35 invalid queries, the length
      limits, numbering per context, the FIPS switch, and defaults per context.
    - The probe's `propset`/`propfips`/`propnew` commands: corpus `properties.txt`, plus random
      queries built from names, operators, values in every base and quoting, and stray
      characters.
    - The `property` fuzz target: the core never panics, and the C API accepts exactly the
      queries that have canonical text and reads that text back.

    Hooks for later steps: the cache flushes and provider default-properties updates come with
    3.1d and 3.1e, and mirroring defaults into child contexts with 3.1d.
  - [x] **3.1d `OSSL_PROVIDER`:** load, try_load, unload, available, do_all, get_params,
    self_test.

    *Done:* 18 exports, in `capi/src/provider.rs`, a port of `crypto/provider_core.c`:
    - **Store and lifecycle:** each library context has its own store. A provider has
      references and activations. It is initialized once (its init function gets the core's
      dispatch table and returns its own) and torn down with its last reference. Unloading
      deactivates it and leaves it in the store, so a later load reactivates the same
      provider.
    - **Fallback and order:** any `OSSL_PROVIDER_load`, even one that fails, stops the
      fallback to `default`; otherwise `OSSL_PROVIDER_available` and `OSSL_PROVIDER_do_all`
      activate it. `try_load` can keep the fallback, which can then add a second `default`,
      as OpenSSL's does. The store keeps OpenSSL's order: sorted at each lookup, with later
      additions last.
    - **Error libraries:** every provider made takes a number from
      `ERR_get_next_error_library`.
    - **Built-ins** (`provider/builtin.rs`): `default`, `base`, and `null`, each an init
      function and dispatch tables in the form an external provider has. They report the
      same names, versions, status, gettable parameters, and context (null's is its handle),
      and offer no algorithms until the algorithm steps.
    - **Modules** (`provider/module.rs`): any other name is looked up as OpenSSL's DSO loader
      does: the search path, `$OPENSSL_MODULES`, or `MODULESDIR`; the platform's extension;
      `dlopen`, with OpenSSL's errors and the loader's message. A module that opens isn't run
      yet (9.1).
    - **Core table:** so far it offers `core_get_libctx` (`provider/upcalls.rs`).
    - **Other exports:** `get0_name`, `get0_provider_ctx`, `get0_dispatch`,
      `gettable_params`, the search path, and the configuration parameters (given to
      `load_ex`, added, read, and read as Booleans).

    Tests:
    - `tests/c/provider.c`: 23 checks, covering the fallback, the built-ins and what they
      report, repeated loads, the store's order, callbacks that stop or unload, failed module
      lookups (codes only: on macOS the loader's message lists `DYLD_LIBRARY_PATH`), the
      error libraries taken, and configuration parameters.
    - The probe's `pload`/`ptry`/`punload`/`pavail`/`pall`/`pparams` commands: corpus
      `provider.txt`, and random sequences in eight slots.

    There is no fuzz target: nothing here parses input.

    Moved:
    - `OSSL_PROVIDER_query_operation` and `_unquery_operation` to 3.1e;
    - the default provider's `get_capabilities` (TLS groups and signature algorithms) to 7.3;
    - `OSSL_PROVIDER_add_builtin`, `OSSL_LIB_CTX_new_from_dispatch`, `OSSL_LIB_CTX_new_child`,
      the rest of the core table, and the `legacy` provider (a module in OpenSSL's default
      build) to 9.1.
  - [x] **3.1e The method store and cache:** `EVP_*_fetch`, `is_a`, names,
    `do_all_provided`; `OSSL_PROVIDER_query_operation` and `_unquery_operation` (from 3.1d).

    *Done:* 18 exports. The machinery, ported from `core_namemap.c`, `property/property.c`,
    `core_fetch.c`, `core_algorithm.c`, and `evp/evp_fetch.c`:
    - **Name map** (`rustyssl_crypto::namemap`): each context numbers algorithm names. Keys are
      OpenSSL's hash-table keys: the first 63 octets with bit 5 cleared, so letters match
      without case and a few other pairs collide as in OpenSSL. Lists like
      `"SHA2-256:SHA-256"` get one number, with OpenSSL's errors for empty and conflicting
      names.
    - **Method store** (`rustyssl_crypto::method_store`): implementations by method number
      (name number and operation), with their provider and property definition. A choice is
      the first non-optional match, or the most matches when the query has optional
      properties, and is cached per query text.
    - **Fetch** (`capi/src/evp/fetch.rs`):
      - Each active provider is asked for the operation's algorithms on every construction
        pass, but they're stored only once while it stays active. Algorithms a provider says
        not to store go to a store for that fetch, whose choices aren't cached.
      - Property definitions are parsed once per context, and queries are parsed in the
        context with its default properties added.
      - The cache is flushed when a provider is activated or the default properties change,
        and a fully deactivated provider's methods are removed.
      - Failures raise `ERR_R_UNSUPPORTED`, or `ERR_R_FETCH_FAILED` if a method couldn't be
        made, with OpenSSL's text.
      - Providers' functions and constructors run without a lock held.
    - **`EVP_MD`** (`capi/src/evp/digest.rs`): made from an algorithm (the function-count
      rule, and its sizes and flags read from its parameters, with OpenSSL's errors). Exports:
      `EVP_MD_fetch`, `_up_ref`, `_free`, `_get0_name`, `_get0_description`, `_is_a`,
      `_names_do_all`, `_get0_provider`, `_do_all_provided`, `_get_params`,
      `_gettable_params`, `_get_type`, `_get_size`, `_get_block_size`, and `_get_flags`.
    - **Providers:** `OSSL_PROVIDER_add_builtin` (moved back from 9.1, as the tests need it;
      such a provider sees the core table 3.1d offers) and `query_operation`/
      `unquery_operation`.

    Tests:
    - `tests/c/fetch.c`: 17 checks, with test providers of its own. It covers names and
      aliases, property queries with and without defaults, the same method on repeated
      fetches, optional matches and ties, algorithms that can't be made and their errors,
      providers asked once, a provider that mustn't be stored, `do_all_provided`, and
      unloading and reloading.
    - The probe's `fnew`/`ffetch`/`fdefault`/`fall`/`fload`/`funload` commands: two providers
      of the probe's own, corpus `fetch.txt`, and random queries.

    Error data is compared with its numbers masked: OpenSSL numbers a context's names after the
    legacy algorithms' (`OBJ_NAME` digests and ciphers, `EVP_PKEY` methods), which rustyssl adds
    with those tables (3.3 onwards).

    Moved:
    - the legacy-name pre-filling, the NIDs `EVP_MD_get_type` reports, and implicit fetch for
      the `EVP_sha256()`-style getters to 3.3;
    - the other `EVP_*_fetch` methods to their own steps;
    - `OSSL_LIB_CTX_get_data` (it returns internal stores) to 9.4.

  The built-in providers (`default`, `base`, `legacy`, `null`) are Rust implementations
  registered through the **same dispatch model** that external providers use in Phase 9.
- [x] **3.2 Backend layer** (`rustyssl-crypto`): Digest, Cipher (block, stream, AEAD), Mac,
  Kdf, and Rng traits; adapters for the vetted RustCrypto crates; entries in
  `docs/DEPENDENCIES.md`; CPU-feature dispatch (AES-NI, ARMv8 crypto, SHA extensions) through
  crate features. In five sub-steps, each its own PR:
  - [x] **3.2a Digests:** the backend trait and every digest 3.3 offers.

    *Done:* `rustyssl_crypto::md`:
    - **Interface:** an `Algorithm` per digest (with OpenSSL's sizes, block sizes, and XOF
      flag), a `Context` trait (update, finalize, repeated squeezing for XOFs, reset, copy),
      and a `Backend` trait whose default, `RustCrypto`, can be replaced.
    - **Crates** (all pure Rust): SHA-1, SHA-2, MD5, MD4, SM3, BLAKE2s/b, RIPEMD-160, and
      Whirlpool.
    - **Our own code:** the SHA-3 family (SHA3-*, SHAKE, and OpenSSL's KECCAK-KMAC digests,
      the raw sponge with KMAC's padding) is a sponge of ours over the `keccak` crate's
      permutation, because no crate offers KMAC's padding. MD5-SHA1 and NULL are ours too.
    - **CPU features:** the SHA-NI and ARMv8 SHA-1, SHA-2, and SHA-3 instructions are detected
      at run time by the crates (`cpufeatures`), with no configuration or assembly on our
      targets.

    Tests: `tests/md.rs` checks every algorithm against 92 vectors generated by the reference
    OpenSSL's EVP API, over messages around each rate's boundary, fed in five chunk sizes, with
    XOFs also squeezed in pieces; and the context's life cycle. MDC-2 comes with DES (3.4).

    Dependencies: 10 new crates, recorded in `docs/DEPENDENCIES.md` with their review and
    constant-time notes, and exempted in `supply-chain/` pending audit. `cmov`'s inline
    assembly (for constant-time selection) was accepted under rule 8. Whirlpool's table
    lookups aren't constant time; it's legacy-only.
  - [x] **3.2b Cipher primitives:** `rustyssl_crypto::sym`, the raw primitives the cipher
    modes and AEADs of 3.4 are built from.
    - **Block ciphers** (`BlockCipher`, encrypting or decrypting whole blocks in place): AES,
      ARIA, Camellia, SM4, DES, triple DES, Blowfish, CAST5, IDEA, and RC2, from RustCrypto.
      Key lengths are OpenSSL's: Blowfish takes 1 to 72 octets (through the crate's bcrypt key
      schedule), CAST5 pads keys under 5 octets with zeros, and RC2 takes an effective key
      length of 1 to 1024 bits (by default the key's length).
    - **Key streams** (`KeyStream`): ChaCha20 in the crate's 64-bit-counter layout, which
      OpenSSL's 16-octet IV (a little-endian counter, then the nonce) maps onto, so the counter
      carries past 32 bits as it does there; and RC4, our own (a few lines, and the crate's
      state can't be copied, which `EVP_CIPHER_CTX_copy` needs). Copies are fallible rather
      than silently restarting a stream.
    - **Universal hashes** (`UniversalHash`): GHASH, POLYVAL, and Poly1305.
    - **Decision:** modes (ECB, CBC, CFB, OFB, CTR, XTS, wrap), CTS, and the AEADs (GCM, CCM,
      OCB, SIV, GCM-SIV, ChaCha20-Poly1305) are our own code in 3.4, over these primitives.
      The RustCrypto mode and AEAD crates don't match OpenSSL's streaming and partial-block
      behavior. SEED has no vetted crate and will be ours in 3.4.
    - **CPU features:** AES-NI/VAES, the ARMv8 AES instructions, CLMUL/PMULL, and the
      ChaCha20 SIMD backends are detected at run time by the crates.

    Tests: `tests/sym.rs` checks 45 vectors generated by the reference OpenSSL's EVP API:
    - every block cipher in ECB, at the key lengths at OpenSSL's edges, with decryption back;
    - RC4 and ChaCha20 over 300 octets, with a copy taken mid-stream;
    - Poly1305 at lengths around the block;
    - AES-128-GCM assembled from AES and GHASH.

    It also checks POLYVAL against RFC 8452 and the refusal of bad key, IV, and buffer lengths.

    Dependencies: 19 new crates, recorded in `docs/DEPENDENCIES.md` and exempted in
    `supply-chain/` pending audit. AES, ChaCha20, Poly1305, GHASH, and POLYVAL are constant
    time. ARIA, Camellia, SM4, DES, and the legacy ciphers use table lookups (or, for IDEA,
    branches) and are not. OpenSSL's portable C code has the same property for them.
    `zeroize`'s empty `asm!` barrier was accepted under rule 8.
  - [x] **3.2c MACs:** `rustyssl_crypto::mac`, the computations behind every MAC 3.5 offers,
    behind one `Mac` trait (update, finalize into exactly the MAC's size, reset with the same
    key, copy).
    - **Our own code,** composed from `md` and `sym`:
      - HMAC over any fixed-size digest; XOFs are refused, as the reference does, and NULL
        gives an empty MAC.
      - CMAC over any 64- or 128-bit block cipher.
      - GMAC over any 128-bit one, with IVs of any length.
      - KMAC128/256 (and KMACXOF) over our sponge.
      - Poly1305 over the `poly1305` universal hash.
      - SipHash with OpenSSL's choice of rounds and its 64- or 128-bit output; no vetted crate
        offers both.
    - **Crate cores:** BLAKE2BMAC and BLAKE2SMAC run the `blake2` crate's variable-output
      cores with the key, salt, and personalization in the parameter block. Lengths are
      checked first, because the core asserts on them.
    - **Limits** are the reference's: KMAC keys of 4 to 512 octets, customization of at most
      512, output under 2^21; SipHash keys of 16 and sizes 8 or 16; the BLAKE2 MACs' key,
      size, salt, and customization bounds.
    - **Left to the EVP layer (3.5):** CMAC's check that the cipher is in CBC mode, and
      GMAC's IV when none is set (the reference's GCM then makes up a random one).
    - **Secrets:** every hash crate's `zeroize` feature is on, and our Keccak sponge wipes its
      state, because HMAC and KMAC keep keyed digest states.

    Tests: `tests/mac.rs` checks 327 vectors and 19 refusals generated by the reference
    OpenSSL's EVP_MAC API:
    - HMAC with all 19 fixed-size digests, keys around the block size;
    - CMAC over AES, ARIA, Camellia, SM4, 2- and 3-key triple DES, and Blowfish;
    - GMAC over AES, ARIA, and SM4 with IVs of 1, 12, 16, and 60 octets;
    - KMAC128/256 over key, customization, size, and XOF combinations;
    - SipHash (both sizes, 1-3 and 4-8 rounds) and the BLAKE2 MACs at their bounds.

    Each vector is also fed in pieces, after a reset, and finished from a copy made midway.
    It also checks Poly1305 against RFC 8439's example.

    Dependencies: none new.
  - [x] **3.2d KDFs:** `rustyssl_crypto::kdf`, the computations behind every KDF 3.6 offers,
    plus `EVP_BytesToKey`. Each is one function deriving into an output buffer.
    - **Covered:**
      - HKDF (extract, expand, both) and TLS 1.3's (HKDF-Expand-Label, and the
        derive-then-extract step);
      - PBKDF1, PBKDF2, PKCS12KDF, PVKKDF, and `EVP_BytesToKey`;
      - SSKDF (hash, HMAC, or KMAC), X963KDF, and X942KDF-ASN1 (its DER `OtherInfo` built here,
        with the counter patched in place);
      - KBKDF (counter and feedback modes over HMAC or CMAC, with the reference's 32-bit L
        and counter-range check);
      - TLS1-PRF (P_hash, and the MD5/SHA-1 split), SSHKDF, and KRB5KDF (the reference's
        n-fold, and triple DES's random-to-key);
      - scrypt (our Salsa20/8, with the reference's memory checks and its 32-bit Integerify);
      - Argon2d/i/id (RFC 9106, versions 0x10 and 0x13; its H' over BLAKE2b from `mac`).
    - **Decision:** the backend checks what the computations need, with the reference's
      limits. Parameter names, defaults, required parameters, and their errors are the EVP
      layer's (3.6). That includes KBKDF over KMAC (plain KMAC), SSKDF's KMAC
      customization and default salts, X942's key-length switch, and PBKDF2's lower-bound
      checks. Argon2 computes its lanes in turn; the `threads` parameter only changes speed.
    - **Deviation:** SSHKDF over the NULL digest loops forever in the reference. All the KDFs
      here refuse digests of no size and XOFs, as the reference does for every other KDF.

    Tests: `tests/kdf.rs` checks 171 derivations and 44 refusals generated by the reference
    OpenSSL's EVP_KDF API. They cover every KDF at its limits (output lengths, label lengths,
    scrypt's memory bound, Argon2's memory and salt) and NULL and SHAKE256 with each
    hash-based KDF. Also RFC vectors: 5869, 7914, 9106, and 6070. Fuzz target `kdf` drives
    every KDF with arbitrary parameters and checks that each is deterministic and that a
    block-stream output's prefix is the shorter output.

    Dependencies: none new.
  - [x] **3.2e Random generators:** `rustyssl_crypto::rand`, the DRBG mechanisms as the
    reference implements them, behind a `Drbg` trait (instantiate, reseed, generate,
    uninstantiate, and the limits each publishes), plus the OS entropy source.
    - **Mechanisms:**
      - CTR-DRBG over AES-128/192/256, with or without the derivation function. Its 128-bit
        counter, the derivation function's output reused after generating with additional
        input, and inputs XORed and truncated without it.
      - Hash-DRBG (seed length 55 or 111) and HMAC-DRBG over any non-XOF digest.
      - HMAC-DRBG-KDF is HMAC-DRBG with no personalization and no request limit.
    - **Seed source:** `os_entropy` over the `getrandom` crate (`getrandom(2)` on Linux,
      `getentropy` on macOS).
    - **Decision:** everything around the mechanisms is 3.7's: entropy and nonces from the
      parent, the default personalization string (`"OpenSSL NIST SP 800-90A DRBG"` with its
      NUL, 29 octets), reseed intervals and forks, prediction resistance (a reseed with the
      request's additional input, then generating without it), and a caller's entropy (a
      reseed with it, then another from the parent). The EVP layer skips empty requests and
      splits requests over the limit into chunks, each with the same additional input. The
      mechanisms report their limits (`Limits`) rather than enforce them, as HMAC-DRBG-KDF
      needs.

    Tests: `tests/rand.rs` replays 32 schedules from the reference's EVP_RAND API (a TEST-RAND
    parent) on every mechanism and configuration. Each schedule instantiates with the default
    or a given personalization, then generates with and without additional input, reseeds,
    uses prediction resistance, and reseeds with the caller's entropy. It also checks
    HMAC-DRBG-KDF (70,000 octets, past the request limit), the life cycle, the limits, and OS
    entropy. Fuzz target `drbg`: arbitrary operation sequences on two instances.

    Dependencies: `getrandom` (its build script read and allowed) and `r-efi` (UEFI only),
    exempted in `supply-chain/` pending audit.
  - [x] **3.2c MACs:** `rustyssl_crypto::mac`, the computations behind every MAC 3.5 offers,
    behind one `Mac` trait (update, finalize into exactly the MAC's size, reset with the same
    key, copy).
    - **Our own code,** composed from `md` and `sym`:
      - HMAC over any fixed-size digest; XOFs are refused, as the reference does, and NULL
        gives an empty MAC.
      - CMAC over any 64- or 128-bit block cipher.
      - GMAC over any 128-bit one, with IVs of any length.
      - KMAC128/256 (and KMACXOF) over our sponge.
      - Poly1305 over the `poly1305` universal hash.
      - SipHash with OpenSSL's choice of rounds and its 64- or 128-bit output; no vetted crate
        offers both.
    - **Crate cores:** BLAKE2BMAC and BLAKE2SMAC run the `blake2` crate's variable-output
      cores with the key, salt, and personalization in the parameter block. Lengths are
      checked first, because the core asserts on them.
    - **Limits** are the reference's: KMAC keys of 4 to 512 octets, customization of at most
      512, output under 2^21; SipHash keys of 16 and sizes 8 or 16; the BLAKE2 MACs' key,
      size, salt, and customization bounds.
    - **Left to the EVP layer (3.5):** CMAC's check that the cipher is in CBC mode, and
      GMAC's IV when none is set (the reference's GCM then makes up a random one).
    - **Secrets:** every hash crate's `zeroize` feature is on, and our Keccak sponge wipes its
      state, because HMAC and KMAC keep keyed digest states.

    Tests: `tests/mac.rs` checks 327 vectors and 19 refusals generated by the reference
    OpenSSL's EVP_MAC API:
    - HMAC with all 19 fixed-size digests, keys around the block size;
    - CMAC over AES, ARIA, Camellia, SM4, 2- and 3-key triple DES, and Blowfish;
    - GMAC over AES, ARIA, and SM4 with IVs of 1, 12, 16, and 60 octets;
    - KMAC128/256 over key, customization, size, and XOF combinations;
    - SipHash (both sizes, 1-3 and 4-8 rounds) and the BLAKE2 MACs at their bounds.

    Each vector is also fed in pieces, after a reset, and finished from a copy made midway.
    It also checks Poly1305 against RFC 8439's example.

    Dependencies: none new.
  - [x] **3.2d KDFs:** `rustyssl_crypto::kdf`, the computations behind every KDF 3.6 offers,
    plus `EVP_BytesToKey`. Each is one function deriving into an output buffer.
    - **Covered:**
      - HKDF (extract, expand, both) and TLS 1.3's (HKDF-Expand-Label, and the
        derive-then-extract step);
      - PBKDF1, PBKDF2, PKCS12KDF, PVKKDF, and `EVP_BytesToKey`;
      - SSKDF (hash, HMAC, or KMAC), X963KDF, and X942KDF-ASN1 (its DER `OtherInfo` built here,
        with the counter patched in place);
      - KBKDF (counter and feedback modes over HMAC or CMAC, with the reference's 32-bit L
        and counter-range check);
      - TLS1-PRF (P_hash, and the MD5/SHA-1 split), SSHKDF, and KRB5KDF (the reference's
        n-fold, and triple DES's random-to-key);
      - scrypt (our Salsa20/8, with the reference's memory checks and its 32-bit Integerify);
      - Argon2d/i/id (RFC 9106, versions 0x10 and 0x13; its H' over BLAKE2b from `mac`).
    - **Decision:** the backend checks what the computations need, with the reference's
      limits. Parameter names, defaults, required parameters, and their errors are the EVP
      layer's (3.6). That includes KBKDF over KMAC (plain KMAC), SSKDF's KMAC
      customization and default salts, X942's key-length switch, and PBKDF2's lower-bound
      checks. Argon2 computes its lanes in turn; the `threads` parameter only changes speed.
    - **Deviation:** SSHKDF over the NULL digest loops forever in the reference. All the KDFs
      here refuse digests of no size and XOFs, as the reference does for every other KDF.

    Tests: `tests/kdf.rs` checks 171 derivations and 44 refusals generated by the reference
    OpenSSL's EVP_KDF API. They cover every KDF at its limits (output lengths, label lengths,
    scrypt's memory bound, Argon2's memory and salt) and NULL and SHAKE256 with each
    hash-based KDF. Also RFC vectors: 5869, 7914, 9106, and 6070. Fuzz target `kdf` drives
    every KDF with arbitrary parameters and checks that each is deterministic and that a
    block-stream output's prefix is the shorter output.

    Dependencies: none new.
  - [x] **3.2e Random generators:** `rustyssl_crypto::rand`, the DRBG mechanisms as the
    reference implements them, behind a `Drbg` trait (instantiate, reseed, generate,
    uninstantiate, and the limits each publishes), plus the OS entropy source.
    - **Mechanisms:**
      - CTR-DRBG over AES-128/192/256, with or without the derivation function. Its 128-bit
        counter, the derivation function's output reused after generating with additional
        input, and inputs XORed and truncated without it.
      - Hash-DRBG (seed length 55 or 111) and HMAC-DRBG over any non-XOF digest.
      - HMAC-DRBG-KDF is HMAC-DRBG with no personalization and no request limit.
    - **Seed source:** `os_entropy` over the `getrandom` crate (`getrandom(2)` on Linux,
      `getentropy` on macOS).
    - **Decision:** everything around the mechanisms is 3.7's: entropy and nonces from the
      parent, the default personalization string (`"OpenSSL NIST SP 800-90A DRBG"` with its
      NUL, 29 octets), reseed intervals and forks, prediction resistance (a reseed with the
      request's additional input, then generating without it), and a caller's entropy (a
      reseed with it, then another from the parent). The EVP layer skips empty requests and
      splits requests over the limit into chunks, each with the same additional input. The
      mechanisms report their limits (`Limits`) rather than enforce them, as HMAC-DRBG-KDF
      needs.

    Tests: `tests/rand.rs` replays 32 schedules from the reference's EVP_RAND API (a TEST-RAND
    parent) on every mechanism and configuration. Each schedule instantiates with the default
    or a given personalization, then generates with and without additional input, reseeds,
    uses prediction resistance, and reseeds with the caller's entropy. It also checks
    HMAC-DRBG-KDF (70,000 octets, past the request limit), the life cycle, the limits, and OS
    entropy. Fuzz target `drbg`: arbitrary operation sequences on two instances.

    Dependencies: `getrandom` (its build script read and allowed) and `r-efi` (UEFI only),
    exempted in `supply-chain/` pending audit.
- [ ] **3.3 EVP_MD**, in two sub-steps, each its own PR:
  - [x] **3.3a Digesting:** the default provider's digests and the `EVP_MD_CTX` API.

    *Done:* 34 exports. They cover the context's life cycle (new, free, reset, copy, copy_ex,
    dup), `EVP_DigestInit`/`_ex`/`_ex2`, `EVP_DigestUpdate`, `EVP_DigestFinal`/`_ex`,
    `EVP_DigestFinalXOF`, `EVP_DigestSqueeze`, `EVP_Digest`, `EVP_Q_digest`, the context's and
    digest's parameters and parameter lists, `EVP_MD_CTX_get_size_ex`, the accessors, flags,
    `EVP_MD_CTX_ctrl`, the legacy update function, and `EVP_MD_xof`.
    - **The provider:** the default provider offers its 27 digests (`deflt_digests`, with the
      reference's names) through dispatch tables in `rustyssl-capi`
      (`provider/digests.rs`). Each family's table has exactly the reference's functions,
      since the EVP layer's behavior follows from which exist. The semantics are in
      `rustyssl_crypto::provided::digest`:
      - plain digests over `md`, and SHA2-256/192 (new in 3.5; SHA-256 truncated);
      - SHA-1's and MD5-SHA1's SSLv3 master secret (`ssl3-ms`);
      - a port of the reference's `KECCAK1600_CTX` for SHA-3, KECCAK (new), SHAKE, and
        KECCAK-KMAC. It reproduces SHAKE's missing default length, a length that persists
        across re-initialization, updates after a squeeze (not absorbed, but they shift the
        buffered output), finals after a squeeze, and KECCAK-KMAC's squeeze always failing
        silently (it gets SHA-3's methods on the reference's generic and ARMv8 builds);
      - BLAKE2's `size`, applied at the next init while the gettable size follows at once;
        a context whose init refused its size still takes data and finishes empty.
    - **The EVP layer** (`evp/md_ctx.rs`) follows `crypto/evp/digest.c`'s paths:
      - the algorithm context is reused when re-initializing with the same digest;
      - `EVP_MD_CTX_FLAG_NO_INIT` takes the legacy path;
      - the finalized flag: updates and finals after a final fail, squeezes don't set it;
      - `EVP_DigestFinalXOF` passes `xoflen` and then finalizes any digest;
      - `copy_ex` reuses the destination's algorithm context (`copyctx`) when the digests
        match.
      The two internal flags (`KEEP_PKEY_CTX`, `FINALISED`) come from the reference's
      internal header, which the vendored public headers don't include.
    - **Deviations:** NULL contexts and NULL output buffers are refused, and `FinalXOF` on
      a fixed-size Keccak digest writes only the length asked for (docs/DEVIATIONS.md). An
      `ENGINE` argument is refused: the engine API can't make one.

    Tests:
    - `tests/c/evp_digest.c`, 142 checks: every digest whole and in pieces at lengths
      around the block sizes; SHAKE's lengths, squeezing, and misuse; FinalXOF on fixed-size
      digests; BLAKE2's size; SSLv3's master secret; copies, resets, flags, NO_INIT with a
      legacy update function, ctrl, and the accessors.
    - The probe's `d*` commands on two contexts: corpus `digest.txt` and random sessions.
      The random sessions found the KECCAK-KMAC squeeze and the uninitialized BLAKE2 context
      above. 10,000 more sessions were clean.
    - Unit tests: the Keccak port against the backend, and the deviations.

    Moved:
    - MD4, Whirlpool, and MDC2 (with DES) to 9.1, with the legacy provider they're in, which
      OpenSSL ships as a module;
    - `EVP_MD_CTX_get_pkey_ctx`/`set_pkey_ctx`, `EVP_DigestSign*`/`Verify*`, and
      `PEM_SignInit`/`Update`/`Final` (from 2.6) to Phase 4, which has keys;
    - the `EVP_MD_meth_*` digests to 3.11.
  - [ ] **3.3b Legacy names:** the digest name table behind `EVP_get_digestbyname` (and
    `EVP_get_digestbynid`/`_byobj`), which `OPENSSL_INIT_ADD_ALL_DIGESTS` fills (it aborts
    until then; see 1.2); `EVP_add_digest`, `EVP_MD_do_all`/`_sorted`; the legacy names each
    context's name map starts with; the NIDs of fetched digests (`EVP_MD_get_type`,
    `EVP_MD_get_pkey_type`); and the `EVP_sha256()`-style getters with implicit fetch (from
    3.1e).
- [ ] **3.4 EVP_CIPHER:**
  - AES in ECB, CBC, CFB1/8/128, OFB, CTR, GCM, CCM, XTS, OCB, SIV, GCM-SIV, wrap, wrap-pad,
    and the CBC-HMAC composites
  - ARIA, Camellia, ChaCha20, ChaCha20-Poly1305, SM4, 3DES (all modes and wrap), NULL
  - legacy provider: DES, BF, CAST5, IDEA, RC2, RC4 (including RC4-HMAC-MD5), SEED
  - the full `EVP_CIPHER_CTX` API, including padding, AEAD ctrls, and the TLS AAD and IV ctrls
  - the cipher name table behind `EVP_get_cipherbyname`, which `OPENSSL_INIT_ADD_ALL_CIPHERS`
    fills (it aborts until then; see 1.2)
  - encrypted PEM (from 2.6): `PEM_get_EVP_CIPHER_INFO`, `PEM_do_header`, and
    `PEM_ASN1_write`/`_bio`/`_bio_ctx`
- [ ] **3.5 EVP_MAC:** HMAC, CMAC, GMAC, KMAC128/256, Poly1305, SipHash, and BLAKE2 MACs;
  the legacy `HMAC_*` and `CMAC_*` APIs; `EVP_Q_mac`.
- [ ] **3.6 EVP_KDF:** HKDF, TLS13-KDF, PBKDF1, PBKDF2, scrypt, SSKDF, X963KDF, X942KDF,
  KBKDF, TLS1-PRF, SSHKDF, PKCS12KDF, KRB5KDF, Argon2i/d/id, HMAC-DRBG-KDF, and the legacy
  provider's PVKKDF; `PKCS5_PBKDF2_HMAC*`, `EVP_PBE_scrypt`, `EVP_BytesToKey`. Over the
  backend of 3.2d; a C test pins the SSHKDF-over-NULL deviation (docs/DEVIATIONS.md).
- [ ] **3.7 RAND and DRBG:** (`OPENSSL_thread_stop_ex(ctx)` must then free the thread's
  generators for `ctx`, as OpenSSL's `rand_delete_thread_state` does; see 1.3.)
  - `EVP_RAND`: CTR-, HASH-, and HMAC-DRBG, SEED-SRC, TEST-RAND
  - the primary/public/private DRBG hierarchy, per thread, with reseed policy and fork safety
  - `RAND_bytes(_ex)`, `RAND_priv_bytes(_ex)`, `RAND_seed`, `RAND_add`, `RAND_status`,
    `RAND_poll`, `RAND_load_file`, `RAND_write_file`, `RAND_set_DRBG_type`
  - `BIO_f_nbio_test` (moved from 1.6c: it picks its short reads and writes with
    `RAND_priv_bytes`)
  - legacy `RAND_METHOD`
  - seeding from the OS (getrandom/getentropy)
- [ ] **3.8 Deprecated low-level symmetric APIs** (still exported in 3.x):
  - `SHA*_`, `MD4_`, `MD5_`, `RIPEMD160_`
  - `AES_*` (including `AES_wrap_key` and IGE)
  - the `DES_*` family, `BF_*`, `CAST_*`, `RC2_*`, `RC4*`, `IDEA_*`, `SEED_*`, `Camellia_*`
  - the `CRYPTO_{gcm,ccm,xts,ocb}128_*` and `CRYPTO_{cbc,ctr,cfb}128_*` mode helpers

  ⚠ Their contexts (`SHA256_CTX`, `AES_KEY`, `DES_key_schedule`, …) are **public-layout**
  and often live on the application's stack, so all state must live *inside* the C struct.
  No hidden heap pointers.
- [ ] **3.9 EVP filter BIOs:** `BIO_f_md`, `BIO_f_cipher`.
- [ ] **3.10 `EVP_SKEY` / `EVP_SKEYMGMT`** (3.5 opaque symmetric keys).
- [ ] **3.11 Custom method APIs:** `EVP_MD_meth_*`, `EVP_CIPHER_meth_*`. These are
  application-defined algorithms implemented in C that we call back into.
- [ ] **3.12 Config subset:** enough of `openssl.cnf` (see 6.1) to activate providers and set
  `default_properties`. Distro crypto policies depend on it. Includes
  `OSSL_LIB_CTX_load_config` (from 3.1b).

**Exit:** M1. All Wycheproof and CAVP/ACVP suites for these algorithms pass. Upstream
`evp_test` passes the symmetric data files. Differential fuzzing of streaming EVP (random
chunking) is clean.

## Phase 4: BIGNUM and public-key cryptography

- [ ] **4.1 BIGNUM** (the full `BN_*` API, about 200 functions):
  - arithmetic, shifts, and bit operations
  - conversions: bin, lebin, native, hex, dec, mpi, ASN.1
  - `ASN1_bn_print` (moved from 2.5)
  - the `OSSL_PARAM` big-number functions (moved from 3.1a): `OSSL_PARAM_get_BN`,
    `OSSL_PARAM_set_BN`, `OSSL_PARAM_BLD_push_BN`, `OSSL_PARAM_BLD_push_BN_pad`,
    `OSSL_PARAM_allocate_from_text`, `OSSL_PARAM_print_to_bio`
  - `BN_CTX`, `BN_MONT_CTX`, `BN_RECP_CTX`, `BN_BLINDING`, `BN_GENCB`
  - primes: `BN_check_prime`, `BN_generate_prime_ex(2)`
  - `BN_mod_sqrt` (with the CVE-2022-0778 loop bound), `BN_mod_inverse`, `BN_gcd`,
    `BN_kronecker`, `BN_GF2m_*`
  - `BN_FLG_CONSTTIME` semantics, print functions

  General arithmetic is our own implementation on u64 limbs. Secret-dependent operations go
  through a constant-time backend (crypto-bigint).
- [ ] **4.2 EVP_PKEY framework:**
  - EVP_PKEY lifecycle and keymgmt (import and export through `OSSL_PARAM`, `fromdata` /
    `todata`, get/set params)
  - `EVP_PKEY_CTX` for keygen, paramgen, sign, verify, verify_recover, encrypt, decrypt,
    derive, and encapsulate/decapsulate
  - message-signing API (3.5)
  - `EVP_DigestSign*` / `EVP_DigestVerify*`, `EVP_PKEY_Q_keygen`
  - the fetchable `EVP_SIGNATURE`, `EVP_ASYM_CIPHER`, `EVP_KEYEXCH`, `EVP_KEM`, and
    `EVP_KEYMGMT` objects
  - `EVP_PKEY_print_*` (byte-exact), `eq`, `bits`, `security_bits`, `size`
  - the legacy `EVP_PKEY_assign` / `get1_*` APIs, and the `EVP_PKEY_meth_*` and
    `EVP_PKEY_asn1_*` custom-method APIs
  - `PEM_bytes_read_bio`/`_secmem` and `PEM_ASN1_read`/`_bio` (from 2.6), whose matching of
    `ANY PRIVATE KEY` and `PARAMETERS` names consults the ASN.1 methods
- [ ] **4.3 RSA:**
  - keygen (multi-prime)
  - PKCS#1 v1.5 signatures
  - PKCS#1 v1.5 encryption with **implicit rejection** (the 3.2+ default)
  - OAEP (label, MGF1 digest)
  - PSS (the special salt-length values)
  - X9.31, `RSA_NO_PADDING`, blinding
  - the legacy `RSA_*` and `RSA_meth_*` APIs

  Private-key operations are constant-time.
- [ ] **4.4 EC:**
  - `EC_GROUP`: every named curve in the default build (NIST, secp*k1, brainpool, SM2,
    binary curves), explicit parameters, `check`, conversion forms
  - the full `EC_POINT` API
  - legacy `EC_KEY` and `EC_KEY_METHOD`
  - ECDSA (random and deterministic, RFC 6979), ECDH (cofactor), SM2 sign and encrypt

  Document the constant-time level for each curve.
- [ ] **4.5 ECX and post-quantum:**
  - X25519, X448, Ed25519, Ed448 (including ph and ctx variants)
  - ML-KEM-512/768/1024, ML-DSA-44/65/87, and every SLH-DSA parameter set
  - the hybrid TLS groups (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)
  - key input/output formats exactly as OpenSSL implements them (seed vs. expanded keys)
- [ ] **4.6 DH and DSA:**
  - DH: the FFDHE (RFC 7919) and MODP groups, X9.42 DHX, paramgen, the check functions
    (CVE-2023-3446/3817 bounds)
  - DSA: keygen and FIPS 186-4 paramgen, signatures (including deterministic DSA)
  - the legacy `DH_*`/`DSA_*` APIs and their methods
- [ ] **4.7 Key encoders and decoders:**
  - the `OSSL_ENCODER` and `OSSL_DECODER` frameworks and their built-in implementations
  - formats: DER and PEM, PKCS#8 (plain, and encrypted with PBES2/scrypt or legacy PBES1),
    SPKI, PKCS#1, SEC1, "traditional" PEM with DEK-Info, MSBLOB/PVK, text
  - `PEM_{read,write}_bio_{PrivateKey,PUBKEY,RSAPrivateKey,…}`,
    `d2i/i2d_{PrivateKey,PublicKey,PUBKEY}`, `d2i_AutoPrivateKey`
  - the password-callback contract
- [ ] **4.8 HPKE** (`OSSL_HPKE_*`): the base, psk, auth, and authpsk modes, every KEM/KDF/AEAD
  combination, and GREASE.

**Exit:** all asymmetric Wycheproof suites pass. The Marvin toolkit finds no measurable RSA
timing signal. dudect is clean on the constant-time paths. Key encode, decode, and print are
identical to the reference. Upstream `bntest`, `ectest`, `rsa_test`, and the `evp_test` pkey
files pass.

## Phase 5: X.509 and certificate verification

- [ ] **5.1 Objects:**
  - `X509`
  - `X509_NAME` / `X509_NAME_ENTRY` (canonical-encoding cache; `X509_NAME_hash_ex` and
    `hash_old` byte-exact, for hashed-directory lookups; `oneline` and `print_ex` with every
    `XN_FLAG_*`)
  - `X509_PUBKEY`, `X509_ALGOR` (public layout)
  - the `X509_get_*` / `X509_set_*` family
  - sign/verify (including the `_ctx` variants), digests, `check_private_key`, the `cmp`
    family
  - `X509_REQ`, `X509_CRL` / `X509_REVOKED`, `X509_ATTRIBUTE`, `X509_EXTENSION`,
    `X509_ACERT` (3.4)
  - `X509_INFO` and `PEM_X509_INFO_read_bio`
  - `X509_AUX` trust settings ("TRUSTED CERTIFICATE")
  - Netscape SPKI
- [ ] **5.2 X509v3 extensions:**
  - the public `X509V3_EXT_METHOD` registry (including `X509V3_EXT_add` for
    application-defined methods)
  - every built-in extension: BC, KU, EKU, SKI, AKI, SAN, IAN (`GENERAL_NAME`; the
    CVE-2023-0286 lesson), CRL DP, freshestCRL, AIA, SIA, policies, mappings, constraints,
    inhibitAnyPolicy, name constraints, TLS feature, SCT list, RFC 3779, IDP, Netscape
    extensions, …
  - the `v2i`/`i2v`/`s2i`/`i2s`/`i2r`/`r2i` conversions
  - `X509V3_EXT_conf_nid` / `X509V3_EXT_nconf` (the config-string language)
  - `X509V3_get_d2i`, `X509V3_add1_i2d`, `X509V3_EXT_print` (byte-exact)
- [ ] **5.3 Store and lookup:**
  - `X509_STORE`, `X509_OBJECT`
  - `X509_LOOKUP` methods: file, hash_dir (c_rehash naming, including CRLs), store
  - `load_locations`, default paths (`SSL_CERT_FILE`, `SSL_CERT_DIR`, OPENSSLDIR)
  - every store callback setter
- [ ] **5.4 Path validation** (core in `rustyssl-pki`):
  - chain building over multiple candidate issuers (alternate chains, the CVE-2015-1793
    lesson), trusted-first, partial chains
  - RFC 5280 checks: signatures under security levels, validity time, basic constraints and
    path length, key usage, name constraints (including the CN-as-hostname rules), the policy
    tree (with a bound, the CVE-2023-0464 lesson)
  - EKU and purpose checks (`X509_PURPOSE`, `X509_check_purpose`, `X509_check_ca`)
  - `X509_TRUST`
  - CRLs (delta, indirect, IDP)
  - Suite B, DANE, proxy certificates
  - the full `X509_STORE_CTX` API with exact verify-callback semantics (the callback is
    invoked per error with an override, and the error, depth, and current certificate are
    exact)
  - `X509_verify_cert_error_string`, byte-exact
- [ ] **5.5 Identity checks:** `X509_check_host` (every `X509_CHECK_FLAG_*`, the wildcard
  rules, `peername`), `X509_check_email`, `X509_check_ip(_asc)`, and the
  `X509_VERIFY_PARAM_*` host, email, and IP setters.
- [ ] **5.6 Printing:** the `X509`, `X509_CRL`, `X509_REQ`, and `X509_NAME` `print_ex`
  functions, `X509_signature_print`, `X509_ocspid_print`. All byte-exact.
- [ ] **5.7 Certificate Transparency:** `SCT`, `CTLOG`, `CTLOG_STORE`,
  `CT_POLICY_EVAL_CTX`, SCT validation.

**Exit:** x509-limbo results equal the reference's (any difference is a documented
deviation). Differential verification over a large real-world chain corpus matches in both
result and error/depth. Mutation-based differential tests are clean. Upstream
`25-test_verify`, `x509` tests, and `v3ext` tests pass.

## Phase 6: PKI containers, config, misc libcrypto

- [ ] **6.1 CONF/NCONF and the config modules:**
  - the full `openssl.cnf` grammar: `.include`, `.pragma` (dollarid, abspath, includedir),
    `$var` and `ENV::` expansion
  - `CONF_modules_load_file`, `OPENSSL_config`, `OPENSSL_INIT_LOAD_CONFIG`
  - modules: providers, `alg_section`, random, `ssl_conf` (handed to libssl), engines
    (compatible no-op), `oid_section`, `stbl_section`
  - `ASN1_generate_nconf`/`ASN1_generate_v3` (moved from 2.5), the string → DER mini-language
- [ ] **6.2 UI:** `UI_*` (including `UI_OpenSSL` reading the tty), `UI_UTIL_read_pw`,
  `PEM_def_callback` (from 2.6), `EVP_read_pw_string`.
- [ ] **6.3 PKCS#7:** encode and decode, sign and verify (detached, S/MIME), encrypt and
  decrypt. `SMIME_read/write_PKCS7` uses a strict, bounded MIME parser.
  `PEM_write_bio_ASN1_stream` comes here (from 2.6), with the ASN.1 streaming BIO.
- [ ] **6.4 CMS:**
  - every content type and recipient-info type present in the target headers
  - signed attributes and receipts
  - BIO streaming, `SMIME_read/write_CMS`
  - CMS compression behaves as in the default build (zlib disabled)
  - the RFC 3211 KEK unwrap is bounds-checked (CVE-2025-9230)
- [ ] **6.5 PKCS#12:**
  - `PKCS12_parse`/`PKCS12_create(_ex)`
  - MACs: HMAC and PBMAC1 (3.4)
  - safe bags, PBES2/AES by default, legacy RC2/3DES through the legacy provider
  - the `PKCS12_SAFEBAG_*` and `PKCS8_PRIV_KEY_INFO` APIs
- [ ] **6.6 OCSP:** the request and response structures, `OCSP_basic_verify`,
  `OCSP_check_validity`, `OCSP_resp_find_status`, the responder APIs, nonces, printing, and
  `OCSP_sendreq_*`.
- [ ] **6.7 TS (RFC 3161) and ESS:** request, response, verify, `TS_RESP_CTX`, and
  signing-certificate v1/v2.
- [ ] **6.8 HTTP client** (`OSSL_HTTP_*`): get and transfer, proxies and `no_proxy` (the
  CVE-2025-9232 lesson), the TLS hook, redirects, and a strict response parser with limits.
- [ ] **6.9 OSSL_STORE:** the `file:` loader (PEM bundles, DER, PKCS#12, directories),
  `OSSL_STORE_INFO`, search, and custom `OSSL_STORE_LOADER` registration.
- [ ] **6.10 CMP/CRMF** (RFC 4210/4211/9480): the structures, the `OSSL_CMP_CTX` client, and
  the server/mock APIs. Large and seldom used, so it's scheduled last in this phase.
- [ ] **6.11 Remainder:**
  - `TXT_DB`, SRP (deprecated)
  - `COMP_*`, matching the default build (no zlib, brotli, or zstd)
  - `ASYNC_*`: jobs run synchronously to completion unless a consumer needs pausing; log it in
    DEVIATIONS.md
  - `OSSL_SELF_TEST_*` callbacks, the `OSSL_INDICATOR` callback

**Exit:** differential tests on the PKCS#7, CMS, PKCS#12, OCSP, and TS corpora pass. Interop
holds both ways: we read what the reference writes and the reference reads what we write.
The upstream cms, pkcs12, ocsp, ts, and cmp recipes pass.

## Phase 7: libssl, TLS 1.3 and 1.2 core → M2, M4

Order: 7.1 → 7.2 → 7.3 client (curl, **M2**) → 7.3 server (nginx) → 7.4 → 7.5 → 7.6 (**M4**).

- [ ] **7.1 Sans-IO TLS core** (`rustyssl-tls`):
  - the record layer: version-specific protection, fragmentation, the
    `max_fragment_length` and `record_size_limit` extensions, padding
  - a typed codec for every handshake message and extension (unknown extensions are kept for
    the callbacks)
  - client and server state machines (typestate internally, mapped to OpenSSL's observable
    `SSL_ST_*` and `SSL_state_string(_long)` values)
  - the key schedule and transcript hash
  - crypto calls into `rustyssl-crypto`
- [ ] **7.2 SSL objects in capi:**
  - the `SSL_METHOD` set
  - `SSL_CTX` and `SSL` lifecycle and refcounts, CTX → SSL inheritance, `SSL_set_SSL_CTX`,
    ex_data
  - BIO integration (`SSL_set_fd`/`rfd`/`wfd`, `SSL_set_bio` and the `set0_rbio`/`set0_wbio`
    ownership rules, `BIO_f_ssl`, `BIO_new_ssl_connect`)
  - `SSL_read`/`write`/`peek` and their `_ex` forms, `pending`, `has_pending`
  - **exact `SSL_get_error` behavior** (WANT_READ, WANT_WRITE, WANT_X509_LOOKUP,
    WANT_CLIENT_HELLO_CB, WANT_ASYNC, ZERO_RETURN, SYSCALL, SSL), for blocking and
    non-blocking I/O
  - `SSL_MODE_*` (partial write, moving buffer, auto-retry, release buffers)
  - `SSL_shutdown` (bidirectional, quiet shutdown), `SSL_clear`, `SSL_do_handshake`,
    `SSL_connect`, `SSL_accept`
- [ ] **7.3 TLS 1.3:**
  - the full handshake, HRR, and the default 3.5 groups and key shares (hybrid
    **X25519MLKEM768** and X25519), including the 3.5 group-list syntax (tuples and key-share
    markers); the default provider's `TLS-GROUP` and `TLS-SIGALG` capabilities
    (`OSSL_PROVIDER_get_capabilities`, from 3.1d)
  - PSK (external, and resumption with stateful or stateless tickets, `num_tickets`, ticket
    key callbacks)
  - 0-RTT (`SSL_{read,write}_early_data`, limits, anti-replay)
  - KeyUpdate, post-handshake authentication, stateless cookies, middlebox compatibility mode
  - certificate compression (3.2), raw public keys (3.2; the CVE-2024-12797 lesson)
  - signature-algorithm negotiation and certificate selection across several key types
- [ ] **7.4 TLS 1.2:**
  - ECDHE, DHE, and RSA key exchange
  - AEAD suites, and CBC suites with constant-time MAC-then-encrypt processing (Lucky13) and
    encrypt-then-MAC
  - Extended Master Secret
  - secure renegotiation (RFC 5746) initiated by either side, with
    `SSL_OP_NO_RENEGOTIATION`/`ALLOW_CLIENT_RENEGOTIATION` (the CVE-2021-3449 lesson)
  - session IDs and tickets, the PSK and ECDHE-PSK suites, SRP suites, anonymous suites
    (present but excluded by the default cipher list)
  - OCSP stapling, CT validation in the handshake
  - no heartbeat (removed upstream)
- [ ] **7.5 Configuration and introspection surface:**
  - the **cipher-string parser**, with exact semantics for `DEFAULT`, `HIGH`, `!`, `+`, `-`,
    `@STRENGTH`, `@SECLEVEL=n`, and the aliases; the oracle is the reference's
    `SSL_get_ciphers` order
  - `set_ciphersuites`, the groups and sigalgs lists, min/max protocol version
  - every 64-bit `SSL_OP_*` option
  - the security-level framework and its callback, with defaults matching the reference
  - `SSL_CONF_CTX`/`SSL_CONF_cmd` (every command) and the `ssl_conf` module
  - verification settings (`set_verify`, depth, verify-param inheritance, `SSL_set1_host`,
    DANE)
  - client CA lists, certificate chain loading and building, `cert_cb`, `client_cert_cb`
  - ALPN (`SSL_select_next_proto`; the CVE-2024-5535 lesson), NPN, SNI (callback and
    `SSL_get_servername` semantics)
  - custom extensions, the client hello callback
  - the info, msg, and keylog callbacks, with exact argument values
  - `SSL_SESSION`: the full API, a **wire-compatible `i2d`/`d2i_SSL_SESSION`** so external
    session caches interoperate, the cache modes and callbacks, and `flush_sessions(_ex)`
  - `SSL_export_keying_material(_early)`, `get_finished`, `client_random`/`server_random`,
    `master_key`
  - `SSL_get_shared_ciphers` buffer semantics, the get0 vs. get1 peer-certificate ownership
    rules
- [ ] **7.6 Errors and strings:**
  - the exact `SSL_R_*` reasons where applications branch on them (for example,
    `UNEXPECTED_EOF_WHILE_READING` together with `SSL_OP_IGNORE_UNEXPECTED_EOF`)
  - `SSL_alert_desc_string(_long)`, `SSL_state_string(_long)`, `SSL_get_version`
  - `SSL_CIPHER_get_name`/`standard_name`/`description`, byte-exact
- [ ] **7.7 Default-build mirroring:** kTLS and `ssl-trace` are absent from the default build,
  so their symbols behave the way they do there.

**Exit:** M2 and M4. The BoGo shim meets its pass target. The tlsfuzzer server scripts
(including the Bleichenbacher/Marvin and Lucky13 timing scripts) pass. The interop matrix is
green. The upstream `sslapitest`, `ssl_test` (`ssl-tests/*.cnf`), `tls13*`, and
`cipherlist_test` pass.

## Phase 8: libssl breadth → M5

- [ ] **8.1 DTLS 1.0/1.2:**
  - epochs and the replay window
  - bounded fragment reassembly
  - retransmission timers (`DTLSv1_get_timeout`/`handle_timeout`, the timer callback)
  - `DTLSv1_listen` stateless cookies
  - MTU handling and `BIO_dgram` ctrls
  - the SRTP extension
  - SCTP as in the default build (disabled)
  - DTLS 1.3 if the target ABI includes it
- [ ] **8.2 TLS 1.0/1.1** behave exactly as the 3.x default does: the protocol code is
  present, but the default security level makes it effectively unusable unless
  `@SECLEVEL=0`. SSLv3 is compiled out, as in the default build.
- [ ] **8.3 Coverage sweep to 100% of `libssl.num`**, ordered by `docs/symbol-usage.md`:
  - async fds, record padding, `SSL_stateless`, the remaining `tlsext` ctrls
  - temporary/auto DH, the CA-subject loaders, the early-data callback
  - `SSL_CTX_compress_certs`, `SSL_COMP_*`, SRP, the status callbacks, the CT callback
  - `SSL_dane_*`, `OPENSSL_init_ssl`, …

**Exit:** M5. libssl coverage is 100%. The BoGo, tlsfuzzer, and DTLS targets are met.
DTLS interop with the reference and GnuTLS works under loss and reordering.

## Phase 9: Provider ABI, long tail, 100% libcrypto → M6

- [ ] **9.1 Loading external C providers:**
  - `OSSL_PROVIDER_load` of `.so` modules (`OSSL_provider_init`, MODULESDIR; 3.1d finds
    them), `OSSL_LIB_CTX_new_from_dispatch` and
    `OSSL_LIB_CTX_new_child` (from 3.1b), and the `legacy` provider as a module in
    `MODULESDIR`, as OpenSSL ships it
  - **every core upcall**: params, thread start, libctx, error raising and marks, obj sigid
    and create, memory, BIO, self-test, entropy and nonce, child-provider callbacks
  - EVP operations dispatched through external function tables, and key import/export across
    providers

  Validate with pkcs11-provider, oqs-provider, and tpm2-openssl.
- [ ] **9.2 Remaining custom-method APIs:** `RSA_meth_*`, `EC_KEY_METHOD_*`, `DH_meth_*`,
  `DSA_meth_*`, `RAND_METHOD`, `UI_METHOD`, `X509_LOOKUP_METHOD`.
- [ ] **9.3 ENGINE API** (3.x only): export every `ENGINE_*` symbol with "no engines
  available" semantics, i.e. how a normal build with no engines installed behaves. Settle the
  details by testing against consumers.
- [ ] **9.4 Long-tail sweep:** every remaining `DEPRECATEDIN_*` family, the exported data
  symbols, and the platform helpers (`OPENSSL_ia32cap_loc`, …), until libcrypto coverage
  reaches 100%; `OSSL_LIB_CTX_get_data` (from 3.1e).
- [ ] **9.5 3.6 delta:** diff the 3.5 and 3.6 `.num` files and headers, implement the
  additions under the `OPENSSL_3.6.0` node, and re-run the full test plan against the 3.6
  reference.

**Exit:** M6.

## Phase 10: QUIC

- [ ] **10.1 Sans-IO QUIC transport** (`rustyssl-quic`):
  - packet protection and header protection
  - frames, streams, flow control
  - congestion control (NewReno, as upstream) and loss detection
  - address validation (Retry, tokens), version negotiation
  - idle timeout, migration limits
- [ ] **10.2 The OpenSSL QUIC API:**
  - the client methods (3.2), the server and listener API (3.5)
  - the stream API (`SSL_new_stream`, `accept_stream`, `stream_conclude`, `stream_reset`,
    default stream mode, incoming stream policy)
  - `SSL_handle_events`, `get_event_timeout`, blocking and non-blocking, thread-assisted mode
  - `SSL_poll` and `SSL_get_value_*`/`SSL_set_value_*` (3.3)
  - `BIO_s_dgram_pair`, `BIO_sendmmsg`/`BIO_recvmmsg`
- [ ] **10.3 Third-party QUIC stack API** (3.5: `SSL_set_quic_tls_cbs` and related), as used
  by ngtcp2 and others.

**Exit:** the quic-interop-runner core cases pass against ngtcp2, quiche, and quic-go. curl
HTTP/3 works over the OpenSSL QUIC backend. upstream `quicapitest` and
`quic_multistream_test` pass.

## Phase 11: The `openssl` command-line tool

Until this phase, the upstream `apps/` sources compiled against our libraries serve as the
CLI, both for users and for the upstream test recipes.

- [ ] **11.1** Write a Rust implementation of the `openssl` binary with **identical options,
  exit codes, and byte-exact output**. Golden tests are generated from the reference.
  Priority: `version`, `x509`, `req`, `genpkey`, `pkey`, `pkeyutl`, `dgst`, `enc`, `rand`,
  `s_client`, `s_server`, `verify`, `crl`, `ca`, `pkcs12`, `cms`, `smime`, `pkcs7`, `ocsp`,
  `ts`, `asn1parse`, `ciphers`, `list`, `speed`, `rehash`, then the rest.
- [ ] **11.2** Run the upstream app-driven test recipes with our CLI in place of upstream's.

## Phase 12: Hardening, performance, release 1.0 → M7

- [ ] **12.1 Performance:** benchmark against the reference (per TEST_PLAN L10). Close the gaps
  with intrinsics in vetted backends and with profiling. Assembly is not allowed. Set the
  targets once there's a baseline (initial goal: within 1.25× of the reference on hot
  symmetric paths and within 1.5× on handshakes).
- [ ] **12.2 Security:**
  - a third-party audit (the crypto backends and all `unsafe` in capi)
  - the complete CVE regression suite
  - OSS-Fuzz onboarding (start after M2)
  - a review of the `unsafe` budget
  - a constant-time verification report
- [ ] **12.3 Packaging:** Debian/Fedora/Alpine (musl)/Homebrew layouts, pkg-config files, a
  default `openssl.cnf`, MODULESDIR, side-by-side installation and an alternatives mechanism,
  and migration docs. Decide the Fedora ABI extras found in 0.10 (MD2, SCTP, and the
  `OPENSSL_3.1.0` versions of `EVP_{MD,CIPHER}_CTX_dup`). Rerun `cargo xtask usage-scan`
  against the distributions current at release.
- [ ] **12.4 Distro validation:** the system tests in TEST_PLAN L11.
- [ ] **12.5 Release 1.0.** The ABI stability promise is OpenSSL's 3.x ABI. The Rust crates
  follow SemVer.

## Phase 13: OpenSSL 4.0 ABI → M8

- [ ] **13.1** Vendor the 4.0 headers and `.num` files and generate the delta. Already
  observed: about 140 `ENGINE_*` functions and some deprecated `EVP_*`/`ERR_*` APIs are
  removed, and `ech.h` and `posix_time.h` are new.
- [ ] **13.2** Build the `.so.4` facades from the same core, with per-ABI selection in capi
  (build-time `abi-3`/`abi-4` features, so each library exports exactly its own table).
  Record this in an ADR.
- [ ] **13.3** Encrypted Client Hello (client and server, the `SSL_ech_*` API, ECHConfig,
  GREASE) and the other 4.0 features.
- [ ] **13.4** Run the full test plan against the 4.0 reference.

---

## Cross-cutting tracks (continuous from Phase 0)

- **Coverage dashboard:** `xtask coverage` runs in CI, and regressions block merges.
- **DEVIATIONS.md:** every intentional behavioral difference, with its rationale and test.
- **Fuzzing:** every new parser or state machine gets a fuzz target in the same PR.
- **Consumers:** add each consumer's test suite as soon as the APIs it needs are covered.
- **Re-vendoring:** a monthly job diffs the latest 3.5.x/3.6.x/4.0.x patch releases (`.num`,
  headers, man pages) and opens issues for the changes.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Huge ABI surface (about 6,900 functions) | Generators (stubs, ASN.1 functions, constants), coverage-driven sweeps, and usage-ranked ordering (0.10). |
| Byte-exact output and undocumented behavior | Differential tests against the reference, golden files generated from the reference, and the upstream and consumer test suites. |
| The ASN1_ITEM engine is unsafe code interpreting C tables | Keep it small, fuzz it with every header-declared item, run Miri on synthetic tables, and cross-check against the reference. |
| Constant-time guarantees in third-party crates | Vet each crate, run dudect and ctgrind in CI, and keep backends swappable. |
| Two Rust libraries (std duplication, static linking, symbol binding) | The Phase 0.6 spike and ADR before any feature work. |
| Logic bugs (Rust doesn't prevent them) | The CVE regression suite, BoGo, tlsfuzzer, x509-limbo, and differential fuzzing. |
| Performance without assembly | Intrinsics, profiling, an explicit performance budget, and accepting a small gap. |
| Upstream keeps moving | Pinned versions plus the monthly re-vendor diff job. |
| Re-entrancy and threading with C callbacks | The lock-discipline rule, `loom` for core concurrency, TSan on the C and consumer tests. |
