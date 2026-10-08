# rustssl Implementation Plan

Baseline: **OpenSSL 3.5 LTS ABI → 3.6 additions → OpenSSL 4.0 ABI.**
See [AGENTS.md](../AGENTS.md) for the rules and architecture, and [TEST_PLAN.md](TEST_PLAN.md)
for how each step is verified.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done. Update this file as you work.

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
  placeholder `src/lib.rs`. Create the crate skeletons from AGENTS.md, `rust-toolchain.toml`
  (stable, at least 1.99), and workspace lints: `forbid(unsafe_code)` everywhere except
  `rustssl-capi` and `libs/*`, plus the clippy set from the security rules. Add `rustfmt.toml`,
  `license = "Apache-2.0"` in the workspace package metadata, and a `NOTICE` that carries
  OpenSSL's attribution for the vendored files. (`LICENSE.txt` already exists.)
  *Done.* The workspace has every `crates/*` from AGENTS.md except `rustssl-quic` (deferred
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
- [x] **0.3 `rustssl-abi`.** Generate it with bindgen from the vendored headers, **once per
  target** (see the `configuration.h` note in 0.2), selected with
  `cfg(target_arch, target_os)`. The output is committed so users don't need libclang. It
  holds opaque type declarations, every public struct and union with `#[repr(C)]`, and all
  constants. Generate layout assertions too.
  *Done* (`cargo xtask codegen`, output in `crates/rustssl-abi/src/generated/`). Notes:
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
  - Linux version scripts (`OPENSSL_3.0.0` … `OPENSSL_3.6.0` plus `RUSTSSL_PRIVATE`) and
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
    `RUSTSSL_PRIVATE` node exports the glob `rustssl_private_*`, a placeholder until 0.6
    settles the names.
  - **Stubs abort** instead of returning an error (see rule 10 in AGENTS.md). There's one
    per export: 6,476, generated from bindgen prototypes parsed with `syn`. `va_list`
    parameters become `VaList`. All three targets must produce identical stubs, and they
    compile on each. A C program linked to the built `libcrypto.dylib` gets the message and
    SIGABRT. 26 exports are declared only in internal headers (`DSO_*`, `conf_ssl_*`,
    `OPENSSL_DIR_*`, …), so six of those are now vendored, and `rustssl-abi` includes their
    types. The wrapper also puts headers first when another header declares extra
    functions only after them (`cms.h` declares the `PEM_*_CMS` functions only if `pem.h`
    came first).
  - **Error strings.** Three sources are cross-checked: `openssl.txt` (names and codes), the
    headers (codes, as `rustssl-abi` constants), and the C string tables `*_err.c`, which
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
  - **libssl defines its own exports.** Its 603 stubs moved from `rustssl-capi` into
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
  1. libssl's `SSL_*` exports forward into libcrypto's `RUSTSSL_PRIVATE` entry points.
  2. A binary **linked against real OpenSSL** resolves every versioned symbol against our libs.
  3. macOS two-level-namespace binding resolves correctly.
  4. `-lssl -lcrypto` static linking works and doesn't duplicate Rust `std` symbols.
  5. Forwarding overhead is negligible.

  OpenSSL 3.5 exports no data symbols (the `.num` files list only functions), so there's
  nothing to test there.

  *Done:* see [ADR 0001](adr/0001-library-layout.md) for the decision and evidence.
  - **Design.** libssl's exports are generated one-branch forwarders to libcrypto's
    `rustssl_private_<name>`, which hold the stubs (and later the implementations).
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
- [x] **0.7 FFI primitives** in `rustssl-capi`:
  - the `ffi_export!` wrapper (catches unwinds, pushes an ERR entry, returns the failure
    value);
  - the opaque handle model (Arc-backed, with `*_up_ref`/`*_free` and stable interior
    addresses for `get0`);
  - `CRYPTO_malloc`-backed allocation helpers;
  - checked int/size conversions;
  - the C-variadic export pattern.

  Prove them out on `BUF_MEM`.

  *Done.* Modules in `crates/rustssl-capi/src/`:
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
    `tests/c/buf_mem.c` (26 checks) passes against the reference and rustssl, with
    identical output: Homebrew 3.6.5 on macOS and Debian 3.5.7 on Linux, the same binary
    run against both. Where OpenSSL crashes (null buffer), rustssl fails cleanly.
  - **Checks:** the `rustssl-capi` tests pass under Miri
    (`cargo +nightly miri test -p rustssl-capi`). Codegen's implemented-function scan now
    skips comments; doc examples had been hiding the `BIO_printf` stubs.
- [x] **0.8 Test infrastructure** (details in TEST_PLAN.md):
  - `cargo xtask ref-openssl 3.5`, which builds the reference into `target/ref/`;
  - the C conformance harness in `tests/c`, with dual runs (reference and ours). The first
    test, `tests/c/buf_mem.c` (TAP output), is already there and has been dual-run by hand
    (0.7);
  - Miri on the `rustssl-capi` tests;
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
    `tests/differential/probe.c` on the reference and on rustssl and compares output line
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
  - **Implemented** means `rustssl-capi` defines the export and a `tests/c` program calls
    it, which is AGENTS.md's rule made mechanical. Calls come from the undefined symbols of
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
    upstream 3.5 ABI doesn't have, so they wouldn't load on rustssl. Fedora's libcrypto
    (checked) has three extras:
    - MD2 (`EVP_md2`, `MD2_*`; ipmitool, perl-Net-SSLeay, qca), which upstream disables by
      default and AGENTS.md keeps disabled;
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
     - libcrypto also exports `rustssl_private_*`, exactly one per libssl function, under
       `RUSTSSL_PRIVATE`. Nothing else is exported, including no Rust runtime symbols.
     - Linux symbols are read from the ELF version tables, extending `usage_scan/elf.rs`'s
       reader to defined symbols and `.gnu.version_d`. macOS uses `nm` and the export list.
  2. **Library metadata:**
     - the soname or install name;
     - `NEEDED` entries: libssl needs libcrypto, and neither needs anything beyond libc,
       libm, libpthread, libdl and the unwinder;
     - the version definitions and their parent chain;
     - macOS compatibility and current versions 3.0.0.
  3. **Signatures.** Every hand-written `extern "C"` export in `rustssl-capi` (outside
     `generated/`), including the `rustssl_private_*` definitions of libssl functions, must
     match the bindgen prototype exactly: parameter and return types, pointer constness,
     and variadics. The generated stubs and forwarders match by construction.
  4. **Layouts.** A generated C program, compiled with the official headers, prints
     `sizeof`, `alignof`, and `offsetof` for every public struct and union. The values must
     equal `rustssl-abi`'s layout for the host target.
  5. **Constants.** The C compiler evaluates every integer and string macro constant with
     the real libc headers, and each value must equal `rustssl-abi`'s.
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
    - libcrypto exports 5,876 functions plus 603 `rustssl_private_*`; libssl exports 603.
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
    `rustssl-capi/src/generated/signatures.rs`. It assigns each hand-written export to a
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
    against the reference with `-z now`/`-bind_at_load`. It loads on rustssl's libraries,
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
  (The internal allocator exists in `rustssl-capi/src/mem.rs` since 0.7; this step exports
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
    - Every allocation, rustssl's own included, goes through the functions installed with
      `CRYPTO_set_mem_functions`. Our own pass the file `"rustssl"` and the Rust line.
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
  rustssl. Record it in `DEVIATIONS.md` if it differs from upstream.

  *Done:* 23 exports, now 50 of libcrypto's 5,876.
  - **Version policy** (`version.rs`; `DEVIATIONS.md` explains why):
    - The numbers (`OpenSSL_version_num`, `OPENSSL_version_major`/`_minor`/`_patch`,
      `OPENSSL_VERSION_STRING`) and the release date are the vendored 3.5.9's.
    - rustssl names itself in the build metadata, which OpenSSL's man page reserves "for
      other parties, such as `+fips`": `OpenSSL 3.5.9+rustssl.0.1.0 29 Sep 2026`.
  - **Build information:**
    - `cargo xtask vendor` now records each target's `PLATFORM`, `OPENSSLDIR`,
      `ENGINESDIR`, `MODULESDIR`, and `DSO_EXTENSION` from OpenSSL's Makefile in
      `config/<target>/build.toml`, and codegen turns them into `rustssl_abi::build`.
      x86_64 Linux gets `lib64`, as upstream's default build does.
    - Packagers override the directories with `RUSTSSL_OPENSSLDIR`/`_ENGINESDIR`/
      `_MODULESDIR` at build time; that's for 12.3.
    - `CPUINFO` is `N/A`, since rustssl has no `OPENSSL_ia32cap`-steered assembly. The
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
      rustssl-specific strings and the new deviations.
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
    - `OSSL_set_max_threads`/`OSSL_get_max_threads` keep the default context's limit
      until library contexts exist (3.1 moves it into them). They return 0 for any other
      context, none of which can exist yet.
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
- [ ] **1.4 Error queue (all of `ERR_*`):**
  - a thread-local queue with marks
  - `ERR_raise`, `ERR_raise_data`, `ERR_set_debug`, `ERR_set_error` (variadic)
  - the get/peek variants (`_all`, `_data`, `_last`)
  - `ERR_error_string(_n)`, byte-exact
  - `ERR_print_errors_fp` / `ERR_print_errors_cb`
  - application-defined libraries (`ERR_get_next_error_library`, `ERR_load_strings`)
  - `ERR_add_error_data` / `ERR_add_error_vdata`

  The reason strings already exist (`err_reasons.rs`, from 0.4). Extend codegen to also
  emit the library names (`ERR_str_libraries`) and the common `ERR_R_*` reasons
  (`ERR_str_reasons`) from the vendored `crypto/err/err.c`.

  From 1.1:
  - Errors raised by `CRYPTO_malloc` and `CRYPTO_secure_malloc` carry the caller's file and
    line and no function (`ERR_set_debug(file, line, NULL)`).
  - Allocating a thread's error state closes `CRYPTO_set_mem_functions`, as OpenSSL's
    `CRYPTO_zalloc` of `ERR_STATE` does (`mem::close_customization`).
- [ ] **1.5 Containers and utilities:**
  - `OPENSSL_sk_*`, including the comparator and sort quirks (for example, `find` sorts an
    unsorted stack)
  - `OPENSSL_LH_*`
  - `BUF_MEM`
  - the string helpers (`OPENSSL_strdup`, `strlcpy`, `hexstr2buf`, `buf2hexstr`,
    `strcasecmp`, …)
  - `OPENSSL_DIR_read`
  - `ex_data` (`CRYPTO_get_ex_new_index`, `new_ex_data`, `dup`, `free`, `set`, `get`, with
    per-class index spaces)
- [ ] **1.6 BIO core:**
  - the BIO object, chains, and the full `BIO_ctrl` protocol (every `BIO_CTRL_*`)
  - `read`/`write`/`gets`/`puts` and their `_ex` variants
  - `BIO_printf`, `BIO_snprintf`, `BIO_vprintf`: C-printf-compatible, byte-exact with the
    reference
  - `BIO_meth_*`, for application-defined BIOs
  - callbacks (`BIO_set_callback_ex`)
  - `BIO_ADDR`, `BIO_ADDRINFO`, and the socket helpers
  - source/sink BIOs: mem (including read-only), secmem, file, fd, socket, connect, accept,
    null, dgram, dgram_pair, BIO pair
  - filters: buffer, null, base64, readbuffer, prefix, indent, nbio_test
  - `BIO_dump*`

  The md and cipher filters come in Phase 3.
- [ ] **1.7 Tracing:** `OSSL_trace_*` with the default build's behavior (tracing disabled).

**Exit:** C conformance tests for ERR, BIO, stack, lhash, ex_data, and memory pass on both
the reference and ours. The printf corpus is byte-identical to the reference. The printf and
base64 fuzzers run clean.

## Phase 2: ASN.1, objects, encodings

- [ ] **2.1 OBJ:**
  - the generated NID table (`rustssl_asn1::objects`, from 0.4), plus
    `OBJ_create`/`OBJ_add_object` for runtime OIDs
  - `OBJ_txt2obj`/`OBJ_obj2txt` (byte-exact, including large arcs)
  - `OBJ_find_sigid_algs`, `OBJ_add_sigid`
  - the `OBJ_NAME_*` alias registry
- [ ] **2.2 DER/BER engine** (`rustssl-asn1`):
  - safe and zero-copy, with bounded depth and size
  - indefinite-length BER (needed for PKCS#7, CMS, and PKCS#12)
  - strict DER, plus a documented list of the leniencies OpenSSL accepts
  - `ASN1_get_object`/`ASN1_put_object`
- [ ] **2.3 Universal types** (public-layout `ASN1_STRING` family):
  - INTEGER/ENUMERATED (BN and int64 conversions, negative handling)
  - BIT STRING (unused bits and flags)
  - OCTET STRING and every string type
  - `ASN1_mbstring_copy`, `ASN1_STRING_to_UTF8`, `ASN1_STRING_print_ex` (RFC 2253 flags)
  - OBJECT, BOOLEAN, NULL
  - TIME/UTCTIME/GENERALIZEDTIME (parse, compare, diff, print formats, the
    `OPENSSL_gmtime*` family)
  - `ASN1_TYPE`, `ASN1_STRING_TABLE`
- [ ] **2.4 ASN1_ITEM template engine** (in `capi`; this is the most security-sensitive unsafe
  code):
  - interprets `ASN1_ITEM`, `ASN1_TEMPLATE`, and `ASN1_AUX` tables, including callbacks,
    SEQUENCE, CHOICE, SET OF, EXPLICIT/IMPLICIT tagging, ADB, EMBED, REFCOUNT, ENCODING
    cache, EXTERN, MSTRING, and COMPAT
  - the `ASN1_item_*` API
  - built-in types exposed as `ASN1_ITYPE_EXTERN` items
  - **generated** `d2i_`/`i2d_`/`_new`/`_free`/`_dup`/`_it` functions for every type declared
    with `DECLARE_ASN1_*` in the headers
- [ ] **2.5 Utilities:**
  - `ASN1_parse_dump` (byte-exact `asn1parse` output)
  - `ASN1_generate_nconf`/`ASN1_generate_v3` (the string → DER mini-language)
  - the `i2a_*`/`a2i_*` helpers, `ASN1_tag2str`
- [ ] **2.6 Base64 and PEM framing:**
  - `EVP_Encode*`/`EVP_Decode*`, including the exact line-handling quirks, and
    `EVP_EncodeBlock`/`EVP_DecodeBlock`
  - `BIO_f_base64`
  - `PEM_read_bio`/`PEM_write_bio`/`PEM_read_bio_ex`/`PEM_bytes_read_bio`, plus
    `Proc-Type`/`DEK-Info` header handling

  The typed PEM functions arrive with their types.

**Exit:** d2i → i2d round trips and print output are identical to the reference on the
corpora (OpenSSL fuzz corpora, CT certificates). The DER, template, PEM, and base64 fuzzers
have run for at least 24 CPU-hours with no findings.

## Phase 3: Provider core, EVP symmetric, RAND → M1

- [ ] **3.1 Library contexts, params, and providers:**
  - `OSSL_LIB_CTX` (default and child contexts); move `OSSL_set_max_threads`'s limit, kept
    for the default context since 1.3, into each context
  - `OSSL_PARAM`: all types, the `*_ptr` semantics, the modified flags, and `OSSL_PARAM_BLD`
  - `OSSL_PROVIDER`: load, try_load, unload, available, do_all, get_params, self_test
  - the property-query parser and matcher
  - the method store and cache: `EVP_*_fetch`, `is_a`, names, `do_all_provided`
  - implicit fetch for the legacy `EVP_sha256()`-style getters

  The built-in providers (`default`, `base`, `legacy`, `null`) are Rust implementations
  registered through the **same dispatch model** that external providers use in Phase 9.
- [ ] **3.2 Backend layer** (`rustssl-crypto`): Digest, Cipher (block, stream, AEAD), Mac,
  Kdf, and Rng traits; adapters for the vetted RustCrypto crates; entries in
  `docs/DEPENDENCIES.md`; CPU-feature dispatch (AES-NI, ARMv8 crypto, SHA extensions) through
  crate features.
- [ ] **3.3 EVP_MD:**
  - SHA-1, the SHA-2 family (including 512/224 and 512/256), SHA-3, SHAKE (XOF,
    `EVP_DigestFinalXOF`, `EVP_DigestSqueeze`), KECCAK-KMAC, MD5, MD5-SHA1, SM3, BLAKE2s/b,
    RIPEMD-160, NULL
  - legacy provider: MD4, MDC2, Whirlpool
  - the full `EVP_MD_CTX` API, `EVP_Digest`, `EVP_Q_digest`
  - the digest name table behind `EVP_get_digestbyname`, which `OPENSSL_INIT_ADD_ALL_DIGESTS`
    fills (it aborts until then; see 1.2)
- [ ] **3.4 EVP_CIPHER:**
  - AES in ECB, CBC, CFB1/8/128, OFB, CTR, GCM, CCM, XTS, OCB, SIV, GCM-SIV, wrap, wrap-pad,
    and the CBC-HMAC composites
  - ARIA, Camellia, ChaCha20, ChaCha20-Poly1305, SM4, 3DES (all modes and wrap), NULL
  - legacy provider: DES, BF, CAST5, IDEA, RC2, RC4 (including RC4-HMAC-MD5), SEED
  - the full `EVP_CIPHER_CTX` API, including padding, AEAD ctrls, and the TLS AAD and IV ctrls
  - the cipher name table behind `EVP_get_cipherbyname`, which `OPENSSL_INIT_ADD_ALL_CIPHERS`
    fills (it aborts until then; see 1.2)
- [ ] **3.5 EVP_MAC:** HMAC, CMAC, GMAC, KMAC128/256, Poly1305, SipHash, and BLAKE2 MACs;
  the legacy `HMAC_*` and `CMAC_*` APIs; `EVP_Q_mac`.
- [ ] **3.6 EVP_KDF:** HKDF, TLS13-KDF, PBKDF1, PBKDF2, scrypt, SSKDF, X963KDF, X942KDF,
  KBKDF, TLS1-PRF, SSHKDF, PKCS12KDF, KRB5KDF, Argon2i/d/id, HMAC-DRBG-KDF;
  `PKCS5_PBKDF2_HMAC*`, `EVP_PBE_scrypt`, `EVP_BytesToKey`.
- [ ] **3.7 RAND and DRBG:** (`OPENSSL_thread_stop_ex(ctx)` must then free the thread's
  generators for `ctx`, as OpenSSL's `rand_delete_thread_state` does; see 1.3.)
  - `EVP_RAND`: CTR-, HASH-, and HMAC-DRBG, SEED-SRC, TEST-RAND
  - the primary/public/private DRBG hierarchy, per thread, with reseed policy and fork safety
  - `RAND_bytes(_ex)`, `RAND_priv_bytes(_ex)`, `RAND_seed`, `RAND_add`, `RAND_status`,
    `RAND_poll`, `RAND_load_file`, `RAND_write_file`, `RAND_set_DRBG_type`
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
  `default_properties`. Distro crypto policies depend on it.

**Exit:** M1. All Wycheproof and CAVP/ACVP suites for these algorithms pass. Upstream
`evp_test` passes the symmetric data files. Differential fuzzing of streaming EVP (random
chunking) is clean.

## Phase 4: BIGNUM and public-key cryptography

- [ ] **4.1 BIGNUM** (the full `BN_*` API, about 200 functions):
  - arithmetic, shifts, and bit operations
  - conversions: bin, lebin, native, hex, dec, mpi, ASN.1
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
- [ ] **5.4 Path validation** (core in `rustssl-pki`):
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
- [ ] **6.2 UI:** `UI_*` (including `UI_OpenSSL` reading the tty), `UI_UTIL_read_pw`,
  `PEM_def_callback`, `EVP_read_pw_string`.
- [ ] **6.3 PKCS#7:** encode and decode, sign and verify (detached, S/MIME), encrypt and
  decrypt. `SMIME_read/write_PKCS7` uses a strict, bounded MIME parser.
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

- [ ] **7.1 Sans-IO TLS core** (`rustssl-tls`):
  - the record layer: version-specific protection, fragmentation, the
    `max_fragment_length` and `record_size_limit` extensions, padding
  - a typed codec for every handshake message and extension (unknown extensions are kept for
    the callbacks)
  - client and server state machines (typestate internally, mapped to OpenSSL's observable
    `SSL_ST_*` and `SSL_state_string(_long)` values)
  - the key schedule and transcript hash
  - crypto calls into `rustssl-crypto`
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
    markers)
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
  - `OSSL_PROVIDER_load` of `.so` modules (`OSSL_provider_init`, MODULESDIR),
    `OSSL_PROVIDER_add_builtin`
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
  reaches 100%.
- [ ] **9.5 3.6 delta:** diff the 3.5 and 3.6 `.num` files and headers, implement the
  additions under the `OPENSSL_3.6.0` node, and re-run the full test plan against the 3.6
  reference.

**Exit:** M6.

## Phase 10: QUIC

- [ ] **10.1 Sans-IO QUIC transport** (`rustssl-quic`):
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
