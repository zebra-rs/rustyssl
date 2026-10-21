# The `unsafe` budget review (Phase 12.2)

Reviewed 2026-10-21 on `main` 4b424688 (OpenSSL 3.6.5 ABI). This note records where rustyssl's
`unsafe` code is, how it is kept honest, what this review checked, and what it found. Auditors
start here; [the audit package](audit/README.md) has the rest.

## Where `unsafe` is allowed

Security rule 1 (README.md) allows `unsafe` in three places only. Every other crate
(`rustyssl-abi`, `-asn1`, `-conf`, `-crypto`, `-pki`, `-tls`, `-quic`, `-cli`, and `xtask`) carries
`#![forbid(unsafe_code)]`, which `cargo xtask unsafe-audit` checks.

| Crate | Role | Hand-written `unsafe` blocks | `unsafe fn`s | `unsafe impl`s | `extern` blocks | unguarded callbacks |
|---|---|---:|---:|---:|---:|---:|
| `rustyssl-capi` | the C ABI: every export, handles, BIO, OSSL_PARAM, ERR, the ASN1_ITEM engine, providers | 35 815 | 11 361 | 166 | 4 | 413 |
| `rustyssl-ossl` | the `openssl` tool's safe wrappers over the public C API (ADR 0007) | 2 325 | 103 | 2 | 0 | 92 |
| `libs/libssl` | generated one-branch forwarders to libcrypto's private twins | 603 (generated) | 603 (generated) | 0 | 1 | 0 |
| `libs/libcrypto` | the archive's root, no code of its own | 0 | 0 | 0 | 0 | 0 |

`rustyssl-capi`'s generated code (`src/generated/`) holds no `unsafe` any more: every export is
implemented, so the aborting stubs are gone, and `signatures.rs` only names function-pointer
types. The largest modules are `evp` (4 574 blocks), `provider` (4 444), `x509` (3 726), `ssl`
(3 040), `x509v3`, `cmp`, `cms` and `asn1`; the per-module numbers are in
[`unsafe-budget.txt`](unsafe-budget.txt).

The counts are large because the C ABI is large (6 500 exports) and the lints below require one
unsafe operation per block: almost every block is a single pointer dereference, a call into
another export, or a call through a C function pointer, each with its own `SAFETY:` comment.

## How it is kept honest (automated, on every PR)

- **One operation per block, each justified.** The workspace denies
  `clippy::undocumented_unsafe_blocks`, `clippy::multiple_unsafe_ops_per_block` and
  `unsafe_op_in_unsafe_fn` (Cargo.toml `[workspace.lints]`), so every unsafe operation sits in
  its own block under its own `// SAFETY:` comment, also inside `unsafe fn`s.
- **No truncating casts** (rule 2). `cast_possible_truncation`, `cast_possible_wrap` and
  `cast_sign_loss` are denied. Six functions allow one of them, each reproducing a C conversion
  on purpose (reviewed below).
- **No panics across the boundary** (rule 3). Every export runs in `ffi::guard`, through
  `ffi_export!` or, for C-variadic exports, a direct `guard` call. `cargo xtask unsafe-audit`
  now checks this for every hand-written `no_mangle`/`export_name` function: none is unguarded.
- **The budget.** `cargo xtask unsafe-audit` counts the unsafe sites per module (blocks,
  `unsafe fn` definitions, `unsafe impl`/`trait`s, `extern` blocks, and unguarded `extern "C"`
  callbacks) and fails when a count grows past `docs/security/unsafe-budget.txt` or a new module
  appears. `--bless` records the new counts, so growth shows in the diff and gets reviewed. It
  runs in CI's "generated files are up to date" job and in `scripts/gates.sh`.
- **Miri.** `cargo +nightly miri test -p rustyssl-capi` runs the FFI layer's tests (about 20
  shards' worth, split in CI) under Miri on the host and on `x86_64-unknown-linux-gnu`, catching
  undefined behaviour the tests reach: out-of-bounds or misaligned access, use after free, and
  aliasing violations.
- **Differential and conformance testing.** Every export has a C conformance test run on both
  libraries under the platform's C toolchain (`cargo xtask test-c`, 272 programs), and the
  fuzzers in `fuzz/` (108 targets) drive the parsers and the C boundary.

## What this review checked by hand

The automated checks establish that each unsafe operation is isolated and commented. This review
looked for the bug classes the comments could still get wrong, by pattern across all
hand-written code of the three crates.

| Rule | Pattern | Sites | Result |
|---|---|---:|---|
| 2 | `slice::from_raw_parts[_mut]` (a NULL pointer is UB even with length 0) | 311 | Most go through `ffi::bytes`, which maps (NULL, 0) to `&[]` and (NULL, n) to `None`, or sit right after a NULL/length check. The 37 without a check in the preceding lines were read: each is reached only with a non-NULL pointer (an earlier `is_null` return, a positive length the caller must back, or an object's own buffer). None found to be reachable with NULL. |
| 2 | `as` conversions between C integer types | ~500 | Clippy denies the lossy ones. The six allowances: `evp/legacy_md.rs` `size`/`block` (const digest sizes ≤ 168), `evp/cipher_ctx.rs` `widen`/`narrow`/`to_size`/`to_int` (C's own conversions of flags and of `EVP_Cipher`'s and the tag length's return values, as upstream's `int` returns behave), `params.rs` `UNMODIFIED` (`SIZE_MAX`). All intended. |
| 3 | hand-written exports outside `ffi_export!` | — | All call `guard` (checked by `unsafe-audit`). |
| 3 | `extern "C"` callbacks without the guard | 505 | Stack free functions, `EVP_PKEY_METHOD`/`OSSL_DISPATCH` tables, BIO and SSL trampolines (`rustyssl-ossl/src/ssl_cb.rs`). A panic in one cannot unwind into C: since Rust 1.81 a panic reaching an `extern "C"` frame aborts the process. That is fail-closed (no undefined behaviour), at the cost of availability; most are one-line forwarders to guarded exports. Their count per module is budgeted. |
| 6 | `Box::from_raw` / `CRYPTO_free` pairing | 58 / — | Handles are created with `Box::into_raw` in `handle_type!` and freed by the same type's `*_free`; C-visible memory comes from `mem` (`CRYPTO_malloc`). Miri's leak and invalid-free checks run over the tests. |
| 7 | a lock guard alive while a C callback runs | — | A scan of every `let x = ….lock()/read()/write()` followed by a call through a callback before `drop(x)` found one candidate (`bn/prime.rs`), a false positive: the guard is a temporary dropped before the call. Callback sites copy what they need and release the lock first (`ssl/` documents "no lock held" at each). |
| — | `transmute` | 70 | Function-pointer casts that mirror C's generic callback APIs (`SSL_CTX_callback_ctrl`, `ENGINE_set_*`, `CRYPTO_set_mem_functions`, `i2d`/`d2i` item functions). Each converts between pointer types of the same size and ABI; the types are those the C API documents. |
| — | `static mut` | 3 | `extern` declarations of C's `stdin`/`stderr` (`ui/console.rs`, `cmp/util.rs`), read only. |

**Findings.** No memory-safety defect was found in the reviewed patterns. The review added the
`unsafe-audit` command and its budget, and made the rule-3 check mechanical.

## What remains for the external audit

- The **ASN1_ITEM template engine** (`crates/rustyssl-capi/src/asn1/tpl/`), which interprets
  application-defined templates over `#[repr(C)]` structs: the densest pointer arithmetic.
- The **provider ABI** (`provider/`, ADR 0003): third-party C providers' dispatch tables and
  OSSL_PARAM arrays are attacker-shaped input if a malicious provider is loaded.
- **Lifetimes of `get0` pointers** (README.md, "get0 pointers stay valid"): sub-objects at stable
  heap addresses; a reviewer should confirm no path reallocates them while a parent lives.
- The **secure heap** (ADR 0005) and the global allocator's scoping.
- The trampolines in `rustyssl-ossl` that hand Rust closures to C as `void *` arguments.
