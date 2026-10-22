# rustyssl: the security audit package

For the outside firm doing rustyssl's external security audit (Phase 12.2, milestone M7). It
says what rustyssl is, what to look at and why, how to build and test it, and what is already
known. Written 2026-10-21 against `main` 4b424688 (the OpenSSL 3.6.5 ABI).

| Document | Contents |
|---|---|
| This file | what rustyssl is, the scope, an architecture summary, prior findings, a suggested plan |
| [threat-model.md](threat-model.md) | assets, attackers, trust boundaries, what is and isn't in scope |
| [testing.md](testing.md) | building, and running every test suite and tool |
| [../unsafe-review.md](../unsafe-review.md) | where the `unsafe` code is, its budget, and the internal review |
| [../constant-time.md](../constant-time.md) | the constant-time verification report |
| [../../DEVIATIONS.md](../../DEVIATIONS.md) | every place rustyssl deliberately differs from OpenSSL, with a test |
| [../../adr/](../../adr/) | the architecture decisions (0001 library layout … 0007 the CLI) |

## What rustyssl is

A memory-safe reimplementation of OpenSSL's libcrypto and libssl in Rust that is a **drop-in
binary replacement**: the same exported symbols and ELF symbol versions, sonames, struct
layouts, `*_ctrl` numbers, error codes, and byte-identical output, so applications built
against OpenSSL 3 run unchanged (README.md, "Compatibility target"). All 5 899 libcrypto and 603
libssl exports of OpenSSL 3.6.5 are implemented, as is the `openssl` command-line tool.

Its reason to exist is removing OpenSSL's memory-safety and parser CVE classes while keeping the
C ABI. The audit's main question is therefore: **can a C caller, a network peer, or a crafted
input cause memory unsafety, a secret leak, or a wrong security decision in rustyssl?**

## Scope

| Area | Where | Why it matters |
|---|---|---|
| The C ABI layer | `crates/rustyssl-capi` (391 k lines, almost all hand-written) | All `unsafe` code but the CLI's; every pointer from C is turned into Rust references here. In practice much protocol and format logic also lives here (X.509, CMS, PKCS#7/#12, OCSP, TS, CMP, the provider implementations, BIO), not only in the safe core crates. |
| The ASN1_ITEM template engine | `rustyssl-capi/src/asn1/tpl/` | Interprets application-defined `ASN1_ITEM` tables over `#[repr(C)]` memory: the densest pointer arithmetic. |
| Parsers of untrusted input | `rustyssl-asn1` (DER/BER, PEM, base64), capi's d2i/PEM/SMIME/HTTP readers, `rustyssl-conf` | OpenSSL's CVE history concentrates here. |
| TLS 1.0–1.3 and DTLS | `rustyssl-tls` (sans-IO state machines, record layer, cipher-string parser), `rustyssl-capi/src/ssl/` (the `SSL` API, BIO plumbing, callbacks) | Network-facing; downgrade, state-machine, and record-layer bugs. |
| QUIC | `rustyssl-quic`, `rustyssl-capi/src/ssl/quic*` | Network-facing; packet protection, stream state, flow control. |
| Cryptography | `rustyssl-crypto` (algorithm facade, DRBG, BIGNUM, built-in provider algorithms) over RustCrypto and dalek backends (docs/DEPENDENCIES.md) | Correctness and constant-time behaviour; RSA PKCS#1 v1.5 implicit rejection (Marvin), CBC padding. |
| Providers | `rustyssl-capi/src/provider/`, ADR 0003 | The OSSL_DISPATCH/OSSL_PARAM boundary, including third-party C providers. |
| The secure heap and allocator | `rustyssl-capi/src/mem*`, ADR 0005 | `CRYPTO_malloc` discipline, `CRYPTO_set_mem_functions`, secret zeroization. |
| The `openssl` tool | `crates/rustyssl-cli` (forbids `unsafe`) over `crates/rustyssl-ossl` (its FFI wrappers) | Lower priority: it runs as the invoking user; its servers (`s_server`, `ocsp -port`, `cmp` mock server) are network-facing. |

Out of scope: the vendored OpenSSL headers and `.num` files (inputs to code generation), `xtask`
(build and test tooling), the C test programs, and the RustCrypto/dalek crates themselves beyond
how rustyssl uses them (they have their own audits; docs/DEPENDENCIES.md records each one's
status).

## Architecture in brief

- **One implementation, two ABI facades** (ADR 0001). All code and state live in libcrypto;
  libssl is generated forwarders to libcrypto's `rustyssl_private_*` functions. Objects such as
  an `X509 *` are shared between the two without copies.
- **Safe, sans-IO core crates** (`rustyssl-asn1`, `-conf`, `-crypto`, `-pki`, `-tls`, `-quic`)
  forbid `unsafe`. `rustyssl-capi` adapts them to C: opaque handles (`SSL`, `X509`, `EVP_PKEY`,
  …) are pointers to Rust objects with OpenSSL's reference counting; public-layout structs
  (`ASN1_STRING`, `GENERAL_NAME`, `OSSL_PARAM`, …) are `#[repr(C)]` mirrors in `CRYPTO_malloc`
  memory.
- **Every export** runs inside `ffi::guard` (`ffi_export!`): a panic becomes an
  `ERR_R_INTERNAL_ERROR` and the function's failure value. Release builds keep integer overflow
  checks on.
- **Fail closed.** Unimplemented functions abort; deviations from OpenSSL exist only where
  OpenSSL's behaviour is unsafe, each documented and tested (about 300 entries in
  DEVIATIONS.md).
- **Generated ABI facts.** Struct layouts, constants, NIDs, error codes, export lists and
  version scripts come from OpenSSL's headers through `cargo xtask codegen`, never typed by hand;
  `cargo xtask abi-check` verifies symbols, versions, signatures, layouts and constants against
  the reference build.

The security rules are in README.md ("Security rules"); auditors should treat them as the
claims to test.

## Prior findings

What rustyssl's own testing has found, as context for where bugs have appeared (each fixed with
a regression test; git history has the details):

- **Timing:** LLVM turned the TLS CBC padding masks into data-dependent code (|t| 18–20 in
  dudect; fixed with an optimization barrier). On Apple silicon without Arm DIT, X25519 timing
  depended on the key's structure; every secret operation now runs with DIT set
  (TEST_PLAN.md, constant-time verification; [../constant-time.md](../constant-time.md)).
- **Logic:** differential testing against the reference found, among others, an HMAC DRBG that
  honoured a `cipher` parameter upstream ignores, AES-CBC-HMAC composites that refused TLS
  record mode on x86_64, and many error-code and output differences (Phase 9–11 plans).
- **Upstream unsafety recorded as deviations:** OpenSSL behaviours rustyssl refuses to copy,
  e.g. the OCSP responder that spins forever after an empty connection, a POP3 STARTTLS greeting
  read into uninitialized memory, null-pointer writes in `OPENSSL_cleanse(NULL, n)`.
- The internal unsafe review ([../unsafe-review.md](../unsafe-review.md)) found no
  memory-safety defect in the patterns it checked. Bugs that Miri and the fuzzers caught during
  development were fixed in the commits that introduced the code; the git history has them.

## Suggested audit plan

1. **Week 1: the boundary.** Read README.md's security rules and ADR 0001; sample the `unsafe`
   blocks of `rustyssl-capi` by module from `docs/security/unsafe-budget.txt` (largest first:
   `evp`, `provider`, `x509`, `ssl`); verify pointer/length handling (`ffi::bytes`), NULL
   conventions, integer conversions, and ownership (`get0`/`get1`/`set0`/`set1`, `*_free`).
2. **Week 2: the template engine and parsers.** `asn1/tpl/`, d2i/i2d of X.509, CMS, PKCS#12,
   OCSP; PEM and base64; CONF. Run and extend the fuzz targets (`fuzz/`, 108 targets).
3. **Week 3: TLS, DTLS and QUIC.** State machines in `rustyssl-tls` and `rustyssl-quic`,
   callback re-entrancy in `rustyssl-capi/src/ssl/` (rule 7: no lock held across a C callback),
   session resumption and tickets (rustyssl's own ticket format), downgrade protection.
4. **Week 4: cryptography.** Constant-time paths (RSA decryption and implicit rejection, ECDSA
   nonces, CBC padding, MAC/tag comparison, BN `CONSTTIME`), the DRBG and its seeding, key
   zeroization, and the providers' parameter handling; reproduce `cargo xtask test-timing`.
5. **Throughout:** the deviations list, and the differences between what the man pages promise
   and what rustyssl does (the reference build is the oracle: `cargo xtask ref-openssl`).
