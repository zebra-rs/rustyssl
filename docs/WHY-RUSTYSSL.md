# Why rustyssl's approach is worth it

*A reply to: "What security concerns? People `curl | bash` anyway. OpenSSL has been forked and
replaced for years. Changing the language removes one class of bugs, but plenty of real bugs are
outside that class."*

The comment has a point, and rustyssl agrees with its last sentence. This reply explains why the
project is still worth doing. It rests on three things you can check in the repository: **Miri**
for the unsafe code that remains, **fuzzing** for the parsers, and a **regression test for every
historical OpenSSL CVE**, including the many that have nothing to do with memory safety.

## 1. "People run `curl | bash` anyway"

That's true, and it doesn't change the problem. Careless users endanger themselves. A bug in a TLS
library endangers everyone who connects to an affected server, however careful they are.
Heartbleed (CVE-2014-0160) leaked private keys and passwords from servers whose operators had done
nothing wrong. The library is a single dependency shared by millions of programs, so fixing a
whole class of bugs once, there, gives more security per unit of work than almost anything else.

Security theater means measures that look good and change nothing. The test of rustyssl is the
opposite: whether it measurably removes bugs. The rest of this note is that measurement.

## 2. "As if C were the problem. There are already BoringSSL, LibreSSL, rustls..."

Those projects solve different problems:

| Option | Memory-safe? | Runs existing binaries unchanged? |
|---|---|---|
| OpenSSL, LibreSSL, BoringSSL | no (C) | OpenSSL yes; LibreSSL's API and ABI differ; BoringSSL has no stable ABI and isn't meant for general use |
| rustls, Go's `crypto/tls`, other language-native stacks | yes | no: applications must be rewritten or rebuilt against a different API |
| **rustyssl** | **yes, except an internally reviewed FFI layer** | **yes**: the same `libcrypto.so.3` / `libssl.so.3`, the same symbols and symbol versions, no recompile |

The forks kept C, so they kept the bug class. The native stacks removed the bug class, but each
application has to be ported to them, and most C, C++, Python, Ruby and Node.js software never
will be. rustyssl's niche is the combination of the two: memory-safe code that runs *existing
binaries* unchanged. That is why it carries the whole OpenSSL 3.6.5 ABI: all 5,899 libcrypto
exports and all 603 libssl exports.

As for whether C is the problem: Microsoft and Google's Chromium team have each reported that
roughly 70% of their serious security bugs were memory-safety bugs. OpenSSL's own record shows
the same pattern: Heartbleed was a buffer over-read; CVE-2022-3602/3786 were punycode buffer
overflows; CVE-2023-0286 was a type confusion in `GENERAL_NAME`; and dozens of ASN.1 parser CVEs
since 2002 were out-of-bounds reads and writes. Removing that class isn't everything, but it's
the largest single class.

## 3. Pillar one: Miri, for the unsafe code that has to remain

rustyssl doesn't claim to be "100% safe Rust". A C ABI can't be implemented without `unsafe`.
The claim is narrower and checkable:

- **`unsafe` is confined to the FFI layer** (`rustyssl-capi`, the CLI's bindings, and generated
  forwarders). Every crate that parses or speaks a protocol (ASN.1, X.509, PKCS, CMS, TLS, DTLS,
  QUIC, the config language) has `#![forbid(unsafe_code)]`, and CI checks this. The
  attacker-facing code, where OpenSSL's CVEs concentrated, is safe Rust.
- **Every unsafe operation is isolated and justified.** Lints require one unsafe operation per
  block, each with its own `// SAFETY:` comment. An unsafe budget per module fails CI when a count
  grows, so any new `unsafe` shows up in review. The FFI layer is big (about 38,000 one-operation
  blocks for about 6,500 exports), and nobody hides that: the numbers are in
  [`docs/security/unsafe-budget.txt`](security/unsafe-budget.txt).
- **Miri runs the whole FFI layer's test suite on every pull request,** in five parallel CI jobs.
  Miri is Rust's interpreter for undefined behaviour. It detects out-of-bounds and misaligned
  accesses, use-after-free, double frees, leaks, and violations of Rust's aliasing rules, none of
  which a normal test run would notice.

Miri has caught real bugs, which is the point of running it:

- **`RSA_up_ref` leaked every key it was ever called on.** Every provider operation
  up-references its key. Miri's leak check found it.
- **Handle teardown was undefined behaviour under Stacked Borrows.** A provider's teardown made
  upcalls that reached back into the object while it was being dropped. Miri reported it, and
  handles were redesigned so that teardown runs before the object drops.

Neither would have shown up in a normal test run, and in C the equivalent bugs are exactly what
later become CVEs.

## 4. Pillar two: fuzzing, for parsers and the C boundary

- **108 fuzz targets** cover every parser of untrusted input and much of the C boundary: DER and
  BER, X.509 certificates, CRLs and names, PKCS#7/#8/#12, CMS, OCSP, TS, CMP and CRMF, PEM and
  base64, TLS messages and records, DTLS, QUIC packets, frames and transport parameters, and the
  config language.
- **Many targets are model-based or round-trip checks,** not just crash detectors. They check
  that a decoded value re-encodes to the same bytes, or that a structure behaves like a reference
  model. That catches logic errors, not only crashes.
- **They run continuously.** ClusterFuzzLite runs on every pull request. The full set (6 shards,
  5 minutes per target) runs weekly and blocks every release. OSS-Fuzz project files are ready to
  submit. Any panic counts as a bug, and no panic can cross into C: every export catches unwinds,
  reports an error and fails closed.

Real bugs the fuzzers found:

- **A memory leak in `EVP_PKEY_CTX_set_params`:** octets copied for a legacy key method's ctrl
  were never freed. LeakSanitizer in the `meth` target found it.
- **A TLS encoder asymmetry:** a CertificateStatus message with no response re-encoded into a
  form the decoder (correctly, as OpenSSL does) refuses. The `tls_msgs` round-trip target found
  it.

The fuzzers also found OpenSSL's own quirks. For example, OpenSSL clears the y-bit when it
re-encodes a compressed point with x = 0 on a binary curve. These are behaviours rustyssl has to
match, and the fuzzers made them explicit instead of leaving them to be found in the field.

## 5. Pillar three: every OpenSSL CVE, memory-safety or not

The comment's strongest point is that plenty of real bugs are outside the memory-safety class.
That's correct, and it's why rustyssl doesn't rely on Rust alone. [`tests/cve/cves.txt`](../tests/cve/cves.txt) lists
**every OpenSSL CVE**: 304 of them, from CHANGES.md and OpenSSL's vulnerability page. Each one is
classified:

| Status | Count |
|---|---:|
| A regression test in `tests/cve/` (run against both rustyssl and the reference OpenSSL) | 235 |
| Covered by another suite: dudect timing tests, or upstream's own test | 19 |
| Covered by a CLI test | 2 |
| Not applicable (SSLv2, Kerberos, the FIPS module, other platforms' assembly, ...) | 47 |
| **Gap** (CVE-2018-0737, RSA key-generation timing; the note explains why dudect doesn't apply) | **1** |

Many of the tested CVEs are **logic, protocol and timing bugs that Rust would not prevent**, for
example:

- **CVE-2014-0224 (CCS injection):** a ChangeCipherSpec before the key exchange must fail the
  handshake.
- **CVE-2015-1793 (alternative chains):** chain building must not let a non-CA issue
  certificates.
- **CVE-2016-2107 and CVE-2003-0078 (CBC padding oracles):** they're tested for behaviour and for
  constant time with dudect.
- **CVE-2003-0131 (Bleichenbacher/Marvin):** RSA PKCS#1 v1.5 decryption is tested for constant
  time and implicit rejection.
- **CVE-2014-3566 (POODLE fallback):** `TLS_FALLBACK_SCSV` below the server's best version must
  get `inappropriate_fallback`.
- **CVE-2022-0778 and CVE-2023-0464 (denial of service):** `BN_mod_sqrt` with a composite modulus
  must return, and policy trees must be verified in bounded time and memory.
- **CVE-2021-3450:** `X509_V_FLAG_X509_STRICT` must not skip the CA purpose check.

Constant-time behaviour gets special attention, because it's exactly what a compiler can break.
Testing found that LLVM had turned rustyssl's TLS CBC padding masks into data-dependent branches
(dudect |t| of 18–20). An optimization barrier fixed it. Every secret operation on Apple silicon
now runs with Arm's DIT (data-independent timing) mode set.

Beyond the CVE suite, rustyssl's behaviour is checked against the reference OpenSSL by:
- upstream's own test tree (`test/recipes`), run on both libraries;
- Wycheproof's test vectors;
- BoringSSL's BoGo TLS test runner;
- tlsfuzzer;
- the test suites of rust-openssl, pyca/cryptography, ruby/openssl and Node.js;
- differential testing.

These differential tests found logic bugs too, such as an HMAC DRBG that honoured a parameter
OpenSSL ignores.

## 6. Where rustyssl refuses OpenSSL's bugs

Drop-in compatibility doesn't mean copying unsafe behaviour. Where OpenSSL itself crashes or
misbehaves, rustyssl fails safely instead, and records each case with a test in
[`docs/DEVIATIONS.md`](DEVIATIONS.md). Examples:

- `OPENSSL_cleanse(NULL, n)` writes to address 0 in OpenSSL; rustyssl does nothing.
- An `lhash` `doall` callback that deletes the next item makes OpenSSL visit freed memory.
- `OPENSSL_DIR_end` leaves a dangling pointer that a second call frees again.
- `openssl s_client -starttls pop3` can print uninitialized memory.
- `openssl ocsp -port` spins at 100% CPU forever after one empty connection.

## 7. What rustyssl does *not* claim

To be fair to the comment:

- **Rust doesn't remove logic bugs.** That's why the CVE suite, the differential testing and the
  timing tests exist. A new class of logic bug can still appear.
- **The FFI layer is large and `unsafe`.** Miri only checks the paths the tests reach, and
  fuzzers only find what they reach. Both reduce risk; neither proves its absence.
- **An external security audit hasn't been done yet.** The audit package is prepared
  ([`docs/security/audit/`](security/audit/README.md)), and the release notes say so plainly.
- **Performance is lower,** typically 2–5× slower on AES and full handshakes, because assembly is
  ruled out. That's the trade-off the project chose: security first, compatibility second,
  performance third.
- **It keeps OpenSSL's API, footguns included,** because the point is that existing programs run
  unchanged.

## Summary

rustyssl doesn't argue that "C is the only problem." It argues something narrower:

1. The largest class of historical OpenSSL bugs can be removed **for programs that will never be
   ported to another TLS stack**, without recompiling them.
2. Every other historical bug class is still tested for, **CVE by CVE**.
3. The unsafe code that remains is **budgeted, justified line by line, and checked by Miri** on
   every change.
4. The parsers are **fuzzed continuously**, and every finding gets a regression test.

That isn't security theater. Each claim comes with a test you can run: `cargo xtask test-cve`,
`cargo +nightly miri test -p rustyssl-capi`, and `cargo +nightly fuzz run <target>`.
