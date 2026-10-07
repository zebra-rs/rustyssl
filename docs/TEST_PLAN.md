# rustssl Test Plan

Companion to [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). Rules are in
[AGENTS.md](../AGENTS.md).

## Goals

The tests must prove three things:

1. **Correctness.** The crypto and the protocols are right (vectors, RFCs, interop).
2. **Compatibility.** To an application, rustssl can't be told apart from OpenSSL: same
   ABI, same results, same error codes, same output bytes.
3. **Security.** No memory unsafety, no panics on hostile input, constant-time handling of
   secrets, bounded resource use, and no regressions of any historical OpenSSL CVE class.

Rust removes memory-safety bugs. It does not remove **logic, DoS, or timing bugs**, such as
CVE-2024-12797 (raw public key authentication not enforced) or CVE-2023-0464 (policy-tree
explosion). Layers L5, L7, and L9 exist for those.

## Oracles

| Oracle | Use |
|---|---|
| **Reference OpenSSL**: pinned 3.5.x, then 3.6.x and 4.0.x, built from source by `cargo xtask ref-openssl` with the default `./Configure` options and debug info, the same version as `abi/` | Ground truth for behavior, output bytes, and error codes |
| Wycheproof (C2SP), NIST CAVP/ACVP JSON vectors, RFC test vectors | Ground truth for cryptographic correctness |
| The upstream OpenSSL test suite, BoGo, tlsfuzzer, TLS-Anvil, x509-limbo, quic-interop-runner | Ground truth for protocol and PKI behavior |
| Consumer test suites (curl, nginx, OpenSSH, CPython, …) | Ground truth for "drop-in" |

**The golden rule:** expected outputs come from the reference or from the spec, **never from
rustssl itself**. You can only regenerate golden files with
`cargo xtask regen-golden --from-ref`.

## Test layers

| Layer | What | Where | Runs |
|---|---|---|---|
| L1 | Unit and property tests | `crates/*/src`, `crates/*/tests` | every PR |
| L2 | Known-answer tests | `tests/kat/` | PR (subset), nightly (full) |
| L3 | ABI conformance | `xtask abi-check` | every PR (gating) |
| L4 | C API conformance, dual-run | `tests/c/` | every PR |
| L5 | Differential against the reference | `tests/differential/`, `fuzz/` | PR (smoke), nightly |
| L6 | Upstream OpenSSL test suite | `xtask test-openssl-suite` | nightly |
| L7 | Protocol conformance and interop | `tests/interop/` | nightly and weekly |
| L8 | Consumer drop-in suites | `tests/consumers/` | nightly |
| L9 | Security: fuzzing, sanitizers, Miri, constant-time, CVE regressions | `fuzz/`, `tests/cve/` | PR (short), nightly and weekly (long) |
| L10 | Performance and resources | `benches/`, `xtask bench` | nightly, on a dedicated runner |
| L11 | Distro system tests | `tests/system/` | weekly and release |

---

### L1: Unit and property tests (Rust)

- Unit tests sit next to the code in every core crate.
- `proptest` properties:
  - DER encode/decode round trips for every type
  - BN arithmetic against `num-bigint` as the oracle
  - base64 and PEM round trips
  - OID text ↔ DER
  - cipher-string parser invariants
  - TLS record fragmentation and reassembly
  - DTLS reassembly with arbitrary fragment order
  - OSSL_PARAM get/set conversions
- `loom` models for the concurrent core: refcount handles, the method-store cache, the
  per-thread DRBG, and the session cache.
- Coverage through `cargo llvm-cov`: target at least 90% of lines in core crates, with branch
  coverage reported for parsers and state machines.

### L2: Known-answer tests

- **Wycheproof:** every AEAD (AES-GCM/CCM/EAX/SIV/GCM-SIV, ChaCha20-Poly1305), AES-CBC-PKCS5,
  AES-KW/KWP, HMAC, CMAC, HKDF, PBKDF2, RSA (PKCS#1 sign, verify, encrypt, decrypt; OAEP;
  PSS), ECDSA (every curve, DER and P1363 encodings), ECDH (including invalid-curve points),
  X25519, X448, Ed25519, Ed448, DSA, ML-KEM, ML-DSA, primality.
- **NIST CAVP/ACVP:** SHA-1/2/3, SHAKE, the AES modes, the DRBGs, the SP 800-108 and 800-56C
  KDFs, ECDSA, RSA, ML-KEM, ML-DSA, SLH-DSA.
- **RFC vectors:**
  - RFC 8448: TLS 1.3 traces, replayed **byte-exact** with a deterministic RNG test hook
  - RFC 5869 (HKDF), RFC 6070 (PBKDF2), RFC 7914 (scrypt), RFC 9106 (Argon2)
  - RFC 6979 (deterministic ECDSA), RFC 8032 (EdDSA), RFC 7748 (X25519/X448)
  - RFC 8439 (ChaCha20-Poly1305), RFC 9180 (HPKE), RFC 9001 (QUIC initial secrets and packet
    protection)
- **Upstream data files:** `test/recipes/30-test_evp_data/*.txt` (evpciph, evpmd, evpkdf,
  evpmac, evppkey, …) run through the public EVP API, once by a Rust runner and once by
  upstream `evp_test` in L6.

### L3: ABI conformance (`cargo xtask abi-check`, gating on every PR)

1. **The symbol set.** The dynamic exports of `target/dist` libraries equal the set derived
   from `*.num` under the default-build conditions. Each symbol carries the correct version
   node (`readelf --dyn-syms -V`; `nm` plus the export list on macOS). Nothing extra is
   exported except `RUSTSSL_PRIVATE`.
2. **Library metadata:** soname and install_name, `NEEDED` entries, version definitions,
   macOS compatibility versions.
3. **Signatures.** Every Rust `extern "C"` export matches the bindgen prototype of the
   vendored headers exactly: integer widths, pointer constness, variadics, and return types.
   Codegen asserts it at compile time: `generated/signatures.rs` assigns each hand-written
   export to a function pointer of the prototype's type, which compiles only if they match,
   on every target. abi-check confirms every export has its assertion.
4. **Layouts.** A generated C program, compiled with the official headers, prints
   `sizeof`, `alignof`, and `offsetof` for every public struct and union. These must equal
   the Rust `offset_of!` assertions.
5. **Constants.** The C compiler evaluates every header `#define` constant, and the results
   must equal `rustssl-abi`.
6. **Binary compatibility.** Binaries **prebuilt against the reference OpenSSL** run against
   our libraries (`LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH`). That exercises versioned-symbol
   resolution and two-level-namespace binding.
7. **Static linking.** `cc app.c libssl.a libcrypto.a` links and runs.
8. **Installed headers and pkg-config:** every installed header compiles on its own and with
   the others; `pkg-config --cflags --libs openssl` works.

### L4: C API conformance (dual-run)

- Each test in `tests/c/<family>/*.c` is a small C program with TAP output, compiled **once**
  against the official headers and then **run twice**: against the reference libraries and
  against ours. Passing on the reference validates the test. Passing on ours validates the
  implementation.
- Each test asserts:
  - return values, and NULL and edge-argument behavior, per the man page
  - ownership (`get0`/`get1`/`set0`/`set1`), with tests run under ASan+LSan and valgrind to
    catch double frees and leaks
  - refcounts
  - error-queue contents (`ERR_GET_LIB`/`ERR_GET_REASON`)
  - callback invocation order and arguments
  - re-entrancy (calling the API from inside callbacks)
- **NULL-robustness differential:** a generated test calls every export with NULL or zero
  arguments in a subprocess. If the reference survives, ours must return the same result. If
  the reference crashes, ours must not crash (being more robust is allowed and gets logged).
- **No export is marked "implemented" without at least one dual-run C test** (see the
  Definition of Done below).

### L5: Differential testing against the reference

- **Harness:** a small C *probe* program built twice, once linked to the reference and once
  to ours, each running in its own process. A Rust driver sends the same operations to both
  over a pipe and compares the results. Separate processes isolate crashes and avoid symbol
  clashes. On Linux, a `dlmopen` in-process mode can be added for fuzzing speed.
- **What's compared:** return codes, output bytes (DER, PEM, text and print output), the
  error queue (lib and reason), verify results (error code and depth), and `SSL_get_error`
  sequences. Accepted differences go in an allowlist where each entry points to a
  `DEVIATIONS.md` item.
- **Deterministic corpora:**
  - certificates: CT-log samples, the Mozilla and Debian CA bundles, x509-limbo, the upstream
    `test/certs`, frankencert-style mutants
  - CRLs and CSRs
  - keys in every format: PEM, DER, PKCS#8 plain and encrypted, PKCS#1, SEC1, MSBLOB, PVK
  - PKCS#12 files from OpenSSL, NSS `pk12util`, Java `keytool`, Windows `certutil`, and macOS
  - CMS, PKCS#7, and S/MIME messages; OCSP and TS responses
  - cipher strings, `openssl.cnf` files, ASN.1 mini-language strings, BN operations
- **Differential fuzzing:** libFuzzer targets drive both implementations with the same input:
  - DER by type, PEM, base64
  - `OBJ_txt2obj`, `ASN1_generate_nconf`
  - X.509 verification of fuzzed chains
  - the cipher-string and `SSL_CONF_cmd` parsers
  - BN operations
  - EVP streaming with random chunking
  - TLS server reactions to fuzzed ClientHellos (compare accept or reject and the alert type)
- When the **reference is wrong** (an upstream bug), record it and **don't copy it** if it's
  security-relevant. Report it upstream.

### L6: The upstream OpenSSL test suite (`cargo xtask test-openssl-suite`)

- Configure the pinned upstream tree and build it normally (internal-API tests need upstream's
  own static libraries). Then **relink** the public-API test programs and `apps/` against
  our libraries and run the `test/recipes/*.t` harness.
- Classify every test, and keep the list in `tests/openssl-suite/classification.toml`:
  - **(a) Public API** → must pass.
  - **(b) Needs internal symbols or headers** → excluded, with the reason.
  - **(c) Tests implementation details** (internal error strings, FIPS module) → excluded,
    with the justification.
- Key suites: `evp_test`, `sslapitest`, `ssl_test` (the `ssl-tests/*.cnf` matrices), the
  `tls13*` tests, `recordlentest`, `sslcorrupttest`, `servername_test`, `clienthellotest`,
  `cipherlist_test`, `dtlstest`, `quicapitest`, `quic_multistream_test`, `bntest`, `ectest`,
  `rsa_test`, the x509/verify/v3ext tests, `cms`, `pkcs12`, `ocsp`, `ts`, `cmp`, `conf`,
  `param`, and `provider` tests, plus the app-driven recipes (first with upstream `apps/`
  relinked, then with our CLI after Phase 11).
- Metrics: the pass rate per recipe goes on the dashboard. **No regressions** is a gating
  rule. Milestone targets are in the gate table below.

### L7: Protocol conformance and interoperability

- **BoGo** (the BoringSSL TLS test runner) with a rustssl shim written in C against the
  OpenSSL API, which also exercises capi. A config file lists the BoringSSL-only features
  we skip.
- **tlsfuzzer**, against `s_server` (upstream app relinked, later our CLI): the script set
  OpenSSL and GnuTLS run in their CI, covering fragmentation, extensions, renegotiation,
  invalid ECDHE points, version negotiation, and the timing scripts for Bleichenbacher/Marvin
  and Lucky13.
- **TLS-Anvil** combinatorial client and server testing, weekly.
- **The interop matrix** (docker-compose, nightly). Our client and our server each run
  against every peer, combining:

  | Dimension | Values |
  |---|---|
  | Peers | reference OpenSSL 3.5 / 3.0 / 1.1.1, BoringSSL, rustls, GnuTLS, NSS (`tstclnt`/`selfserv`), Go `crypto/tls`, Java JSSE, mbedTLS, wolfSSL |
  | Versions | TLS 1.0 / 1.1 (at `@SECLEVEL=0`), 1.2, 1.3 |
  | Key types | RSA 2048/3072/4096, RSA-PSS, ECDSA P-256/P-384/P-521, Ed25519, Ed448, ML-DSA |
  | Features | full and resumed handshakes (IDs and tickets), HRR, PSK, 0-RTT, client auth and post-handshake auth, ALPN, SNI, OCSP stapling, renegotiation, KeyUpdate, certificate compression, record size limit, hybrid PQ groups |
- **DTLS:** interop with the reference and GnuTLS, with loss, duplication, and reordering
  injected (a fault-injecting BIO plus netem).
- **QUIC:** quic-interop-runner cases (handshake, transfer, retry, resumption, zerortt,
  chacha20, keyupdate, multiplexing), plus curl and nghttp3 over HTTP/3.
- **PKI:** the full x509-limbo suite. Results equal the reference's or are stricter only
  where `DEVIATIONS.md` documents it. A dedicated hostname-verification corpus covers
  wildcards, IDNA, IP SANs, and the CN-fallback flags.

### L8: Consumer drop-in suites (`cargo xtask test-consumers <name>`)

Each consumer is built against the **official headers**. Its own test suite then runs twice,
once with the reference libraries and once with ours (in containers with the system
`libssl3`/`libcrypto3` swapped out). **Pass criterion: the same pass/fail set as the
reference run.** Any difference is the signal to investigate.

| Consumer | Exercises | Suite | From milestone |
|---|---|---|---|
| curl | libssl client (TLS, later QUIC) | `runtests.pl` TLS tests, plus live HTTPS | M2 |
| nginx | libssl server | nginx-tests `ssl*.t` | M2 |
| OpenSSH | libcrypto only | `make tests` (regress + unittests) | M3 |
| CPython | ssl, hashlib, hmac | `test_ssl`, `test_hashlib`, `test_hmac`, the asyncio SSL tests | M4 |
| Apache httpd | libssl server | perl-framework `t/ssl` | M4 |
| HAProxy | libssl | `reg-tests/ssl` | M4 |
| PostgreSQL | libssl | `src/test/ssl` TAP | M4 |
| Ruby `openssl` gem | very broad libcrypto and libssl | the gem's test suite | M5 |
| pyca/cryptography | very broad libcrypto | its test suite and vectors | M6 |
| rust-openssl (`openssl` crate) | broad | its test suite | M6 |
| Node.js (`--shared-openssl`) | broad | `test/parallel/test-crypto*`, `test-tls*` | M6 |
| OpenVPN, stunnel, socat, wget, git, Tor, BIND 9, Unbound, OpenLDAP, Postfix | mixed | their own suites, or smoke tests | M6 |
| pkcs11-provider, oqs-provider, tpm2-openssl | the provider ABI | their own suites | Phase 9 |
| ngtcp2 (ossl backend) | third-party QUIC API | its tests | Phase 10 |

### L9: Security testing

**Fuzzing (`fuzz/`, cargo-fuzz/libFuzzer).** Every parser and state machine has a target:
- DER, the `asn1_item_*` template engine (one target per built-in item), X.509, CRL, CSR
- PKCS#7, CMS, PKCS#12, OCSP, TS, CT, PEM, base64
- CONF, the ASN.1 mini-language, `BIO_printf`, BN operations
- the cipher-string and `SSL_CONF` parsers, MIME and S/MIME, HTTP responses
- the TLS client (fed server flights) and server (fed client flights), with structure-aware
  generators for the typed handshake messages
- DTLS and QUIC packets
- **API-sequence fuzzing:** random sequences of public calls on `SSL`/`SSL_CTX`/`EVP_*`
  objects, to find state-machine panics and capi UB

Seeds come from the upstream OpenSSL and BoringSSL fuzz corpora. Every PR fuzzes the affected
targets for 2–5 minutes. Nightly runs give each target an hour. OSS-Fuzz is onboarded after
M2. **Any crash, panic, hang, or OOM is a P0 bug** and gets a minimized regression test.

**Sanitizers and checkers:**
- L4, L5, and part of L8 run with ASan+UBSan on the C side and with our libraries built with
  `-Zsanitizer=address` (nightly toolchain, CI-only).
- TSan for multithreaded tests (a shared `SSL_CTX` under load, DRBG, session cache).
- valgrind memcheck for ownership and leaks.
- **Miri** on core-crate unit tests, and on the capi handle model and template engine with
  synthetic tables.
- An **unsafe budget**: `cargo geiger` reports per release, every `unsafe` block is reviewed,
  and a CODEOWNERS entry covers `rustssl-capi`.

**Constant-time verification:**
1. **dudect-style statistical tests** in CI for AES (backend), GHASH, Poly1305, X25519,
   ECDSA signing (nonce and scalar multiplication), RSA private decryption and the padding
   check, the CBC padding and MAC check, BN `CONSTTIME` modexp, HMAC verification, and ML-KEM
   decapsulation (implicit rejection).
2. **ctgrind-style taint checks:** secrets are marked undefined under valgrind, so any
   secret-dependent branch or index gets reported.
3. **The Marvin toolkit** against RSA decryption, both through the API and through TLS RSA
   key exchange.
4. **The tlsfuzzer timing scripts** (Lucky13, Bleichenbacher/Marvin).

**CVE regression suite (`tests/cve/`).** Every OpenSSL security advisory since 2014
(openssl-library.org vulnerabilities list) is classified as **applicable** (a test
reproduces the trigger and asserts safe behavior) or **not applicable** (the feature doesn't
exist; recorded with the reason). Representative entries:

| CVE | Class | Test |
|---|---|---|
| CVE-2014-0160 (Heartbleed) | over-read | the heartbeat extension is not supported; the peer request is ignored or rejected |
| CVE-2014-0224 | early CCS state confusion | an out-of-order ChangeCipherSpec is rejected |
| CVE-2015-1793 | alternate-chain forgery | the forged chain is rejected |
| CVE-2016-2105/2106 | length overflow | `EVP_EncodeUpdate`/`EncryptUpdate` with huge lengths fail safely |
| CVE-2016-2108 | ASN.1 negative zero | encode and decode are correct |
| CVE-2016-6309 | UAF on message realloc | large handshake messages are handled safely |
| CVE-2020-1971 | EDIPARTYNAME NULL deref | GENERAL_NAME_cmp is correct |
| CVE-2021-3449 | renegotiation NULL deref | renegotiation without sigalgs is handled |
| CVE-2021-3711 / 3712 | SM2 overflow / non-NUL-terminated ASN1_STRING | correct sizing; no reads past `length` |
| CVE-2022-0778 | BN_mod_sqrt infinite loop | it terminates on a non-prime modulus |
| CVE-2022-3602 / 3786 | punycode overflow | malicious name constraints are safe |
| CVE-2023-0286 | GENERAL_NAME X.400 type confusion | correct CHOICE typing |
| CVE-2023-0464 | policy-tree DoS | the bound is enforced in time and memory |
| CVE-2023-0215 / 0217 | BIO_new_NDEF UAF / DSA NULL deref | safe |
| CVE-2023-3446 / 3817 / 5678 | DH check and keygen DoS | bounded time with huge parameters |
| CVE-2024-0727 | PKCS#12 NULL deref | malformed PKCS#12 is rejected |
| CVE-2024-5535 | `SSL_select_next_proto` over-read | the empty-list edge cases match the fixed behavior |
| CVE-2024-6119 | otherName type confusion | identity checks are correct |
| CVE-2024-9143 | GF(2^m) out-of-bounds | invalid inputs are handled |
| CVE-2024-12797 | RPK authentication not enforced (logic) | the handshake aborts on verification failure |
| CVE-2025-9230 / 9231 / 9232 | KEK unwrap OOB / SM2 timing / `no_proxy` over-read | bounds and constant-time checks |

**Resource-exhaustion tests.** Assert explicit limits, with bounded time and memory, for
ASN.1 nesting depth, element counts, certificate chain length, `max_cert_list`, DTLS fragment
buffering, QUIC stream and flow limits, BN operand sizes (DH, RSA, and DSA parameter caps),
and the PEM, MIME, and HTTP header sizes.

**Misuse and robustness tests.** Calls after a fatal error, re-entrant calls from callbacks,
`SSL_CTX` mutated while shared across threads (TSan), and non-blocking BIOs that return 0 or
`-1` at every possible point.

**Supply chain.** `cargo deny check` (advisories daily, licenses, bans on C/asm build
dependencies), `cargo vet`, `cargo audit`, a reproducible-build check, and SBOM generation for
each release.

### L10: Performance and resources

- **Benchmarks**, using `criterion` plus a C bench harness that follows the `openssl speed`
  methodology:
  - digests, ciphers, and AEADs at 16 B to 16 KiB
  - sign and verify ops/s and key-exchange/KEM ops/s per algorithm
  - the RSA keygen time distribution
  - TLS handshakes/s (full and resumed, 1.2 and 1.3, RSA and ECDSA, hybrid PQ)
  - bulk loopback throughput
  - memory per idle connection and per `SSL_CTX`
  - `OPENSSL_init_crypto` startup cost, DRBG throughput
  - multithreaded scaling (a shared `SSL_CTX`, session-cache and DRBG contention)
- Everything is compared against the reference on the same dedicated runner. A slowdown of
  **more than 5% against the `main` baseline blocks merges**. The release targets against the
  reference are set after the first baseline (initial goals are in Implementation Plan 12.1).

### L11: Distro system tests (release gate)

- Container images: Debian 13, Ubuntu LTS, Fedora (current), an EL10-compatible distro, and
  Alpine (musl). Each has the system libssl and libcrypto replaced by rustssl packages.
- Scenarios:
  - package-manager operations over HTTPS
  - `sshd` and ssh logins
  - nginx and httpd serving TLS
  - `curl`/`wget`/`git clone` over HTTPS
  - `pip install`
  - a PostgreSQL connection with `sslmode=verify-full`
  - Fedora `update-crypto-policies --set DEFAULT|LEGACY|FUTURE`, whose effect must match the
    reference
- macOS: a swapped Homebrew `openssl@3` formula, running curl and Python.

---

## CI organization

| Tier | Trigger | Contents | Budget |
|---|---|---|---|
| PR fast | every push | fmt, clippy, L1, L2 subset, **L3**, L4 (dual-run), L5 smoke, fuzz 2–5 min on affected targets, `cargo deny` | ≤ 30 min |
| PR extended | merge queue | the full L2, L5 corpora, an L6 subset, interop smoke, sanitizer builds | ≤ 2 h |
| Nightly | daily | the full L6, BoGo, tlsfuzzer, x509-limbo, L8, fuzz 1 h/target, Miri, ctgrind, dudect, L10 | none |
| Weekly | weekly | TLS-Anvil, quic-interop-runner, long fuzzing campaigns, Marvin, L11 | none |
| Release | tag | everything, plus the distro matrix, a perf report, and audit sign-off | none |

Platforms: Linux x86_64 and aarch64 on glibc (Tier 1), Linux x86_64 on musl, and macOS
arm64 (Tier 2). Windows comes later.

**Today** (`.github/workflows/ci.yml`, since Phase 0.8), every push and PR runs these on
Linux x86_64:
- fmt, clippy, and the Rust tests;
- L4 dual runs (`test-c`) and L5 with 1,000 random sessions;
- Miri, `cargo deny`, and `cargo vet`;
- a codegen job that fails if regenerating from `abi/` or `cargo xtask coverage` changes any
  committed file, or if an export is defined without a `tests/c` program that calls it;
- L3, `cargo xtask abi-check`.

The weekly cron and manual runs add Linux aarch64, macOS arm64, and 5 minutes of fuzzing
per target. Those wait for a weekly run because the repository is private, so macOS
minutes cost 10x. The tiers above are filled in as their test layers come into being.

## Definition of Done for one exported function

A function counts as **implemented** in the coverage report only when all of these hold:

1. It's exported with the correct symbol version (L3).
2. Its signature matches the header (L3).
3. At least one **dual-run C conformance test** passes on the reference and on ours,
   including the documented error and NULL paths (L4).
4. If it computes or serializes something, a KAT or differential test covers it (L2/L5).
5. If it parses untrusted input, a fuzz target reaches it (L9).
6. For documented failures, the error-queue codes match the reference.
7. No new `unsafe` lacks a `SAFETY` comment and a review.
8. `xtask coverage` is updated.

## Milestone gates

| Milestone | Required |
|---|---|
| M0 | L3 fully green (with stubs); the L4 harness works on the reference |
| M1 | L2 green for digests, ciphers, MACs, KDFs, and DRBG; upstream `evp_test` symmetric files pass; EVP differential fuzzing clean for 24 h |
| M2 | curl and nginx L8 smoke pass; interop with reference `s_client`/`s_server` on TLS 1.3; TLS client and server fuzzers clean for 24 h |
| M3 | the OpenSSH regression suite matches the reference |
| M4 | nginx, curl, CPython, httpd, HAProxy, and PostgreSQL match the reference; the tlsfuzzer core set passes; at least 90% of eligible upstream ssl and x509 recipes pass |
| M5 | 100% libssl coverage; BoGo pass target (set once measured); the DTLS interop matrix is green |
| M6 | 100% libcrypto coverage; **at least 98% of eligible upstream tests** pass; the Ruby, pyca, rust-openssl, and Node suites match the reference |
| M7 | everything above, plus L11 green, the CVE suite complete, constant-time reports clean, perf targets met, and the external audit closed |
| M8 | M7 repeated against the 4.0 reference |

## Test data management

- Small vectors and golden files are committed under `tests/data/`.
- Large external suites (Wycheproof, x509-limbo, the upstream OpenSSL tree, BoGo, tlsfuzzer,
  consumer sources) are fetched by `xtask` at **pinned commits with checksums** into
  `target/testdata/`, never committed. They're untrusted data: each lives in its own
  directory, and their scripts run only inside the test containers.
- Downloaded packages for `usage-scan` are parsed, never executed.

## Reporting

A CI dashboard (published from the nightly run) shows the coverage % per API family, the
upstream suite pass rate per recipe, the consumer matrix, the interop matrix, fuzzing
stats (executions, coverage, open crashes), the constant-time results, and performance
against the reference.
