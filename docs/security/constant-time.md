# Constant-time verification report (Phase 12.2)

Measured 2026-10-21 on `main` 4b424688 plus this phase's fix, on an Apple M5 Max (macOS,
aarch64). Security rule 4 (README.md) requires secret-independent timing: no branches or memory
indexes that depend on secret data, constant-time comparison of MACs and tags, constant-time
RSA PKCS#1 v1.5 (implicit rejection, Marvin) and CBC padding checks. This report collects how
that is checked and what the checks show. The method's history (the earlier CBC and X25519
findings, the DIT policy and its cost) is in TEST_PLAN.md, "Constant-time verification".

## How it is checked

| Check | Covers | Status |
|---|---|---|
| **dudect** (`cargo xtask test-timing`, `tests/timing/dudect.c`): Welch's t-test between a fixed and a random class of secret inputs, cropped at several percentiles; a target fails at \|t\| ≥ 10 (dudect's "definitely not constant time"), and is measured once more before it fails | AES-GCM, GHASH, Poly1305, `CRYPTO_memcmp`, X25519 (whole, derivation, context), BN `CONSTTIME` modular exponentiation, ML-KEM decapsulation, ECDSA signing, RSA raw and PKCS#1 v1.5 decryption (Marvin's valid/invalid-padding split), the TLS CBC record check through `SSL_read` (Lucky13) | run, both libraries, results below |
| **Arm DIT** (`PSTATE.DIT`): every operation on secrets runs with data-independent timing set on cores that have it (`rustyssl-crypto/src/dit.rs`) | instruction-level timing on Apple silicon and Armv8.4+ cores | in place since Phase 9; TEST_PLAN.md lists the operations |
| **Backends' claims** (docs/DEPENDENCIES.md, per crate) | the RustCrypto and dalek primitives | reviewed per crate; the non-constant-time ones are listed below |
| **Code review of rule 4's paths** | `subtle` comparisons, masks behind optimization barriers, DIT scopes | this phase: found and fixed the BN reduction below |
| tlsfuzzer's timing scripts (`test-tlsfuzzer --timing`) | Lucky13, Bleichenbacher/Marvin over TLS | not run here: they capture with `tcpdump`, which needs root (`/dev/bpf*`) on macOS. Their two concerns are measured by dudect's `tls-cbc-record` and `rsa-pkcs1-decrypt` instead; on Linux CI with root they run as the TEST_PLAN's weekly job. |
| ctgrind-style taint checks (valgrind) | secret-dependent branches and indexes, statically per run | not run: valgrind doesn't support macOS on Apple silicon; a Linux job remains (TEST_PLAN.md, L9 item 2) |

## Finding this phase: BN Montgomery reduction (fixed)

`bn-modexp-consttime` times `BN_mod_exp_mont_consttime` on a 2048-bit modulus with a fixed
exponent (2^2047: one set bit) against random 2048-bit exponents. At `test-timing`'s 40 000
measurements it passed (\|t\| 3.8–7.5 over four runs, the reference 1.1–2.0), but the margin was
suspicious, so it was measured at 160 000:

| rustyssl | \|t\| at 160 000 | fixed / random mean (ticks) |
|---|---:|---:|
| before | 14.56, 12.21 | 82 398 / 82 455 |
| before, with DIT set | 10.40 | 82 049 / 82 097 |
| after | 0.98, 1.84 | 82 693 / 82 701 |

The fixed class ran about 55 ticks (0.07%) faster, with or without DIT, so the cause was in the
code rather than the core's instruction timing. In `rustyssl-crypto/src/bn/mont.rs`, `redc`
computed OpenSSL's carry with the short-circuit `||` and `&&`, `sub_into` its borrow with `||`,
and the final selections (`redc`'s `carry - borrow` mask, the exponentiation's last
subtraction, and the window table scan's equality masks) were visible to the optimizer, which
can turn such selections into branches (as it did in the TLS CBC check, TEST_PLAN.md). They now
use `|` and `&`, and every mask passes through an optimization barrier (`core::hint::black_box`).
The cost is about 2% on this operation. The target now takes 160 000 measurements so that a
signal this small fails the run. RSA private operations, DH and DSA go through the same
exponentiation.

## Results

`cargo xtask test-timing`, rustyssl's \|t\| (the reference's in parentheses); every target under 10
on both runs (exit 0):

| Target | Measurements | Before the fix (40 000 for BN) | After |
|---|---:|---|---|
| aes-gcm | 400 000 | 1.57 (1.22) | 2.90 (2.28) |
| ghash | 400 000 | 1.89 (1.12) | 1.56 (2.12) |
| poly1305 | 400 000 | 1.66 (2.80) | 2.90 (1.33) |
| memcmp | 200 000 | 1.99 (1.94) | 1.83 (2.16) |
| x25519 | 100 000 | 1.82 (2.05) | 1.55 (2.42) |
| x25519-derive | 100 000 | 1.45 (3.00) | 1.56 (2.38) |
| x25519-ctx | 100 000 | 1.31 (1.38) | 1.32 (1.15) |
| bn-modexp-consttime | 160 000 (was 40 000) | 7.53 (1.13) | 1.19 (1.94) |
| ml-kem-decap | 100 000 | 2.49 (2.20) | 0.76 (1.65) |
| ecdsa-sign | 40 000 | 1.12 (3.05) | 1.84 (2.48) |
| rsa-raw-decrypt | 40 000 | 1.79 (1.91) | 1.85 (1.36) |
| rsa-pkcs1-decrypt | 40 000 | 1.52 (2.18) | 2.98 (3.04) |
| tls-cbc-record | 40 000 | 1.47 (2.53) | 1.57 (1.56) |

## Primitives that aren't constant time

From docs/DEPENDENCIES.md: the S-box table ciphers ARIA, Camellia, SM4, DES/3DES, Blowfish,
CAST5, RC2 and IDEA, and the Whirlpool digest, look up tables by secret-dependent indexes, as
OpenSSL's portable C implementations do. All but triple DES, ARIA, Camellia and SM4 are in the
legacy provider only. AES (AES-NI, Armv8 AES, or bitsliced software), ChaCha20, Poly1305,
GHASH/POLYVAL, the SHA-2/SHA-3 families, and the 25519/448 and NIST-curve arithmetic are
constant time by construction, with DIT covering the instruction level on Arm.

## Left

- tlsfuzzer's timing scripts and a ctgrind/valgrind taint run, both on Linux (above).
- dudect targets for the operations not yet measured directly: ML-DSA and SLH-DSA signing,
  EdDSA signing, DH/ECDH derivation on the NIST curves, the AES-CBC-HMAC composite ciphers'
  TLS mode, and HMAC verification through `EVP_DigestVerify`.
- Measurements on x86_64 (all of the above ran on Apple silicon).
