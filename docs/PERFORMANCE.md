# Performance

How rustyssl compares with the reference OpenSSL (3.6.5, `-O3` with its assembly), how it's
measured, the targets, and what's left. Phase 12.1; TEST_PLAN.md L10.

## Measuring

`cargo xtask bench [--quick] [--runs N] [--seconds S] [speed|tls|misc...]`:

- `speed`: upstream's `openssl speed -mr` (the reference's binary) run on each library: digests,
  ciphers and AEADs at 16 B to 16 KiB; sign, verify, key exchange and KEM operations per second.
- `tls`, `misc`: `tests/bench/bench.c`, built against each library: handshakes per second (full
  and resumed, TLS 1.2 and 1.3, RSA and ECDSA P-256 servers, X25519MLKEM768; client and server in
  one thread over a BIO pair, the client verifying the chain), TLS 1.3 bulk throughput, heap per
  `SSL_CTX` and per connection, start-up, DRBG throughput, RSA-2048 key generation, and scaling
  over 1 to 8 threads sharing an `SSL_CTX`.

Each measurement runs `--runs` times (3), alternating the libraries; the report
(`target/bench-report.md`) has the medians and their spread, the numbers go to
`target/bench.json`. **Cost** is how many times slower (or bigger) rustyssl is.

**The regression gate.** `cargo xtask bench --compare <baseline.json>` fails when any of
rustyssl's numbers is more than `--threshold` percent (5) worse than the baseline's. It is meant
for a dedicated, quiet machine: keep a `bench.json` from `main` there and compare each branch with
it. Shared CI runners vary by more than 5%, so CI doesn't run it. (It caught a regression in this
phase: a whole-buffer wipe that halved 16-octet AES-CTR.) The thread-scaling numbers are the
noisiest (spreads to 45%); read them over several runs.

## Results (2026-10-21, Apple M-series, macOS, arm64)

"Before" is `main` at f007b4f8 (the phase's baseline); "after" is branch `p12-perf`.

### Symmetric (MB/s)

| measurement | unit | reference | rustyssl before | rustyssl after | cost before | cost after |
|---|---|---:|---:|---:|---:|---:|
| sha256 16 B | MB/s | 297 | 151 | 149 | 1.95× | 2.00× |
| sha256 64 B | MB/s | 1010 | 545 | 537 | 1.82× | 1.88× |
| sha256 256 B | MB/s | 2184 | 1535 | 1516 | 1.42× | 1.44× |
| sha256 1024 B | MB/s | 3022 | 2669 | 2641 | 1.15× | 1.14× |
| sha256 8192 B | MB/s | 3472 | 3393 | 3392 | 1.02× | 1.02× |
| sha256 16384 B | MB/s | 3494 | 3452 | 3468 | 1.01× | 1.01× |
| sha512 16 B | MB/s | 162 | 97.96 | 99.40 | 1.64× | 1.63× |
| sha512 64 B | MB/s | 638 | 388 | 399 | 1.63× | 1.60× |
| sha512 256 B | MB/s | 1127 | 903 | 918 | 1.24× | 1.23× |
| sha512 1024 B | MB/s | 1679 | 1545 | 1547 | 1.09× | 1.09× |
| sha512 8192 B | MB/s | 1955 | 1925 | 1936 | 1.01× | 1.01× |
| sha512 16384 B | MB/s | 1964 | 1964 | 1985 | 1.02× | 0.99× |
| sha3-256 16 B | MB/s | 86.52 | 63.89 | 65.03 | 1.35× | 1.33× |
| sha3-256 64 B | MB/s | 345 | 259 | 261 | 1.33× | 1.32× |
| sha3-256 256 B | MB/s | 865 | 713 | 715 | 1.21× | 1.21× |
| sha3-256 1024 B | MB/s | 1047 | 944 | 967 | 1.09× | 1.08× |
| sha3-256 8192 B | MB/s | 1161 | 1105 | 1125 | 1.03× | 1.03× |
| sha3-256 16384 B | MB/s | 1180 | 1133 | 1153 | 1.03× | 1.02× |
| aes-128-gcm 16 B | MB/s | 182 | 29.17 | 30.87 | 6.27× | 5.91× |
| aes-128-gcm 64 B | MB/s | 759 | 103 | 118 | 7.25× | 6.46× |
| aes-128-gcm 256 B | MB/s | 2847 | 273 | 393 | 10.26× | 7.24× |
| aes-128-gcm 1024 B | MB/s | 6071 | 489 | 1117 | 12.43× | 5.44× |
| aes-128-gcm 8192 B | MB/s | 8662 | 658 | 2611 | 13.04× | 3.32× |
| aes-128-gcm 16384 B | MB/s | 8943 | 674 | 2834 | 13.25× | 3.16× |
| aes-256-gcm 16 B | MB/s | 183 | 23.29 | 24.04 | 7.88× | 7.63× |
| aes-256-gcm 64 B | MB/s | 893 | 83.89 | 92.96 | 10.84× | 9.61× |
| aes-256-gcm 256 B | MB/s | 2466 | 234 | 319 | 10.98× | 7.72× |
| aes-256-gcm 1024 B | MB/s | 5476 | 443 | 959 | 12.50× | 5.71× |
| aes-256-gcm 8192 B | MB/s | 8400 | 623 | 2424 | 13.67× | 3.46× |
| aes-256-gcm 16384 B | MB/s | 8790 | 635 | 2681 | 13.81× | 3.28× |
| aes-128-cbc 16 B | MB/s | 1043 | 183 | 211 | 6.04× | 4.94× |
| aes-128-cbc 64 B | MB/s | 2641 | 425 | 472 | 6.52× | 5.59× |
| aes-128-cbc 256 B | MB/s | 3048 | 577 | 751 | 5.51× | 4.06× |
| aes-128-cbc 1024 B | MB/s | 3114 | 663 | 807 | 5.00× | 3.86× |
| aes-128-cbc 8192 B | MB/s | 3163 | 712 | 887 | 4.65× | 3.57× |
| aes-128-cbc 16384 B | MB/s | 3236 | 716 | 904 | 4.65× | 3.58× |
| aes-128-ctr 16 B | MB/s | 2249 | 200 | 307 | 11.43× | 7.34× |
| aes-128-ctr 64 B | MB/s | 7132 | 452 | 1021 | 15.50× | 6.99× |
| aes-128-ctr 256 B | MB/s | 14208 | 648 | 1652 | 22.16× | 8.60× |
| aes-128-ctr 1024 B | MB/s | 19570 | 759 | 2658 | 25.89× | 7.36× |
| aes-128-ctr 8192 B | MB/s | 20796 | 811 | 4182 | 25.69× | 4.97× |
| aes-128-ctr 16384 B | MB/s | 20761 | 826 | 4358 | 25.23× | 4.76× |
| chacha20-poly1305 16 B | MB/s | 645 | 140 | 157 | 4.58× | 4.10× |
| chacha20-poly1305 64 B | MB/s | 929 | 247 | 271 | 3.73× | 3.44× |
| chacha20-poly1305 256 B | MB/s | 1732 | 387 | 437 | 4.44× | 3.96× |
| chacha20-poly1305 1024 B | MB/s | 2471 | 722 | 887 | 3.39× | 2.79× |
| chacha20-poly1305 8192 B | MB/s | 2467 | 781 | 957 | 3.15× | 2.58× |
| chacha20-poly1305 16384 B | MB/s | 2467 | 786 | 958 | 3.11× | 2.57× |

### Public key (op/s)

| measurement | unit | reference | rustyssl before | rustyssl after | cost before | cost after |
|---|---|---:|---:|---:|---:|---:|
| rsa2048 sign | op/s | 3410 | 622 | 1057 | 5.43× | 3.22× |
| rsa2048 verify | op/s | 132139 | 7736 | 42844 | 17.08× | 3.08× |
| rsa3072 sign | op/s | 1178 | 254 | 383 | 4.60× | 3.08× |
| rsa3072 verify | op/s | 60669 | 3447 | 18488 | 17.88× | 3.28× |
| ecdsap256 sign | op/s | 106030 | 2462 | 18811 | 43.01× | 5.64× |
| ecdsap256 verify | op/s | 35150 | 1235 | 4967 | 28.29× | 7.08× |
| ecdsap384 sign | op/s | 14783 | 985 | 6084 | 14.92× | 2.43× |
| ecdsap384 verify | op/s | 7071 | 534 | 1927 | 13.16× | 3.67× |
| ed25519 sign | op/s | 81960 | 110282 | 108889 | 0.74× | 0.75× |
| ed25519 verify | op/s | 32018 | 41938 | 42303 | 0.76× | 0.76× |
| ecdhp256 derive | op/s | 42282 | 2213 | 7538 | 20.76× | 5.61× |
| ecdhx25519 derive | op/s | 59174 | 42523 | 43137 | 1.39× | 1.37× |
| ffdh2048 derive | op/s | 8485 | 2195 | 2559 | 3.83× | 3.32× |
| ML-KEM-768 keygen | op/s | 78303 | 32213 | 32377 | 2.42× | 2.42× |
| ML-KEM-768 encaps | op/s | 135009 | 76905 | 77422 | 1.73× | 1.74× |
| ML-KEM-768 decaps | op/s | 91392 | 49616 | 49803 | 1.85× | 1.84× |
| ML-DSA-65 keygen | op/s | 13835 | 9930 | 9896 | 1.39× | 1.40× |
| ML-DSA-65 sign | op/s | 2779 | 2865 | 2854 | 0.97× | 0.97× |
| ML-DSA-65 verify | op/s | 15599 | 13232 | 13326 | 1.17× | 1.17× |

### TLS

| measurement | unit | reference | rustyssl before | rustyssl after | cost before | cost after |
|---|---|---:|---:|---:|---:|---:|
| handshake tls1.3 ecdsa full | /s | 3729 | 508 | 1216 | 7.78× | 3.07× |
| handshake tls1.3 rsa full | /s | 1830 | 415 | 636 | 4.62× | 2.88× |
| handshake tls1.3 ecdsa resume | /s | 4944 | 2413 | 2560 | 2.17× | 1.93× |
| handshake tls1.3 ecdsa full X25519MLKEM768 | /s | 3904 | 505 | 1236 | 8.26× | 3.16× |
| handshake tls1.2 ecdsa full | /s | 5805 | 543 | 1500 | 11.44× | 3.87× |
| handshake tls1.2 rsa full | /s | 2230 | 443 | 689 | 5.22× | 3.24× |
| handshake tls1.2 rsa resume | /s | 32458 | 8391 | 12383 | 4.05× | 2.62× |
| bulk tls1.3 aes-128-gcm | MB/s | 3466 | 290 | 809 | 12.19× | 4.28× |
| threads_full_1 | /s | 3725 | 512 | 1213 | 7.71× | 3.07× |
| threads_full_2 | /s | 7135 | 958 | 2163 | 7.45× | 3.30× |
| threads_full_4 | /s | 13495 | 1649 | 3257 | 8.27× | 4.14× |
| threads_full_8 | /s | 20665 | 1748 | 2739 | 12.01× | 7.54× |
| threads_resume_1 | /s | 4957 | 2385 | 2569 | 2.15× | 1.93× |
| threads_resume_2 | /s | 9307 | 3773 | 4482 | 2.47× | 2.08× |
| threads_resume_4 | /s | 17224 | 5072 | 6953 | 3.41× | 2.48× |
| threads_resume_8 | /s | 24491 | 3763 | 5990 | 6.56× | 4.09× |
| threads_drbg_1 | /s | 7637503 | 854067 | 864299 | 9.15× | 8.84× |
| threads_drbg_2 | /s | 11979572 | 1403910 | 1559182 | 8.57× | 7.68× |
| threads_drbg_4 | /s | 8647953 | 2781616 | 3027255 | 3.13× | 2.86× |
| threads_drbg_8 | /s | 7987201 | 3605219 | 4085518 | 2.17× | 1.96× |

### Other

| measurement | unit | reference | rustyssl before | rustyssl after | cost before | cost after |
|---|---|---:|---:|---:|---:|---:|
| ctx_bytes | B | 23280 | 13312 | 13696 | 0.57× | 0.59× |
| conn_bytes | B | 150320 | 174624 | 141304 | 1.16× | 0.94× |
| init OPENSSL_init_ssl | us | 401 | 530 | 550 | 1.36× | 1.37× |
| init whole process | ms | 3.01 | 3.04 | 3.15 | 1.03× | 1.05× |
| drbg_32 | MB/s | 240 | 27.30 | 27.80 | 9.00× | 8.64× |
| drbg_4096 | MB/s | 9658 | 605 | 1765 | 16.24× | 5.47× |
| rsa_keygen_p10 | ms | 8.48 | 66.72 | 48.61 | 6.10× | 5.73× |
| rsa_keygen_median | ms | 20.62 | 163 | 114 | 8.66× | 5.52× |
| rsa_keygen_p90 | ms | 39.19 | 437 | 336 | 9.73× | 8.56× |


## Targets

The initial goals (Implementation Plan 12.1) were within 1.25× of the reference on hot symmetric
paths and within 1.5× on handshakes. Measured against an assembly-optimized reference, with
assembly ruled out (AGENTS.md) and primitives from vetted crates:

| Target | Met? | Where it stands |
|---|---|---|
| Hashes (SHA-2, SHA-3) at 1 KiB and up: ≤ 1.25× | **met** | 1.02–1.15× |
| Hashes at 16 B: ≤ 1.25× | missed | ~2× (per-call overhead of the EVP layer) |
| AES-GCM / AES-CTR / AES-CBC bulk: ≤ 1.25× | missed | 3–5× (the `aes` crate's ARMv8 backend and our per-call layers; OpenSSL's are hand-written pipelined assembly) |
| ChaCha20-Poly1305 bulk: ≤ 1.25× | missed | 2.6× (Poly1305 has no ARM backend in its crate) |
| Ed25519, ML-DSA: ≤ 1.5× | **met** | 0.75×, 0.97–1.4× |
| X25519, ML-KEM: ≤ 1.5× | partly | 1.4×; 1.7–2.4× |
| Handshakes: ≤ 1.5× | missed | resumption 1.9–2.6×, full 2.9–3.9× (P-256 and RSA arithmetic) |
| Memory per connection | **met** | 0.94×; per `SSL_CTX` 0.59× |
| Start-up (whole process) | **met** | ~1.05× |

**Targets set for 1.0** (from this baseline, the user's decision 2026-10-22; tracked with `bench --compare`): no regression past 5%
on a dedicated machine; hashes ≤ 1.25× at 1 KiB and up (met); handshakes ≤ 4× and resumption
≤ 3× (met); AEAD bulk ≤ 5× (met). The initial 1.25×/1.5× goals stay the aim, and need the
follow-ups below.

## What was done

- Ciphers: CTR, CBC decryption and GCM's CTR encrypt 32 blocks per call into the cipher (its
  parallel path); CBC encryption chains in the cipher's own type; stream modes and GCM run in the
  caller's output buffer (no copy, allocation or wipe); GCM's GHASH is keyed once.
- BIGNUM: Montgomery's CIOS without allocation, in vectorizable loops; `mul_n` unrolled for fixed
  sizes; RSA keys keep their Montgomery contexts (as OpenSSL's `_method_mod_*`); public exponents
  by square-and-multiply over their bits; DH keeps its group prime's context.
- EC: field elements on the stack; fields cached per process; the standard generator by a
  constant-time fixed-base comb (complete formulas, table scanned whole).
- DRBG: output blocks in batches.
- Locks: EVP fetch lookups under a read lock; RAND_bytes without a lock when there's no random
  provider; TLS group and signature-algorithm discovery once per `SSL_CTX` (as OpenSSL).

Every change keeps the output byte for byte (upstream `evp_test`, `bntest`, `ectest`, `rsa_test`,
`test-c`, and a unit test of the comb against the ladder on every named curve) and keeps secret
paths constant time (`test-timing`).

## Follow-ups

- P-256/P-384: a faster field (dedicated squaring, special-prime reduction) and larger comb
  windows; a windowed multiplication for the arbitrary point (verify, ECDH).
- RSA: a dedicated Montgomery squaring; RSA key generation (sieve, fewer trial exponentiations).
- AES: a pipelined CTR/GCM over `core::arch` intrinsics in a vetted backend (or contributing one
  to RustCrypto); Poly1305 for ARM likewise.
- Per-call overhead for small inputs (EVP digest and cipher setup, DIT toggling per operation).
- Thread scaling: per-thread EVP method caches (the shared read lock still bounces between
  cores), the primary DRBG's reseed-counter lock.
- The CTR-DRBG's per-generate re-key (key expansion and a boxed cipher each time).
- x86_64 measurements (all of these are arm64 macOS).
