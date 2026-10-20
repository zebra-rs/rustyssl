# ADR 0005: Private keys in the secure heap

- **Status:** Accepted, 2026-10-19 (milestone M6). The user decided that rustyssl stores
  secrets in the secure heap when it's enabled, as OpenSSL does.

## Context

`CRYPTO_secure_malloc_init` sets up OpenSSL's secure heap: one arena between guard pages,
locked into memory (`mlock`) and, on Linux, left out of core dumps. rustyssl implements it in
`crates/rustyssl-capi/src/secure.rs`, with OpenSSL's block placement (`secure/buddy.rs`).

OpenSSL 3.6.5 puts secrets there when the heap is set up: the digits of secure `BIGNUM`s
(`BN_secure_new`, and any `BIGNUM` flagged `BN_FLG_SECURE` when it next grows), the private
keys the key managers make (RSA, DH, DSA, EC, ECX, ML-KEM, ML-DSA, SLH-DSA, MAC keys),
private keys decoded from DER or PEM, and the random generator's entropy pools. Measured on
the reference (`CRYPTO_secure_used()` around each operation), it does *not* put there a
cipher's key schedule, a MAC's or KDF's key, the DRBGs' state, or public keys.

rustyssl's secrets are Rust values (`BigNum` limbs in a `Vec`, `Option<Vec<u8>>` for ECX keys,
third-party crates' key types), so before this decision nothing of a key was in the arena:
`CRYPTO_secure_used()` stayed at 0 while keys existed, and Node.js's
`test-crypto-secure-heap` failed on it. Reporting arena use without the keys being there would
claim work not done (`AGENTS.md`, rule 10).

## Decision

1. **A scoped global allocator.** libcrypto's Rust global allocator (`secure/global.rs`) is
   the system allocator, except on a thread inside `secure::scope`: there, when the arena is
   set up, an allocation is placed in it. A block in the arena stays there: growing it moves it
   to another arena block, freeing it zeroes it and returns it to the arena (from any thread),
   and a value moved into the arena from the system heap leaves its old block zeroed. Nothing
   in `rustyssl-crypto` changes; it stays `#![forbid(unsafe_code)]`.
2. **Copy the finished key, don't make it in a scope.** Scoping a whole key generation also
   catches one-time state its first use sets up (lazily built tables, the private DRBG, method
   caches), which would stay in the arena for the life of the process: a first attempt left
   200 KB there after one RSA key. So the key managers' results are copied into the arena once
   made (`Keymgmt::move_to_secure`: a scoped `dup`, the original freed), after key generation
   (`EVP_PKEY_generate`), loading from a decoder (`evp_keymgmt_load`), `EVP_PKEY_fromdata`, and
   a legacy key's export to its provider. Only rustyssl's own key managers are copied (an
   external provider's memory is its own) and only key data with a private key.
   `EVP_PKEY_dup` and the key managers' `dup` of a private key run in a scope.
3. **Secure `BIGNUM`s and legacy keys.** A store into a `BIGNUM` flagged `BN_FLG_SECURE` runs in
   a scope (`Bignum::store`, `Bignum::update`). The legacy `RSA`, `DH` and `DSA` objects move
   their private numbers into the arena whenever they're set (`update_key`, `replace`, and the
   generators), and the `BIGNUM`s `RSA_get0_*`, `DH_get0_*` and `DSA_get0_*` hand out for
   private numbers are secure ones, as OpenSSL's are.
4. **A reserve for the library's own secure allocations.** A key object copied whole is larger
   than OpenSSL's private components (an X25519 key: 352 bytes against 32; ML-KEM-768: 12544
   against 2048). So that keys can't starve the allocations OpenSSL makes in the arena (a new
   thread's DRBG entropy, an application's `OPENSSL_secure_malloc`), Rust's allocations use the
   arena only while it is less than half full; past that they fall back to the system
   allocator. Explicit `CRYPTO_secure_malloc` calls can use all of it, as before. Without the
   reserve, 40 Ed25519 keys in a 4 KiB arena stop a new thread's DRBG from instantiating
   (`tests/c/secure_heap_full.c`).

## Consequences

- With the secure heap set up, private keys live in locked, guard-paged memory that's left out
  of core dumps, and are zeroed when freed, as with OpenSSL. Node.js's `test-crypto-secure-heap`
  passes, and `CRYPTO_secure_used()` grows while keys exist and shrinks when they're freed.
- The amounts differ from OpenSSL's: the whole key object is in the arena (its public parts
  too), and `BIGNUM`s grow by what they need where OpenSSL rounds up. Tests compare only whether
  the counter grows, stays, or shrinks (`tests/c/secure_heap_keys.c`). Unlike OpenSSL, rustyssl
  returns to an empty heap once the keys are freed (the reference keeps some memory of RSA and
  SLH-DSA keys).
- When the arena can't hold a key, OpenSSL's operation fails (a 4 KiB arena can't hold an
  ML-DSA-65 key); rustyssl keeps the key in ordinary, zeroized memory instead. A Rust allocation
  can't fail gracefully, and failing would fail operations OpenSSL completes, since rustyssl
  needs more of the arena (`docs/DEVIATIONS.md`).
- An X25519 private key made with `EVP_PKEY_new_raw_private_key` goes to the arena, where the
  reference keeps it elsewhere (`docs/DEVIATIONS.md`).
- The cost, when no secure heap is set up: one thread-local read per Rust allocation, and an
  address-range check per free. When one is, one copy of each private key.
