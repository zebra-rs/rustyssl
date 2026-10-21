# Threat model

rustyssl is a library loaded into other programs in place of OpenSSL. Its threat model is
OpenSSL's, minus the memory-safety bugs it exists to remove.

## Assets

- **Private keys and secrets** in memory: long-term keys (RSA, EC, EdDSA, ML-DSA, SLH-DSA),
  session keys and traffic secrets, PSKs, DRBG state, passwords handed to PEM/PKCS#12.
- **Integrity of security decisions:** certificate path validation results
  (`X509_V_ERR_*`), signature and MAC verification, TLS/QUIC handshake outcomes (the negotiated
  version, cipher, peer identity).
- **The host process:** memory safety and availability of the application that loaded the
  library.

## Attackers and what they control

| Attacker | Controls | Expected protection |
|---|---|---|
| A network peer (TLS/DTLS/QUIC client or server, OCSP/CMP/HTTP server) | every byte on the wire, timing of messages | no memory unsafety, no state confusion, correct handshake decisions, constant-time handling of secrets |
| A supplier of encoded data (certificates, CRLs, CMS/PKCS#7/#12, PEM, keys, configuration) | the bytes the application parses | no memory unsafety, bounded resource use, correct verification |
| An observer of timing or cache behaviour (same host or remote) | measurement | no secret-dependent branches or memory indexes in secret operations (rule 4) |
| A C caller misusing the API | arguments, call order, callbacks | OpenSSL's documented behaviour; where OpenSSL corrupts memory on misuse, rustyssl fails safely and records the deviation |

## Trust boundaries

1. **The C ABI** (`rustyssl-capi`). Pointers, lengths and callback pointers from the application
   are trusted only as far as OpenSSL's documentation says they are valid (security rule 2); the
   layer converts them once, checks what OpenSSL checks, and fails like OpenSSL where it fails.
   A C caller can always corrupt its own process (passing a wrong length, freeing twice); that
   is outside what any C library can prevent, and outside scope.
2. **Callbacks into the application** (verify, SNI, ALPN, PSK, ticket, BIO methods, providers).
   They may call back into the library on the same object (rule 7) or misbehave; rustyssl must
   stay consistent across them, and never hold a lock while one runs.
3. **Third-party C providers** (ADR 0003): loaded code with the process's full privileges.
   rustyssl can't defend against a malicious provider, but must not misuse a correct one
   (dispatch tables, `OSSL_PARAM` ownership, core upcalls).
4. **Configuration** (`openssl.cnf`, `OPENSSL_CONF`, `OPENSSL_MODULES`): trusted as in OpenSSL
   (it can load modules); parsed with bounds, includes followed as OpenSSL does.
5. **The network**, through BIOs and the QUIC datagram layer: fully untrusted.

## Not in scope

- Side channels beyond timing and cache access patterns (power, EM, fault injection).
- Denial of service by resources the application allows (huge certificates within configured
  limits, many connections): rustyssl keeps OpenSSL's limits and adds bounds where OpenSSL has
  none (security rule 5), but doesn't promise more.
- The FIPS provider: rustyssl has none (README.md, "Compatibility target").
- Algorithms OpenSSL itself doesn't protect: the legacy provider's ciphers with S-box tables
  (docs/DEPENDENCIES.md lists which backends aren't constant-time), MD4/MD5/SHA-1 collisions.
