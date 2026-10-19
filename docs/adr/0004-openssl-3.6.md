# ADR 0004: The default build implements OpenSSL 3.6's ABI

- **Status:** Accepted, 2026-10-19 (implementation plan step 9.5). Decision 2 (no selectable
  3.5 build) was put to the user, who chose "3.6 only" on 2026-10-19.

## Context

rustyssl implemented OpenSSL 3.5's ABI first (the LTS series) and plans to add 3.6's
(`AGENTS.md`, compatibility target). OpenSSL 3.6.5 and 3.5.9 were released on the same day.
3.6's `libcrypto.num` adds 23 functions under `OPENSSL_3.6.0` and removes none; 26 existing
`EVP_PKEY_asn1_*` entries gain `DEPRECATEDIN_3_6` but stay exported; `libssl.num` is unchanged.
So a library exporting 3.6's symbol set is a strict superset of 3.5's, and a binary built
against 3.5 loads and resolves every symbol on it, the same way it does on OpenSSL 3.6 itself.

The headers change more than the `.num` files show: new objects (HKDF-SHA256/384/512, the
AES-CBC-HMAC-SHA*-ETM ciphers, the CMS KEM recipient info), new parameter and dispatch names
(the security category, deriving into an `EVP_SKEY`), new `X509_V_ERR_*` codes and
`X509_V_FLAG_OCSP_RESP_CHECK*`, new `SSL_CTRL_*` commands (142, 143) and `SSL_OP_*` bits, and
one changed default (`PKCS12_SALT_LEN` 8 to 16). Some of 3.6's behavior differs from 3.5's
where both define the same function.

Every generator, `dist`, the reference build and `abi-check` read the vendored series through
one constant, `OPENSSL_SERIES` in `xtask/src/targets.rs`; the version a library reports comes
from the generated header constants.

## Decision

1. **3.6.5 is vendored next to 3.5.9** (`abi/openssl-3.6/`, by `cargo xtask vendor 3.6.5`, the
   signature and checksum verified as for 3.5), and **`OPENSSL_SERIES` becomes `"3.6"`.** From
   then on codegen generates the bindings, constants, export lists and version scripts (with
   the `OPENSSL_3.6.0` node), stubs, error and object tables from 3.6; `dist` builds 3.6's
   libraries; `cargo xtask ref-openssl` builds the 3.6.5 reference; and every harness compares
   against it. The library reports `OpenSSL 3.6.5+rustyssl.<version>`.
2. **No selectable 3.5 build.** Keeping one would mean a second set of generated bindings per
   target, behavior switches through every crate wherever 3.5 and 3.6 differ, and a second
   reference and test matrix in CI. A 3.5 binary already runs unchanged on the 3.6 build
   (decision 3 checks it), so the only thing a 3.5 build would add is 3.5's exact behavior where
   3.6 changed it. Those changes are listed in `docs/IMPLEMENTATION_PLAN.md` (step 9.5), for
   users coming from the 3.5 LTS; if a distribution needs one of them kept, it is reconsidered
   then, per behavior, rather than by forking the whole build. The user confirmed this choice
   ("3.6 only") on 2026-10-19.
3. **3.5 compatibility is checked, not assumed.** `abi/openssl-3.5/` stays vendored, and
   `abi-check` verifies that every 3.5 export is exported with the same symbol version, that
   its prototype is unchanged, and that every public struct layout and constant 3.5 defines is
   unchanged in 3.6 (or lists the difference).
4. **Header differences beyond the `.num` files** are found by diffing the vendored headers'
   macro definitions (new, removed, changed) and by `abi-check` against the 3.6 reference; each
   new constant, control command, option bit, object, error code and parameter name gets an
   implementation or a recorded reason (for example `OPENSSL_NO_LMS`: LMS is off in the default
   build).
5. **3.6's behavior wins** wherever 3.6 differs from 3.5, measured against the 3.6.5 reference,
   since the library claims to be 3.6.

## Consequences

- Every generated file changes at once; the switch lands as one commit, with the 3.6 additions
  after it, each with its conformance test.
- Tests and expectations that named 3.5.9 (version strings, the reference's directory) follow
  the vendored version instead of a literal.
- A distribution that pins 3.5 LTS gets 3.6's behavior where 3.6 changed it; the list in the
  plan says where.
