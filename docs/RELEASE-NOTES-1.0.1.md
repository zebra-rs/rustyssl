A security release: 1.0.1 fixes one advisory in a dependency, and changes nothing else in the libraries or the `openssl` tool (the same OpenSSL 3.6.5 ABI; `OpenSSL_version()` reads `OpenSSL 3.6.5+rustyssl.1.0.1 ...`). Upgrading from 1.0.0 is recommended.

## Security

- **[RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385)** in `ctutils` (now 0.4.5): before 0.4.4, `ctutils::Choice`'s mask functions could compile to a branch on a secret value, and its `u128` comparisons branched on 32-bit targets. RustCrypto's `digest` (MAC verification) and `universal-hash` (Poly1305, POLYVAL/GHASH) use it, so a timing side channel in those paths can't be ruled out for 1.0.0.

## Upgrading

Install this release's package for your layout in place of 1.0.0's ([docs/MIGRATION.md](https://github.com/zebra-rs/rustyssl/blob/v1.0.1/docs/MIGRATION.md)), or rebuild with `cargo xtask dist`. Programs that use rustyssl need no rebuild.

What 1.0 is, what was verified where, and its known gaps: [rustyssl 1.0.0's release notes](https://github.com/zebra-rs/rustyssl/releases/tag/v1.0.0).
