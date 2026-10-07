# abi/: vendored OpenSSL ABI definitions

These files are the source of truth for the C API and ABI that rustssl reproduces. They are
copied unmodified from a signed OpenSSL release by `cargo xtask vendor <version>`. Don't edit
them by hand: re-run the command, which replaces the whole `openssl-<major>.<minor>/`
directory.

Each `openssl-<major>.<minor>/` directory contains:

| Path | Contents |
|---|---|
| `VERSION.toml` | Release version, download URL, SHA-256, signing key, and the `Configure` targets used |
| `include/openssl/*.h` | The public headers, generated with default `Configure` options, except `configuration.h` |
| `config/<target>/openssl/configuration.h` | The one header that differs per target (for example, `RC4_INT` changes the size of `RC4_KEY`) |
| `util/libcrypto.num`, `util/libssl.num` | Every exported symbol with its version and build conditions |
| `crypto/objects/` | `objects.txt`, `obj_mac.num` (NIDs), and `obj_xref.txt` (signature-algorithm mapping) |
| `crypto/err/openssl.txt` | Error reason codes and strings |
| `doc/man3/`, `doc/man7/` | The API man pages (POD), our behavioral spec |
| `LICENSE.txt` | OpenSSL's license (Apache-2.0) |

To compile C code against a target's headers, put its config directory first:

```sh
cc -I abi/openssl-3.5/config/linux-x86_64 -I abi/openssl-3.5/include ...
```

`cargo xtask vendor` accepts a release only if its signature verifies against
`xtask/keys/openssl-pubkeys.asc` and chains to OpenSSL's trust anchor
`B146 647E 45A7 B339 47AB 226B 2A2C 87D1 6169 2D40`, and its SHA-256 matches both the published
checksum and any pin already recorded in `VERSION.toml`. It also checks that every file except
`configuration.h` is identical across the configured targets.
