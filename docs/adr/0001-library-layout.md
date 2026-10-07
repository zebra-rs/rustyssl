# ADR 0001: One implementation, two ABI facades

- **Status:** Accepted, 2026-10-07 (implementation plan step 0.6)
- **Replaces:** the `build.rs`-based linking planned for step 0.5

## Context

OpenSSL ships two libraries. Applications link `-lssl -lcrypto`, or only `-lcrypto`, and
pass objects such as `X509*` and `EVP_PKEY*` freely between the two. Binaries also record
where each function comes from:
- **Linux:** each reference names a symbol version, such as `SSL_CTX_new@OPENSSL_3.0.0`.
- **macOS:** each reference names a library, because of the two-level namespace.

A drop-in replacement must satisfy both, and work when linked statically.

If rustssl built two independent Rust libraries, each would carry its own Rust runtime:
allocator, panic machinery and statics. An object allocated by one library could then be
freed by the other. Statically linking both archives would also duplicate the standard
library.

## Decision

1. **libcrypto holds all code and state** (`rustssl-capi`). That includes everything libssl
   does, which lives under the private names `rustssl_private_<function>`. libcrypto exports
   them only for libssl: in its `RUSTSSL_PRIVATE` version node on Linux, and as ordinary
   exports with that prefix on macOS.
2. **libssl is only forwarders.** It defines exactly OpenSSL's libssl exports, and each one
   is a generated forwarder: `SSL_CTX_new` calls `rustssl_private_SSL_CTX_new` with the same
   arguments. It has no state and no Rust runtime: no standard library and no allocator
   shim. `cargo xtask dist` builds libssl from the crate's own forwarder objects alone, and
   fails if they reference anything besides `rustssl_private_*`.
3. **Cargo builds static archives, and `cargo xtask dist` links the shared libraries** with
   the C compiler. rustc gives every cdylib an anonymous version script, and GNU ld refuses
   to combine it with OpenSSL's named version nodes ("anonymous version tag cannot be
   combined with other version tags").
4. **Static archives:**
   - `libcrypto.a` is the whole implementation, Rust runtime included.
   - `libssl.a` holds the forwarder objects only.
   - Programs link `-lssl -lcrypto`, as with OpenSSL.
5. **To implement a libssl function,** write `rustssl_private_<name>` in `rustssl-capi` and
   run `cargo xtask codegen`. Its stub disappears, and the forwarder already exists. Nothing
   is ever implemented in `libs/libssl`.

## Evidence

Measured on macOS arm64, Linux glibc aarch64 and x86_64 (Debian trixie, `rust:1.99.0-slim-trixie`),
and Linux musl aarch64 (Alpine, `rust:1.99.0-alpine`):

| Check | Result |
|---|---|
| Exports | libcrypto: the 5,873 OpenSSL functions (5,876 since `enable-ec_nistp_64_gcc_128`; see Consequences) plus 603 private ones. libssl: exactly its 603. On Linux every symbol carries its OpenSSL version node, with no differences from the map. |
| Dependency | libssl needs libcrypto (`NEEDED libcrypto.so.3`, or an `LC_LOAD_DYLIB` entry), and on glibc records the `RUSTSSL_PRIVATE` version it uses |
| Forwarder code | A single tail-call branch: `b …@plt` on aarch64, `jmp *GOT` on x86_64, `b` to the stub on macOS |
| Binaries linked against **real OpenSSL**, run on ours with every symbol bound at load (`DYLD_BIND_AT_LAUNCH`, `LD_BIND_NOW`) | Homebrew 3.6.5: all 6,476 functions resolve (two-level namespace included). Debian 3.5.7: 6,459. Alpine 3.5: 6,402. Each is every function the distro build and ours have in common. |
| Static linking | A program referencing all 6,476 functions links from `libssl.a` + `libcrypto.a` without duplicate symbols on every platform, and calls reach libcrypto |
| Size of libssl | `libssl.a` is 95 KB (macOS) or ~240 KB (Linux), down from 19 MB when it carried its own runtime. The shared libssl is 137–226 KB. |
| Cost of forwarding | About 0.2 ns per call: 0.20 ns on macOS arm64, 0.16–0.22 ns on Linux aarch64. Measured with an equivalent pair of C libraries whose forwarder compiles to the same single branch. |

## Alternatives considered

- **Two independent Rust libraries,** each with its own code. Rejected: two runtimes and
  allocators sharing objects is unsound, and static linking duplicates the standard library.
- **Define the `SSL_*` functions in libcrypto and keep libssl empty.** glibc binds by version
  name rather than by library, so this would work there, but macOS's two-level namespace
  binds each symbol to the library recorded at link time. Rejected as non-portable.
- **Re-export from libcrypto on macOS** (`-reexported_symbols_list`). This costs nothing at
  run time, but it's macOS-only, and the forwarders cost 0.2 ns everywhere. It could come
  back later as an optimization.
- **A cdylib with a version script from `build.rs`** (the original step 0.5 plan). Rejected:
  rustc's own version script conflicts with it, as described under Decision.

## Consequences

- **Cost per call:** every libssl call takes one extra branch.
- **Tools:** `cargo xtask dist` needs `ar` and `nm`. On Alpine, libcrypto also needs
  `llvm-libunwind-dev` (rustc's musl std asks for `-lunwind`).
- **Extra dependencies from Rust's runtime:** compared with OpenSSL's libraries, libcrypto
  also depends on `ld-linux` and `libgcc_s` (glibc) or `libiconv` (macOS). On musl, gcc's
  startup files add `NEEDED libgcc_s.so.1` to libssl. All are harmless system libraries.
- **Export set vs distribution builds:** distributions configure OpenSSL differently from
  its default build:
  - **Supersets:** Debian builds without IDEA and MDC2. Alpine also leaves out the GF2m
    curves, compression, and SEED. Exporting more than they do is harmless.
  - **Closed gap:** Debian and Homebrew build with `enable-ec_nistp_64_gcc_128` and so
    export `EC_GFp_nistp224_method`, `EC_GFp_nistp256_method`, and `EC_GFp_nistp521_method`.
    rustssl now vendors with that option too (`CONFIGURE_OPTIONS` in
    `xtask/src/vendor.rs`), and binaries linked against Homebrew and Debian resolve all
    6,479 and 6,462 functions, including these three.
  - **Left out on purpose:** Debian also builds with `enable-unit-test`, which exports
    `SSL_test_functions`, a hook that hands OpenSSL's own unit tests pointers to its
    internal functions. Homebrew doesn't export it and no application needs it, so it's
    left out.
